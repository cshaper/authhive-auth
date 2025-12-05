using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Auth.Repository;   // IConnectedIdRepository
using AuthHive.Core.Interfaces.Infra;            // IUserRepository, IOrganizationRepository (추가됨)
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.Auth.ConnectedId;   // Entity
using AuthHive.Core.Models.Auth.ConnectedId.Commands; // Command
using AuthHive.Core.Models.Auth.ConnectedId.Events;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.Organization.Repositories;
using AuthHive.Core.Enums.Core; // Status, Event


namespace AuthHive.Auth.Handlers.Auth.ConnectedId;

/// <summary>
/// [v18 Final] ConnectedId(멤버십) 생성 핸들러
/// SaaS 정책(비트와이즈 인증 체크, 가입 승인 정책)을 반영하여 사용자를 조직에 연결합니다.
/// </summary>
public class CreateConnectedIdCommandHandler : IRequestHandler<CreateConnectedIdCommand, Guid>
{
    private readonly IConnectedIdRepository _connectedIdRepository;
    private readonly IUserRepository _userRepository;             // 정책 체크용
    private readonly IOrganizationRepository _organizationRepository; // 정책 체크용
    private readonly IPublisher _publisher;
    private readonly ILogger<CreateConnectedIdCommandHandler> _logger;
    private readonly IValidator<CreateConnectedIdCommand> _validator;

    public CreateConnectedIdCommandHandler(
        IConnectedIdRepository connectedIdRepository,
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IPublisher publisher,
        ILogger<CreateConnectedIdCommandHandler> logger,
        IValidator<CreateConnectedIdCommand> validator)
    {
        _connectedIdRepository = connectedIdRepository;
        _userRepository = userRepository;
        _organizationRepository = organizationRepository;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Guid> Handle(CreateConnectedIdCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Creating ConnectedId for User {UserId} in Org {OrgId}", command.UserId, command.OrganizationId);

        // 1. 기본 유효성 검사 (Command 필드 검증)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("ConnectedId creation failed.", errorMessages);
        }

        // 2. 데이터 조회 (정책 판단을 위해 User와 Organization 정보가 필요함)
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null) 
            throw new DomainEntityNotFoundException($"User {command.UserId} not found.");

        var organization = await _organizationRepository.GetByIdAsync(command.OrganizationId, cancellationToken);
        if (organization == null) 
            throw new DomainEntityNotFoundException($"Organization {command.OrganizationId} not found.");

        // 3. 중복 가입 체크
        bool exists = await _connectedIdRepository.ExistsByUserAndOrganizationAsync(command.UserId, command.OrganizationId, cancellationToken);
        if (exists)
        {
            throw new InvalidOperationException("User is already a member of this organization.");
        }

        // ---------------------------------------------------------
        // 🚦 [SaaS 정책 로직] v2 - Bitwise Verification Check
        // ---------------------------------------------------------
        
        ConnectedIdStatus initialStatus = ConnectedIdStatus.Pending;

        // A. 관리자/초대 시스템에 의한 강제 가입 (TriggeredBy 체크 등)
        // Command에 ActivateImmediately 플래그가 있다고 가정
        if (command.ActivateImmediately) 
        {
            initialStatus = ConnectedIdStatus.Active;
            _logger.LogInformation("Policy Check: Skipped (Immediate Activation Requested).");
        }
        else if (organization.JoinPolicy == OrganizationJoinPolicy.InvitationOnly)
        {
            // B. 초대 전용 정책인데 직접 가입 시도 -> 차단
            throw new InvalidOperationException("This organization accepts invitations only.");
        }
        else
        {
            // C. 사용자의 현재 인증 상태 계산 (User Entity -> Flags 변환)
            JoinRequirement userStatus = JoinRequirement.None;

            if (user.IsEmailVerified) 
                userStatus |= JoinRequirement.EmailVerified;
            
            if (user.IsMobileVerified) 
                userStatus |= JoinRequirement.MobileVerified;

            if (user.IsIdentityVerified) 
                userStatus |= JoinRequirement.IdentityVerified;

            // D. 조직의 요구사항 충족 여부 체크 (Bitwise AND)
            // (조직 요구사항 & 유저 상태) == 조직 요구사항 이면 통과
            bool meetsRequirements = (organization.JoinRequirements & userStatus) == organization.JoinRequirements;

            if (!meetsRequirements)
            {
                // 실패 시: 어떤 조건이 부족한지 계산
                var missing = organization.JoinRequirements & ~userStatus;
                
                throw new DomainValidationException(
                    "User does not meet the join requirements.", 
                    new[] { $"Required: {organization.JoinRequirements}, Missing: {missing}" }
                );
            }

            // E. 요구사항 통과 후, 정책(Policy)에 따른 초기 상태 결정
            switch (organization.JoinPolicy)
            {
                case OrganizationJoinPolicy.Automatic:
                    initialStatus = ConnectedIdStatus.Active;
                    break;
                
                case OrganizationJoinPolicy.AdminApproval:
                    initialStatus = ConnectedIdStatus.Pending; // 조건은 맞지만 승인 대기
                    break;
                    
                default:
                    initialStatus = ConnectedIdStatus.Pending;
                    break;
            }
        }

        // 4. 엔티티 생성 (결정된 Status 반영)
        var entity = new AuthHive.Core.Entities.Auth.ConnectedId.ConnectedId
        {
            UserId = command.UserId,
            OrganizationId = command.OrganizationId,
            
            // 정책에 의해 결정된 상태값 적용
            Status = initialStatus, 
            MembershipType = command.MembershipType, 
            
            DisplayName = command.DisplayName ?? $"{user.FirstName} {user.LastName}".Trim(),
            OrganizationEmail = command.OrganizationEmail ?? user.Email, // 별도 지정 없으면 기본 이메일
            
            JoinedAt = DateTime.UtcNow,
            LastActiveAt = DateTime.UtcNow,
            
            // 기타 메타데이터
            TriggeredBy = command.TriggeredBy ?? "System"
        };

        // 5. 저장
        await _connectedIdRepository.AddAsync(entity, cancellationToken);

        _logger.LogInformation("ConnectedId created. ID: {Id}, Status: {Status}", entity.Id, entity.Status);

        // 6. 이벤트 발행
        var createdEvent = new ConnectedIdCreatedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = entity.Id,
            OccurredOn = DateTime.UtcNow,
            
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,

            ConnectedId = entity.Id,
            UserId = entity.UserId,
            MembershipType = entity.MembershipType,
            JoinedAt = entity.JoinedAt,
            InitialStatus = entity.Status
        };

        await _publisher.Publish(createdEvent, cancellationToken);

        return entity.Id;
    }
}