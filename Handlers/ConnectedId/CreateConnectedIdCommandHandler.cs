using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Infra;           // IPublisher
using AuthHive.Core.Exceptions;


using AuthHive.Core.Interfaces.Auth.Repositories; 

// 2. 타 도메인 리포지토리
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserQueryRepository

// [Models & Entities]
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Models.Auth.ConnectedId.Commands;
using AuthHive.Core.Models.Auth.ConnectedId.Events;

// [Enums]
using static AuthHive.Core.Enums.Core.OrganizationEnumConstants;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using ConnectedIdEntity = AuthHive.Core.Entities.Auth.ConnectedId.ConnectedId;
using AuthHive.Core.Interfaces.Auth.ConnectedId;
using AuthHive.Core.Interfaces.Organization.Core;

namespace AuthHive.Auth.Handlers.Auth.ConnectedId;

/// <summary>
/// [Command Handler] ConnectedId(멤버십) 생성 핸들러 (v18 Final - CQRS Refactored)
/// </summary>
public class CreateConnectedIdCommandHandler : IRequestHandler<CreateConnectedIdCommand, Guid>
{
    // [Write] 데이터 변경 (저장, 수정, 삭제)
    private readonly IConnectedIdCommandRepository _connectedIdCommandRepository;
    
    // [Read] 데이터 조회 (유효성 검사, 존재 여부 확인)
    private readonly IConnectedIdQueryRepository _connectedIdQueryRepository;
    private readonly IUserQueryRepository _userQueryRepository;           
    private readonly IOrganizationQueryRepository _organizationQueryRepository; 
    
    private readonly IPublisher _publisher;
    private readonly ILogger<CreateConnectedIdCommandHandler> _logger;
    private readonly IValidator<CreateConnectedIdCommand> _validator;

    public CreateConnectedIdCommandHandler(
        IConnectedIdCommandRepository connectedIdCommandRepository, // Write
        IConnectedIdQueryRepository connectedIdQueryRepository,     // Read (본인 도메인 조회)
        IUserQueryRepository userQueryRepository,                 
        IOrganizationQueryRepository organizationQueryRepository, 
        IPublisher publisher,
        ILogger<CreateConnectedIdCommandHandler> logger,
        IValidator<CreateConnectedIdCommand> validator)
    {
        _connectedIdCommandRepository = connectedIdCommandRepository;
        _connectedIdQueryRepository = connectedIdQueryRepository;
        _userQueryRepository = userQueryRepository;               
        _organizationQueryRepository = organizationQueryRepository; 
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Guid> Handle(CreateConnectedIdCommand command, CancellationToken cancellationToken)
    {
        // =================================================================
        // 1. 기본 유효성 검사
        // =================================================================
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid) 
            throw new DomainValidationException("Validation failed", validationResult.Errors.Select(e => e.ErrorMessage));

        // =================================================================
        // 2. 연관 엔티티 조회 (Read Repository 사용 - AsNoTracking 최적화)
        // =================================================================
        var user = await _userQueryRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null) 
            throw new DomainEntityNotFoundException($"User {command.UserId} not found.");

        var organization = await _organizationQueryRepository.GetByIdAsync(command.OrganizationId, cancellationToken);
        if (organization == null) 
            throw new DomainEntityNotFoundException($"Organization {command.OrganizationId} not found.");

        // =================================================================
        // 3. 비즈니스 로직: 중복 가입 체크 (Query Repository 사용)
        // =================================================================
        // ExistsByUserAndOrganizationAsync는 QueryRepository에 있어야 합니다.
        if (await _connectedIdQueryRepository.ExistsByUserAndOrganizationAsync(command.UserId, command.OrganizationId, cancellationToken))
            throw new InvalidOperationException("User is already a member of this organization.");

        // =================================================================
        // 4. 비즈니스 로직: SaaS 가입 정책(Policy) 검증
        // =================================================================
        ConnectedIdStatus initialStatus = ConnectedIdStatus.Pending;

        // 4-1. 강제 활성화 (관리자 생성 등)
        if (command.ActivateImmediately) 
        {
            initialStatus = ConnectedIdStatus.Active;
        }
        // 4-2. 초대 전용 조직인지 확인
        else if (organization.JoinPolicy == OrganizationJoinPolicy.InvitationOnly)
        {
            throw new InvalidOperationException("This organization accepts members by invitation only.");
        }
        // 4-3. 가입 요건(Requirements) 충족 확인
        else
        {
            JoinRequirement userFlags = JoinRequirement.None;
            if (user.IsEmailVerified)    userFlags |= JoinRequirement.EmailVerified;
            if (user.IsMobileVerified)   userFlags |= JoinRequirement.MobileVerified;
            if (user.IsIdentityVerified) userFlags |= JoinRequirement.IdentityVerified;

            JoinRequirement required = organization.JoinRequirements;
            
            // 필수 조건 미충족 시 예외
            if ((required & userFlags) != required)
            {
                JoinRequirement missing = required & ~userFlags;
                throw new DomainValidationException("Join requirements not met.", new[] { $"Missing Requirements: {missing}" });
            }

            // 자동 가입 정책이면 Active, 아니면 승인 대기(Pending)
            initialStatus = organization.JoinPolicy == OrganizationJoinPolicy.Automatic 
                ? ConnectedIdStatus.Active 
                : ConnectedIdStatus.Pending;
        }

        // =================================================================
        // 5. 엔티티 생성
        // =================================================================
        string triggeredByString = command.TriggeredBy.HasValue 
            ? command.TriggeredBy.Value.ToString() 
            : "System";

        var entity = new ConnectedIdEntity
        {
            UserId = command.UserId,
            OrganizationId = command.OrganizationId,
            Status = initialStatus,
            MembershipType = command.MembershipType,
            
            DisplayName = command.DisplayName ?? $"{user.FirstName} {user.LastName}".Trim(),
            OrganizationEmail = command.OrganizationEmail ?? user.Email,
            
            JoinedAt = DateTime.UtcNow,
            LastActiveAt = DateTime.UtcNow,
            TriggeredBy = triggeredByString
        };

        // =================================================================
        // 6. 저장 (Command Repository 사용)
        // =================================================================
        await _connectedIdCommandRepository.AddAsync(entity, cancellationToken);

        // =================================================================
        // 7. 도메인 이벤트 발행
        // =================================================================
        var createdEvent = new ConnectedIdCreatedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = entity.Id,
            OccurredAt = DateTime.UtcNow,
            OrganizationId = command.OrganizationId,
            
            ConnectedId = entity.Id,
            UserId = entity.UserId,
            MembershipType = entity.MembershipType,
            InitialStatus = entity.Status,
            JoinedAt = entity.JoinedAt,
            
            Provider = "Internal",
            InvitedByConnectedId = null 
        };

        await _publisher.Publish(createdEvent, cancellationToken);

        return entity.Id;
    }
}