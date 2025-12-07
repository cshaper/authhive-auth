using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Infra;           
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Models.Auth.ConnectedId.Commands;
using AuthHive.Core.Models.Auth.ConnectedId.Events;

// [Enums]
using static AuthHive.Core.Enums.Core.OrganizationEnumConstants;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.Organization.Repositories;
using ConnectedIdEntity = AuthHive.Core.Entities.Auth.ConnectedId.ConnectedId;

namespace AuthHive.Auth.Handlers.Auth.ConnectedId;

public class CreateConnectedIdCommandHandler : IRequestHandler<CreateConnectedIdCommand, Guid>
{
    // ... (생성자 및 필드는 기존과 동일) ...
    private readonly IConnectedIdRepository _connectedIdRepository;
    private readonly IUserRepository _userRepository;             
    private readonly IOrganizationRepository _organizationRepository; 
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
        // 1~3. 유효성 검사 및 조회 (기존 동일)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid) throw new DomainValidationException("Validation failed", validationResult.Errors.Select(e => e.ErrorMessage));

        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null) throw new DomainEntityNotFoundException($"User {command.UserId} not found.");

        var organization = await _organizationRepository.GetByIdAsync(command.OrganizationId, cancellationToken);
        if (organization == null) throw new DomainEntityNotFoundException($"Organization {command.OrganizationId} not found.");

        if (await _connectedIdRepository.ExistsByUserAndOrganizationAsync(command.UserId, command.OrganizationId, cancellationToken))
            throw new InvalidOperationException("Already a member.");

        // ---------------------------------------------------------
        // 🚦 [SaaS 정책 로직] v2
        // ---------------------------------------------------------
        ConnectedIdStatus initialStatus = ConnectedIdStatus.Pending;

        if (command.ActivateImmediately) 
        {
            initialStatus = ConnectedIdStatus.Active;
        }
        else if (organization.JoinPolicy == OrganizationJoinPolicy.InvitationOnly)
        {
            throw new InvalidOperationException("Invitation only.");
        }
        else
        {
            // Bitwise Check
            JoinRequirement userFlags = JoinRequirement.None;
            if (user.IsEmailVerified)    userFlags |= JoinRequirement.EmailVerified;
            if (user.IsMobileVerified)   userFlags |= JoinRequirement.MobileVerified;
            if (user.IsIdentityVerified) userFlags |= JoinRequirement.IdentityVerified;

            JoinRequirement required = organization.JoinRequirements;
            if ((required & userFlags) != required)
            {
                JoinRequirement missing = required & ~userFlags;
                throw new DomainValidationException("Requirements not met.", new[] { $"Missing: {missing}" });
            }

            initialStatus = organization.JoinPolicy == OrganizationJoinPolicy.Automatic 
                ? ConnectedIdStatus.Active 
                : ConnectedIdStatus.Pending;
        }

        // 4. 엔티티 생성 (TriggeredBy 수정)
        // [수정됨 CS0019]: Guid?(Command)와 string("System") 간의 ?? 연산 불가 -> ToString() 변환 필요
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
            TriggeredBy = triggeredByString // [Fix applied]
        };

        // 5. 저장
        await _connectedIdRepository.AddAsync(entity, cancellationToken);

        // 6. 이벤트 발행 (Provider 및 InvitedBy 처리)
        var createdEvent = new ConnectedIdCreatedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = entity.Id, // BaseEvent
            OccurredAt = DateTime.UtcNow, // BaseEvent
            OrganizationId = command.OrganizationId, // BaseEvent
            
            ConnectedId = entity.Id,
            UserId = entity.UserId,
            MembershipType = entity.MembershipType,
            InitialStatus = entity.Status,
            JoinedAt = entity.JoinedAt,

            // [추가됨] Event 정의에 있는 required 필드 매핑
            Provider = "Internal", // 기본값 혹은 Command에서 전달받아야 함
            InvitedByConnectedId = null // 초대 로직이 아니므로 null (추후 초대 수락 로직 시 변경)
        };

        await _publisher.Publish(createdEvent, cancellationToken);

        return entity.Id;
    }
}