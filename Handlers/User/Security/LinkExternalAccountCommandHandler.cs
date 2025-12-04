using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Repositories.Security; // IUserSocialAccountRepository
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// [Models & Entities]
using AuthHive.Core.Models.User.Commands.Security;
using AuthHive.Core.Models.User.Events.Integration; // ExternalSystemLinkedEvent
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Enums.Auth; // SocialProvider Enum
using AuthHive.Core.Exceptions;
using FluentValidation;

namespace AuthHive.Auth.Handlers.User.Security;

/// <summary>
/// [Auth] 외부 ID 계정 연결 핸들러 (Link External Account)
/// </summary>
public class LinkExternalAccountCommandHandler : IRequestHandler<LinkExternalAccountCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUserSocialAccountRepository _socialRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<LinkExternalAccountCommandHandler> _logger;
    private readonly IValidator<LinkExternalAccountCommand> _validator;
    public LinkExternalAccountCommandHandler(
        IUserRepository userRepository,
        IUserSocialAccountRepository socialRepository,
        IUnitOfWork unitOfWork,
        IValidator<LinkExternalAccountCommand> validator,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<LinkExternalAccountCommandHandler> logger)
    {
        _userRepository = userRepository;
        _socialRepository = socialRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<Unit> Handle(LinkExternalAccountCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling LinkExternalAccountCommand for User {UserId} with {Type}:{Id}",
            command.UserId, command.ExternalSystemType, command.ExternalUserId);
        // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);

        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);

            throw new DomainValidationException("Validation failed.", errorMessages);
        }

        // 2. 사용자 존재 확인 (연결 대상)
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new KeyNotFoundException($"Target User not found: {command.UserId}");
        }

        // 3. Entity 생성 및 SocialProvider 매핑
        if (!Enum.TryParse<SocialProvider>(command.ExternalSystemType, ignoreCase: true, out var providerEnum))
        {
            throw new ArgumentException($"Invalid ExternalSystemType: {command.ExternalSystemType}");
        }

        var socialAccount = new UserSocialAccount
        {
            UserId = command.UserId,
            Provider = providerEnum,
            ProviderId = command.ExternalUserId, // ProviderId is the entity field name
            Email = command.Email,
            DisplayName = command.DisplayName,
            // AccessToken, RefreshToken logic omitted for brevity
        };

        // 4. 저장 및 커밋
        await _socialRepository.AddAsync(socialAccount, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행
        var linkedEvent = new ExternalSystemLinkedEvent
        {
            // BaseEvent Props
            EventId = Guid.NewGuid(),
            AggregateId = command.UserId,
            OccurredOn = _timeProvider.UtcNow,
            // Assuming Audit fields were added to LinkExternalAccountCommand
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = command.CorrelationId.ToString(),

            // Event Props
            UserId = command.UserId,
            ExternalSystemType = command.ExternalSystemType,
            ExternalUserId = command.ExternalUserId,
            ExternalEmail = command.Email, // Event requires ExternalEmail
            DisplayName = command.DisplayName,
            LinkedAt = _timeProvider.UtcNow
        };
        await _mediator.Publish(linkedEvent, cancellationToken);

        _logger.LogInformation("External account {Provider} linked successfully to User {UserId}", socialAccount.Provider, command.UserId);

        return Unit.Value;
    }
}