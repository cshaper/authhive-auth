using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserQueryRepository
using AuthHive.Core.Interfaces.User.Repositories.Security;  // IUserSocialAccountCommandRepository
using AuthHive.Core.Interfaces.Infra;

// [Models & Entities]
using AuthHive.Core.Models.User.Commands.Security;
using AuthHive.Core.Models.User.Events.Integration;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User.Security;

/// <summary>
/// [Auth] 외부 ID 계정 연결 핸들러
/// </summary>
public class LinkExternalAccountCommandHandler : IRequestHandler<LinkExternalAccountCommand, Unit>
{
    private readonly IUserQueryRepository _userQueryRepository; // [변경] 조회용
    private readonly IUserSocialAccountCommandRepository _socialCommandRepository; // [변경] 쓰기용
    
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<LinkExternalAccountCommandHandler> _logger;
    private readonly IValidator<LinkExternalAccountCommand> _validator;
    
    // [추가] 이벤트 발행 전용
    private readonly IPublisher _publisher;
    
    // [추가] 요청자 식별
    private readonly IPrincipalAccessor _principalAccessor;

    public LinkExternalAccountCommandHandler(
        IUserQueryRepository userQueryRepository,           // [변경]
        IUserSocialAccountCommandRepository socialCommandRepository, // [변경]
        IUnitOfWork unitOfWork,
        IValidator<LinkExternalAccountCommand> validator,
        IDateTimeProvider timeProvider,
        IPublisher publisher,                               // [변경]
        ILogger<LinkExternalAccountCommandHandler> logger,
        IPrincipalAccessor principalAccessor)               // [추가]
    {
        _userQueryRepository = userQueryRepository;
        _socialCommandRepository = socialCommandRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _timeProvider = timeProvider;
        _publisher = publisher;
        _logger = logger;
        _principalAccessor = principalAccessor;
    }

    public async Task<Unit> Handle(LinkExternalAccountCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling LinkExternalAccount (Cmd: {CommandId}) for User {UserId} with {Type}:{Id}",
            command.CommandId, command.UserId, command.ExternalSystemType, command.ExternalUserId);

        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Validation failed.", errorMessages);
        }

        // 2. 사용자 존재 확인 (Query Repo)
        var user = await _userQueryRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new KeyNotFoundException($"Target User not found: {command.UserId}");
        }

        // 3. Provider Enum 변환
        if (!Enum.TryParse<SocialProvider>(command.ExternalSystemType, ignoreCase: true, out var providerEnum))
        {
            throw new ArgumentException($"Invalid ExternalSystemType: {command.ExternalSystemType}");
        }

        // 4. [중요] 중복 연결 체크 (이미 연결된 계정인지 확인)
        // CommandRepo를 통해 최신 상태를 확인하는 것이 안전합니다.
        var existingAccount = await _socialCommandRepository.GetByProviderKeyAsync(providerEnum, command.ExternalUserId, cancellationToken);
        
        if (existingAccount != null)
        {
            if (existingAccount.UserId == command.UserId)
            {
                _logger.LogWarning("Account already linked to this user. Skipping. User: {UserId}", command.UserId);
                return Unit.Value; // 멱등성 처리
            }
            else
            {
                // 다른 사용자가 이미 쓰고 있는 소셜 계정인 경우
                throw new InvalidOperationException("This external account is already linked to another user.");
            }
        }

        // 5. Entity 생성
        var socialAccount = new UserSocialAccount
        {
            UserId = command.UserId,
            Provider = providerEnum,
            ProviderId = command.ExternalUserId,
            Email = command.Email,
            DisplayName = command.DisplayName,
            LinkedAt = _timeProvider.UtcNow,
            IsActive = true
            // AccessToken 등은 필요 시 추가
        };

        // 6. 저장 및 커밋 (Command Repo)
        await _socialCommandRepository.AddAsync(socialAccount, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 7. 이벤트 발행
        var linkedEvent = new ExternalSystemLinkedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = command.UserId,
            OccurredAt = _timeProvider.UtcNow,

            // Audit Context
            TriggeredBy = _principalAccessor.UserId ?? command.UserId, // 인증되지 않은 상태면 본인으로 가정
            OrganizationId = _principalAccessor.OrganizationId,
            CorrelationId = command.CommandId.ToString(),

            // Event Props
            UserId = command.UserId,
            ExternalSystemType = command.ExternalSystemType,
            ExternalUserId = command.ExternalUserId,
            ExternalEmail = command.Email,
            DisplayName = command.DisplayName,
            LinkedAt = _timeProvider.UtcNow
        };
        
        await _publisher.Publish(linkedEvent, cancellationToken);

        _logger.LogInformation("External account {Provider} linked successfully to User {UserId}", socialAccount.Provider, command.UserId);

        return Unit.Value;
    }
}