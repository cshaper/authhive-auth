using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IDateTimeProvider
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository
using AuthHive.Core.Interfaces.User.Repositories.Security; // IUserSocialAccountRepository (New)
using AuthHive.Core.Interfaces.Security; // ITokenService (for audit context)
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// [Models & Entities]
using AuthHive.Core.Models.User.Commands.Security;
using AuthHive.Core.Models.User.Events.Integration; // ExternalSystemUnlinkedEvent
using AuthHive.Core.Entities.User; // User Entity
using AuthHive.Core.Enums.Auth; // SocialProvider Enum
using AuthHive.Core.Exceptions;
using FluentValidation;

namespace AuthHive.Auth.Handlers.User.Security;

/// <summary>
/// [Auth] 외부 ID 계정 연결 해제 핸들러 (Unlink External Account)
/// </summary>
public class UnlinkExternalAccountCommandHandler : IRequestHandler<UnlinkExternalAccountCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUserSocialAccountRepository _socialRepository; // [New]
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<UnlinkExternalAccountCommandHandler> _logger;
    private readonly IValidator<UnlinkExternalAccountCommand> _validator; // Command Validator

    public UnlinkExternalAccountCommandHandler(
        IUserRepository userRepository,
        IUserSocialAccountRepository socialRepository,
        IUnitOfWork unitOfWork,
        IValidator<UnlinkExternalAccountCommand> validator,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<UnlinkExternalAccountCommandHandler> logger)
    {
        _userRepository = userRepository;
        _socialRepository = socialRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<Unit> Handle(UnlinkExternalAccountCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling UnlinkExternalAccountCommand for User {UserId} with {Type}:{Id}",
            command.UserId, command.ExternalSystemType, command.ExternalUserId);

        // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);

        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);

            throw new DomainValidationException("Validation failed.", errorMessages);
        }

        // 2. 사용자 및 소셜 계정 조회
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new KeyNotFoundException($"Target User not found: {command.UserId}");
        }

        // ExternalSystemType 문자열을 Enum으로 변환
        if (!Enum.TryParse<SocialProvider>(command.ExternalSystemType, ignoreCase: true, out var providerEnum))
        {
            throw new ArgumentException($"Invalid ExternalSystemType: {command.ExternalSystemType}");
        }

        // 3. 해제할 Social Account 엔티티 획득 (존재하지 않으면 이미 해제된 것으로 간주 가능)
        var socialAccountToDelete = await _socialRepository.GetByProviderKeyAsync(
            providerEnum,
            command.ExternalUserId,
            cancellationToken);

        if (socialAccountToDelete == null)
        {
            _logger.LogWarning("Account not found for unlinking. Assuming idempotency for User {UserId}.", command.UserId);
            return Unit.Value; // 멱등성(Idempotency)
        }

        // 4. 저장 및 커밋 (삭제)
        await _socialRepository.DeleteAsync(socialAccountToDelete, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행
        var unlinkedEvent = new ExternalSystemUnlinkedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = command.UserId,
            OccurredOn = _timeProvider.UtcNow,

            // Audit Context
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = command.CorrelationId.ToString(),

            // Event Props
            UserId = command.UserId,
            ExternalSystemType = command.ExternalSystemType,
            ExternalUserId = command.ExternalUserId,
            Reason = command.Reason, // Command에 Reason이 있다면 사용
            UnlinkedAt = _timeProvider.UtcNow
        };
        await _mediator.Publish(unlinkedEvent, cancellationToken);

        _logger.LogInformation("External account {Provider} unlinked successfully from User {UserId}", providerEnum, command.UserId);

        return Unit.Value;
    }
}