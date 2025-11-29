using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.User.Validators; // [Fix] 특화 Validator 인터페이스
using AuthHive.Core.Interfaces.Infra.Cache;

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events.Lifecycle;

// [Entities]
using AuthHive.Core.Entities.User;

// [Exceptions]
using AuthHive.Core.Exceptions;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Handlers.User;

public class SuspendUserCommandHandler : IRequestHandler<CreateUserSuspensionCommand, UserSuspensionResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUserSuspensionRepository _suspensionRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IUserSuspensionValidator _validator; // [Fix] 타입 변경
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ICacheService _cacheService;
    private readonly ILogger<SuspendUserCommandHandler> _logger;

    public SuspendUserCommandHandler(
        IUserRepository userRepository,
        IUserSuspensionRepository suspensionRepository,
        IUnitOfWork unitOfWork,
        IUserSuspensionValidator validator, // [Fix] 주입 변경
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ICacheService cacheService,
        ILogger<SuspendUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _suspensionRepository = suspensionRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task<UserSuspensionResponse> Handle(CreateUserSuspensionCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사 (특화 메서드 호출)
        var validationResult = await _validator.ValidateCreateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("User suspension failed.", validationResult.Errors);
        }

        // 2. 사용자 조회
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new DomainEntityNotFoundException("User", command.UserId);
        }

        // 3. 상태 변경 (DDD)
        user.ChangeStatus(UserStatus.Suspended, command.Reason);
        await _userRepository.UpdateAsync(user, cancellationToken);

        // 4. 제재 이력 기록
        var suspensionLog = new UserSuspension
        {
            UserId = user.Id,
            SuspendedAt = _timeProvider.UtcNow,
            SuspendedUntil = command.SuspendedUntil,
            SuspensionReason = command.Reason,
            SuspendedBy = command.SuspendedBy
        };

        await _suspensionRepository.AddAsync(suspensionLog, cancellationToken);

        // 5. 트랜잭션 커밋
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 6. 캐시 무효화
        string cacheKey = $"UserResponse:{user.Id}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);

        // 7. 이벤트 발행
        var suspendedEvent = new UserAccountSuspendedEvent
        {
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = command.SuspendedBy,
            UserId = user.Id,
            SuspendedUntil = command.SuspendedUntil,
            Reason = command.Reason,
            SuspendedBy = command.SuspendedBy
        };

        await _mediator.Publish(suspendedEvent, cancellationToken);

        _logger.LogWarning("User {UserId} suspended. Reason: {Reason}", user.Id, command.Reason);

        // 8. 응답
        return new UserSuspensionResponse(
            suspensionLog.Id,
            suspensionLog.UserId,
            suspensionLog.SuspendedAt,
            suspensionLog.SuspendedUntil,
            suspensionLog.SuspensionReason,
            suspensionLog.SuspendedBy
        );
    }
}