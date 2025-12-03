using System;
using System.Linq; // [필수] Select 사용
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // [필수] 표준 Validator

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository, IUserSuspensionRepository 위치
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;

// [Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Responses.Lifecycle;
using AuthHive.Core.Models.User.Events.Lifecycle;

// [Entities]
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core; // UserStatus

// [Exceptions]
using AuthHive.Core.Exceptions;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Handlers.User.Lifecycle;

public class SuspendUserCommandHandler : IRequestHandler<CreateUserSuspensionCommand, UserSuspensionResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUserSuspensionRepository _suspensionRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IValidator<CreateUserSuspensionCommand> _validator; // [수정] 표준 Validator
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ICacheService _cacheService;
    private readonly ILogger<SuspendUserCommandHandler> _logger;

    public SuspendUserCommandHandler(
        IUserRepository userRepository,
        IUserSuspensionRepository suspensionRepository,
        IUnitOfWork unitOfWork,
        IValidator<CreateUserSuspensionCommand> validator, // [수정] 주입 타입 변경
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
        // 1. 유효성 검사 (표준화)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] 에러 메시지 리스트 추출하여 예외 처리
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("User suspension failed.", errorMessages);
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

        // 6. 캐시 무효화 (사용자 정보가 변경되었으므로)
        string cacheKey = $"UserResponse:{user.Id}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);

        // 7. 이벤트 발행
        var suspendedEvent = new UserAccountSuspendedEvent
        {
            EventId = Guid.NewGuid(),
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