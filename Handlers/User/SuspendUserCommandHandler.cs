// [AuthHive.Auth] SuspendUserCommandHandler.cs
// v17 CQRS "본보기": 'User'의 Status를 'Suspended'로 변경하는 'SuspendUserCommand'를 처리합니다.
// (SOP 1-Write-P, v16의 UpdateUserCommand에서 분리됨)

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Lifecycle; // UserAccountSuspendedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 정지" 유스케이스 핸들러 (SOP 1-Write-P)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class SuspendUserCommandHandler : IRequestHandler<SuspendUserCommand, Unit>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<SuspendUserCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public SuspendUserCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<SuspendUserCommandHandler> logger,
            IUserValidator userValidator)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<Unit> Handle(SuspendUserCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling SuspendUserCommand for User {UserId}, Reason: {Reason}", 
                command.UserId, command.SuspensionReason);

            // 1. 유효성 검사 (Validator로 책임 이관)
            var validationResult = await _userValidator.ValidateSuspendAsync(command);
            if (!validationResult.IsSuccess)
            {
                throw new ValidationException(validationResult.ErrorMessage ?? "User suspension validation failed.");
            }

            // 2. 엔티티 조회 (Validator가 이미 조회했지만, 상태 변경을 위해 다시 조회)
            var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (user == null)
            {
                // Validator가 통과했으므로 이론적으로 발생하면 안 됨
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }

            // 3. 변경 사항 적용
            if (user.Status == UserStatus.Suspended)
            {
                _logger.LogInformation("User {UserId} is already suspended. Skipping.", command.UserId);
                return Unit.Value; // 멱등성(Idempotency)
            }

            // [v17 정합성] Command 데이터를 v16 엔티티 필드에 매핑
            user.Status = UserStatus.Suspended;
            user.LockReason = command.SuspensionReason;
            user.AccountLockedUntil = command.SuspensionEndsAt;
            // (v16 엔티티에는 SuspensionType 필드가 없음 )

            // 4. 데이터베이스 저장 (Update)
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("User {UserId} suspended successfully.", command.UserId);

            // 5. 이벤트 발행 (Notify)
            var suspendedEvent = new UserAccountSuspendedEvent(
                userId: user.Id,
                suspendedByConnectedId: command.TriggeredBy, // 요청자
                organizationId: command.OrganizationId, // BaseCommand에서 상속 (작업 컨텍스트)
                suspensionReason: command.SuspensionReason,
                suspensionType: command.SuspensionType,
                suspensionEndsAt: command.SuspensionEndsAt,
                appealProcess: null, // (추후 Command에 추가 가능)
                correlationId: command.CorrelationId,
                source: "UserCommandHandler" // v17 표준
            );
            await _mediator.Publish(suspendedEvent, cancellationToken);
            
            // 6. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}