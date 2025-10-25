// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UpdateUserAccountSuspensionStatusHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountSuspendedEvent를 처리하는 핸들러입니다.
// 목적: 사용자의 Write Model (User 엔티티) 상태를 'Suspended'로 업데이트합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;

using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus 열거형 (가정)

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountSuspendedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// User 엔티티의 상태를 'Suspended'로 변경합니다.
    /// </summary>
    public class UpdateUserAccountSuspensionStatusHandler
        : IDomainEventHandler<UserAccountSuspendedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserRepository _userRepository;
        private readonly ILogger<UpdateUserAccountSuspensionStatusHandler> _logger;

        public UpdateUserAccountSuspensionStatusHandler(
            IUserRepository userRepository,
            ILogger<UpdateUserAccountSuspensionStatusHandler> logger)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 일시 정지 이벤트를 처리하여 User 엔티티의 상태를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogCritical( // 일시 정지는 Critical 레벨로 로깅
                    "Starting User account status update to 'Suspended' for UserId: {UserId} (Reason: {Reason})",
                    @event.UserId, @event.SuspensionReason);

                // 1. 상태 업데이트 로직 호출
                // (가정) IUserRepository에 정지 상태와 기간을 업데이트하는 전용 메서드가 존재합니다.
                // 이 메서드는 User 엔티티의 Status를 Suspended로 변경하고 SuspensionUntil 값을 설정합니다.

                var updateResult = await _userRepository.UpdateSuspensionStatusAsync(
                 userId: @event.UserId,
                 status: UserStatus.Suspended, // Assuming UserStatus.Suspended from UserEnums
                 suspensionEndsAt: @event.SuspensionEndsAt, // Fixed: Replaced SuspendedUntil with SuspensionEndsAt
                 suspensionReason: @event.SuspensionReason,
                 suspendedByConnectedId: @event.SuspendedByConnectedId,
                 cancellationToken: cancellationToken
             );

                // 2. 결과 확인
                if (updateResult) // UpdateSuspensionStatusAsync가 bool을 반환한다고 가정
                {
                    _logger.LogCritical(
                       "User account status successfully set to 'Suspended'. (UserId: {UserId})",
                       @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to update User account status to 'Suspended'. (UserId: {UserId})",
                        @event.UserId);
                    throw new InvalidOperationException($"Failed to set User account status to Suspended for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("User suspension status update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating User account suspension status. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
