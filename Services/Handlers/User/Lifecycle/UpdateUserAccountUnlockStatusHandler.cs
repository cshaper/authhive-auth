// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UpdateUserAccountUnlockStatusHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountUnlockedEvent를 처리하는 핸들러입니다.
// 목적: 사용자의 Write Model (User 엔티티) 상태를 잠금 해제(Active)로 업데이트합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;


namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountUnlockedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// User 엔티티의 잠금 상태를 해제하고 상태를 'Active'로 변경합니다.
    /// </summary>
    public class UpdateUserAccountUnlockStatusHandler
        : IDomainEventHandler<UserAccountUnlockedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserRepository _userRepository;
        private readonly ILogger<UpdateUserAccountUnlockStatusHandler> _logger;

        public UpdateUserAccountUnlockStatusHandler(
            IUserRepository userRepository,
            ILogger<UpdateUserAccountUnlockStatusHandler> logger)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 잠금 해제 이벤트를 처리하여 User 엔티티의 상태를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Starting User account status update to 'Active' (Unlock) for UserId: {UserId} (Reason: {Reason})",
                    @event.UserId, @event.UnlockReason);

                // 1. 잠금 해제 상태 업데이트 로직 호출
                // IUserRepository의 UpdateUserUnlockStatusAsync 메서드를 사용합니다.
                var updateResult = await _userRepository.UpdateUserUnlockStatusAsync(
                    @event.UserId, 
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (updateResult) // UpdateUserUnlockStatusAsync가 bool을 반환한다고 가정
                {
                     _logger.LogInformation(
                        "User account status successfully set to 'Active' (Unlocked). (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to update User account status to 'Active' (Unlock). (UserId: {UserId})",
                        @event.UserId);
                    throw new InvalidOperationException($"Failed to unlock User account status for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("User unlock status update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating User account unlock status. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
