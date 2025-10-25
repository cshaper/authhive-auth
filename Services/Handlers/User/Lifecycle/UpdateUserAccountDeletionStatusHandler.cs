// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UpdateUserAccountDeletionStatusHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountDeletedEvent를 처리하는 핸들러입니다.
// 목적: 사용자의 Write Model (User 엔티티) 상태를 'Deleted'로 업데이트합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Core; // UserStatus 열거형 (가정)
using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus 열거형 (가정)

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountDeletedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// User 엔티티의 상태를 'Deleted'로 변경합니다.
    /// </summary>
    public class UpdateUserAccountDeletionStatusHandler
        : IDomainEventHandler<UserAccountDeletedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserRepository _userRepository;
        private readonly ILogger<UpdateUserAccountDeletionStatusHandler> _logger;

        public UpdateUserAccountDeletionStatusHandler(
            IUserRepository userRepository,
            ILogger<UpdateUserAccountDeletionStatusHandler> logger)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 삭제 이벤트를 처리하여 User 엔티티의 상태를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogCritical( // 계정 삭제는 Critical 레벨로 로깅
                    "Starting User account status update to 'Deleted' (Soft Delete) for UserId: {UserId} (Reason: {Reason})",
                    @event.UserId, @event.DeletionReason);

                // 1. 상태 업데이트 로직 호출
                // IUserRepository의 UpdateUserStatusAsync 메서드를 사용하여 상태를 Deleted로 변경합니다.
                // (가정) UserStatus 열거형에 Deleted 상태가 있습니다.
                var updateResult = await _userRepository.UpdateUserStatusAsync(
                    @event.UserId, 
                    UserStatus.Deleted, 
                    @event.DeletedByConnectedId, // 삭제를 수행한 ConnectedId
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (updateResult) // UpdateUserStatusAsync가 bool을 반환한다고 가정
                {
                     _logger.LogCritical(
                        "User account status successfully set to 'Deleted'. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to update User account status to 'Deleted'. (UserId: {UserId})",
                        @event.UserId);
                    throw new InvalidOperationException($"Failed to set User account status to Deleted for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("User deletion status update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating User account deletion status. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
