// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/UpdateUserLockStatusOnAccountLockedHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러 - ❗️ 오류 수정본]
// CS1061 오류를 해결하기 위해 User 엔티티 및 IUserRepository의
// 실제 속성/메서드 사용 방식을 반영하여 수정합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication.Events;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
// (한글 주석) ❗️ User 엔티티 클래스의 using 문이 필요합니다. (경로 확인 필요)
// 예시: using AuthHive.Core.Entities.User;

namespace AuthHive.Auth.Handlers.Authentication.AccountState
{
    /// <summary>
    /// (한글 주석) 계정 잠금 이벤트 발생 시 사용자 엔티티의 잠금 관련 상태를 업데이트하는 핸들러입니다.
    /// </summary>
    public class UpdateUserLockStatusOnAccountLockedHandler :
        IDomainEventHandler<AccountLockedEvent>,
        IService
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UpdateUserLockStatusOnAccountLockedHandler> _logger;

        public int Priority => 50;
        public bool IsEnabled => true;

        public UpdateUserLockStatusOnAccountLockedHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<UpdateUserLockStatusOnAccountLockedHandler> logger)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 계정 잠금 이벤트를 처리하여 사용자 상태를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(AccountLockedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            try
            {
                _logger.LogInformation("Updating lock status for User {UserId} due to AccountLocked event.", userId);

                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    _logger.LogWarning("User with ID {UserId} not found. Cannot update lock status.", userId);
                    return;
                }

                user.IsAccountLocked = true;        // 👈 수정됨
                user.AccountLockedUntil = @event.LockedUntil; // 👈 수정됨 (DateTime? 타입)
                user.LockReason = @event.Reason;           // 👈 수정됨 (다시 추가)
                user.FailedLoginAttempts = 0;

                // (한글 주석) ❗️ [오류 수정] 명시적인 Update 호출 제거 (UnitOfWork가 변경 감지)
                // _userRepository.Update(user);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                _logger.LogInformation("Successfully updated lock status for User {UserId}.", userId);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update lock status for User {UserId} from AccountLockedEvent: {EventId}", userId, @event.EventId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // throw; // 필요 시 예외 다시 던지기
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("UpdateUserLockStatusOnAccountLockedHandler initialized.");
            return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(IsEnabled);
        }
        #endregion
    }
}