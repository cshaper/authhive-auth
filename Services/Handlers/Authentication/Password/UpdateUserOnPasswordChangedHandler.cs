// File: AuthHive.Auth/Services/Handlers/Authentication/Password/UpdateUserOnPasswordChangedHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Entities.User; // User 엔티티
using AuthHive.Core.Models.Auth.Authentication.Events;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Infra; //  alias 추가

namespace AuthHive.Auth.Handlers.Authentication.Password
{
    /// <summary>
    /// 비밀번호 변경 시, 사용자 엔티티의 관련 정보를 갱신합니다.
    /// (예: PasswordChangedAt, 비밀번호 재설정 토큰 무효화)
    /// </summary>
    public class UpdateUserOnPasswordChangedHandler :
        IDomainEventHandler<PasswordChangedEvent>,
        IService
    {
        // IUserService가 아닌 IRepository를 직접 사용
        private readonly IRepository<UserEntity> _userRepository; // UserEntity alias 사용
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTime; 
        private readonly ILogger<UpdateUserOnPasswordChangedHandler> _logger;

        public int Priority => 5; 
        public bool IsEnabled => true;

        public UpdateUserOnPasswordChangedHandler(
            IRepository<UserEntity> userRepository, // UserEntity alias 사용
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTime,
            ILogger<UpdateUserOnPasswordChangedHandler> logger)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _dateTime = dateTime;
            _logger = logger;
        }

        public async Task HandleAsync(PasswordChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;

            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);

                if (user == null)
                {
                    _logger.LogWarning("User not found while handling PasswordChangedEvent. UserId: {UserId}", userId);
                    return;
                }

                var now = _dateTime.UtcNow;

                user.PasswordChangedAt = now; 
                user.PasswordResetToken = null;
                user.PasswordResetTokenExpiresAt = null; 

                // 3. 변경사항 표시 및 트랜잭션 커밋
                // [수정됨] CS1061 오류 수정: Update -> UpdateAsync
                await _userRepository.UpdateAsync(user, cancellationToken); 
                
                await _unitOfWork.CommitTransactionAsync(cancellationToken); 

                _logger.LogInformation(
                    "Successfully updated PasswordChangedAt for User {UserId} via PasswordChangedEvent.",
                    userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling PasswordChangedEvent for User {UserId} in UpdateUserOnPasswordChangedHandler.", userId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}