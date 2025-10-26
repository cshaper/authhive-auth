// File: AuthHive.Auth/Services/Handlers/Authentication/Login/UpdateUserOnAuthenticationSuccessHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// AuthenticationSuccessEvent 발생 시 사용자 정보를 업데이트합니다.
// (예: 마지막 로그인 시각, IP, 실패 횟수 초기화)
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.User; // User 엔티티

namespace AuthHive.Auth.Handlers.Authentication.Login // Authentication/Login 폴더
{
    /// <summary>
    /// (한글 주석) 인증 성공 시 사용자 엔티티의 관련 정보를 업데이트하는 핸들러입니다.
    /// </summary>
    public class UpdateUserOnAuthenticationSuccessHandler :
        IDomainEventHandler<AuthenticationSuccessEvent>,
        IService
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UpdateUserOnAuthenticationSuccessHandler> _logger;

        public int Priority => 50; // 감사 로깅 후 실행될 수 있도록
        public bool IsEnabled => true;

        public UpdateUserOnAuthenticationSuccessHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<UpdateUserOnAuthenticationSuccessHandler> logger)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 인증 성공 이벤트를 처리하여 사용자 정보를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(AuthenticationSuccessEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            try
            {
                _logger.LogInformation("Updating user info on successful authentication for User {UserId}.", userId);

                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    _logger.LogWarning("User with ID {UserId} not found. Cannot update info.", userId);
                    return;
                }

                bool changed = false;

                // (한글 주석) 마지막 로그인 시각 업데이트
                user.LastLoginAt = @event.OccurredAt.ToUniversalTime(); // UTC로 저장
                changed = true;

                // (한글 주석) 마지막 로그인 IP 업데이트
                if (user.LastLoginIp != @event.ClientIpAddress)
                {
                    user.LastLoginIp = @event.ClientIpAddress;
                    changed = true;
                }

                // (한글 주석) 실패한 로그인 시도 횟수 초기화
                if (user.FailedLoginAttempts > 0)
                {
                    user.FailedLoginAttempts = 0;
                    changed = true;
                }

                // (한글 주석) 최초 로그인 시각 기록 (FirstLoginAt이 null인 경우)
                if (!user.FirstLoginAt.HasValue)
                {
                    user.FirstLoginAt = user.LastLoginAt;
                    changed = true;
                    // (한글 주석) 필요 시 FirstLoginEvent 발행 고려
                    // var firstLoginEvent = new FirstLoginEvent(userId, ...);
                    // await _eventBus.PublishAsync(firstLoginEvent, cancellationToken);
                }


                // (한글 주석) 변경 사항이 있을 경우에만 DB 업데이트
                if (changed)
                {
                    await _unitOfWork.CommitTransactionAsync(cancellationToken);
                    _logger.LogInformation("Successfully updated user info for User {UserId} after successful login.", userId);
                }
                else
                {
                     _logger.LogInformation("No user info changes required for User {UserId} after login.", userId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update user info on AuthenticationSuccessEvent: {EventId}", @event.EventId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // throw;
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}