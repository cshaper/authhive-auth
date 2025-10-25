// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Session/UpdateUserLastLoginHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLoggedInEvent를 처리하는 핸들러입니다.
// 목적: 사용자의 Write Model (User 엔티티)에 마지막 로그인 시각과 IP를 업데이트합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Session; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Session
{
    /// <summary>
    /// <see cref="UserLoggedInEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// User 엔티티의 최종 로그인 정보를 업데이트합니다.
    /// </summary>
    public class UpdateUserLastLoginHandler
        : IDomainEventHandler<UserLoggedInEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserRepository _userRepository;
        private readonly ILogger<UpdateUserLastLoginHandler> _logger;

        public UpdateUserLastLoginHandler(
            IUserRepository userRepository,
            ILogger<UpdateUserLastLoginHandler> logger)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 로그인 이벤트를 처리하여 최종 로그인 정보를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(UserLoggedInEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Starting last login update for UserId: {UserId} (IP: {IpAddress})",
                    @event.UserId, @event.ClientIpAddress);

                // 1. 상태 업데이트 로직 호출
                // IUserRepository의 UpdateUserLastLoginAsync 메서드를 사용합니다.
                var updateResult = await _userRepository.UpdateUserLastLoginAsync(
                    @event.UserId, 
                    @event.OccurredAt, // BaseEvent에서 상속받는 이벤트 발생 시각 (로그인 시각)
                    @event.ClientIpAddress, 
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (updateResult) // UpdateUserLastLoginAsync가 bool을 반환한다고 가정
                {
                     _logger.LogInformation(
                        "User last login information successfully updated. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    // 상태 업데이트 실패는 심각하지 않으므로 (로그인 자체는 성공했으므로), 로그만 남깁니다.
                    _logger.LogWarning(
                        "Failed to update User last login information. (UserId: {UserId})",
                        @event.UserId);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("User last login update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating User last login information. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
