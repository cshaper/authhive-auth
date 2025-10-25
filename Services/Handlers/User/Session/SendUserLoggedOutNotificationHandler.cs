// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Session/SendUserLoggedOutNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLoggedOutEvent를 처리하는 핸들러입니다.
// 목적: 사용자 로그아웃 성공 시 정보성 알림을 발송합니다. (선택적)
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events.Session; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest, EmailRequestDetails
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Session
{
    /// <summary>
    /// <see cref="UserLoggedOutEvent"/>를 처리하는 알림 핸들러입니다.
    /// 로그아웃 알림을 발송합니다.
    /// </summary>
    public class SendUserLoggedOutNotificationHandler
        : IDomainEventHandler<UserLoggedOutEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true; // 기본적으로 true로 설정하나, 실제 구현 시 알림 설정에 따라 필터링될 수 있습니다.

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendUserLoggedOutNotificationHandler> _logger;

        public SendUserLoggedOutNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendUserLoggedOutNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 로그아웃 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserLoggedOutEvent @event, CancellationToken cancellationToken = default)
        {
            // 로그아웃 알림은 일반적으로 필터링됩니다. (너무 빈번하므로)
            // Critical, Forced Logout 등의 경우에만 발송하도록 로직을 구현합니다.
            // (수정) LogoutMethod 대신 LogoutType을 사용
            if (@event.LogoutType == "Manual")
            {
                _logger.LogDebug("Skipping notification for manual logout. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                // 1. 알림 대상 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for logout event.", @event.UserId);
                    return;
                }

                // 2. 알림 발송 로깅 (강제 로그아웃/세션 만료 등 비정상 종료 시에만 Warning)
                _logger.LogInformation(
                    // (수정) LogoutMethod 대신 LogoutType을 사용
                    "Sending Logout Confirmation Notice to User {Email} (Method: {Method})",
                    user.Email, @event.LogoutType);

                // 3. 템플릿 변수 준비
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "User" },
                    // (수정) Timestamp 대신 CreatedAt을 사용
                    { "LogoutTime", @event.OccurredAt.ToString("yyyy-MM-dd HH:mm UTC") },
                    // (수정) LogoutMethod 대신 LogoutType을 사용
                    { "LogoutMethod", @event.LogoutType ?? "Unknown" },
                    // (수정) SessionDurationMs 속성 제거
                    { "SessionDuration", "N/A" }, // SessionDurationMs가 이벤트에 없으므로 N/A 처리
                    { "IpAddress", @event.ClientIpAddress ?? "Unknown" }
                };

                // 4. 알림 요청 생성
                var notificationRequest = new NotificationSendRequest
                {
                    RecipientConnectedIds = @event.ConnectedId.HasValue ? new List<Guid> { @event.ConnectedId.Value } : new List<Guid>(),
                    
                    TemplateKey = "USER_LOGGED_OUT_NOTICE", // 로그아웃 확인 알림 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.Low, // 정보성 알림
                    SendImmediately = true
                };

                // 5. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Logout Confirmation Notice sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Logout notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendUserLoggedOutNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
