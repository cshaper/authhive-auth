// File: AuthHive.Auth/Services/Handlers/User/Activity/SendSuspiciousActivityNotificationHandler.cs
// (이벤트의 AggregateId가 UserId이므로 User/Activity 경로에 생성)
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events; // SuspiciousActivityNotificationEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Activity
{
    /// <summary>
    /// 의심스러운 활동 알림 이벤트를 받아 사용자에게 보안 알림을 발송합니다.
    /// </summary>
    public class SendSuspiciousActivityNotificationHandler :
        IDomainEventHandler<SuspiciousActivityNotificationEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendSuspiciousActivityNotificationHandler> _logger;

        public int Priority => 20; // 알림 핸들러
        public bool IsEnabled => true;

        public SendSuspiciousActivityNotificationHandler(
            INotificationService notificationService,
            ILogger<SendSuspiciousActivityNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(SuspiciousActivityNotificationEvent @event, CancellationToken cancellationToken = default)
        {
            // 이벤트에 NotificationRequired 플래그가 있을 경우, 이를 확인 (없으면 기본값 true)
            if (@event.NotificationRequired == false)
            {
                _logger.LogInformation("Notification skipped for SuspiciousActivityNotificationEvent for User {UserId} as NotificationRequired is false.", @event.AggregateId);
                return;
            }

            try
            {
                // 알림 템플릿에 전달할 파라미터 구성
                var parameters = new Dictionary<string, string>
                {
                    { "activityDescription", @event.ActivityDescription },
                    { "detectedAt", @event.DetectedAt.ToString("yyyy-MM-dd HH:mm:ss UTC") },
                    // 필요시 IP 주소, 위치 등 @event.Metadata에서 추가 정보 추출
                    { "ipAddress", @event.ClientIpAddress ?? "N/A" },
                    { "userAgent", @event.UserAgent ?? "N/A" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.User,
                    RecipientIdentifiers = new List<string> { @event.AggregateId.ToString() }, // UserId
                    TemplateKey = "SuspiciousActivityAlert", // (가정) 의심 활동 알림 템플릿 키
                    TemplateVariables = parameters,
                    Priority = NotificationPriority.High, // 보안 알림은 높은 우선순위
                    SendImmediately = true
                };

                // INotificationService를 통해 알림 큐에 추가
                await _notificationService.QueueNotificationAsync(
                    notificationRequest,
                    cancellationToken
                );

                _logger.LogInformation(
                    "Successfully queued SuspiciousActivity notification for User {UserId}.",
                    @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SuspiciousActivity notification for User {UserId}: {EventId}",
                    @event.AggregateId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}