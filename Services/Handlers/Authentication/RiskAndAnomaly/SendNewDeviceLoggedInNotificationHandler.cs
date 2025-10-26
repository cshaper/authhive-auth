// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/SendNewDeviceLoggedInNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events; // NewDeviceLoggedInEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience; // Enum (RecipientType, NotificationPriority)
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// 새 기기 로그인 이벤트를 받아 사용자에게 보안 알림(이메일 등)을 발송합니다.
    /// </summary>
    public class SendNewDeviceLoggedInNotificationHandler :
        IDomainEventHandler<NewDeviceLoggedInEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendNewDeviceLoggedInNotificationHandler> _logger;

        // 알림 핸들러 (외부 통신)
        public int Priority => 20; 
        public bool IsEnabled => true;

        public SendNewDeviceLoggedInNotificationHandler(
            INotificationService notificationService,
            ILogger<SendNewDeviceLoggedInNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(NewDeviceLoggedInEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 알림 템플릿에 전달할 파라미터 구성
                var parameters = new Dictionary<string, string>
                {
                    // (가정) 템플릿 변수
                    { "dateTime", @event.OccurredAt.ToString("yyyy-MM-dd HH:mm:ss") }, 
                    { "ipAddress", @event.IpAddress },
                    { "userAgent", @event.UserAgent ?? "Unknown" },
                    { "location", @event.Location ?? "Unknown location" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.User,
                    RecipientIdentifiers = new List<string> { @event.UserId.ToString() },
                    TemplateKey = "NewDeviceLoggedInAlert", // (가정) 새 기기 로그인 알림 템플릿
                    TemplateVariables = parameters,
                    Priority = NotificationPriority.High, // 보안 알림
                    SendImmediately = true
                };

                // INotificationService를 통해 알림 큐에 추가
                await _notificationService.QueueNotificationAsync(
                    notificationRequest, 
                    cancellationToken
                );

                _logger.LogInformation(
                    "Successfully queued NewDeviceLoggedIn notification for User {UserId}.",
                    @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send NewDeviceLoggedIn notification for User {UserId}: {EventId}", 
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}