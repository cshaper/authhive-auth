// File: AuthHive.Auth/Services/Handlers/Authentication/SecuritySettings/SendDeviceLimitWarningNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events; // TrustedDeviceRegisteredEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience; 
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // for Tags.Contains
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.SecuritySettings
{
    /// <summary>
    /// 기기 등록 시 한도에 도달했는지 확인하고, 필요한 경우 경고 알림을 발송합니다.
    /// </summary>
    public class SendDeviceLimitWarningNotificationHandler :
        IDomainEventHandler<TrustedDeviceRegisteredEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendDeviceLimitWarningNotificationHandler> _logger;

        public int Priority => 20; // 알림 핸들러
        public bool IsEnabled => true;

        public SendDeviceLimitWarningNotificationHandler(
            INotificationService notificationService,
            ILogger<SendDeviceLimitWarningNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(TrustedDeviceRegisteredEvent @event, CancellationToken cancellationToken = default)
        {
            bool isWarning = @event.Tags.Contains("UsageWarning");
            bool isCritical = @event.Tags.Contains("UsageCritical");

            // 경고 또는 위험 태그가 없으면 알림을 보낼 필요가 없음
            if (!isWarning && !isCritical)
            {
                return;
            }

            try
            {
                // 템플릿 키와 우선순위 결정
                string templateKey = isCritical ? "DeviceLimitCriticalAlert" : "DeviceLimitWarningAlert";
                var priority = isCritical ? NotificationPriority.High : NotificationPriority.Normal;

                var parameters = new Dictionary<string, string>
                {
                    { "currentCount", @event.CurrentDeviceCount.ToString() },
                    { "maxLimit", @event.MaxDeviceLimit.ToString() },
                    { "planType", @event.PlanType }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.User,
                    RecipientIdentifiers = new List<string> { @event.UserId.ToString() },
                    TemplateKey = templateKey, // (가정) 기기 한도 경고/위험 템플릿
                    TemplateVariables = parameters,
                    Priority = priority,
                    SendImmediately = true // 즉시 발송
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Successfully queued {TemplateKey} notification for User {UserId}.",
                    templateKey, @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send DeviceLimitWarning notification for User {UserId}: {EventId}", 
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}