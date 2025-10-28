// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/SendSuspiciousApiKeyActivityAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationSuspiciousApiKeyActivityEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.Json; // 딕셔너리 직렬화
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 의심스러운 API 키 활동 감지 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendSuspiciousApiKeyActivityAlertHandler :
        IDomainEventHandler<ApplicationSuspiciousApiKeyActivityEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendSuspiciousApiKeyActivityAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendSuspiciousApiKeyActivityAlertHandler(
            INotificationService notificationService,
            ILogger<SendSuspiciousApiKeyActivityAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationSuspiciousApiKeyActivityEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "ApiKeyId", @event.AggregateId.ToString() },
                    { "ApplicationId", @event.ApplicationId?.ToString() ?? "N/A" },
                    { "OrganizationId", @event.OrganizationId?.ToString() ?? "N/A" },
                    { "ActivityType", @event.ActivityType },
                    // Details 딕셔너리를 JSON 문자열로 변환하여 전달
                    { "DetailsJson", JsonSerializer.Serialize(@event.Details) },
                    { "DetectedAt", @event.OccurredAt.ToString("o") }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_API_KEY_SUSPICIOUS_ACTIVITY", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for SuspiciousApiKeyActivity event for ApiKeyId {ApiKeyId}", @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SuspiciousApiKeyActivity alert for ApiKeyId: {ApiKeyId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}