// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/SendApiKeyAuthFailedAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyAuthFailedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// API 키 인증 실패 시 보안팀에 Critical 알림을 발송합니다.
    /// (너무 빈번할 경우 알림 임계치 적용 고려)
    /// </summary>
    public class SendApiKeyAuthFailedAlertHandler :
        IDomainEventHandler<ApplicationApiKeyAuthFailedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendApiKeyAuthFailedAlertHandler> _logger;
        // TODO: 알림 대상을 조회하기 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendApiKeyAuthFailedAlertHandler(
            INotificationService notificationService,
            ILogger<SendApiKeyAuthFailedAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyAuthFailedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            // TODO: 동일 IP/AppId에 대해 너무 많은 알림이 가지 않도록 Throttling 로직 필요
            // (예: ICacheService를 사용하여 5분 이내 동일 경고 발생 시 Skip)

            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "ApplicationId", @event.AggregateId.ToString() },
                    { "OrganizationId", @event.OrganizationId?.ToString() ?? "N/A" },
                    { "AttemptedKey", @event.AttemptedKey }, // (주의: 마스킹 필요)
                    { "FailureReason", @event.FailureReason },
                    { "ClientIp", @event.ClientIp ?? "Unknown" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_API_KEY_AUTH_FAILED", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for ApiKeyAuthFailed event for AppId {AppId}", @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send ApiKeyAuthFailed alert for AppId: {AppId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}