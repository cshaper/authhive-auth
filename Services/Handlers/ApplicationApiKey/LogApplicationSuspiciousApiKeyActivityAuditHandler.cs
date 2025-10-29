// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationSuspiciousApiKeyActivityAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationSuspiciousApiKeyActivityEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Extensions;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 의심스러운 API 키 활동 감지 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationSuspiciousApiKeyActivityAuditHandler :
        IDomainEventHandler<ApplicationSuspiciousApiKeyActivityEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationSuspiciousApiKeyActivityAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogApplicationSuspiciousApiKeyActivityAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationSuspiciousApiKeyActivityAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationSuspiciousApiKeyActivityEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System

            try
            {
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationSuspiciousApiKeyActivity event. ApiKeyId: {ApiKeyId}, AppId: {AppId}, Type: {ActivityType}",
                    apiKeyId, applicationId, @event.ActivityType);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["activity_type"] = @event.ActivityType,
                    ["details"] = @event.Details,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger); 

                // 보안 이벤트 전용 로깅 사용
                await _auditService.LogSecurityEventAsync(
                    eventType: "APPLICATION_API_KEY_SUSPICIOUS_ACTIVITY",
                    severity: AuditEventSeverity.Critical,
                    description: $"Suspicious activity '{@event.ActivityType}' detected for API Key {apiKeyId}",
                    connectedId: null, // 시스템 이벤트
                    details: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationSuspiciousApiKeyActivityEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}