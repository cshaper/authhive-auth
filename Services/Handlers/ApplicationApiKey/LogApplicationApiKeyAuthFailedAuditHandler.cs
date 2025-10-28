// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyAuthFailedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyAuthFailedEvent
using AuthHive.Auth.Extensions; // (필요시)
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 애플리케이션 API 키 인증 실패 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationApiKeyAuthFailedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyAuthFailedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyAuthFailedAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogApplicationApiKeyAuthFailedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyAuthFailedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyAuthFailedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId; // ApplicationId
            var initiator = @event.TriggeredBy ?? Guid.Empty; // 인증되지 않았으므로 Empty

            try
            {
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationApiKeyAuthFailed event. AppId: {AppId}, Reason: {Reason}, IP: {ClientIp}",
                    applicationId, @event.FailureReason, @event.ClientIp);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["attempted_key_prefix"] = @event.AttemptedKey, // (주의: 키 접두사만 로깅 권장)
                    ["failure_reason"] = @event.FailureReason,
                    ["client_ip"] = @event.ClientIp ?? "Unknown",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Authentication, // 인증 액션
                    action: "APPLICATION_API_KEY_AUTH_FAILED",
                    connectedId: initiator, // 행위자 없음 (시스템)
                    success: false, // 실패
                    errorMessage: @event.FailureReason,
                    resourceType: "ApplicationAuthentication",
                    resourceId: applicationId.ToString(), // 리소스는 Application
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyAuthFailedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}