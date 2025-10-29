// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyExpiredAuditHandler.cs

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyExpiredEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 애플리케이션 API 키가 만료되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationApiKeyExpiredAuditHandler :
        IDomainEventHandler<ApplicationApiKeyExpiredEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyExpiredAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationApiKeyExpiredAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyExpiredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyExpiredEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System-triggered

            try
            {
                _logger.LogWarning( // 키 만료는 Warning 레벨
                    "Recording audit log for ApplicationApiKeyExpired event. ApiKeyId: {ApiKeyId}, AppId: {AppId}",
                    apiKeyId, applicationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["expired_at"] = @event.OccurredAt, // 이벤트 발생 시각 = 만료 시각
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 만료는 Warning
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.StatusChange, // 상태 변경 (만료)
                    action: "APPLICATION_API_KEY_EXPIRED",
                    connectedId: initiator, // 시스템 (Empty Guid)
                    success: true, // 만료 처리 자체는 성공
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyExpiredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}