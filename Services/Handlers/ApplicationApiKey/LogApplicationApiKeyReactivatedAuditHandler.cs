// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyReactivatedAuditHandler.cs
using AuthHive.Auth.Extensions;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyReactivatedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 애플리케이션 API 키가 재활성화되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationApiKeyReactivatedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyReactivatedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyReactivatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationApiKeyReactivatedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyReactivatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyReactivatedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.ReactivatedByConnectedId; 

            try
            {
                _logger.LogWarning( // 키 재활성화는 Warning 레벨 (보안상 민감)
                    "Recording audit log for ApplicationApiKeyReactivated event. ApiKeyId: {ApiKeyId}, AppId: {AppId}",
                    apiKeyId, applicationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["reactivated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 재활성화는 Warning
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.StatusChange, // 상태 변경
                    action: "APPLICATION_API_KEY_REACTIVATED",
                    connectedId: initiator,
                    success: true,
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyReactivatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}