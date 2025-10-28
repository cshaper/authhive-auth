// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyUpdatedAuditHandler.cs
using AuthHive.Auth.Extensions;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyUpdatedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.Json; // ❗️ System.Text.Json 사용 (지침 확인)
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 애플리케이션 API 키가 업데이트되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationApiKeyUpdatedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyUpdatedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyUpdatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationApiKeyUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyUpdatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyUpdatedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.UpdatedByConnectedId; 

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationApiKeyUpdated event. ApiKeyId: {ApiKeyId}, AppId: {AppId}, Changes: {ChangeCount}",
                    apiKeyId, applicationId, @event.ChangedProperties?.Count ?? 0);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["updated_by_connected_id"] = initiator,
                    ["changed_properties"] = @event.ChangedProperties != null
                        ? JsonSerializer.Serialize(@event.ChangedProperties, new JsonSerializerOptions { WriteIndented = false })
                        : "None",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // ❗️ .Info 사용
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "APPLICATION_API_KEY_UPDATED",
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
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}