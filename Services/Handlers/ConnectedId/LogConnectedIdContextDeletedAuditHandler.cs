// File: AuthHive.Auth/Services/Handlers/ConnectedId/LogConnectedIdContextDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.ConnectedId.Events; // ConnectedIdContextDeletedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ConnectedId
{
    /// <summary>
    /// ConnectedId 컨텍스트 삭제 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogConnectedIdContextDeletedAuditHandler :
        IDomainEventHandler<ConnectedIdContextDeletedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogConnectedIdContextDeletedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogConnectedIdContextDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogConnectedIdContextDeletedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ConnectedIdContextDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty;

            try
            {
                _logger.LogWarning(
                    "Recording audit log for ConnectedIdContextDeleted event. ConnectedId: {ConnectedId}, Org: {OrgId}, Reason: {Reason}",
                    connectedId, organizationId, @event.Reason ?? "N/A");

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = connectedId,
                    ["organization_id"] = organizationId,
                    // ❗️ [수정] CS1061 오류 수정: ContextEntityId 제거
                    // ["context_entity_id"] = @event.ContextEntityId ?? Guid.Empty,
                    ["deleted_by_connected_id"] = initiator,
                    ["reason"] = @event.Reason ?? "N/A",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    "CONNECTEDID_CONTEXT_DELETED",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "ConnectedIdContext",
                    // ❗️ 수정: 리소스 ID를 ConnectedId로 사용 (ContextEntityId가 없으므로)
                    resourceId: connectedId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ConnectedIdContextDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}