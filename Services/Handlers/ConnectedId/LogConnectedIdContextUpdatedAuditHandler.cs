// File: AuthHive.Auth/Services/Handlers/ConnectedId/LogConnectedIdContextUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.ConnectedId.Events; // ConnectedIdContextUpdatedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // JSON 직렬화 사용 가능
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ConnectedId
{
    /// <summary>
    /// ConnectedId 컨텍스트 업데이트 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogConnectedIdContextUpdatedAuditHandler :
        IDomainEventHandler<ConnectedIdContextUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogConnectedIdContextUpdatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogConnectedIdContextUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogConnectedIdContextUpdatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ConnectedIdContextUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ConnectedIdContextUpdated event. ConnectedId: {ConnectedId}, Org: {OrgId}, Changes: {ChangeCount}",
                    connectedId, organizationId, @event.Changes?.Count ?? 0);

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = connectedId,
                    ["organization_id"] = organizationId,
                    // ContextEntityId 속성은 이벤트에 없음
                    ["updated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString(),
                    // ❗️ [수정] Changes 딕셔너리 자체를 기록 (새 값만 포함됨)
                    // 복잡한 객체 값은 JSON으로 직렬화될 수 있음 (IAuditService 구현에 따라 다름)
                    ["changes"] = @event.Changes ?? new Dictionary<string, object>()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "CONNECTEDID_CONTEXT_UPDATED",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "ConnectedIdContext",
                    resourceId: connectedId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ConnectedIdContextUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}