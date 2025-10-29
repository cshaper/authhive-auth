// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionAnomalyAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionAnomalyDetectedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 사용 이상 패턴 감지 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionAnomalyAuditHandler :
        IDomainEventHandler<PermissionAnomalyDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionAnomalyAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionAnomalyAuditHandler(IAuditService auditService, ILogger<LogPermissionAnomalyAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionAnomalyDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = Guid.Empty; // 시스템 감지

            try
            {
                _logger.LogWarning(
                    "Recording audit log for PermissionAnomalyDetected event. Org: {OrgId}, User: {ConnectedId}, Type: {AnomalyType}",
                    organizationId, @event.ConnectedId, @event.AnomalyType);

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = @event.ConnectedId,
                    ["organization_id"] = organizationId,
                    ["anomaly_type"] = @event.AnomalyType,
                    ["details"] = @event.Details,
                    ["lookback_days"] = @event.LookbackDays,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.High.ToString() // 이상 감지는 High
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Security,
                    "PERMISSION_ANOMALY_DETECTED",
                    initiator,
                    success: true, // 감지 작업 자체는 성공
                    errorMessage: @event.Details,
                    resourceType: "ConnectedIdPermission",
                    resourceId: @event.ConnectedId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionAnomalyDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}