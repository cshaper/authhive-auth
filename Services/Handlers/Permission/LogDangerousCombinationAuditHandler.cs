// File: AuthHive.Auth/Services/Handlers/Permission/LogDangerousCombinationAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // DangerousPermissionCombinationDetectedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 위험한 권한 조합 감지 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogDangerousCombinationAuditHandler :
        IDomainEventHandler<DangerousPermissionCombinationDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDangerousCombinationAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogDangerousCombinationAuditHandler(IAuditService auditService, ILogger<LogDangerousCombinationAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(DangerousPermissionCombinationDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.DetectedBy; // 감지 주체 (시스템 또는 관리자)

            try
            {
                _logger.LogCritical(
                    "Recording audit log for DangerousPermissionCombinationDetected event. Org: {OrgId}, User: {ConnectedId}, Level: {RiskLevel}",
                    organizationId, @event.ConnectedId, @event.RiskLevel);

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = @event.ConnectedId,
                    ["organization_id"] = organizationId,
                    ["risk_level"] = @event.RiskLevel,
                    ["scopes_involved"] = @event.Scopes,
                    ["dangerous_combinations"] = @event.DangerousCombinations,
                    ["permission_ids"] = @event.PermissionIds,
                    ["detected_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // 심각한 보안 이벤트
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Security, // 보안 경고 액션 타입
                    "PERMISSION_DANGEROUS_COMBINATION",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "ConnectedIdPermission",
                    resourceId: @event.ConnectedId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DangerousPermissionCombinationDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}