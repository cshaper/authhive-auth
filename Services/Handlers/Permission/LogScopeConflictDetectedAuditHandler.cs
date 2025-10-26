// File: AuthHive.Auth/Services/Handlers/Permission/LogScopeConflictDetectedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // ScopeConflictDetectedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 범위 충돌 감지 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogScopeConflictDetectedAuditHandler :
        IDomainEventHandler<ScopeConflictDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogScopeConflictDetectedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogScopeConflictDetectedAuditHandler(IAuditService auditService, ILogger<LogScopeConflictDetectedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ScopeConflictDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.DetectedBy; // 감지 주체 (시스템 또는 관리자)

            try
            {
                _logger.LogWarning(
                    "Recording audit log for ScopeConflictDetected event. Org: {OrgId}, Type: {ConflictType}, Scopes: {Scopes}",
                    organizationId, @event.ConflictType, string.Join(", ", @event.ConflictingScopes));

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["conflict_type"] = @event.ConflictType,
                    ["description"] = @event.Description,
                    ["conflicting_scopes"] = @event.ConflictingScopes,
                    ["detected_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 충돌은 Warning
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Configuration, // 설정 이슈
                    "PERMISSION_SCOPE_CONFLICT_DETECTED",
                    initiator,
                    success: true, // 감지 작업 자체는 성공
                    errorMessage: @event.Description,
                    resourceType: "PermissionConfiguration",
                    resourceId: organizationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ScopeConflictDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}