// File: AuthHive.Auth/Services/Handlers/Permission/LogBatchPermissionValidatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // BatchPermissionValidatedEvent
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
    /// 일괄 권한 유효성 검사 완료 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogBatchPermissionValidatedAuditHandler :
        IDomainEventHandler<BatchPermissionValidatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogBatchPermissionValidatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogBatchPermissionValidatedAuditHandler(IAuditService auditService, ILogger<LogBatchPermissionValidatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(BatchPermissionValidatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.ConnectedId; // 검증 요청 주체

            try
            {
                var severity = @event.FailureCount > 0 ? AuditEventSeverity.Warning : AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for BatchPermissionValidated event. Org: {OrgId}, Success: {SuccessCount}/{TotalCount}, Failures: {FailureCount}",
                    organizationId, @event.SuccessCount, @event.TotalCount, @event.FailureCount);

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = initiator,
                    ["organization_id"] = organizationId,
                    ["total_count"] = @event.TotalCount,
                    ["success_count"] = @event.SuccessCount,
                    ["failure_count"] = @event.FailureCount,
                    ["failed_scopes"] = @event.FailedScopes,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Validation,
                    "BATCH_PERMISSION_VALIDATED",
                    initiator,
                    success: @event.FailureCount == 0, // 실패가 0일 때만 성공으로 간주
                    errorMessage: @event.FailureCount > 0 ? $"Validation failed for {@event.FailureCount} scopes." : null,
                    resourceType: "PermissionValidation",
                    resourceId: organizationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BatchPermissionValidatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}