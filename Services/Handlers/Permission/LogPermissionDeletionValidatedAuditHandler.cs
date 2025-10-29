// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionDeletionValidatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionDeletionValidatedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 삭제 유효성 검사 완료 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionDeletionValidatedAuditHandler :
        IDomainEventHandler<PermissionDeletionValidatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionDeletionValidatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionDeletionValidatedAuditHandler(IAuditService auditService, ILogger<LogPermissionDeletionValidatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionDeletionValidatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.DeletedBy; // 삭제 시도 주체

            try
            {
                var severity = @event.IsSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning;
                var resultMessage = @event.IsSuccess ? "Deletion validated and possible." : "Deletion validated but blocked due to dependencies.";

                _logger.LogInformation(
                    "Recording audit log for PermissionDeletionValidated event. Org: {OrgId}, Scope: {Scope}, Success: {Success}",
                    organizationId, @event.Scope, @event.IsSuccess);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = @event.PermissionId,
                    ["scope"] = @event.Scope,
                    ["deleted_by"] = initiator,
                    ["has_dependencies"] = @event.HasDependencies,
                    ["dependencies"] = @event.Dependencies,
                    ["organization_id"] = organizationId,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Validation,
                    "PERMISSION_DELETION_VALIDATED",
                    initiator,
                    success: @event.IsSuccess, // 검증 결과를 성공 여부에 반영
                    errorMessage: @event.IsSuccess ? null : resultMessage,
                    resourceType: "PermissionDefinition",
                    resourceId: @event.PermissionId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionDeletionValidatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}