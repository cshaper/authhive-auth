// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionUpdateValidatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionUpdateValidatedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 업데이트 유효성 검사 완료 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionUpdateValidatedAuditHandler :
        IDomainEventHandler<PermissionUpdateValidatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionUpdateValidatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionUpdateValidatedAuditHandler(IAuditService auditService, ILogger<LogPermissionUpdateValidatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionUpdateValidatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.UpdatedBy; // 업데이트 시도 주체

            try
            {
                var severity = @event.IsSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning;

                _logger.LogInformation(
                    "Recording audit log for PermissionUpdateValidated event. Org: {OrgId}, Scope: {NewScope}, Success: {Success}",
                    organizationId, @event.NewScope, @event.IsSuccess);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = @event.PermissionId,
                    ["old_scope"] = @event.OldScope,
                    ["new_scope"] = @event.NewScope,
                    ["updated_by"] = initiator,
                    ["validation_result"] = @event.ValidationResult,
                    ["organization_id"] = organizationId,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Validation,
                    "PERMISSION_UPDATE_VALIDATED",
                    initiator,
                    success: @event.IsSuccess,
                    errorMessage: @event.IsSuccess ? null : @event.ValidationResult,
                    resourceType: "PermissionUpdateValidation",
                    resourceId: @event.PermissionId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionUpdateValidatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}