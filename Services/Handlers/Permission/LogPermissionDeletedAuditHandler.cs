// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionDeletedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 정의 삭제 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionDeletedAuditHandler :
        IDomainEventHandler<PermissionDeletedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionDeletedAuditHandler> _logger;

        public int Priority => 10; // Logging handler
        public bool IsEnabled => true;

        public LogPermissionDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionDeletedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionId = @event.AggregateId; // PermissionId
            // The user/process that initiated the deletion (assuming ConnectedId)
            var initiator = @event.DeletedBy ?? Guid.Empty; 

            try
            {
                _logger.LogWarning( // Deletion is significant, use Warning level
                    "Recording audit log for PermissionDeleted event. PermissionId: {PermissionId}, Scope: {Scope}",
                    permissionId, @event.Scope);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = permissionId,
                    ["scope"] = @event.Scope,
                    ["was_system_permission"] = @event.WasSystemPermission,
                    ["deleted_by_connected_id"] = initiator, // Assuming DeletedBy is ConnectedId
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    // Deletion might be Critical depending on policy
                    ["severity"] = AuditEventSeverity.Warning.ToString() 
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    "PERMISSION_DEFINITION_DELETED",
                    initiator, // connectedId performing the action
                    success: true, // The delete action itself succeeded
                    errorMessage: null,
                    resourceType: "PermissionDefinition", // The resource is the definition
                    resourceId: permissionId.ToString(), // ID of the deleted definition
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}