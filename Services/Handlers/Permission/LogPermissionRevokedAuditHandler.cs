// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionRevokedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionRevokedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 사용자로부터 권한이 취소되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionRevokedAuditHandler :
        IDomainEventHandler<PermissionRevokedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionRevokedAuditHandler> _logger;

        public int Priority => 10; // Logging handler
        public bool IsEnabled => true;

        public LogPermissionRevokedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionRevokedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionRevokedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionGrantId = @event.AggregateId; // The grant being revoked
            var targetUserId = @event.UserId;
            // The user/process that initiated the revocation (assuming ConnectedId)
            var initiator = @event.RevokedByUserId; 

            try
            {
                _logger.LogWarning( // Revocation is a significant event, use Warning level
                    "Recording audit log for PermissionRevoked event. TargetUser: {TargetUserId}, Scope: {Scope}, RevokedBy: {RevokedBy}",
                    targetUserId, @event.PermissionScope, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["target_user_id"] = targetUserId,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty, // Context where permission was revoked
                    ["permission_scope"] = @event.PermissionScope,
                    ["revoked_by_user_id"] = initiator, // Assuming RevokedByUserId is ConnectedId
                    ["reason"] = @event.Reason ?? "N/A",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // Revocation is Warning level
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.PermissionUpdated, // Revocation is a type of permission update
                    "USER_PERMISSION_REVOKED",
                    initiator, // connectedId performing the action
                    success: true, // The revocation action itself succeeded
                    errorMessage: null,
                    resourceType: "UserPermissionGrant", // The resource affected is the grant
                    resourceId: permissionGrantId.ToString(), // ID of the grant being revoked
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionRevokedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}