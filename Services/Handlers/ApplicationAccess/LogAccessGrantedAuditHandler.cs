// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogAccessGrantedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // AccessGrantedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess // New Namespace
{
    /// <summary>
    /// Logs an audit entry when application access is granted.
    /// </summary>
    public class LogAccessGrantedAuditHandler :
        IDomainEventHandler<AccessGrantedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAccessGrantedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAccessGrantedAuditHandler(
            IAuditService auditService,
            ILogger<LogAccessGrantedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(AccessGrantedEvent @event, CancellationToken cancellationToken = default)
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user granted access
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.GrantedByConnectedId; // The user who granted access

            try
            {
                _logger.LogInformation(
                    "Recording audit log for AccessGranted event. ConnectedId: {ConnectedId}, AppId: {AppId}, Level: {Level}",
                    connectedId, applicationId, @event.AccessLevel);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["access_level"] = @event.AccessLevel.ToString(),
                    ["role_id"] = @event.RoleId ?? (object)DBNull.Value,
                    ["template_id"] = @event.TemplateId ?? (object)DBNull.Value,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty, // Use OrgId from event
                    ["granted_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // Renamed enum value
                };
                // @event.Metadata.MergeInto(auditData); // Helper needed if you want BaseEvent metadata

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Grant, // Use Grant type
                    action: "APPLICATION_ACCESS_GRANTED",
                    connectedId: initiator, // The actor
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // ID of the access record
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AccessGrantedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}