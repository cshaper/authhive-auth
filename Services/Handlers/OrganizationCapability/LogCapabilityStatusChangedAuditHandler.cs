// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogCapabilityStatusChangedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored CapabilityStatusChangedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // Capability namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when a capability's active status changes (CapabilityStatusChangedEvent).
    /// </summary>
    public class LogCapabilityStatusChangedAuditHandler :
        IDomainEventHandler<CapabilityStatusChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogCapabilityStatusChangedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogCapabilityStatusChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogCapabilityStatusChangedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(CapabilityStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var capabilityAssignmentId = @event.AggregateId; // Assignment ID
            var initiator = @event.ChangedByConnectedId;
            var organizationId = @event.OrganizationId; // From BaseEvent

            try
            {
                // Determine action name based on the change
                var action = @event.NewIsActive ? "ORGANIZATION_CAPABILITY_ACTIVATED" : "ORGANIZATION_CAPABILITY_DEACTIVATED";
                var severity = AuditEventSeverity.Info; // Status change is usually Info, unless deactivation needs Warning

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Capability: {Capability}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Capability, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["capability_assignment_id"] = capabilityAssignmentId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["capability"] = @event.Capability.ToString(),
                    ["old_is_active"] = @event.OldIsActive,
                    ["new_is_active"] = @event.NewIsActive,
                    ["changed_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Status change is an 'Update'
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "OrganizationCapabilityAssignment", // Resource type
                    resourceId: capabilityAssignmentId.ToString(), // Resource ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for CapabilityStatusChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}