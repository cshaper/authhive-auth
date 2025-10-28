// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogCapabilityAssignedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored CapabilityAssignedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // New Capability namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when a capability is assigned to an organization (CapabilityAssignedEvent).
    /// </summary>
    public class LogCapabilityAssignedAuditHandler :
        IDomainEventHandler<CapabilityAssignedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogCapabilityAssignedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogCapabilityAssignedAuditHandler(
            IAuditService auditService,
            ILogger<LogCapabilityAssignedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(CapabilityAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            var capabilityAssignmentId = @event.AggregateId; // Assignment ID
            var initiator = @event.AssignedByConnectedId;
            var organizationId = @event.OrganizationId; // From BaseEvent

            try
            {
                const string action = "ORGANIZATION_CAPABILITY_ASSIGNED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Capability: {Capability}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Capability, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["capability_assignment_id"] = capabilityAssignmentId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["capability"] = @event.Capability.ToString(),
                    ["settings_json"] = @event.Settings ?? string.Empty, // Handle null settings
                    ["is_active"] = @event.IsActive,
                    ["assigned_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create, // Assignment is a 'Create' action
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "OrganizationCapabilityAssignment", // Resource type: assignment record
                    resourceId: capabilityAssignmentId.ToString(), // Resource ID: assignment ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for CapabilityAssignedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}