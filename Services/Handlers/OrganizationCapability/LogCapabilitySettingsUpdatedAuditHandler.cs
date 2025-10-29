// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogCapabilitySettingsUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored CapabilitySettingsUpdatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // Capability namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when capability settings are updated (CapabilitySettingsUpdatedEvent).
    /// </summary>
    public class LogCapabilitySettingsUpdatedAuditHandler :
        IDomainEventHandler<CapabilitySettingsUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogCapabilitySettingsUpdatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogCapabilitySettingsUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogCapabilitySettingsUpdatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(CapabilitySettingsUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var capabilityAssignmentId = @event.AggregateId; // Assignment ID
            var initiator = @event.UpdatedByConnectedId;
            var organizationId = @event.OrganizationId; // From BaseEvent

            try
            {
                const string action = "ORGANIZATION_CAPABILITY_SETTINGS_UPDATED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Capability: {Capability}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Capability, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["capability_assignment_id"] = capabilityAssignmentId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["capability"] = @event.Capability.ToString(),
                    ["old_settings_json"] = @event.OldSettings ?? string.Empty,
                    ["new_settings_json"] = @event.NewSettings,
                   ["effective_from"] = (object?)@event.EffectiveFrom ?? DBNull.Value, // Handle nullable DateTime
                    ["updated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Settings change is an 'Update'
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
                _logger.LogError(ex, "Failed to log audit for CapabilitySettingsUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}