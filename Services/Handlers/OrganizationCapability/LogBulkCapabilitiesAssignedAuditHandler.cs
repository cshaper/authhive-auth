// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogBulkCapabilitiesAssignedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored BulkCapabilitiesAssignedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // Needed for Select
using System.Text.Json; // Needed for JsonSerializer
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // Capability namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when capabilities are bulk assigned to an organization (BulkCapabilitiesAssignedEvent).
    /// </summary>
    public class LogBulkCapabilitiesAssignedAuditHandler :
        IDomainEventHandler<BulkCapabilitiesAssignedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogBulkCapabilitiesAssignedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogBulkCapabilitiesAssignedAuditHandler(
            IAuditService auditService,
            ILogger<LogBulkCapabilitiesAssignedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(BulkCapabilitiesAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // OrganizationId
            var initiator = @event.AssignedByConnectedId;

            try
            {
                const string action = "ORGANIZATION_BULK_CAPABILITIES_ASSIGNED";
                // Determine severity based on failures
                var severity = @event.FailureCount > 0 ? AuditEventSeverity.Warning : AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {Initiator}, Success: {Success}, Failed: {Failed}",
                    action, organizationId, initiator, @event.SuccessCount, @event.FailureCount);

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    // Convert enum list to string list for better logging/serialization
                    ["assigned_capabilities"] = @event.Capabilities.Select(c => c.ToString()).ToList(),
                    ["capability_settings_json"] = @event.CapabilitySettings != null ? JsonSerializer.Serialize(@event.CapabilitySettings) : string.Empty,
                    ["success_count"] = @event.SuccessCount,
                    ["failure_count"] = @event.FailureCount,
                    ["failure_reasons"] = @event.FailureReasons ?? new List<string>(), // Handle null
                    ["assigned_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Bulk assignment modifies the organization's capabilities
                    action: action,
                    connectedId: initiator,
                    success: @event.FailureCount == 0, // Overall success if no failures
                    errorMessage: @event.FailureCount > 0 ? $"{@event.FailureCount} capabilities failed to assign." : null,
                    resourceType: "Organization", // Resource type: Organization
                    resourceId: organizationId.ToString(), // Resource ID: Organization ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BulkCapabilitiesAssignedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}