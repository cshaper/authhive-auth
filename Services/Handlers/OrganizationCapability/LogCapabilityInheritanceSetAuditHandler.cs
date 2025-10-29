// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogCapabilityInheritanceSetAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored CapabilityInheritanceSetEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // Capability namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when capability inheritance settings change (CapabilityInheritanceSetEvent).
    /// </summary>
    public class LogCapabilityInheritanceSetAuditHandler :
        IDomainEventHandler<CapabilityInheritanceSetEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogCapabilityInheritanceSetAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogCapabilityInheritanceSetAuditHandler(
            IAuditService auditService,
            ILogger<LogCapabilityInheritanceSetAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(CapabilityInheritanceSetEvent @event, CancellationToken cancellationToken = default)
        {
            var childOrganizationId = @event.AggregateId; // Child Org ID (affected org)
            var initiator = @event.SetByConnectedId;
            var parentOrganizationId = @event.ParentOrganizationId;

            try
            {
                const string action = "ORGANIZATION_CAPABILITY_INHERITANCE_SET";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Capability: {Capability}, ChildOrg: {ChildOrgId}, ParentOrg: {ParentOrgId}, Initiator: {Initiator}",
                    action, @event.Capability, childOrganizationId, parentOrganizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["child_organization_id"] = childOrganizationId,
                    ["parent_organization_id"] = parentOrganizationId,
                    ["capability"] = @event.Capability.ToString(),
                    ["enable_inheritance"] = @event.EnableInheritance,
                    ["allow_override"] = @event.AllowOverride,
                    ["reason"] = @event.Reason ?? string.Empty,
                    ["set_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Changing inheritance is an 'Update'
                    action: action,
                    connectedId: initiator,
                    success: true,
                    // Resource represents the inheritance setting *on the child*
                    resourceType: "OrganizationCapabilityInheritance",
                    resourceId: childOrganizationId.ToString(), // Child org is the affected resource
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for CapabilityInheritanceSetEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}