// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainDeactivatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored DomainDeactivatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // OrganizationDomain namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when a domain is deactivated (DomainDeactivatedEvent).
    /// </summary>
    public class LogDomainDeactivatedAuditHandler :
        IDomainEventHandler<DomainDeactivatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainDeactivatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainDeactivatedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainDeactivatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // DomainId
            var initiator = @event.ChangedByConnectedId;
            var organizationId = @event.OrganizationId; // From BaseEvent

            try
            {
                const string action = "ORGANIZATION_DOMAIN_DEACTIVATED";
                var severity = AuditEventSeverity.Warning; // Deactivation is Warning

                _logger.LogWarning( // Log as Warning
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Domain, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["domain_name"] = @event.Domain,
                    ["deactivated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Deactivation is a status update
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "OrganizationDomain", // Resource type
                    resourceId: domainId.ToString(), // Resource ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DomainDeactivatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}