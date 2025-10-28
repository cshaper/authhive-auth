// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogSslCertificateRenewedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // Refactored SslCertificateRenewedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // OrganizationDomain namespace
{
    /// <summary>
    /// **[New]** Logs an audit entry when a domain's SSL certificate is renewed (SslCertificateRenewedEvent).
    /// </summary>
    public class LogSslCertificateRenewedAuditHandler :
        IDomainEventHandler<SslCertificateRenewedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogSslCertificateRenewedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogSslCertificateRenewedAuditHandler(
            IAuditService auditService,
            ILogger<LogSslCertificateRenewedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(SslCertificateRenewedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // Domain ID
            var initiator = @event.RenewedByConnectedId; // Guid?
            var organizationId = @event.OrganizationId; // From BaseEvent

            try
            {
                const string action = "ORGANIZATION_DOMAIN_SSL_RENEWED";
                var severity = AuditEventSeverity.Info; // Successful renewal is Info

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, NewExpiry: {NewExpiry}",
                    action, @event.Domain, organizationId, @event.NewExpiryDate);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["domain_name"] = @event.Domain,
                    ["old_expiry_date"] = (object?)@event.OldExpiryDate ?? DBNull.Value, // Handle nullable DateTime
                    ["new_expiry_date"] = @event.NewExpiryDate,
                    ["renewed_by_connected_id"] = initiator ?? Guid.Empty, // System renewal possible
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit action
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Renewal updates the certificate status
                    action: action,
                    connectedId: initiator ?? Guid.Empty, // Could be system
                    success: true,
                    resourceType: "OrganizationDomainSSL", // Resource type
                    resourceId: @event.Domain, // Use domain name as resource ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SslCertificateRenewedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}