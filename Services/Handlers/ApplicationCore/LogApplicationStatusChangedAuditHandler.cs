// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogApplicationStatusChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationStatusChangedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Records an audit log when an application's status changes.
    /// </summary>
    public class LogApplicationStatusChangedAuditHandler :
        IDomainEventHandler<ApplicationStatusChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationStatusChangedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApplicationStatusChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationStatusChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId;

            try
            {
                var severity = GetSeverity(@event.NewStatus); // Determine severity based on new status
                _logger.Log(severity == AuditEventSeverity.Warning ? LogLevel.Warning : LogLevel.Information,
                    "Recording audit log for ApplicationStatusChanged event. AppId: {AppId}, {OldStatus} -> {NewStatus}",
                    applicationId, @event.OldStatus, @event.NewStatus);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["changed_by_connected_id"] = initiator,
                    ["old_status"] = @event.OldStatus.ToString(),
                    ["new_status"] = @event.NewStatus.ToString(),
                    ["reason"] = @event.Reason ?? "N/A",
                    ["changed_at"] = @event.ChangedAt,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.StatusChange,
                    action: "APPLICATION_STATUS_CHANGED",
                    connectedId: initiator,
                    success: true,
                    resourceType: "Application",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationStatusChangedEvent: {EventId}", @event.EventId);
            }
        }

        private AuditEventSeverity GetSeverity(ApplicationStatus newStatus) =>
            newStatus switch {
                ApplicationStatus.Suspended => AuditEventSeverity.Warning,
                ApplicationStatus.Deleted => AuditEventSeverity.Critical, // Should be handled by DeletedEvent handler
                _ => AuditEventSeverity.Info
            };

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}