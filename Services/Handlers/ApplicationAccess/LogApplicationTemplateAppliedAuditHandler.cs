// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogApplicationTemplateAppliedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationTemplateAppliedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// Logs an audit entry when an access template is applied to a user's application access.
    /// </summary>
    public class LogApplicationTemplateAppliedAuditHandler :
        IDomainEventHandler<ApplicationTemplateAppliedEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationTemplateAppliedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApplicationTemplateAppliedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationTemplateAppliedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationTemplateAppliedEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user the template was applied to
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.AppliedByConnectedId; // The user who applied the template

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationTemplateApplied event. ConnectedId: {ConnectedId}, AppId: {AppId}, TemplateId: {TemplateId}",
                    connectedId, applicationId, @event.TemplateId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["template_id"] = @event.TemplateId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["applied_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // Use .Info
                };
                // auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Applying a template updates access
                    action: "APPLICATION_TEMPLATE_APPLIED",
                    connectedId: initiator, // Actor
                    success: true, // Action succeeded
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // ID of the access record
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationTemplateAppliedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}