// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Logs an audit entry when an Application API Key is permanently deleted.
    /// </summary>
    public class LogApplicationApiKeyDeletedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyDeletedEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyDeletedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApplicationApiKeyDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyDeletedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyDeletedEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.DeletedByConnectedId;

            try
            {
                // Deletion is critical
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationApiKeyDeleted event. ApiKeyId: {ApiKeyId}, AppId: {AppId}, DeletedBy: {Initiator}",
                    apiKeyId, applicationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["deleted_by_connected_id"] = initiator,
                    ["reason"] = @event.Reason ?? "N/A",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // Deletion is critical
                };
                // auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: "APPLICATION_API_KEY_DELETED",
                    connectedId: initiator,
                    success: true, // The deletion action itself succeeded
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}