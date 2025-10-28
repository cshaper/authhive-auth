// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyCreatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyCreatedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey // New Namespace
{
    /// <summary>
    /// Logs an audit entry when a new Application API Key is created.
    /// </summary>
    public class LogApplicationApiKeyCreatedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyCreatedEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyCreatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApplicationApiKeyCreatedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyCreatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyCreatedEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var apiKeyId = @event.AggregateId; // The ID of the API Key itself
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.CreatedByConnectedId; // The user who created the key

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationApiKeyCreated event. ApiKeyId: {ApiKeyId}, AppId: {AppId}, Name: {KeyName}",
                    apiKeyId, applicationId, @event.KeyName);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["key_name"] = @event.KeyName,
                    ["key_prefix"] = @event.KeyPrefix,
                    ["key_source"] = @event.KeySource.ToString(),
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["created_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // Key creation is informational but important
                };
                // auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: "APPLICATION_API_KEY_CREATED",
                    connectedId: initiator, // Actor
                    success: true,
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(), // ID of the key
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyCreatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}