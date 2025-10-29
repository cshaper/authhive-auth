// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyScopeChangedAuditHandler.cs

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyScopeChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For string.Join
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Logs a critical audit entry when an Application API Key's scopes are changed.
    /// </summary>
    public class LogApplicationApiKeyScopeChangedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyScopeChangedEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyScopeChangedAuditHandler> _logger;

        public int Priority => 5; // High priority logging for critical events
        public bool IsEnabled => true;

        public LogApplicationApiKeyScopeChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyScopeChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyScopeChangedEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId;

            try
            {
                // Scope changes are critical
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationApiKeyScopeChanged event. ApiKeyId: {ApiKeyId}, AppId: {AppId}",
                    apiKeyId, applicationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["changed_by_connected_id"] = initiator,
                    ["old_scopes"] = @event.OldScopes,
                    ["new_scopes"] = @event.NewScopes,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // Scope change is Critical
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // BaseEvent metadata

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.PermissionUpdated, // Scope change modifies permissions
                    action: "APPLICATION_API_KEY_SCOPE_CHANGED",
                    connectedId: initiator,
                    success: true,
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyScopeChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}