// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogOAuthSettingsChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // OAuthSettingsChangedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // SequenceEqual
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Records an audit log when application OAuth settings change.
    /// </summary>
    public class LogOAuthSettingsChangedAuditHandler :
        IDomainEventHandler<OAuthSettingsChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOAuthSettingsChangedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogOAuthSettingsChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogOAuthSettingsChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(OAuthSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId;

            try
            {
                _logger.LogWarning( // OAuth changes are important
                    "Recording audit log for OAuthSettingsChanged event. AppId: {AppId}",
                    applicationId);

                // Check what actually changed to include in metadata
                bool callbacksChanged = !AreListsEqual(@event.OldCallbackUrls, @event.NewCallbackUrls);
                bool originsChanged = !AreListsEqual(@event.OldAllowedOrigins, @event.NewAllowedOrigins);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["changed_by_connected_id"] = initiator,
                    ["callback_urls_changed"] = callbacksChanged,
                    ["allowed_origins_changed"] = originsChanged,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // Security-related config change
                    // Optionally include Old/New lists if size isn't excessive
                    // ["old_callback_urls"] = @event.OldCallbackUrls ?? (object)DBNull.Value,
                    // ["new_callback_urls"] = @event.NewCallbackUrls ?? (object)DBNull.Value,
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration,
                    action: "OAUTH_SETTINGS_CHANGED",
                    connectedId: initiator,
                    success: true,
                    resourceType: "ApplicationOAuthSettings",
                    resourceId: applicationId.ToString(), // Settings belong to the Application
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for OAuthSettingsChangedEvent: {EventId}", @event.EventId);
            }
        }

        // Helper from ApplicationEventHandler (modified for IReadOnlyList)
        private bool AreListsEqual(IReadOnlyList<string>? list1, IReadOnlyList<string>? list2)
        {
            if (ReferenceEquals(list1, list2)) return true;
            if (list1 is null || list2 is null) return false;
            // Use SequenceEqual for order-dependent comparison, or convert to HashSet for order-independent
            return list1.SequenceEqual(list2);
        }


        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}