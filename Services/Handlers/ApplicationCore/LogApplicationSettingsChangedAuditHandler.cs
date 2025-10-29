// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogApplicationSettingsChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationSettingsChangedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Logs an audit entry when an *important* application setting changes.
    /// (Logic from ApplicationEventHandler's HandleApplicationSettingsChangedAsync)
    /// </summary>
    public class LogApplicationSettingsChangedAuditHandler :
        IDomainEventHandler<ApplicationSettingsChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationSettingsChangedAuditHandler> _logger;

        // Define important settings (copied from ApplicationEventHandler)
        private static readonly HashSet<string> ImportantSettings = new(StringComparer.OrdinalIgnoreCase)
        {
            "ApiRateLimit", "MaxSessionDuration", "RequireApiKey", "SecurityLevel", /* other important settings */
        };

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApplicationSettingsChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationSettingsChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // Only log if the setting is considered important
            if (!IsImportantSetting(@event.SettingKey))
            {
                return;
            }

            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for important ApplicationSettingsChanged event. AppId: {AppId}, Key: {SettingKey}",
                    applicationId, @event.SettingKey);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["changed_by_connected_id"] = initiator,
                    ["setting_key"] = @event.SettingKey,
                    ["old_value"] = @event.OldValue ?? DBNull.Value, // Handle null
                    ["new_value"] = @event.NewValue ?? DBNull.Value, // Handle null
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // Configuration changes are usually Info
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration,
                    action: "APPLICATION_SETTING_CHANGED",
                    connectedId: initiator,
                    success: true,
                    resourceType: "ApplicationSetting",
                    // Use composite resource ID for uniqueness
                    resourceId: $"{applicationId}:{@event.SettingKey}",
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationSettingsChangedEvent: {EventId}", @event.EventId);
            }
        }

        // Helper from ApplicationEventHandler
        private bool IsImportantSetting(string settingKey) => ImportantSettings.Contains(settingKey);

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}