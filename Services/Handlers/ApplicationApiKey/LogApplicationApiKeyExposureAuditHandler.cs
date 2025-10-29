// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyExposureAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyExposureEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Logs a critical audit entry when an Application API Key exposure is detected.
    /// </summary>
    public class LogApplicationApiKeyExposureAuditHandler :
        IDomainEventHandler<ApplicationApiKeyExposureEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyExposureAuditHandler> _logger;

        public int Priority => 1; // Highest priority logging
        public bool IsEnabled => true;

        public LogApplicationApiKeyExposureAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyExposureAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyExposureEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System

            try
            {
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationApiKeyExposure event. ApiKeyId: {ApiKeyId}, Location: {Location}",
                    apiKeyId, @event.ExposureLocation);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["exposure_location"] = @event.ExposureLocation,
                    ["exposure_url"] = @event.ExposureUrl ?? "N/A",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // Use LogSecurityEventAsync for critical security events
                await _auditService.LogSecurityEventAsync(
                    eventType: "APPLICATION_API_KEY_EXPOSURE",
                    severity: AuditEventSeverity.Critical,
                    description: $"API Key exposure detected in {@event.ExposureLocation}",
                    connectedId: null, // System event
                    details: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log critical audit for ApplicationApiKeyExposureEvent: {EventId}", @event.EventId);
                // Even if logging fails, subsequent handlers (like deactivation) must run.
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}