// File: AuthHive.Auth/Services/Handlers/ApplicationApi/LogApiUsageThresholdAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiUsageThresholdEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApi // New Namespace assumed
{
    /// <summary>
    /// Logs a warning audit entry when application API usage reaches a threshold.
    /// </summary>
    public class LogApiUsageThresholdAuditHandler :
        IDomainEventHandler<ApplicationApiUsageThresholdEvent>, // ❗️ Renamed event
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApiUsageThresholdAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApiUsageThresholdAuditHandler(
            IAuditService auditService,
            ILogger<LogApiUsageThresholdAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiUsageThresholdEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System

            // Avoid division by zero if quota is somehow zero
            var usagePercent = @event.Quota > 0 ? (decimal)@event.CurrentUsage / @event.Quota : 0m;

            try
            {
                _logger.LogWarning(
                    "Recording audit log for ApplicationApiUsageThreshold event. AppId: {AppId}, OrgId: {OrgId}, Type: {Type}, Usage: {UsagePercent:P1}",
                    applicationId, organizationId, @event.ThresholdType, usagePercent);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["threshold_type"] = @event.ThresholdType,
                    ["threshold_percentage"] = @event.ThresholdPercentage,
                    ["current_usage"] = @event.CurrentUsage,
                    ["quota"] = @event.Quota,
                    ["usage_percentage"] = usagePercent,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                     actionType: AuditActionType.ThresholdReached,// Specific type for threshold
                    action: "APPLICATION_API_USAGE_THRESHOLD",
                    connectedId: initiator, // System
                    success: true, // Event occurred successfully
                    resourceType: "ApplicationApiUsage",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiUsageThresholdEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}