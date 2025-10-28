// File: AuthHive.Auth/Services/Handlers/ApplicationApi/SendApiUsageWarningNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiUsageThresholdEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApi
{
    /// <summary>
    /// Sends a warning notification to organization admins when API usage reaches a threshold.
    /// </summary>
    public class SendApiUsageWarningNotificationHandler :
        IDomainEventHandler<ApplicationApiUsageThresholdEvent>, // ❗️ Renamed event
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendApiUsageWarningNotificationHandler> _logger;
        // TODO: Service to get Org Admins based on OrganizationId

        public int Priority => 30;
        public bool IsEnabled => true;

        public SendApiUsageWarningNotificationHandler(
            INotificationService notificationService,
            ILogger<SendApiUsageWarningNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiUsageThresholdEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            // TODO: Throttle notifications to avoid spamming if usage fluctuates around the threshold
            
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var usagePercent = @event.Quota > 0 ? (decimal)@event.CurrentUsage / @event.Quota : 0m;

            try
            {
                var adminConnectedId = new Guid("{00000000-0000-0000-0000-000000000002}"); // Example Org Admin ID

                var templateVariables = new Dictionary<string, string>
                {
                    { "ApplicationId", applicationId.ToString() },
                    { "OrganizationId", organizationId.ToString() },
                    { "ThresholdType", @event.ThresholdType },
                    { "CurrentUsage", @event.CurrentUsage.ToString() },
                    { "Quota", @event.Quota.ToString() },
                    { "UsagePercentage", usagePercent.ToString("P1") }, // Format as percentage (e.g., "80.5%")
                    { "ThresholdPercentage", @event.ThresholdPercentage.ToString("P0") } // Format as percentage (e.g., "80%")
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId,
                    RecipientIdentifiers = new List<string> { adminConnectedId.ToString() },
                    TemplateKey = "APPLICATION_API_USAGE_WARNING", // Warning notification template
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Normal, // It's a warning, not critical yet
                    SendImmediately = false // Can be batched
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("API Usage Warning notification queued for AppId {AppId}, Type {Type}", applicationId, @event.ThresholdType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send API Usage Warning notification for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}