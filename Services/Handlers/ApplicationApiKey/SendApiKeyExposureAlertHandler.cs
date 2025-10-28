// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/SendApiKeyExposureAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyExposureEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Sends a critical alert to the security team upon API Key exposure detection.
    /// </summary>
    public class SendApiKeyExposureAlertHandler :
        IDomainEventHandler<ApplicationApiKeyExposureEvent>, // ❗️ Renamed event
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendApiKeyExposureAlertHandler> _logger;
        // TODO: Service to get target recipients (Org Admins, Security Team)

        public int Priority => 5; // Alerting is high priority
        public bool IsEnabled => true;

        public SendApiKeyExposureAlertHandler(
            INotificationService notificationService,
            ILogger<SendApiKeyExposureAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyExposureEvent @event, CancellationToken cancellationToken = default) // ❗️ Renamed event
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // Example Security Team ID
                // TODO: Also get Organization Admins based on @event.OrganizationId

                var templateVariables = new Dictionary<string, string>
                {
                    { "ApiKeyId", @event.AggregateId.ToString() },
                    { "ApplicationId", @event.ApplicationId?.ToString() ?? "N/A" },
                    { "OrganizationId", @event.OrganizationId?.ToString() ?? "N/A" },
                    { "ExposureLocation", @event.ExposureLocation },
                    { "ExposureUrl", @event.ExposureUrl ?? "N/A" },
                    { "DetectedAt", @event.OccurredAt.ToString("o") }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId,
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() /*, ... org admins */ },
                    TemplateKey = "SECURITY_API_KEY_EXPOSURE_DETECTED", // Critical Alert Template
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true // Send critical alerts immediately
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for ApiKeyExposure event for ApiKeyId {ApiKeyId}", @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send ApiKeyExposure alert for ApiKeyId: {ApiKeyId}", @event.AggregateId);
                // Don't rethrow, ensure deactivation handler runs
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}