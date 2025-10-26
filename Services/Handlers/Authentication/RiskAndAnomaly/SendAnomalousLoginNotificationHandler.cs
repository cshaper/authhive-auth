// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/SendAnomalousLoginNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events; // AnomalousLoginPatternDetectedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// 비정상적인 로그인 패턴 감지 시 사용자에게 보안 알림을 발송합니다.
    /// </summary>
    public class SendAnomalousLoginNotificationHandler :
        IDomainEventHandler<AnomalousLoginPatternDetectedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendAnomalousLoginNotificationHandler> _logger;

        public int Priority => 20; // Notification handler
        public bool IsEnabled => true;

        public SendAnomalousLoginNotificationHandler(
            INotificationService notificationService,
            ILogger<SendAnomalousLoginNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(AnomalousLoginPatternDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // Determine notification priority based on RiskScore
                 var priority = @event.RiskScore switch {
                    >= 80 => NotificationPriority.High, // Use High for Critical/High risk
                    >= 60 => NotificationPriority.High,
                    _ => NotificationPriority.Normal    // Medium/Low risk
                };

                // Prepare parameters for the notification template
                var parameters = new Dictionary<string, string>
                {
                    { "dateTime", @event.OccurredAt.ToString("yyyy-MM-dd HH:mm:ss UTC") },
                    { "ipAddress", @event.IpAddress },
                    { "isNewDevice", @event.IsNewDevice.ToString().ToLower() },
                    { "isNewLocation", @event.IsNewLocation.ToString().ToLower() },
                    { "riskScore", @event.RiskScore.ToString() },
                    // Potentially add userAgent or device details if available in metadata
                    { "userAgent", @event.UserAgent ?? "Unknown" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.User,
                    RecipientIdentifiers = new List<string> { @event.AggregateId.ToString() }, // UserId
                    TemplateKey = "AnomalousLoginAlert", // Assumed template key
                    TemplateVariables = parameters,
                    Priority = priority,
                    SendImmediately = true // Send security alerts immediately
                };

                // Queue the notification
                await _notificationService.QueueNotificationAsync(
                    notificationRequest,
                    cancellationToken
                );

                _logger.LogInformation(
                    "Successfully queued AnomalousLoginAlert notification for User {UserId}.",
                    @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send AnomalousLoginAlert notification for User {UserId}: {EventId}",
                    @event.AggregateId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}