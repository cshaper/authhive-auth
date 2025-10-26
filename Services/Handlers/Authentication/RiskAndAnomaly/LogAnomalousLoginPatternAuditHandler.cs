// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogAnomalousLoginPatternAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // AnomalousLoginPatternDetectedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// 비정상적인 로그인 패턴 감지 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogAnomalousLoginPatternAuditHandler :
        IDomainEventHandler<AnomalousLoginPatternDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAnomalousLoginPatternAuditHandler> _logger;

        public int Priority => 10; // Logging handler
        public bool IsEnabled => true;

        public LogAnomalousLoginPatternAuditHandler(
            IAuditService auditService,
            ILogger<LogAnomalousLoginPatternAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(AnomalousLoginPatternDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            var initiator = @event.TriggeredBy ?? userId; // Usually the user themselves

            try
            {
                // Determine severity based on RiskScore (adjust thresholds as needed)
                var severity = @event.RiskScore switch {
                    >= 80 => AuditEventSeverity.Critical,
                    >= 60 => AuditEventSeverity.High,
                    >= 40 => AuditEventSeverity.Medium,
                    _ => AuditEventSeverity.Low
                };

                _logger.LogWarning( // Log anomaly detection as a warning
                    "Recording audit log for AnomalousLoginPatternDetected event. User: {UserId}, IP: {IpAddress}, RiskScore: {RiskScore}",
                    userId, @event.IpAddress, @event.RiskScore);

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["ip_address"] = @event.IpAddress,
                    ["device_fingerprint"] = @event.DeviceFingerprint ?? "N/A",
                    ["is_new_location"] = @event.IsNewLocation,
                    ["is_new_device"] = @event.IsNewDevice,
                    ["risk_score"] = @event.RiskScore,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // Log the audit record
                await _auditService.LogActionAsync(
                    AuditActionType.Security,
                    "USER_LOGIN_ANOMALY_DETECTED", // Specific action key
                    initiator,
                    success: true, // The anomaly *detection* was successful
                    errorMessage: null,
                    resourceType: "UserLoginAttempt", // Resource type
                    resourceId: userId.ToString(), // Resource ID (User related)
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AnomalousLoginPatternDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}