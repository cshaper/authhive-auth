// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogAnomalousLoginAuditHandler.cs
// ----------------------------------------------------------------------
// [New Handler]
// Logs an audit entry when an AnomalousLoginPatternDetectedEvent occurs.
// (Tracks suspicious login patterns)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // Extension method for MergeMetadata

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly // Folder: Authentication/RiskAndAnomaly
{
    /// <summary>
    /// (한글 주석) 비정상적인 로그인 패턴 감지 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAnomalousLoginAuditHandler :
        IDomainEventHandler<AnomalousLoginPatternDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAnomalousLoginAuditHandler> _logger;

        // --- IDomainEventHandler Implementation ---
        public int Priority => 15; // Higher priority than regular login success/failure
        public bool IsEnabled => true;

        public LogAnomalousLoginAuditHandler(
            IAuditService auditService,
            ILogger<LogAnomalousLoginAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 비정상 로그인 패턴 감지 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AnomalousLoginPatternDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // BaseEvent's AggregateId is UserId
            try
            {
                _logger.LogWarning("Recording audit log for AnomalousLoginPatternDetected event. User: {UserId}, IP: {IP}, NewLoc: {NewLoc}, NewDev: {NewDev}, Risk: {Risk}",
                    userId, @event.IpAddress, @event.IsNewLocation, @event.IsNewDevice, @event.RiskScore); // Log as Warning

                // (한글 주석) 감사 로그 메타데이터 준비
                var anomalyData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["ip_address"] = @event.IpAddress ?? "N/A",
                    ["device_fingerprint"] = @event.DeviceFingerprint ?? "N/A", // Nullable string
                    ["is_new_location"] = @event.IsNewLocation,
                    ["is_new_device"] = @event.IsNewDevice,
                    ["risk_score"] = @event.RiskScore,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // Anomaly is typically a Warning
                };

                // (한글 주석) BaseEvent의 Metadata 병합 (확장 메서드 사용)
                anomalyData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.System, // Detected by the system
                    "ANOMALOUS_LOGIN_PATTERN_DETECTED",
                    userId, // Actor is the user attempting login
                    success: false, // Indicate it's a negative security event
                    errorMessage: $"Anomalous login pattern detected (Risk: {@event.RiskScore})", // Add context
                    resourceType: "UserLoginAttempt",
                    resourceId: userId.ToString(), // The user affected
                    metadata: anomalyData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AnomalousLoginPatternDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService Implementation (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogAnomalousLoginAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // Assume IAuditService implements IHealthCheckable
             // return Task.FromResult(IsEnabled && await _auditService.IsHealthyAsync(cancellationToken));
             return Task.FromResult(IsEnabled);
        }
        #endregion
    }
}