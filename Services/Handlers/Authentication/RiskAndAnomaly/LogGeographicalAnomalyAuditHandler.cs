// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogGeographicalAnomalyAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// GeographicalAnomalyDetectedEvent 발생 시 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // 수정된 이벤트 사용
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;


namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// (한글 주석) 지리적 이상 감지 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogGeographicalAnomalyAuditHandler :
        IDomainEventHandler<GeographicalAnomalyDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogGeographicalAnomalyAuditHandler> _logger;

        public int Priority => 5; // BruteForce와 같은 최우선 순위
        public bool IsEnabled => true;

        public LogGeographicalAnomalyAuditHandler(
            IAuditService auditService,
            ILogger<LogGeographicalAnomalyAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 지리적 이상 감지 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(GeographicalAnomalyDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            try
            {
                _logger.LogCritical("Recording audit log for GeographicalAnomalyDetected event. User: {UserId}, ConnectedId: {ConnectedId}, IP: {IP}, NewLoc: {NewLoc}, Risk: {Risk}",
                    userId, @event.ConnectedId, @event.ClientIpAddress, @event.NewLocation, @event.RiskScore);

                // (한글 주석) 감사 로그 메타데이터 준비
                var anomalyData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["connected_id"] = @event.ConnectedId, // ❗️ ConnectedId 포함
                    ["ip_address"] = @event.ClientIpAddress ?? "N/A",
                    ["new_location"] = @event.NewLocation,
                    ["previous_locations"] = @event.PreviousLocations ?? new List<string>(),
                    ["risk_score"] = @event.RiskScore,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // Critical 심각도
                };
                anomalyData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 보안 플로우 중단이 발생했다는 의미로 Blocked 사용
                    "GEOGRAPHICAL_ANOMALY_DETECTED",
                    @event.ConnectedId, // 행위자
                    success: false, // 보안 위협 이벤트는 실패(부정적)로 간주
                    errorMessage: $"Geographical anomaly detected (New Location: {@event.NewLocation}, Risk: {@event.RiskScore})",
                    resourceType: "UserActivity",
                    resourceId: userId.ToString(),
                    metadata: anomalyData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for GeographicalAnomalyDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}