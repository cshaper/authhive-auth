// File: authhive.auth/services/handlers/User/Activity/LogAnomalousActivityHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IDomainEventHandler와 IService를 구현합니다.
// 목적: 'AnomalousActivityDetectedEvent'를 처리하여 감사 로그 및 ML 학습 데이터를 캐시합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Activity; // AnomalousActivityDetectedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Activity
{
    /// <summary>
    /// 이상 활동 감지 시 감사 로그 및 ML 데이터 캐싱을 처리합니다.
    /// </summary>
    public class LogAnomalousActivityHandler : 
        IDomainEventHandler<AnomalousActivityDetectedEvent>, // ❗️ 수정됨
        IService
    {
        private readonly ILogger<LogAnomalousActivityHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;

        private const string CACHE_KEY_PREFIX = "activity";

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAnomalousActivityHandler(
            ILogger<LogAnomalousActivityHandler> logger,
            IAuditService auditService,
            ICacheService cacheService)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
        }

        /// <summary>
        /// (한글 주석) 이상 활동 감지 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(AnomalousActivityDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // (한글 주석) 신뢰도 점수가 높은(예: 75% 이상) 경우에만 감사 로그 및 캐시를 처리합니다.
                if (@event.ConfidenceScore > 0.75)
                {
                    var anomalyData = PrepareAuditMetadata(@event);

                    // 1. (한글 주석) ML 학습용 데이터 캐시 저장 (예시)
                    var mlKey = $"{CACHE_KEY_PREFIX}:anomaly:ml:{@event.UserId:N}:{Guid.NewGuid():N}";
                    await _cacheService.SetAsync(mlKey, anomalyData, TimeSpan.FromDays(7), cancellationToken);

                    // 2. (한글 주석) 감사 로그 기록
                    await _auditService.LogActionAsync(
                        AuditActionType.System, // (한글 주석) 시스템이 감지한 이벤트
                        "ANOMALY_DETECTED",
                        @event.ConnectedId,
                        resourceId: @event.UserId.ToString(), // (한글 주석) 영향받은 사용자 ID
                        metadata: anomalyData);
                    
                    _logger.LogWarning("High confidence anomaly detected for User {UserId}: Type={AnomalyType}, Score={ConfidenceScore}",
                        @event.UserId, @event.AnomalyType, @event.ConfidenceScore);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Anomaly detection processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
            }
        }
        
        // (한글 주석) 감사 로그에 기록할 메타데이터 사전을 준비합니다.
        private Dictionary<string, object> PrepareAuditMetadata(AnomalousActivityDetectedEvent @event)
        {
             return new Dictionary<string, object>
             {
                 ["type"] = @event.AnomalyType,
                 ["description"] = @event.Description,
                 ["confidence_score"] = @event.ConfidenceScore,
                 ["timestamp"] = @event.OccurredAt,
                 ["indicators"] = @event.AnomalyIndicators ?? Array.Empty<string>(),
                 ["ip_address"] = @event.ClientIpAddress ?? "N/A", // BaseEvent 속성
                 ["location"] = @event.Location ?? "N/A",         // BaseEvent 속성
                 ["device"] = @event.DeviceFingerprint ?? "N/A"  // BaseEvent 속성
             };
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // (한글 주석) 이 핸들러가 의존하는 캐시 서비스의 상태를 확인합니다.
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}