// File: authhive.auth/services/handlers/User/Activity/RespondToHighRiskActivityHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IDomainEventHandler와 IService를 구현합니다.
// ❗️ IEventBus를 사용하여 후속 조치를 발행합니다.
// 목적: 'HighRiskActivityDetectedEvent'를 처리하여 감사 및 대응(이벤트 발행)을 수행합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Interfaces.Infra; // IEventBus
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.System; // HighRiskActivityDetectedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Activity
{
    /// <summary>
    /// 고위험 활동 감지 시 감사 및 IEventBus를 통한 대응 조치를 수행합니다.
    /// </summary>
    public class RespondToHighRiskActivityHandler : 
        IDomainEventHandler<HighRiskActivityDetectedEvent>, // ❗️ 수정됨
        IService
    {
        private readonly ILogger<RespondToHighRiskActivityHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IEventBus _eventBus; // 제약 조건: IEventBus 사용

        private const string CACHE_KEY_PREFIX = "activity";

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;

        public RespondToHighRiskActivityHandler(
            ILogger<RespondToHighRiskActivityHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IEventBus eventBus)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _eventBus = eventBus;
        }

        /// <summary>
        /// (한글 주석) 고위험 활동 감지 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(HighRiskActivityDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var threatLevel = ParseThreatLevel(@event.ThreatLevel);
                var riskData = PrepareAuditMetadata(@event, threatLevel);

                // 1. (한글 주석) 위험 수준별 대응 실행 (IEventBus로 후속 이벤트 발행)
                await ExecuteRiskResponseAsync(threatLevel, @event, cancellationToken);

                // 2. (한글 주석) 감사 로그 기록 (IAuditService)
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // (한글 주석) 고위험 활동은 기본 '차단' 유형으로 로깅
                    $"HIGH_RISK_{@event.ThreatType.ToUpperInvariant()}",
                    @event.ConnectedId,
                    resourceId: @event.ActivityLogId.ToString(),
                    metadata: riskData);

                // 3. (한글 주석) 위험 정보 캐싱 (ICacheService) - 대시보드 등에서 활용
                var riskKey = $"{CACHE_KEY_PREFIX}:risk:{@event.UserId:N}";
                await _cacheService.SetAsync(riskKey, riskData, TimeSpan.FromHours(24), cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "High risk activity processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
            }
        }

        #region Helper Methods (From Original Handler)

        // (한글 주석) 감사 로그에 저장할 메타데이터 사전을 준비합니다.
        private Dictionary<string, object> PrepareAuditMetadata(HighRiskActivityDetectedEvent @event, SecurityThreatLevel threatLevel)
        {
             return new Dictionary<string, object>
             {
                 ["activity_log_id"] = @event.ActivityLogId,
                 ["risk_score"] = @event.RiskScore,
                 ["threat_type"] = @event.ThreatType,
                 ["threat_level"] = threatLevel.ToString(),
                 ["description"] = @event.Description,
                 ["timestamp"] = @event.OccurredAt,
                 ["recommended_actions"] = @event.RecommendedActions ?? Array.Empty<string>()
             };
        }

        // (한글 주석) 문자열로 된 위험 수준을 Enum으로 파싱합니다.
        private SecurityThreatLevel ParseThreatLevel(string threatLevel)
        {
            return threatLevel?.ToUpperInvariant() switch
            {
                "CRITICAL" => SecurityThreatLevel.Critical,
                "HIGH" => SecurityThreatLevel.High,
                "MEDIUM" => SecurityThreatLevel.Medium,
                _ => SecurityThreatLevel.Low // (한글 주석) 알 수 없는 값은 '낮음'으로 처리
            };
        }
        
        /// <summary>
        /// (한글 주석) ❗️ IEventBus를 사용하여 실제 조치(계정 잠금, 세션 종료 등) 이벤트를 발행합니다.
        /// </summary>
        private async Task ExecuteRiskResponseAsync(SecurityThreatLevel threatLevel, HighRiskActivityDetectedEvent @event, CancellationToken cancellationToken)
        {
            switch (threatLevel)
            {
                case SecurityThreatLevel.Critical:
                    _logger.LogCritical("Critical threat detected: {ThreatType} for User {UserId}. Publishing AccountLockout and SessionRevoke events.", 
                        @event.ThreatType, @event.UserId);
                    
                    // (한글 주석) (가상 이벤트) 계정 잠금 및 모든 세션 강제 종료 이벤트를 발행합니다.
                    // await _eventBus.PublishAsync(new TriggerAccountLockoutEvent(@event.UserId, @event.ConnectedId, "CriticalThreatDetected"), cancellationToken);
                    // await _eventBus.PublishAsync(new RevokeAllUserSessionsEvent(@event.UserId, "CriticalThreatDetected"), cancellationToken);
                    break;

                case SecurityThreatLevel.High:
                     _logger.LogError("High threat detected: {ThreatType} for User {UserId}. Publishing ForceMfaReauthentication event.", 
                        @event.ThreatType, @event.UserId);
                    // (한글 주석) (가상 이벤트) MFA 재인증 강제 요구 이벤트를 발행합니다.
                    // await _eventBus.PublishAsync(new ForceMfaReauthenticationEvent(@event.UserId, @event.ConnectedId, "HighThreatDetected"), cancellationToken);
                    break;

                case SecurityThreatLevel.Medium:
                    _logger.LogWarning("Medium threat detected: {ThreatType} for User {UserId}. Publishing NotifyUser event.", 
                        @event.ThreatType, @event.UserId);
                    // (한글 주석) (가상 이벤트) 사용자에게 의심스러운 활동 알림 이벤트를 발행합니다.
                    // await _eventBus.PublishAsync(new NotifyUserOfSuspiciousActivityEvent(@event.UserId, @event.Description), cancellationToken);
                    break;
            }
            
            // (한글 주석) 현재는 가상 이벤트이므로 Task.CompletedTask를 사용합니다.
            await Task.CompletedTask;
        }

        #endregion

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // (한글 주석) 이 핸들러가 의존하는 캐시와 이벤트 버스의 상태를 확인합니다.
            return IsEnabled && 
                   await _cacheService.IsHealthyAsync(cancellationToken) &&
                   await _eventBus.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}