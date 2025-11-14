// [AuthHive.Auth] Handlers/Cache/SessionLockedCacheHandler.cs
// v17 CQRS "본보기": 'SessionLockedEvent' (알림)를 구독(Handle)합니다.
// (SOP 2-Notify-C)
//
// 1. INotificationHandler<T>: 'SessionLockedEvent'를 구독하는 "부가 작업" 전문가입니다.
// 2. "캐시 업데이트": v16 SessionEventHandler의 캐시 잠금 플래그 설정 로직을 이관합니다.
// 3. ICacheService: "계약서"에서 확인된 'GetAsync', 'SetAsync'를 사용합니다.

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // [v17] ICacheService
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionLockedEvent (구독 대상)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Cache
{
    /// <summary>
    /// [v17] "세션 잠금 시 캐시" 핸들러 (SOP 2-Notify-C)
    /// 'SessionLockedEvent' 알림을 구독(Handle)하고,
    /// v16 'SessionEventHandler'의 캐시 업데이트 로직을 이관합니다.
    /// </summary>
    /// <remarks>
    /// ### [v17 아키텍처 설명]
    /// 
    /// **1. 언제(When) 이 핸들러가 실행되는가?**
    ///    - 시스템(예: 'RiskAssessmentService')이 사용자의 세션에서 의심스러운 활동을 감지하여
    ///      "세션 잠금" 트랜잭션을 실행하고, 그 결과로 `SessionLockedEvent`를 발행(Publish)할 때 실행됩니다.
    /// 
    /// **2. 왜(Why) 이 작업이 필요한가? (v16 로직 이관)**
    ///    - v16 'SessionEventHandler' 는 세션이 잠겼을 때,
    ///      향후 모든 요청이 이 세션이 "잠겼음"을 즉시 알 수 있도록 캐시된 세션 데이터에
    ///      'IsLocked = true' 플래그를 설정했습니다.
    ///    - 이 핸들러는 v16의 해당 로직을 이관받아, 캐시의 데이터 정합성을 유지합니다.
    /// 
    /// **3. 어떻게(How) 작동하는가?**
    ///    - 'SessionLockedEvent'로부터 "테넌트 ID (OrganizationId)"와 "세션 ID (AggregateId)"를 받습니다.
    ///    - 'ICacheService.GetAsync'로 캐시된 세션 데이터(Dictionary)를 가져옵니다.
    ///    - 딕셔너리에 'IsLocked = true'와 'LockReason'을 설정합니다.
    ///    - 'ICacheService.SetAsync'로 업데이트된 딕셔너리를 캐시에 다시 저장합니다.
    /// </remarks>
    public class SessionLockedCacheHandler : INotificationHandler<SessionLockedEvent>
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<SessionLockedCacheHandler> _logger;
        // v16 이벤트 핸들러의 캐시 TTL 설정을 그대로 사용
        private static readonly TimeSpan SessionCacheTTL = TimeSpan.FromHours(2);

        public SessionLockedCacheHandler(
            ICacheService cacheService,
            ILogger<SessionLockedCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        /// <summary>
        /// SessionLockedEvent 알림을 처리합니다.
        /// </summary>
        public async Task Handle(SessionLockedEvent notification, CancellationToken cancellationToken)
        {
            // 1. [v17 "계약서" 확인]
            // "세션 잠금 계약서"의 속성들을 변수로 추출합니다.
            var tenantId = notification.OrganizationId ?? Guid.Empty;
            var sessionId = notification.AggregateId; // SessionId
            
            _logger.LogWarning("Handling SessionLockedEvent for Session {SessionId} (Tenant: {TenantId}). Updating cache status to Locked.",
                sessionId, tenantId);

            try
            {
                // 2. [v17 로직 이관] v16 'HandleSessionLockedAsync'의 캐시 로직 이관 
                
                // v16 헬퍼 메서드 [cite: 372-374]를 사용하여 세션 키를 생성합니다.
                var cacheKey = GetTenantSessionCacheKey(tenantId, sessionId);

                // "계약서"에서 확인된 'ICacheService.GetAsync<T>' (T: class)를 호출합니다.
                // v16은 Dictionary<string, object>를 사용했습니다. [cite: 424]
                var sessionData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken);
                
                if (sessionData != null)
                {
                    // v16 "본보기" [cite: 425-426]와 동일하게 잠금 상태와 사유를 설정합니다.
                    sessionData["IsLocked"] = true;
                    sessionData["LockReason"] = notification.LockReason;

                    // "계약서"에서 확인된 'ICacheService.SetAsync<T>'로 업데이트된 데이터를 다시 저장합니다.
                    await _cacheService.SetAsync(cacheKey, sessionData, SessionCacheTTL, cancellationToken);
                }
                else
                {
                    _logger.LogWarning("SessionLockedEvent: Could not find cache key '{CacheKey}' for Session {SessionId}. Cache update skipped.",
                        cacheKey, sessionId);
                }
            }
            catch (Exception ex)
            {
                // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
                _logger.LogError(ex, "Failed to update cache for SessionLockedEvent {SessionId}", notification.AggregateId);
            }
        }

        #region v16 Helper Methods [cite: 370-374]
        
        // v16 SessionEventHandler의 헬퍼 메서드를 그대로 이관합니다.
        
        private string GetTenantSessionCacheKey(Guid tenantId, Guid sessionId)
        {
            // v16 "본보기" [cite: 372-374]
            return $"tenant:{tenantId}:session:{sessionId}";
        }

        #endregion
    }
}