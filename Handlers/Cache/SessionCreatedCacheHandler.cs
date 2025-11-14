// [AuthHive.Auth] Handlers/Cache/SessionCreatedCacheHandler.cs
// v17 CQRS "본보기": 'SessionCreatedEvent' (알림)를 구독(Handle)합니다.
// (SOP 2-Notify-C)
//
// 1. INotificationHandler<T>: 'SessionCreatedEvent'를 구독하는 "부가 작업" 전문가입니다.
// 2. "캐시 저장": v16 SessionEventHandler의 캐시 저장 로직을 이관합니다.
// 3. "세션 제한": v16 SessionEventHandler의 동시 접속 제한 로직을 이관합니다.

using AuthHive.Core.Interfaces.Base; // IUnitOfWork (v16 이벤트 핸들러가 사용)
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // [v17] ICacheService
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionCreatedEvent (구독 대상)
using AuthHive.Core.Models.Common; // [v17] IDomainEvent (TerminateSessionCommand용)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionEndReason

namespace AuthHive.Auth.Handlers.Cache
{
    /// <summary>
    /// [v17] "세션 생성 시 캐시" 핸들러 (SOP 2-Notify-C)
    /// 'SessionCreatedEvent' 알림을 구독(Handle)하고,
    /// v16 'SessionEventHandler'의 캐시 저장 및 세션 제한 로직을 이관합니다.
    /// </summary>
    public class SessionCreatedCacheHandler : INotificationHandler<SessionCreatedEvent>
    {
        private readonly IMediator _mediator;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<SessionCreatedCacheHandler> _logger;
        // v16 이벤트 핸들러의 캐시 TTL 설정을 그대로 사용 [cite: 326]
        private static readonly TimeSpan SessionCacheTTL = TimeSpan.FromHours(2);

        public SessionCreatedCacheHandler(
            IMediator mediator,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<SessionCreatedCacheHandler> logger)
        {
            _mediator = mediator;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        /// <summary>
        /// SessionCreatedEvent 알림을 처리합니다.
        /// </summary>
        public async Task Handle(SessionCreatedEvent notification, CancellationToken cancellationToken)
        {
            // v16 'SessionEventHandler' [cite: 332-333]와 동일하게 TenantId(OrganizationId)를 추출합니다.
            // 'SessionCreatedEvent' "계약서"는 'OrganizationId' (Guid?)를 포함합니다.
            var tenantId = notification.OrganizationId ?? Guid.Empty;
            
            _logger.LogInformation("Handling SessionCreatedEvent for Session {SessionId} (Tenant: {TenantId}). Caching session data.", 
                notification.AggregateId, tenantId);

            try
            {
                // 1. [v17 로직 이관] v16 'CacheSessionWithTenantIsolationAsync' 로직 이관 
                // "계약서"에서 확인한 'ICacheService.SetAsync<T>'를 사용합니다.
                
                var cacheKey = GetTenantSessionCacheKey(tenantId, notification.AggregateId);
                var utcNow = _dateTimeProvider.UtcNow;

                // v16 'SessionEventHandler' [cite: 380-386]와 동일하게 Dictionary<string, object>를 생성합니다.
                var sessionData = new Dictionary<string, object>
                {
                    ["SessionId"] = notification.AggregateId,
                    ["UserId"] = notification.UserId,
                    ["TenantId"] = tenantId,
                    ["CreatedAt"] = utcNow, // v16 [cite: 383] (event.OccurredAt 사용 가능)
                    ["ExpiresAt"] = notification.ExpiresAt, // v16 [cite: 384]
                    ["SessionType"] = notification.SessionType.ToString(), // v16 [cite: 385]
                    ["IpAddress"] = notification.IpAddress ?? string.Empty // v16 [cite: 386]
                };

                if (!string.IsNullOrEmpty(notification.UserAgent))
                {
                    sessionData["UserAgent"] = notification.UserAgent; // v16 [cite: 389-392]
                }

                var ttl = notification.ExpiresAt - utcNow;
                
                // ICacheService "계약서"는 T : class를 요구하며, Dictionary는 class이므로 "계약서"를 준수합니다.
                await _cacheService.SetAsync(cacheKey, sessionData, ttl > TimeSpan.Zero ? ttl : SessionCacheTTL, cancellationToken);

                // 2. [v17 로직 이관] v16 'EnforceTenantSessionLimitAsync' 로직 이관 [cite: 387-403]
                
                // v16과 동일하게 사용자별 세션 목록 키를 가져옵니다.
                var userSessionsKey = GetTenantUserSessionsKey(tenantId, notification.UserId);
                
                // ICacheService "계약서"는 GetAsync<T> (T : class)를 요구하며, List<Guid>는 class이므로 "계약서"를 준수합니다.
                var sessions = await _cacheService.GetAsync<List<Guid>>(userSessionsKey, cancellationToken) ?? new List<Guid>();
                
                sessions.Add(notification.AggregateId);
                await _cacheService.SetAsync(userSessionsKey, sessions, TimeSpan.FromDays(7), cancellationToken); // v16 [cite: 399-400]

                // v16과 동일하게 테넌트별 세션 제한 설정을 조회합니다.
                var limitKey = $"tenant:{tenantId}:config:session-limit";
                // ICacheService "계약서"의 GetStringAsync를 사용합니다. (v16 [cite: 391] GetAsync<string>과 동일)
                var limitStr = await _cacheService.GetStringAsync(limitKey, cancellationToken);
                var limit = int.TryParse(limitStr, out var parsed) ? parsed : 5; // v16 [cite: 392]

                if (sessions.Count > limit)
                {
                    // v16 'SessionEventHandler' [cite: 395-400]와 동일하게
                    // 가장 오래된 세션을 종료하기 위해 'TerminateSessionCommand'를 발행(Publish)합니다.
                    var oldestSession = sessions.First();
                    // (TerminateSessionCommand는 IDomainEvent를 구현해야 v16 로직과 호환됨)
                    await _mediator.Publish(new TerminateSessionCommand
                    {
                        SessionId = oldestSession,
                        Reason = SessionEndReason.ConcurrentLimit
                    }, cancellationToken);
                    
                    _logger.LogInformation("Session limit ({Limit}) enforced for Tenant {TenantId}, User {UserId}. Terminating session {OldSessionId}",
                        limit, tenantId, notification.UserId, oldestSession);
                }
            }
            catch (Exception ex)
            {
                // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
                _logger.LogError(ex, "Failed to cache session for SessionCreatedEvent {SessionId}", notification.AggregateId);
            }
        }

        #region v16 Helper Methods [cite: 370-377]
        
        // v16 SessionEventHandler의 헬퍼 메서드를 그대로 이관합니다.
        
        private string GetTenantSessionCacheKey(Guid tenantId, Guid sessionId)
        {
            return $"tenant:{tenantId}:session:{sessionId}"; // v16 [cite: 372-374]
        }

        private string GetTenantUserSessionsKey(Guid tenantId, Guid userId)
        {
            return $"tenant:{tenantId}:user:{userId}:sessions"; // v16 [cite: 375-377]
        }

        #endregion

        #region v16 Internal Event DTOs [cite: 407-427]
        
        // v16 SessionEventHandler [cite: 396]가 의존했던 내부 Command를 정의합니다.
        // v17에서는 이 DTO가 'INotification'을 구현해야 합니다.
        private class TerminateSessionCommand : INotification, IDomainEvent
        {
            public Guid EventId { get; set; } = Guid.NewGuid();
            public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
            public Guid AggregateId => SessionId;
            public Guid SessionId { get; set; }
            public SessionEndReason Reason { get; set; }
        }

        #endregion
    }
}