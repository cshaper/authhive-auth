using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Auth.Session.Events;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Session.Handlers
{
    /// <summary>
    /// 세션 이벤트 핸들러 - 멀티테넌트 SaaS 최적화 버전
    /// 핵심: 동적 데이터 처리, 테넌트 격리, 비용 최적화
    /// </summary>
    public class SessionEventHandler : ISessionEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly ISessionRepository _sessionRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<SessionEventHandler> _logger;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;

        // 캐시 TTL 설정 (비용 최적화)
        private static readonly TimeSpan SessionCacheTTL = TimeSpan.FromHours(2);
        private static readonly TimeSpan ActivityCacheTTL = TimeSpan.FromMinutes(30);
        
        public SessionEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            ISessionRepository sessionRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<SessionEventHandler> logger,
            IEventBus eventBus,
            IUnitOfWork unitOfWork)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _sessionRepository = sessionRepository;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation
        
public Task InitializeAsync(CancellationToken cancellationToken = default)
{
    _logger.LogInformation("SessionEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
    return Task.CompletedTask;
}

public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
{
    var cacheHealthy = await _cacheService.IsHealthyAsync(cancellationToken);
    var auditHealthy = await _auditService.IsHealthyAsync(cancellationToken);
    return cacheHealthy && auditHealthy;
}

        #endregion

        #region Core Session Events (필수 기능만 유지)

        public async Task HandleSessionCreatedAsync(SessionCreatedEvent eventData)
        {
            try
            {
                _logger.LogInformation("Session created: SessionId={SessionId}, UserId={UserId}, Type={SessionType}",
                    eventData.SessionId, eventData.UserId, eventData.SessionType);

                // 테넌트 ID 추출 (ConnectedId 또는 Session에서)
                var tenantId = await ExtractTenantIdAsync(eventData.SessionId, eventData.ConnectedId);
                
                // 1. 감사 로그 - 간소화된 방식
                await _auditService.LogActionAsync(
                    eventData.ConnectedId ?? eventData.UserId,
                    "SESSION_CREATED",
                    AuditActionType.Login,
                    "Session",
                    eventData.SessionId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        UserId = eventData.UserId,
                        SessionType = eventData.SessionType.ToString(),
                        IpAddress = eventData.IpAddress,
                        ExpiresAt = eventData.ExpiresAt
                    }));

                // 2. 테넌트별 캐시 저장
                await CacheSessionWithTenantIsolationAsync(tenantId, eventData);

                // 3. 동시 세션 제한 (테넌트별 설정 적용)
                await EnforceTenantSessionLimitAsync(tenantId, eventData.UserId);

                _logger.LogDebug("Session created successfully for tenant {TenantId}", tenantId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling session created event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleSessionRefreshedAsync(SessionRefreshedEvent eventData)
        {
            try
            {
                var tenantId = await ExtractTenantIdFromSessionAsync(eventData.SessionId);
                
                // 간단한 캐시 업데이트만 수행 (과도한 로깅 제거)
                var cacheKey = GetTenantSessionCacheKey(tenantId, eventData.SessionId);
                var sessionData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);
                
                if (sessionData != null)
                {
                    sessionData["ExpiresAt"] = eventData.NewExpiresAt;
                    sessionData["LastActivity"] = _dateTimeProvider.UtcNow;
                    
                    var ttl = eventData.NewExpiresAt - _dateTimeProvider.UtcNow;
                    await _cacheService.SetAsync(cacheKey, sessionData, ttl);
                }
                
                _logger.LogDebug("Session refreshed: {SessionId}", eventData.SessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling session refresh");
                // 갱신 실패는 크리티컬하지 않으므로 예외를 전파하지 않음
            }
        }

        public async Task HandleSessionTerminatedAsync(SessionTerminatedEvent eventData)
        {
            try
            {
                var tenantId = await ExtractTenantIdFromSessionAsync(eventData.SessionId);
                
                _logger.LogInformation("Session terminated: SessionId={SessionId}, Reason={Reason}",
                    eventData.SessionId, eventData.EndReason);

                // 1. 감사 로그 (중요 이벤트만)
                if (ShouldAuditTermination(eventData.EndReason))
                {
                    await _auditService.LogActionAsync(
                        eventData.UserId,
                        "SESSION_TERMINATED",
                        AuditActionType.Logout,
                        "Session",
                        eventData.SessionId.ToString(),
                        true,
                        JsonSerializer.Serialize(new
                        {
                            EndReason = eventData.EndReason.ToString(),
                            Duration = eventData.Duration.TotalMinutes
                        }));
                }

                // 2. 캐시 정리
                await CleanupTenantSessionCacheAsync(tenantId, eventData.SessionId, eventData.UserId);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling session terminated");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleSessionSwitchedAsync(SessionSwitchedEvent eventData)
        {
            try
            {
                // 조직/앱 전환 - 테넌트 컨텍스트 변경 처리
                _logger.LogInformation("Session context switch: User={UserId}, From={FromOrg}, To={ToOrg}",
                    eventData.UserId, eventData.FromOrganizationId, eventData.ToOrganizationId);

                // 새로운 테넌트 컨텍스트로 캐시 이동
                if (eventData.FromOrganizationId != eventData.ToOrganizationId)
                {
                    await MigrateSessionCacheToNewTenantAsync(
                        eventData.FromOrganizationId ?? Guid.Empty,
                        eventData.ToOrganizationId ?? Guid.Empty,
                        eventData.ToSessionId);
                }

                // 권한 캐시 무효화 (새 조직의 권한 로드 필요)
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.ToOrganizationId);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling session switch");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        #endregion

        #region Simplified Events (과도한 기능 제거)

        public async Task HandleSessionLockedAsync(SessionLockedEvent eventData)
        {
            // 기본 구현만 유지 - 대부분의 SaaS는 복잡한 보안 모니터링 불필요
            _logger.LogWarning("Session locked: SessionId={SessionId}, Reason={Reason}",
                eventData.SessionId, eventData.LockReason);

            var tenantId = await ExtractTenantIdFromSessionAsync(eventData.SessionId);
            
            // 단순 플래그 설정
            var cacheKey = GetTenantSessionCacheKey(tenantId, eventData.SessionId);
            var sessionData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);
            
            if (sessionData != null)
            {
                sessionData["IsLocked"] = true;
                sessionData["LockReason"] = eventData.LockReason;
                await _cacheService.SetAsync(cacheKey, sessionData, SessionCacheTTL);
            }

            // 중요한 경우만 감사 로그
            if (eventData.RiskScore > 80)
            {
                await _auditService.LogActionAsync(
                    eventData.UserId,
                    "SESSION_LOCKED_HIGH_RISK",
                    AuditActionType.Blocked,
                    "Session",
                    eventData.SessionId.ToString(),
                    false,  // success = false (보안 위협으로 차단)
                    JsonSerializer.Serialize(new
                    {
                        RiskScore = eventData.RiskScore,
                        LockReason = eventData.LockReason
                    }));
            }
        }

        public async Task HandleSessionActivityAsync(SessionActivityEvent eventData)
        {
            // Rate limiting만 수행 - 과도한 활동 추적 제거
            var tenantId = await ExtractTenantIdFromSessionAsync(eventData.SessionId);
            var activityKey = $"tenant:{tenantId}:session:{eventData.SessionId}:rate";
            
            var count = await _cacheService.IncrementAsync(activityKey);
            if (count == 1)
            {
                // 첫 활동 시 TTL 설정
                await _cacheService.SetAsync(activityKey, "1", TimeSpan.FromMinutes(1));
            }
            else if (count > 100) // 분당 100회 초과
            {
                _logger.LogWarning("Rate limit exceeded for session {SessionId}", eventData.SessionId);
                await _eventBus.PublishAsync(new RateLimitExceededEvent
                {
                    SessionId = eventData.SessionId,
                    UserId = eventData.UserId
                });
            }
        }

        #endregion

        #region Private Helper Methods - SaaS Optimized

        private async Task<Guid> ExtractTenantIdAsync(Guid sessionId, Guid? connectedId)
        {
            // 세션에서 테넌트 ID 추출 - 실제 구현은 비즈니스 로직에 따름
            if (connectedId.HasValue)
            {
                // ConnectedId에서 조직 정보 추출
                var session = await _sessionRepository.GetByIdAsync(sessionId);
                return session?.OrganizationId ?? Guid.Empty;
            }
            return Guid.Empty;
        }

        private async Task<Guid> ExtractTenantIdFromSessionAsync(Guid sessionId)
        {
            var session = await _sessionRepository.GetByIdAsync(sessionId);
            return session?.OrganizationId ?? Guid.Empty;
        }

        private string GetTenantSessionCacheKey(Guid tenantId, Guid sessionId)
        {
            return $"tenant:{tenantId}:session:{sessionId}";
        }

        private string GetTenantUserSessionsKey(Guid tenantId, Guid userId)
        {
            return $"tenant:{tenantId}:user:{userId}:sessions";
        }

        private Dictionary<string, object> BuildDynamicAuditData(object eventData, Dictionary<string, object> baseData)
        {
            // 동적 데이터 처리 - 이벤트에 포함된 모든 커스텀 데이터 보존
            var properties = eventData.GetType().GetProperties();
            foreach (var prop in properties)
            {
                var key = prop.Name;
                if (!baseData.ContainsKey(key))
                {
                    var value = prop.GetValue(eventData);
                    if (value != null)
                    {
                        baseData[key] = value;
                    }
                }
            }
            return baseData;
        }

        private async Task CacheSessionWithTenantIsolationAsync(Guid tenantId, SessionCreatedEvent eventData)
        {
            var cacheKey = GetTenantSessionCacheKey(tenantId, eventData.SessionId);
            
            // 동적 데이터 구조 - 테넌트가 추가 필드 저장 가능
            var sessionData = new Dictionary<string, object>
            {
                ["SessionId"] = eventData.SessionId,
                ["UserId"] = eventData.UserId,
                ["TenantId"] = tenantId,
                ["CreatedAt"] = _dateTimeProvider.UtcNow,
                ["ExpiresAt"] = eventData.ExpiresAt,
                ["SessionType"] = eventData.SessionType.ToString(),
                ["IpAddress"] = eventData.IpAddress ?? string.Empty
            };

            // UserAgent 등 선택적 데이터
            if (!string.IsNullOrEmpty(eventData.UserAgent))
            {
                sessionData["UserAgent"] = eventData.UserAgent;
            }

            var ttl = eventData.ExpiresAt - _dateTimeProvider.UtcNow;
            await _cacheService.SetAsync(cacheKey, sessionData, ttl);

            // 사용자별 세션 목록 업데이트
            var userSessionsKey = GetTenantUserSessionsKey(tenantId, eventData.UserId);
            var sessions = await _cacheService.GetAsync<List<Guid>>(userSessionsKey) ?? new List<Guid>();
            sessions.Add(eventData.SessionId);
            await _cacheService.SetAsync(userSessionsKey, sessions, TimeSpan.FromDays(7));
        }

        private async Task EnforceTenantSessionLimitAsync(Guid tenantId, Guid userId)
        {
            // 테넌트별 세션 제한 설정 조회 (캐시 활용)
            var limitKey = $"tenant:{tenantId}:config:session-limit";
            var limitStr = await _cacheService.GetAsync<string>(limitKey);
            var limit = int.TryParse(limitStr, out var parsed) ? parsed : 5; // 기본값 5

            var userSessionsKey = GetTenantUserSessionsKey(tenantId, userId);
            var sessions = await _cacheService.GetAsync<List<Guid>>(userSessionsKey) ?? new List<Guid>();

            if (sessions.Count > limit)
            {
                // 가장 오래된 세션 종료
                var oldestSession = sessions.First();
                await _eventBus.PublishAsync(new TerminateSessionCommand
                {
                    SessionId = oldestSession,
                    Reason = SessionEndReason.ConcurrentLimit
                });
                
                _logger.LogInformation("Session limit enforced for tenant {TenantId}, user {UserId}", tenantId, userId);
            }
        }

        private async Task CleanupTenantSessionCacheAsync(Guid tenantId, Guid sessionId, Guid userId)
        {
            // 세션 캐시 제거
            var sessionKey = GetTenantSessionCacheKey(tenantId, sessionId);
            await _cacheService.RemoveAsync(sessionKey);

            // 사용자 세션 목록에서 제거
            var userSessionsKey = GetTenantUserSessionsKey(tenantId, userId);
            var sessions = await _cacheService.GetAsync<List<Guid>>(userSessionsKey);
            if (sessions != null)
            {
                sessions.Remove(sessionId);
                await _cacheService.SetAsync(userSessionsKey, sessions, TimeSpan.FromDays(7));
            }

            // 관련 활동 캐시 제거
            var activityPattern = $"tenant:{tenantId}:session:{sessionId}:*";
            await _cacheService.RemoveByPatternAsync(activityPattern);
        }

        private async Task MigrateSessionCacheToNewTenantAsync(Guid fromTenantId, Guid toTenantId, Guid sessionId)
        {
            if (fromTenantId == toTenantId) return;

            var oldKey = GetTenantSessionCacheKey(fromTenantId, sessionId);
            var newKey = GetTenantSessionCacheKey(toTenantId, sessionId);

            var sessionData = await _cacheService.GetAsync<Dictionary<string, object>>(oldKey);
            if (sessionData != null)
            {
                sessionData["TenantId"] = toTenantId;
                await _cacheService.SetAsync(newKey, sessionData, SessionCacheTTL);
                await _cacheService.RemoveAsync(oldKey);
            }
        }

        private async Task InvalidatePermissionCacheAsync(Guid userId, Guid? organizationId)
        {
            if (!organizationId.HasValue) return;

            // 권한 캐시 무효화 패턴
            var permissionPattern = $"tenant:{organizationId}:user:{userId}:permissions:*";
            await _cacheService.RemoveByPatternAsync(permissionPattern);
        }

        private bool ShouldAuditTermination(SessionEndReason reason)
        {
            // 정상 종료는 감사 불필요
            return reason != SessionEndReason.UserLogout && reason != SessionEndReason.Expired;
        }

        #endregion
    }

    #region Simplified Event Classes (필수만 유지)

    internal class TerminateSessionCommand : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId => SessionId;
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid SessionId { get; set; }
        public SessionEndReason Reason { get; set; }
    }

    internal class RateLimitExceededEvent : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid AggregateId => SessionId;
        public Guid SessionId { get; set; }
        public Guid UserId { get; set; }
    }

    #endregion
}