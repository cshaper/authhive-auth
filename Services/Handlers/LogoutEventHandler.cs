using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Distributed;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Infra.Monitoring;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 로그아웃 이벤트 핸들러 구현 - AuthHive v15
    /// 로그아웃 관련 모든 이벤트를 처리하고 감사 로그, 알림, 보안 분석, 캐시 정리 등을 수행합니다.
    /// SessionService와 긴밀하게 연동됩니다.
    /// </summary>
    public class LogoutEventHandler : ILogoutEventHandler
    {
        #region Dependencies

        private readonly ILogger<LogoutEventHandler> _logger;
        private readonly IAuditLogRepository _auditRepository;
        private readonly IUserRepository _userRepository;
        private readonly IUserActivityLogRepository _activityLogRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionActivityLogRepository _sessionActivityRepository;
        private readonly ISessionService _sessionService;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly INotificationService _notificationService;
        private readonly IEmailService _emailService;
        private readonly ISecurityAnalyzer _securityAnalyzer;
        private readonly IMetricsService _metricsService;
        private readonly ICacheService _cacheService;
        private readonly IDistributedCache _distributedCache;
        private readonly IUnitOfWork _unitOfWork;

        #endregion

        #region Constants

        private const string CACHE_KEY_PREFIX = "logout";
        private const string METRICS_PREFIX = "auth.logout";
        private const string SESSION_CACHE_KEY = "auth:sessions";
        private const string USER_CACHE_KEY = "auth:users";
        private const string PERMISSION_CACHE_KEY = "auth:permissions";
        private const int SUSPICIOUS_LOGOUT_THRESHOLD = 10; // 10 logouts in short time period
        private const int FORCED_LOGOUT_NOTIFICATION_DELAY_MINUTES = 5;

        #endregion

        #region Constructor

        public LogoutEventHandler(
            ILogger<LogoutEventHandler> logger,
            IAuditLogRepository auditRepository,
            IUserRepository userRepository,
            IUserActivityLogRepository activityLogRepository,
            ISessionRepository sessionRepository,
            ISessionActivityLogRepository sessionActivityRepository,
            ISessionService sessionService,
            IConnectedIdRepository connectedIdRepository,
            IDateTimeProvider dateTimeProvider,
            INotificationService notificationService,
            IEmailService emailService,
            ISecurityAnalyzer securityAnalyzer,
            IMetricsService metricsService,
            ICacheService cacheService,
            IDistributedCache distributedCache,
            IUnitOfWork unitOfWork)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditRepository = auditRepository ?? throw new ArgumentNullException(nameof(auditRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _activityLogRepository = activityLogRepository ?? throw new ArgumentNullException(nameof(activityLogRepository));
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _sessionActivityRepository = sessionActivityRepository ?? throw new ArgumentNullException(nameof(sessionActivityRepository));
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _securityAnalyzer = securityAnalyzer ?? throw new ArgumentNullException(nameof(securityAnalyzer));
            _metricsService = metricsService ?? throw new ArgumentNullException(nameof(metricsService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        }

        #endregion

        #region ILogoutEventHandler Implementation

        /// <inheritdoc />
        public async Task HandleLogoutAsync(LogoutEvent eventData)
        {
            try
            {
                _logger.LogInformation(
                    "Logout initiated for User {UserId} (Session: {SessionId}), Reason: {Reason}, IP: {IpAddress}",
                    eventData.UserId, eventData.SessionId, eventData.Reason, eventData.IpAddress);

                // 1. 세션 조회 및 검증
                var session = await _sessionRepository.GetByIdAsync(eventData.SessionId);
                if (session == null)
                {
                    _logger.LogWarning("Session {SessionId} not found for logout", eventData.SessionId);
                    return;
                }

                // 2. SessionService를 통한 세션 종료
                var endResult = await _sessionService.EndSessionAsync(eventData.SessionId, eventData.Reason);
                if (!endResult.IsSuccess)
                {
                    _logger.LogWarning(
                        "Failed to end session {SessionId}: {Error}", 
                        eventData.SessionId, 
                        endResult.ErrorMessage);
                }

                // 3. 세션 활동 로그 기록
                await LogSessionActivityAsync(
                    eventData.SessionId,
                    "LOGOUT",
                    eventData.IpAddress,
                    new { Reason = eventData.Reason });

                // 4. 사용자 활동 로그 기록
                await LogUserActivityAsync(
                    session.ConnectedId ?? Guid.Empty,
                    UserActivityType.Logout,
                    true,
                    new
                    {
                        SessionId = eventData.SessionId,
                        Reason = eventData.Reason,
                        IpAddress = eventData.IpAddress,
                        SessionDuration = CalculateSessionDuration(session)
                    });

                // 5. 캐시 정리
                await ClearSessionCacheAsync(eventData.UserId, eventData.SessionId);
                await ClearUserPermissionCacheAsync(eventData.UserId);

                // 6. 메트릭 기록
                await RecordLogoutMetricsAsync(eventData, session);

                // 7. 감사 로그
                await LogAuditAsync(
                    session.ConnectedId ?? Guid.Empty,
                    "LOGOUT",
                    $"User logged out successfully. Reason: {eventData.Reason}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = eventData.SessionId,
                        ["Reason"] = eventData.Reason.ToString(),
                        ["IpAddress"] = eventData.IpAddress,
                        ["SessionDuration"] = CalculateSessionDuration(session).TotalMinutes
                    });

                // 8. 의심스러운 패턴 탐지
                await DetectSuspiciousLogoutPatternAsync(eventData.UserId, eventData.IpAddress);

                await _unitOfWork.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to handle logout event for User {UserId}, Session {SessionId}", 
                    eventData.UserId, eventData.SessionId);
            }
        }

        /// <inheritdoc />
        public async Task HandleForcedLogoutAsync(ForcedLogoutEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "Forced logout initiated for User {UserId} (Session: {SessionId}) by {ForcedByUserId}. Reason: {Reason}",
                    eventData.UserId, eventData.SessionId, eventData.ForcedByUserId, eventData.ForceReason);

                // 1. 세션 조회
                var session = await _sessionRepository.GetByIdAsync(eventData.SessionId);
                if (session == null)
                {
                    _logger.LogWarning("Session {SessionId} not found for forced logout", eventData.SessionId);
                    return;
                }

                // 2. SessionService를 통한 강제 세션 종료
                var endResult = await _sessionService.EndSessionAsync(eventData.SessionId, SessionEndReason.AdminTerminated);
                
                // 3. 연결된 모든 자식 세션도 종료
                if (session.Level == SessionLevel.Global && session.ParentSessionId.HasValue)
                {
                    // GetChildSessionsAsync를 사용하여 자식 세션들 가져오기
                    var childSessions = await _sessionRepository.GetChildSessionsAsync(session.Id, true);
                    foreach (var childSession in childSessions)
                    {
                        await _sessionService.EndSessionAsync(childSession.Id, SessionEndReason.ParentSessionTerminated);
                    }
                }

                // 4. 세션 활동 로그
                await LogSessionActivityAsync(
                    eventData.SessionId,
                    "FORCED_LOGOUT",
                    "System",
                    new 
                    { 
                        ForceReason = eventData.ForceReason,
                        ForcedBy = eventData.ForcedByUserId 
                    });

                // 5. 사용자 활동 로그
                await LogUserActivityAsync(
                    session.ConnectedId ?? Guid.Empty,
                    UserActivityType.ForcedLogout,
                    true,
                    new
                    {
                        SessionId = eventData.SessionId,
                        ForceReason = eventData.ForceReason,
                        ForcedByUserId = eventData.ForcedByUserId,
                        SessionDuration = CalculateSessionDuration(session)
                    });

                // 6. 캐시 즉시 정리
                await ClearSessionCacheAsync(eventData.UserId, eventData.SessionId);
                await ClearUserPermissionCacheAsync(eventData.UserId);

                // 7. 알림 발송 (지연 실행)
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromMinutes(FORCED_LOGOUT_NOTIFICATION_DELAY_MINUTES));
                    await SendForcedLogoutNotificationAsync(eventData);
                });

                // 8. 보안 이벤트 기록
                await RecordSecurityEventAsync(
                    eventData.UserId,
                    "FORCED_LOGOUT",
                    eventData.ForceReason,
                    SecuritySeverity.High);

                // 9. 감사 로그
                await LogAuditAsync(
                    eventData.ForcedByUserId ?? Guid.Empty,
                    "FORCED_LOGOUT",
                    $"Forced logout executed for user. Reason: {eventData.ForceReason}",
                    eventData.UserId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = eventData.SessionId,
                        ["ForceReason"] = eventData.ForceReason,
                        ["ForcedByUserId"] = eventData.ForcedByUserId ?? Guid.Empty,
                        ["ForcedAt"] = eventData.ForcedAt
                    });

                // 10. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced");
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced.reason.{SanitizeMetricLabel(eventData.ForceReason)}");

                await _unitOfWork.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to handle forced logout event for User {UserId}, Session {SessionId}", 
                    eventData.UserId, eventData.SessionId);
            }
        }

        /// <inheritdoc />
        public async Task HandleSessionExpiredAsync(SessionExpiredEvent eventData)
        {
            try
            {
                _logger.LogInformation(
                    "Session expired for User {UserId} (Session: {SessionId}). Duration: {Duration} minutes",
                    eventData.UserId, eventData.SessionId, eventData.SessionDuration.TotalMinutes);

                // 1. SessionService를 통한 만료 세션 종료
                var endResult = await _sessionService.EndSessionAsync(eventData.SessionId, SessionEndReason.Expired);

                // 2. 세션 정보 조회 (이미 종료되었을 수 있음)
                var session = await _sessionRepository.GetByIdAsync(eventData.SessionId);
                
                // 3. 세션 활동 로그
                await LogSessionActivityAsync(
                    eventData.SessionId,
                    "SESSION_EXPIRED",
                    "System",
                    new 
                    { 
                        SessionDuration = eventData.SessionDuration.TotalMinutes,
                        ExpiredAt = eventData.ExpiredAt 
                    });

                // 4. 사용자 활동 로그
                var connectedId = session?.ConnectedId ?? await GetUserConnectedIdAsync(eventData.UserId);
                await LogUserActivityAsync(
                    connectedId,
                    UserActivityType.SessionExpired,
                    true,
                    new
                    {
                        SessionId = eventData.SessionId,
                        SessionDuration = eventData.SessionDuration.TotalMinutes,
                        ExpiredAt = eventData.ExpiredAt
                    });

                // 5. 캐시 정리
                await ClearSessionCacheAsync(eventData.UserId, eventData.SessionId);

                // 6. 세션 만료 패턴 분석
                await AnalyzeSessionExpirationPatternAsync(eventData.UserId, eventData.SessionDuration);

                // 7. 감사 로그
                await LogAuditAsync(
                    connectedId,
                    "SESSION_EXPIRED",
                    $"Session expired after {eventData.SessionDuration.TotalMinutes:F1} minutes",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = eventData.SessionId,
                        ["SessionDuration"] = eventData.SessionDuration.TotalMinutes,
                        ["ExpiredAt"] = eventData.ExpiredAt
                    });

                // 8. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.expired");
                await _metricsService.RecordHistogramAsync(
                    $"{METRICS_PREFIX}.session_duration_minutes", 
                    eventData.SessionDuration.TotalMinutes);

                await _unitOfWork.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to handle session expired event for User {UserId}, Session {SessionId}", 
                    eventData.UserId, eventData.SessionId);
            }
        }

        /// <inheritdoc />
        public async Task HandleLogoutAllDevicesAsync(LogoutAllDevicesEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "Logout all devices initiated for User {UserId}. Session count: {Count}, Reason: {Reason}",
                    eventData.UserId, eventData.SessionCount, eventData.Reason);

                // 1. 모든 ConnectedId 조회
                var connectedIds = await _connectedIdRepository.GetByUserIdAsync(eventData.UserId);
                var terminatedSessions = new List<Guid>();

                // 2. 각 ConnectedId에 대해 모든 세션 종료
                foreach (var connectedId in connectedIds)
                {
                    var endResult = await _sessionService.EndAllSessionsAsync(connectedId.Id, SessionEndReason.LogoutAllDevices);
                    
                    // ServiceResult<int>로 안전하게 캐스팅
                    if (endResult.IsSuccess)
                    {
                        var countResult = endResult as ServiceResult<int>;
                        if (countResult?.Data > 0)
                        {
                            _logger.LogInformation(
                                "Terminated {Count} sessions for ConnectedId {ConnectedId}",
                                countResult.Data, connectedId.Id);
                        }
                    }

                    // 해당 ConnectedId의 세션 목록 조회
                    var session = await _sessionRepository.GetByConnectedIdAsync(connectedId.Id);
                    if (session != null)
                    {
                        terminatedSessions.Add(session.Id);
                    }
                }

                // 3. 전역 세션도 종료
                var globalSessions = await _sessionRepository.GetActiveSessionsByUserAsync(eventData.UserId);
                foreach (var globalSession in globalSessions.Where(s => s.Level == SessionLevel.Global))
                {
                    if (!terminatedSessions.Contains(globalSession.Id))
                    {
                        await _sessionService.EndSessionAsync(globalSession.Id, SessionEndReason.LogoutAllDevices);
                        terminatedSessions.Add(globalSession.Id);
                    }
                }

                // 4. 사용자 활동 로그
                var primaryConnectedId = connectedIds.FirstOrDefault()?.Id ?? Guid.Empty;
                await LogUserActivityAsync(
                    primaryConnectedId,
                    UserActivityType.LogoutAllDevices,
                    true,
                    new
                    {
                        SessionCount = terminatedSessions.Count,
                        Reason = eventData.Reason,
                        TerminatedSessions = terminatedSessions
                    });

                // 5. 모든 캐시 정리
                await ClearAllUserCachesAsync(eventData.UserId);

                // 6. 보안 알림 발송
                await SendLogoutAllDevicesNotificationAsync(eventData);

                // 7. 보안 이벤트 기록
                await RecordSecurityEventAsync(
                    eventData.UserId,
                    "LOGOUT_ALL_DEVICES",
                    eventData.Reason,
                    SecuritySeverity.High);

                // 8. 감사 로그
                await LogAuditAsync(
                    primaryConnectedId,
                    "LOGOUT_ALL_DEVICES",
                    $"All devices logged out. Reason: {eventData.Reason}",
                    eventData.UserId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["SessionCount"] = terminatedSessions.Count,
                        ["Reason"] = eventData.Reason,
                        ["LogoutAt"] = eventData.LogoutAt,
                        ["TerminatedSessions"] = terminatedSessions
                    });

                // 9. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.all_devices");
                await _metricsService.SetGaugeAsync($"{METRICS_PREFIX}.terminated_sessions", terminatedSessions.Count);

                await _unitOfWork.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to handle logout all devices event for User {UserId}", 
                    eventData.UserId);
            }
        }

        #endregion

        #region Private Helper Methods

        private TimeSpan CalculateSessionDuration(SessionEntity session)
        {
            var startTime = session.CreatedAt;
            var endTime = session.UpdatedAt;
            
            // DateTime subtraction returns TimeSpan?, handle null case
            var duration = endTime - startTime;
            return duration ?? TimeSpan.Zero;
        }

        private async Task<Guid> GetUserConnectedIdAsync(Guid userId)
        {
            var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId);
            return connectedIds.FirstOrDefault()?.Id ?? Guid.Empty;
        }

        private async Task LogSessionActivityAsync(Guid sessionId, string activity, string ipAddress, object? metadata = null)
        {
            try
            {
                // Parse activity string to SessionActivityType enum
                var activityType = ParseSessionActivityType(activity);
                
                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = sessionId,
                    ActivityType = activityType,
                    IPAddress = ipAddress,
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    Timestamp = _dateTimeProvider.UtcNow,
                    CreatedAt = _dateTimeProvider.UtcNow
                };

                await _sessionActivityRepository.AddAsync(activityLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log session activity for session {SessionId}", sessionId);
            }
        }
        
        private SessionActivityType ParseSessionActivityType(string activity)
        {
            return activity switch
            {
                "LOGOUT" => SessionActivityType.Logout,
                "FORCED_LOGOUT" => SessionActivityType.Logout,
                "SESSION_EXPIRED" => SessionActivityType.Logout,
                _ => SessionActivityType.Other
            };
        }

        private async Task LogUserActivityAsync(Guid connectedId, UserActivityType activityType, bool isSuccessful, object? metadata = null)
        {
            try
            {
                if (connectedId == Guid.Empty)
                {
                    _logger.LogWarning("Cannot log user activity with empty ConnectedId");
                    return;
                }

                var activity = new UserActivityLog
                {
                    Id = Guid.NewGuid(),
                    ConnectedId = connectedId,
                    ActivityType = activityType,
                    IsSuccessful = isSuccessful,
                    Timestamp = _dateTimeProvider.UtcNow,
                    IPAddress = "System",
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    CreatedAt = _dateTimeProvider.UtcNow
                };

                await _activityLogRepository.AddAsync(activity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log user activity");
            }
        }

        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? userId,
            AuditEventSeverity severity,
            Dictionary<string, object>? metadata = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = performedByConnectedId,
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = DetermineActionType(action),
                    Action = action,
                    ResourceType = "Session",
                    ResourceId = userId?.ToString(),
                    Success = true,
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    Severity = severity,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = performedByConnectedId
                };

                await _auditRepository.AddAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for action {Action}", action);
            }
        }

        private AuditActionType DetermineActionType(string action)
        {
            return action switch
            {
                "LOGOUT" => AuditActionType.Logout,
                "FORCED_LOGOUT" => AuditActionType.Logout,
                "SESSION_EXPIRED" => AuditActionType.Logout,
                "LOGOUT_ALL_DEVICES" => AuditActionType.Logout,
                _ => AuditActionType.Others
            };
        }

        #endregion

        #region Cache Management

        private async Task ClearSessionCacheAsync(Guid userId, Guid sessionId)
        {
            try
            {
                // 세션 캐시 제거
                var sessionKey = $"{SESSION_CACHE_KEY}:{sessionId}";
                await _distributedCache.RemoveAsync(sessionKey);

                // 사용자의 활성 세션 목록 캐시 갱신
                var userSessionsKey = $"{SESSION_CACHE_KEY}:user:{userId}";
                await _distributedCache.RemoveAsync(userSessionsKey);

                _logger.LogDebug("Cleared cache for session {SessionId}", sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear session cache for session {SessionId}", sessionId);
            }
        }

        private async Task ClearUserPermissionCacheAsync(Guid userId)
        {
            try
            {
                // 사용자 권한 캐시 제거
                var permissionKey = $"{PERMISSION_CACHE_KEY}:{userId}";
                await _distributedCache.RemoveAsync(permissionKey);

                // 역할 기반 권한 캐시도 제거
                var rolePermissionKey = $"{PERMISSION_CACHE_KEY}:roles:{userId}";
                await _distributedCache.RemoveAsync(rolePermissionKey);

                _logger.LogDebug("Cleared permission cache for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear permission cache for user {UserId}", userId);
            }
        }

        private async Task ClearAllUserCachesAsync(Guid userId)
        {
            try
            {
                // 모든 사용자 관련 캐시 제거
                var cacheKeys = new[]
                {
                    $"{SESSION_CACHE_KEY}:user:{userId}",
                    $"{USER_CACHE_KEY}:{userId}",
                    $"{PERMISSION_CACHE_KEY}:{userId}",
                    $"{PERMISSION_CACHE_KEY}:roles:{userId}",
                    $"auth:devices:{userId}",
                    $"auth:locations:{userId}"
                };

                foreach (var key in cacheKeys)
                {
                    await _distributedCache.RemoveAsync(key);
                }

                _logger.LogInformation("Cleared all caches for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear all caches for user {UserId}", userId);
            }
        }

        #endregion

        #region Metrics and Analytics

        private async Task RecordLogoutMetricsAsync(LogoutEvent eventData, SessionEntity session)
        {
            try
            {
                // 기본 메트릭
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.{eventData.Reason.ToString().ToLower()}");
                
                // 세션 지속 시간 히스토그램
                var duration = CalculateSessionDuration(session);
                await _metricsService.RecordHistogramAsync(
                    $"{METRICS_PREFIX}.session_duration_minutes", 
                    duration.TotalMinutes);

                // 세션 타입별 메트릭
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.type.{session.SessionType.ToString().ToLower()}");

                // 시간대별 로그아웃 패턴
                var hour = _dateTimeProvider.UtcNow.Hour;
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.hourly.{hour}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record logout metrics");
            }
        }

        private async Task DetectSuspiciousLogoutPatternAsync(Guid userId, string ipAddress)
        {
            try
            {
                // 최근 로그아웃 횟수 확인
                var recentLogouts = await GetRecentLogoutCountAsync(userId, TimeSpan.FromHours(1));
                
                if (recentLogouts >= SUSPICIOUS_LOGOUT_THRESHOLD)
                {
                    _logger.LogWarning(
                        "Suspicious logout pattern detected for User {UserId}. {Count} logouts in last hour",
                        userId, recentLogouts);

                    await RecordSecurityEventAsync(
                        userId,
                        "SUSPICIOUS_LOGOUT_PATTERN",
                        $"{recentLogouts} logouts in last hour from {ipAddress}",
                        SecuritySeverity.Medium);

                    await _notificationService.SendSecurityAlertAsync(
                        userId,
                        "Unusual Logout Activity",
                        "We've detected unusual logout activity on your account. If this wasn't you, please secure your account.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to detect suspicious logout pattern for user {UserId}", userId);
            }
        }

        private async Task<int> GetRecentLogoutCountAsync(Guid userId, TimeSpan timeWindow)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:recent:{userId}";
            var countStr = await _distributedCache.GetStringAsync(cacheKey);
            
            var count = int.TryParse(countStr, out var c) ? c : 0;
            count++;
            
            await _distributedCache.SetStringAsync(
                cacheKey, 
                count.ToString(),
                new DistributedCacheEntryOptions 
                { 
                    SlidingExpiration = timeWindow 
                });
            
            return count;
        }

        private async Task AnalyzeSessionExpirationPatternAsync(Guid userId, TimeSpan sessionDuration)
        {
            try
            {
                // 평균 세션 지속 시간과 비교
                var avgDurationKey = $"{CACHE_KEY_PREFIX}:avg_duration:{userId}";
                var avgDurationStr = await _distributedCache.GetStringAsync(avgDurationKey);
                
                if (double.TryParse(avgDurationStr, out var avgMinutes))
                {
                    var currentMinutes = sessionDuration.TotalMinutes;
                    var deviation = Math.Abs(currentMinutes - avgMinutes) / avgMinutes;
                    
                    if (deviation > 0.5) // 50% 이상 차이
                    {
                        _logger.LogInformation(
                            "Unusual session duration for User {UserId}. Current: {Current} min, Average: {Average} min",
                            userId, currentMinutes, avgMinutes);
                    }
                    
                    // 이동 평균 업데이트
                    var newAvg = (avgMinutes * 0.9) + (currentMinutes * 0.1);
                    await _distributedCache.SetStringAsync(
                        avgDurationKey,
                        newAvg.ToString("F2"),
                        new DistributedCacheEntryOptions 
                        { 
                            SlidingExpiration = TimeSpan.FromDays(30) 
                        });
                }
                else
                {
                    // 첫 기록
                    await _distributedCache.SetStringAsync(
                        avgDurationKey,
                        sessionDuration.TotalMinutes.ToString("F2"),
                        new DistributedCacheEntryOptions 
                        { 
                            SlidingExpiration = TimeSpan.FromDays(30) 
                        });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze session expiration pattern");
            }
        }

        #endregion

        #region Notifications

        private async Task SendForcedLogoutNotificationAsync(ForcedLogoutEvent eventData)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(eventData.UserId);
                if (user == null) return;

                var forcedByUser = eventData.ForcedByUserId.HasValue 
                    ? await _userRepository.GetByIdAsync(eventData.ForcedByUserId.Value)
                    : null;

                var forcedByName = forcedByUser?.DisplayName ?? "System Administrator";

                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "Session Terminated",
                    $"Your session was terminated by {forcedByName}. Reason: {eventData.ForceReason}. " +
                    $"If you have questions about this action, please contact your administrator.");

                if (!string.IsNullOrEmpty(user.Email))
                {
                    var details = new Dictionary<string, string>
                    {
                        ["Reason"] = eventData.ForceReason,
                        ["ForcedBy"] = forcedByName,
                        ["ForcedAt"] = eventData.ForcedAt.ToString("yyyy-MM-dd HH:mm:ss UTC")
                    };
                    
                    // Get the user's primary ConnectedId
                    var userConnectedIds = await _connectedIdRepository.GetByUserIdAsync(eventData.UserId);
                    var primaryConnectedId = userConnectedIds.FirstOrDefault()?.Id;
                    
                    await _emailService.SendSecurityAlertEmailAsync(
                        user.Email,
                        SecurityAlertType.AccountLocked, // Using generic AccountAction for forced logout
                        details,
                        primaryConnectedId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send forced logout notification for User {UserId}", eventData.UserId);
            }
        }

        private async Task SendLogoutAllDevicesNotificationAsync(LogoutAllDevicesEvent eventData)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(eventData.UserId);
                if (user == null) return;

                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "All Sessions Terminated",
                    $"All your active sessions ({eventData.SessionCount}) have been terminated. " +
                    $"Reason: {eventData.Reason}. You will need to sign in again on all your devices.");

                if (!string.IsNullOrEmpty(user.Email))
                {
                    var details = new Dictionary<string, string>
                    {
                        ["SessionCount"] = eventData.SessionCount.ToString(),
                        ["Reason"] = eventData.Reason,
                        ["LogoutAt"] = eventData.LogoutAt.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                        ["Action"] = "All devices have been logged out"
                    };
                    
                    // Get the user's primary ConnectedId
                    var userConnectedIds = await _connectedIdRepository.GetByUserIdAsync(eventData.UserId);
                    var primaryConnectedId = userConnectedIds.FirstOrDefault()?.Id;
                    
                    await _emailService.SendSecurityAlertEmailAsync(
                        user.Email,
                        SecurityAlertType.AccountLocked, // Using generic AccountAction for all devices logout
                        details,
                        primaryConnectedId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send logout all devices notification for User {UserId}", eventData.UserId);
            }
        }

        #endregion

        #region Security Helper Methods

        private async Task RecordSecurityEventAsync(Guid userId, string eventType, string description, SecuritySeverity severity)
        {
            try
            {
                _logger.LogInformation(
                    "Recording security event: Type={EventType}, UserId={UserId}, Severity={Severity}",
                    eventType, userId, severity);

                // SecurityAnalyzer를 통한 보안 이벤트 기록 (메서드가 있다면)
                // 또는 감사 로그로 대체 기록
                await LogAuditAsync(
                    Guid.Empty,
                    eventType,
                    description,
                    userId,
                    MapSecuritySeverityToAuditSeverity(severity),
                    new Dictionary<string, object>
                    {
                        ["EventType"] = eventType,
                        ["SecuritySeverity"] = severity.ToString()
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record security event {EventType} for user {UserId}", eventType, userId);
            }
        }

        private AuditEventSeverity MapSecuritySeverityToAuditSeverity(SecuritySeverity severity)
        {
            return severity switch
            {
                SecuritySeverity.Critical => AuditEventSeverity.Critical,
                SecuritySeverity.High => AuditEventSeverity.Warning,
                SecuritySeverity.Medium => AuditEventSeverity.Info,
                SecuritySeverity.Low => AuditEventSeverity.Info,
                _ => AuditEventSeverity.Info
            };
        }

        #endregion

        #region Utility Methods

        private string SanitizeMetricLabel(string label)
        {
            if (string.IsNullOrEmpty(label))
                return "unknown";
                
            // 메트릭 라벨에 사용할 수 있도록 문자 정규화
            return label.ToLower()
                .Replace(" ", "_")
                .Replace("-", "_")
                .Replace(".", "_")
                .Replace("/", "_");
        }

        #endregion
    }
}