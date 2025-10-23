using System;
using System.Collections.Generic;
using System.Diagnostics; // Stopwatch 사용
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization; // JsonStringEnumConverter 사용
using System.Threading; // CancellationToken 사용
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Distributed; // IDistributedCache 사용
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit; // IAuditService 사용
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Infra.Monitoring;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Entities.Auth; // SessionEntity, SessionActivityLog 엔티티 사용
using AuthHive.Core.Entities.User; // UserActivityLog 엔티티 사용
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Audit; // AuditEventSeverity, AuditActionType 사용
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Events; // LogoutEvent, ForcedLogoutEvent 사용
using AuthHive.Core.Models.Auth.Session.Events; // SessionExpiredEvent, LogoutAllDevicesEvent 사용

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 로그아웃 이벤트 핸들러 구현 - AuthHive v16
    /// 로그아웃 관련 모든 이벤트를 처리하고 감사 로그, 알림, 보안 분석, 캐시 정리 등을 수행합니다.
    /// SessionService와 긴밀하게 연동됩니다.
    /// </summary>
    public class LogoutEventHandler : ILogoutEventHandler, IService // IService 구현
    {
        #region 의존성 (Dependencies)

        private readonly ILogger<LogoutEventHandler> _logger;
        private readonly IAuditService _auditService; // IAuditLogRepository 대신 사용
        private readonly IUserRepository _userRepository;
        private readonly IUserActivityLogRepository _activityLogRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionActivityLogRepository _sessionActivityRepository;
        private readonly ISessionService _sessionService;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly INotificationService _notificationService; // 사용자 알림 (인앱, 푸시 등)
        private readonly IEmailService _emailService; // 이메일 알림
        private readonly ISecurityAnalyzer _securityAnalyzer; // 보안 분석 서비스 (가정)
        private readonly IMetricsService _metricsService; // 메트릭 기록 서비스
        private readonly ICacheService _cacheService; // 통합 캐시 서비스
        // IDistributedCache는 ICacheService 구현 내부에 캡슐화될 수 있으나, 기존 코드 유지 및 직접 사용
        private readonly IDistributedCache _distributedCache;
        private readonly IUnitOfWork _unitOfWork; // 데이터 일관성을 위한 작업 단위

        #endregion

        #region 상수 (Constants)

        // 캐시 키 접두사 및 이름
        private const string CACHE_KEY_PREFIX = "logout";
        private const string METRICS_PREFIX = "auth.logout";
        private const string SESSION_CACHE_KEY_PREFIX = "auth:sessions";
        private const string USER_CACHE_KEY_PREFIX = "auth:users";
        private const string PERMISSION_CACHE_KEY_PREFIX = "auth:permissions";

        // 보안 분석용 임계값
        private const int SUSPICIOUS_LOGOUT_THRESHOLD = 10;
        private const int FORCED_LOGOUT_NOTIFICATION_DELAY_MINUTES = 5;

        #endregion

        #region 생성자 (Constructor)

        public LogoutEventHandler(
            ILogger<LogoutEventHandler> logger,
            IAuditService auditService,
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
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
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

        #region IService 구현 (IService Implementation)

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _cacheService.ExistsAsync("health_check:logouthandler", cancellationToken);
                // 필요시 다른 의존성 서비스 상태 확인 추가
                return true;
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("LogoutEventHandler health check canceled."); // 영문 로그
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "LogoutEventHandler health check failed"); // 영문 로그
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("LogoutEventHandler initialized at {Time}", _dateTimeProvider.UtcNow); // 영문 로그
            return Task.CompletedTask;
        }

        #endregion

        #region ILogoutEventHandler 구현 (ILogoutEventHandler Implementation)

        /// <inheritdoc />
        public async Task HandleLogoutAsync(LogoutEvent eventData, CancellationToken cancellationToken = default)
        {
            var sessionId = eventData.AggregateId;
            var userId = eventData.UserId;

            try
            {
                _logger.LogInformation(
                    "Handling logout: UserId={UserId}, SessionId={SessionId}, Reason={Reason}, IP={IpAddress}", // 영문 로그
                    userId, sessionId, eventData.Reason, eventData.ClientIpAddress);

                var stopwatch = Stopwatch.StartNew();

                // 1. 세션 조회 및 검증
                var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);
                if (session == null || session.EndedAt.HasValue)
                {
                    _logger.LogWarning("Session {SessionId} not found or already ended.", sessionId); // 영문 로그
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.session_not_found", cancellationToken: cancellationToken);
                    return;
                }
                if (session.UserId != userId)
                {
                     _logger.LogWarning("Logout event data mismatch with session user: SessionId={SessionId}, EventUserId={EventUserId}, SessionUserId={SessionUserId}", // 영문 로그
                                        sessionId, userId, session.UserId);
                     await _metricsService.IncrementAsync($"{METRICS_PREFIX}.data_mismatch", cancellationToken: cancellationToken);
                     // 불일치 시에도 일단 세션 종료 시도 (보안 고려)
                }

                var connectedId = session.ConnectedId ?? Guid.Empty; // 활동/감사 로그용 ConnectedId

                // 2. SessionService를 통한 세션 종료
                var endResult = await _sessionService.EndSessionAsync(sessionId, eventData.Reason, cancellationToken);
                if (!endResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to end session {SessionId}: {Error}", sessionId, endResult.ErrorMessage); // 영문 로그
                }

                // 3. 세션 활동 로그 기록
                var sessionDuration = CalculateSessionDuration(session); // 종료 전 계산
                await LogSessionActivityAsync(
                    sessionId,
                    "LOGOUT",
                    eventData.ClientIpAddress ?? "Unknown",
                    new { Reason = eventData.Reason.ToString() },
                    cancellationToken);

                // 4. 사용자 활동 로그 기록
                await LogUserActivityAsync(
                    connectedId,
                    UserActivityType.Logout,
                    true,
                    new
                    {
                        SessionId = sessionId,
                        Reason = eventData.Reason.ToString(),
                        IpAddress = eventData.ClientIpAddress,
                        SessionDurationMinutes = sessionDuration.TotalMinutes
                    },
                    cancellationToken);

                // 5. 캐시 정리
                await ClearSessionCacheAsync(userId, sessionId, cancellationToken);
                // await ClearUserPermissionCacheAsync(userId, cancellationToken); // 필요시 주석 해제

                // 6. 메트릭 기록
                await RecordLogoutMetricsAsync(eventData.Reason, session, sessionDuration, cancellationToken);

                // 7. 감사 로그 (IAuditService 사용)
                await LogAuditAsync(
                    connectedId, // 행위자 ConnectedId
                    "LOGOUT",
                    $"User logged out successfully. Reason: {eventData.Reason}", // 영문 설명
                    userId, // 대상 사용자
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = sessionId,
                        ["Reason"] = eventData.Reason.ToString(),
                        ["IpAddress"] = eventData.ClientIpAddress ?? "N/A",
                        ["SessionDurationMinutes"] = sessionDuration.TotalMinutes,
                        ["OrganizationId"] = session.OrganizationId ?? Guid.Empty // 세션의 OrganizationId 추가
                    },
                    cancellationToken);

                // 8. 의심스러운 패턴 탐지
                await DetectSuspiciousLogoutPatternAsync(userId, eventData.ClientIpAddress, cancellationToken);

                // UnitOfWork Commit은 보통 상위 레벨에서 처리
                // await _unitOfWork.CommitTransactionAsync(cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.handle.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);
                _logger.LogInformation("Logout handling completed: SessionId={SessionId}, Duration={Duration}ms", sessionId, stopwatch.ElapsedMilliseconds); // 영문 로그
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Logout handling canceled: UserId={UserId}, SessionId={SessionId}", userId, sessionId); // 영문 로그
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle logout event: UserId={UserId}, SessionId={SessionId}", userId, sessionId); // 영문 로그
                 // throw; // 필요시 예외 전파
            }
        }

        /// <inheritdoc />
        public async Task HandleForcedLogoutAsync(ForcedLogoutEvent eventData, CancellationToken cancellationToken = default)
        {
            var sessionId = eventData.AggregateId;
            var targetUserId = eventData.UserId; // ForcedLogoutEvent에는 UserId 속성 사용
            var forcedByConnectedId = eventData.TriggeredBy ?? Guid.Empty; // BaseEvent의 TriggeredBy

            try
            {
                 _logger.LogWarning(
                    "Handling forced logout: TargetUserId={TargetUserId}, SessionId={SessionId}, ForcedByConnectedId={ForcedBy}, Reason={Reason}", // 영문 로그
                    targetUserId, sessionId, forcedByConnectedId, eventData.ForceReason);
                var stopwatch = Stopwatch.StartNew();

                // 1. 대상 세션 조회
                var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);
                if (session == null || session.EndedAt.HasValue)
                {
                    _logger.LogWarning("Session {SessionId} for forced logout not found or already ended.", sessionId); // 영문 로그
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced.session_not_found", cancellationToken: cancellationToken);
                    return;
                }
                if (session.UserId != targetUserId)
                {
                     _logger.LogError("Forced logout security violation: Session({SessionId}) user mismatch with target user({TargetUserId}).", sessionId, targetUserId); // 영문 로그
                     await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced.user_mismatch", cancellationToken: cancellationToken);
                     return;
                }

                var targetConnectedId = session.ConnectedId ?? Guid.Empty;

                // 2. SessionService를 통한 강제 세션 종료
                var endReason = SessionEndReason.AdminTerminated; // 기본값
                if (eventData.ForceReason.Contains("security", StringComparison.OrdinalIgnoreCase)) endReason = SessionEndReason.SecurityViolation;
                else if (eventData.ForceReason.Contains("idle", StringComparison.OrdinalIgnoreCase)) endReason = SessionEndReason.IdleTimeout;

                var endResult = await _sessionService.EndSessionAsync(sessionId, endReason, cancellationToken);
                if (!endResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to forcibly end session {SessionId}: {Error}", sessionId, endResult.ErrorMessage); // 영문 로그
                }

                // 3. 자식 세션 종료 (필요한 경우)
                // if (session.Level == SessionLevel.Global /* && ... */) { ... }

                var sessionDuration = CalculateSessionDuration(session);

                // 4. 세션 활동 로그
                await LogSessionActivityAsync(
                    sessionId,
                    "FORCED_LOGOUT",
                    "System",
                    new { Reason = eventData.ForceReason, ForcedBy = forcedByConnectedId },
                    cancellationToken);

                // 5. 사용자 활동 로그
                await LogUserActivityAsync(
                    targetConnectedId,
                    UserActivityType.ForcedLogout,
                    true,
                    new
                    {
                        SessionId = sessionId,
                        Reason = eventData.ForceReason,
                        ForcedByConnectedId = forcedByConnectedId,
                        SessionDurationMinutes = sessionDuration.TotalMinutes
                    },
                    cancellationToken);

                // 6. 캐시 즉시 정리
                await ClearSessionCacheAsync(targetUserId, sessionId, cancellationToken);
                await ClearUserPermissionCacheAsync(targetUserId, cancellationToken);

                // 7. 알림 발송 (지연 실행 고려)
                _ = Task.Run(async () => {
                     await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken); // 약간 지연
                     await SendForcedLogoutNotificationAsync(targetUserId, forcedByConnectedId, eventData.ForceReason, cancellationToken);
                }, cancellationToken).ContinueWith(t => _logger.LogError(t.Exception, "Failed to send forced logout notification (background)"), TaskContinuationOptions.OnlyOnFaulted);


                // 8. 보안 이벤트 기록
                await RecordSecurityEventAsync(
                    targetUserId,
                    "FORCED_LOGOUT",
                    eventData.ForceReason,
                    SecuritySeverity.High,
                    cancellationToken);

                // 9. 감사 로그 (IAuditService 사용)
                await LogAuditAsync(
                    forcedByConnectedId, // 수행 주체
                    "FORCED_LOGOUT",
                    $"Forced logout executed for user. Reason: {eventData.ForceReason}", // 영문 설명
                    targetUserId, // 대상 사용자
                    AuditEventSeverity.Warning, // 심각도: 경고
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = sessionId,
                        ["Reason"] = eventData.ForceReason,
                        ["ForcedAt"] = eventData.OccurredAt, // 이벤트 발생 시간
                        ["OrganizationId"] = session.OrganizationId ?? Guid.Empty // 세션의 OrganizationId
                    },
                    cancellationToken);

                // 10. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced", cancellationToken: cancellationToken);
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.forced.reason.{SanitizeMetricLabel(eventData.ForceReason)}", cancellationToken: cancellationToken);

                // await _unitOfWork.CommitTransactionAsync(cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.forced.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);
                _logger.LogWarning("Forced logout handling completed: SessionId={SessionId}, Duration={Duration}ms", sessionId, stopwatch.ElapsedMilliseconds); // 영문 로그
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Forced logout handling canceled: TargetUserId={TargetUserId}, SessionId={SessionId}", targetUserId, sessionId); // 영문 로그
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle forced logout event: TargetUserId={TargetUserId}, SessionId={SessionId}", targetUserId, sessionId); // 영문 로그
                 // throw; // 실패 시 예외 전파 고려
            }
        }

        /// <inheritdoc />
        public async Task HandleSessionExpiredAsync(SessionExpiredEvent eventData, CancellationToken cancellationToken = default)
        {
            var sessionId = eventData.AggregateId;
            var userId = eventData.UserId;

            try
            {
                 _logger.LogInformation(
                    "Handling session expiration: UserId={UserId}, SessionId={SessionId}, Duration={Duration:F1} minutes", // 영문 로그
                    userId, sessionId, eventData.SessionDuration.TotalMinutes);
                 var stopwatch = Stopwatch.StartNew();

                // 1. SessionService를 통한 만료 세션 상태 업데이트 (없거나 이미 종료되었어도 안전)
                var endResult = await _sessionService.EndSessionAsync(sessionId, SessionEndReason.Expired, cancellationToken);
                if (!endResult.IsSuccess && endResult.ErrorMessage != null && // null 체크 추가
                    !endResult.ErrorMessage.Contains("not found", StringComparison.OrdinalIgnoreCase) &&
                    !endResult.ErrorMessage.Contains("already ended", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Failed to end expired session {SessionId}: {Error}", sessionId, endResult.ErrorMessage); // 영문 로그
                }

                // 2. 세션 정보 조회 시도 (로그 기록용 ConnectedId 확보)
                var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken); // 종료된 세션도 조회 가능해야 함
                var connectedId = session?.ConnectedId ?? Guid.Empty;
                if (connectedId == Guid.Empty && userId != Guid.Empty)
                {
                    connectedId = await GetPrimaryConnectedIdForUserAsync(userId, cancellationToken); // UserId로 대표 ConnectedId 조회
                }

                // 3. 세션 활동 로그
                await LogSessionActivityAsync(
                    sessionId,
                    "SESSION_EXPIRED",
                    "System",
                    new { SessionDurationMinutes = eventData.SessionDuration.TotalMinutes, ExpiredAt = eventData.OccurredAt }, // ExpiredAt 사용
                    cancellationToken);

                // 4. 사용자 활동 로그
                await LogUserActivityAsync(
                    connectedId, // 최선으로 찾은 ConnectedId
                    UserActivityType.SessionExpired,
                    true,
                    new
                    {
                        SessionId = sessionId,
                        SessionDurationMinutes = eventData.SessionDuration.TotalMinutes,
                        ExpiredAt = eventData.OccurredAt // ExpiredAt 사용
                    },
                    cancellationToken);

                // 5. 캐시 정리
                await ClearSessionCacheAsync(userId, sessionId, cancellationToken);

                // 6. 세션 만료 패턴 분석 (선택 사항)
                // await AnalyzeSessionExpirationPatternAsync(userId, eventData.SessionDuration, cancellationToken);

                // 7. 감사 로그 (IAuditService 사용)
                await LogAuditAsync(
                    connectedId, // 시스템 이벤트이므로 Guid.Empty 또는 관련 ConnectedId
                    "SESSION_EXPIRED",
                    $"Session expired after {eventData.SessionDuration.TotalMinutes:F1} minutes", // 영문 설명
                    userId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = sessionId,
                        ["SessionDurationMinutes"] = eventData.SessionDuration.TotalMinutes,
                        ["ExpiredAt"] = eventData.OccurredAt, // ExpiredAt 사용
                        ["OrganizationId"] = session?.OrganizationId ?? Guid.Empty // 세션에서 OrganizationId 가져오기
                    },
                    cancellationToken);

                // 8. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.expired", cancellationToken: cancellationToken);
                await _metricsService.RecordHistogramAsync($"{METRICS_PREFIX}.session_duration_minutes", eventData.SessionDuration.TotalMinutes, cancellationToken: cancellationToken);

                // 백그라운드 작업일 수 있으므로 자체 Commit 필요할 수 있음
                // await _unitOfWork.CommitTransactionAsync(cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.expired.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);
                _logger.LogInformation("Session expiration handling completed: SessionId={SessionId}, Duration={Duration}ms", sessionId, stopwatch.ElapsedMilliseconds); // 영문 로그
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Session expiration handling canceled: UserId={UserId}, SessionId={SessionId}", userId, sessionId); // 영문 로그
                 // throw; // 백그라운드 작업 취소는 전파하지 않을 수 있음
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle session expired event: UserId={UserId}, SessionId={SessionId}", userId, sessionId); // 영문 로그
                 // 실패해도 다른 작업에 영향 주지 않도록 throw 하지 않음
            }
        }


        /// <inheritdoc />
        public async Task HandleLogoutAllDevicesAsync(LogoutAllDevicesEvent eventData, CancellationToken cancellationToken = default)
        {
            var userId = eventData.AggregateId; // 이벤트 AggregateId가 사용자 ID
            var triggeredByConnectedId = eventData.TriggeredBy ?? Guid.Empty; // 작업을 요청한 주체

            try
            {
                 _logger.LogWarning(
                    "Handling logout all devices: UserId={UserId}, TriggeredByConnectedId={TriggeredBy}, Reason={Reason}", // 영문 로그
                    userId, triggeredByConnectedId, eventData.Reason);
                var stopwatch = Stopwatch.StartNew();

                // 1. 해당 사용자의 모든 활성 세션 조회 (ISessionRepository에 GetActiveSessionsByUserAsync 필요)
                var activeSessions = await _sessionRepository.GetActiveSessionsByUserAsync(userId, cancellationToken);
                var terminatedSessionInfos = new List<(Guid SessionId, Guid? ConnectedId, Guid? OrganizationId)>(); // 종료된 세션 정보 저장

                // 2. 각 세션 종료 (SessionService 사용)
                foreach (var session in activeSessions)
                {
                    var endResult = await _sessionService.EndSessionAsync(session.Id, SessionEndReason.LogoutAllDevices, cancellationToken);
                    if (endResult.IsSuccess)
                    {
                        terminatedSessionInfos.Add((session.Id, session.ConnectedId, session.OrganizationId));
                        // 개별 세션 활동 로그는 선택 사항
                    }
                    else
                    {
                        _logger.LogWarning("Failed to end session during logout all devices: SessionId={SessionId}, Error={Error}", session.Id, endResult.ErrorMessage); // 영문 로그
                    }
                }
                int terminatedCount = terminatedSessionInfos.Count;
                _logger.LogInformation("Logout all devices: UserId={UserId}, terminated {TerminatedCount} out of {TotalCount} active sessions.", userId, terminatedCount, activeSessions.Count()); // 영문 로그

                // 3. 사용자 활동 로그 (대표 로그 1건)
                await LogUserActivityAsync(
                    triggeredByConnectedId, // 작업을 수행한 주체
                    UserActivityType.Logout, // 별도 타입(LogoutAll)이 있다면 사용
                    true,
                    new
                    {
                        Reason = eventData.Reason,
                        TerminatedSessionCount = terminatedCount,
                        // TerminatedSessionIds = terminatedSessionInfos.Select(t => t.SessionId).ToList() // 필요시 ID 목록 포함
                    },
                    cancellationToken);

                // 4. 모든 사용자 관련 캐시 정리
                await ClearAllUserCachesAsync(userId, cancellationToken);

                // 5. 보안 알림 발송
                await SendLogoutAllDevicesNotificationAsync(userId, eventData.Reason, terminatedCount, cancellationToken);

                // 6. 보안 이벤트 기록
                await RecordSecurityEventAsync(
                    userId,
                    "LOGOUT_ALL_DEVICES",
                    eventData.Reason,
                    SecuritySeverity.High,
                    cancellationToken);

                // 7. 감사 로그 (IAuditService 사용)
                await LogAuditAsync(
                    triggeredByConnectedId, // 수행 주체
                    "LOGOUT_ALL_DEVICES",
                    $"All devices logged out. Reason: {eventData.Reason}", // 영문 설명
                    userId, // 대상 사용자
                    AuditEventSeverity.Warning, // 심각도: 경고
                    new Dictionary<string, object>
                    {
                        ["Reason"] = eventData.Reason,
                        ["TerminatedSessionCount"] = terminatedCount,
                        ["LogoutAt"] = eventData.OccurredAt,
                        // 필요한 경우 OrganizationId 목록 추가: ["OrganizationIds"] = terminatedSessionInfos.Select(t => t.OrganizationId).Distinct().ToList()
                    },
                    cancellationToken);

                // 8. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.all_devices", cancellationToken: cancellationToken);
                await _metricsService.RecordHistogramAsync($"{METRICS_PREFIX}.all_devices.terminated_count", terminatedCount, cancellationToken: cancellationToken);

                // await _unitOfWork.CommitTransactionAsync(cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.all_devices.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);
                _logger.LogWarning("Logout all devices handling completed: UserId={UserId}, Duration={Duration}ms", userId, stopwatch.ElapsedMilliseconds); // 영문 로그
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Logout all devices handling canceled: UserId={UserId}", userId); // 영문 로그
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle logout all devices event: UserId={UserId}", userId); // 영문 로그
                 // throw; // 실패 시 예외 전파 고려
            }
        }


        #endregion

        #region 비공개 헬퍼 메서드 (Private Helper Methods)

        /// <summary>
        /// 세션 지속 시간을 계산합니다. 종료되지 않은 경우 현재 시간 기준으로 계산합니다.
        /// </summary>
        private TimeSpan CalculateSessionDuration(SessionEntity session)
        {
            var startTime = session.CreatedAt;
            var endTime = session.EndedAt ?? _dateTimeProvider.UtcNow;
            return (endTime > startTime) ? endTime - startTime : TimeSpan.Zero;
        }

        /// <summary>
        /// UserId를 기반으로 대표 ConnectedId를 조회합니다 (첫 번째 또는 특정 규칙).
        /// </summary>
        private async Task<Guid> GetPrimaryConnectedIdForUserAsync(Guid userId, CancellationToken cancellationToken)
        {
            if (userId == Guid.Empty) return Guid.Empty;
            try
            {
                var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                return connectedIds?.FirstOrDefault()?.Id ?? Guid.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get primary ConnectedId for UserId={UserId}", userId); // 영문 로그
                return Guid.Empty;
            }
        }


        /// <summary>
        /// 세션 활동 로그를 기록합니다.
        /// </summary>
        private async Task LogSessionActivityAsync(Guid sessionId, string activity, string ipAddress, object? metadata = null, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!Enum.TryParse<SessionActivityType>(activity, true, out var activityType))
                {
                    activityType = SessionActivityType.Other;
                    _logger.LogWarning("Unknown session activity type string: {ActivityString}", activity); // 영문 로그
                }

                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = sessionId,
                    ActivityType = activityType,
                    IpAddress = ipAddress,
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata, DefaultJsonSerializerOptions.Options) : null,
                    Timestamp = _dateTimeProvider.UtcNow,
                    CreatedAt = _dateTimeProvider.UtcNow
                };

                await _sessionActivityRepository.AddAsync(activityLog, cancellationToken);
            }
            catch (OperationCanceledException) { _logger.LogTrace("Logging session activity canceled: SessionId={SessionId}", sessionId); } // 영문 로그
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log session activity: SessionId={SessionId}", sessionId); // 영문 로그
            }
        }


        /// <summary>
        /// 사용자 활동 로그를 기록합니다.
        /// </summary>
        private async Task LogUserActivityAsync(Guid connectedId, UserActivityType activityType, bool isSuccessful, object? metadata = null, CancellationToken cancellationToken = default)
        {
            try
            {
                // if (connectedId == Guid.Empty) { ... } // 필요시 로깅

                var activity = new UserActivityLog
                {
                    Id = Guid.NewGuid(),
                    ConnectedId = connectedId,
                    ActivityType = activityType,
                    IsSuccessful = isSuccessful,
                    Timestamp = _dateTimeProvider.UtcNow,
                    IpAddress = metadata?.GetType().GetProperty("IpAddress")?.GetValue(metadata)?.ToString(),
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata, DefaultJsonSerializerOptions.Options) : null,
                    CreatedAt = _dateTimeProvider.UtcNow
                };

                await _activityLogRepository.AddAsync(activity, cancellationToken);
            }
            catch (OperationCanceledException) { _logger.LogTrace("Logging user activity canceled: ConnectedId={ConnectedId}", connectedId); } // 영문 로그
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log user activity: ConnectedId={ConnectedId}, ActivityType={ActivityType}", connectedId, activityType); // 영문 로그
            }
        }

        /// <summary>
        /// 감사 로그를 기록합니다. (IAuditService 사용)
        /// </summary>
        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? targetUserId,
            AuditEventSeverity severity,
            Dictionary<string, object>? metadata = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var fullMetadata = metadata ?? new Dictionary<string, object>();
                fullMetadata["Description"] = description;
                fullMetadata["Severity"] = severity.ToString();

                await _auditService.LogActionAsync(
                    actionType: DetermineActionType(action),
                    action: action,
                    connectedId: performedByConnectedId,
                    resourceType: targetUserId.HasValue ? "UserSession" : "System",
                    resourceId: targetUserId?.ToString(),
                    metadata: fullMetadata,
                    cancellationToken: cancellationToken);
            }
            catch (OperationCanceledException) { _logger.LogTrace("Audit logging canceled: Action={Action}", action); } // 영문 로그
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit: Action={Action}, PerformedBy={PerformedBy}", action, performedByConnectedId); // 영문 로그
            }
        }


        /// <summary>
        /// 감사 로그 액션 타입을 결정합니다.
        /// </summary>
        private AuditActionType DetermineActionType(string action)
        {
            return action.ToUpperInvariant() switch
            {
                "LOGOUT" => AuditActionType.Logout,
                "FORCED_LOGOUT" => AuditActionType.Security,
                "SESSION_EXPIRED" => AuditActionType.System,
                "LOGOUT_ALL_DEVICES" => AuditActionType.Security,
                _ => AuditActionType.Others
            };
        }

        #endregion

        #region 캐시 관리 (Cache Management)

        /// <summary>
        /// 특정 세션 관련 캐시를 제거합니다.
        /// </summary>
        private async Task ClearSessionCacheAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken)
        {
            if (sessionId == Guid.Empty) return;
            try
            {
                var sessionKey = $"{SESSION_CACHE_KEY_PREFIX}:{sessionId}";
                await _cacheService.RemoveAsync(sessionKey, cancellationToken);

                var userSessionsKey = $"{SESSION_CACHE_KEY_PREFIX}:user:{userId}";
                await _cacheService.RemoveAsync(userSessionsKey, cancellationToken);

                _logger.LogDebug("Cleared session cache: SessionId={SessionId}", sessionId); // 영문 로그
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear session cache: SessionId={SessionId}", sessionId); // 영문 로그
            }
        }

        /// <summary>
        /// 사용자 권한 관련 캐시를 제거합니다.
        /// </summary>
        private async Task ClearUserPermissionCacheAsync(Guid userId, CancellationToken cancellationToken)
        {
            if (userId == Guid.Empty) return;
            try
            {
                var userPermissionKey = $"{PERMISSION_CACHE_KEY_PREFIX}:user:{userId}";
                await _cacheService.RemoveAsync(userPermissionKey, cancellationToken);

                var connectedIds = await GetConnectedIdsForUserAsync(userId, false, cancellationToken);
                foreach (var cid in connectedIds)
                {
                    var connectedIdPermissionKey = $"{PERMISSION_CACHE_KEY_PREFIX}:connected:{cid}";
                    await _cacheService.RemoveAsync(connectedIdPermissionKey, cancellationToken);
                }

                _logger.LogDebug("Cleared user permission cache: UserId={UserId}", userId); // 영문 로그
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear user permission cache: UserId={UserId}", userId); // 영문 로그
            }
        }


        /// <summary>
        /// 특정 사용자와 관련된 모든 캐시(세션, 권한, 사용자 정보 등)를 제거합니다.
        /// </summary>
        private async Task ClearAllUserCachesAsync(Guid userId, CancellationToken cancellationToken)
        {
             if (userId == Guid.Empty) return;
            try
            {
                var patternsToRemove = new List<string>
                {
                    $"{SESSION_CACHE_KEY_PREFIX}:user:{userId}",
                    $"{USER_CACHE_KEY_PREFIX}:{userId}",
                    $"{PERMISSION_CACHE_KEY_PREFIX}:user:{userId}",
                };

                 var connectedIds = await GetConnectedIdsForUserAsync(userId, false, cancellationToken);
                 foreach (var cid in connectedIds)
                 {
                     patternsToRemove.Add($"{SESSION_CACHE_KEY_PREFIX}:connected:{cid}");
                     patternsToRemove.Add($"{PERMISSION_CACHE_KEY_PREFIX}:connected:{cid}");
                 }
                 // Be careful with broad patterns like SESSION_CACHE_KEY_PREFIX:*
                 patternsToRemove.Add($"{SESSION_CACHE_KEY_PREFIX}:*");


                var removeTasks = patternsToRemove.Select(pattern =>
                    _cacheService.RemoveByPatternAsync(pattern, cancellationToken)
                        .ContinueWith(t =>
                        {
                            if (t.IsFaulted) _logger.LogError(t.Exception, "Failed to remove cache by pattern: Pattern={Pattern}", pattern); // 영문 로그
                        }, cancellationToken)
                );
                await Task.WhenAll(removeTasks);

                _logger.LogInformation("Attempted to clear all caches for user: UserId={UserId}", userId); // 영문 로그
            }
             catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while clearing all caches for user: UserId={UserId}", userId); // 영문 로그
            }
        }

        #endregion

        #region 메트릭 및 분석 (Metrics and Analytics)

        /// <summary>
        /// 로그아웃 관련 메트릭을 기록합니다.
        /// </summary>
        private async Task RecordLogoutMetricsAsync(SessionEndReason reason, SessionEntity session, TimeSpan duration, CancellationToken cancellationToken)
        {
            try
            {
                var reasonLabel = SanitizeMetricLabel(reason.ToString());
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.reason.{reasonLabel}", cancellationToken: cancellationToken);
                await _metricsService.RecordHistogramAsync($"{METRICS_PREFIX}.session_duration_minutes", duration.TotalMinutes, cancellationToken: cancellationToken);
                // Enum은 항상 값이 있으므로 HasValue 체크 제거
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.type.{SanitizeMetricLabel(session.SessionType.ToString())}", cancellationToken: cancellationToken);

                var hour = _dateTimeProvider.UtcNow.Hour;
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.hourly.{hour}", cancellationToken: cancellationToken);
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record logout metrics"); // 영문 로그
            }
        }

        /// <summary>
        /// 의심스러운 로그아웃 패턴을 탐지하고 조치합니다.
        /// </summary>
        private async Task DetectSuspiciousLogoutPatternAsync(Guid userId, string? ipAddress, CancellationToken cancellationToken)
        {
            if (userId == Guid.Empty) return;
            try
            {
                var recentLogouts = await GetRecentLogoutCountAsync(userId, TimeSpan.FromHours(1), cancellationToken);

                if (recentLogouts >= SUSPICIOUS_LOGOUT_THRESHOLD)
                {
                    _logger.LogWarning(
                        "Suspicious logout pattern detected: UserId={UserId}. {Count} logouts in last hour (IP: {IP})", // 영문 로그
                        userId, recentLogouts, ipAddress ?? "Unknown");

                    await RecordSecurityEventAsync(
                        userId,
                        "SUSPICIOUS_LOGOUT_PATTERN",
                        $"{recentLogouts} logouts in the last hour from IP: {ipAddress ?? "Unknown"}",
                        SecuritySeverity.Medium,
                        cancellationToken);

                    // 필요시 사용자 알림 추가
                    // await _notificationService.SendSecurityAlertAsync(...)
                }
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to detect suspicious logout pattern: UserId={UserId}", userId); // 영문 로그
            }
        }


        /// <summary>
        /// 캐시를 사용해 지정된 시간 동안의 로그아웃 횟수를 가져오고 증가시킵니다. (ICacheService 사용)
        /// </summary>
        private async Task<long> GetRecentLogoutCountAsync(Guid userId, TimeSpan timeWindow, CancellationToken cancellationToken)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:recent:{userId}";
            try
            {
                long currentCount = await _cacheService.IncrementAsync(cacheKey, 1, cancellationToken);
                // TTL 설정 로직 추가 필요 시 여기에
                return currentCount;
            }
            catch (NotSupportedException nse)
            {
                 _logger.LogWarning(nse, "IncrementAsync is not supported. Falling back to non-atomic Get/Set for {CacheKey}.", cacheKey); // 영문 로그
                 var countStr = await _cacheService.GetStringAsync(cacheKey, cancellationToken);
                 long count = long.TryParse(countStr, out var c) ? c : 0;
                 count++;
                 await _cacheService.SetStringAsync(cacheKey, count.ToString(), timeWindow, cancellationToken);
                 return count;
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "Failed to get/increment recent logout count: CacheKey={CacheKey}", cacheKey); // 영문 로그
                 return 0;
            }
        }


        /// <summary>
        /// 세션 만료 패턴을 분석합니다 (예: 평균 지속 시간과 비교). (ICacheService 사용)
        /// </summary>
        private async Task AnalyzeSessionExpirationPatternAsync(Guid userId, TimeSpan sessionDuration, CancellationToken cancellationToken)
        {
            if (userId == Guid.Empty) return;
            try
            {
                var avgDurationKey = $"{CACHE_KEY_PREFIX}:avg_duration:{userId}";
                var currentMinutes = sessionDuration.TotalMinutes;
                var avgDurationStr = await _cacheService.GetStringAsync(avgDurationKey, cancellationToken);

                if (double.TryParse(avgDurationStr, out var avgMinutes) && avgMinutes > 0)
                {
                    var deviation = Math.Abs(currentMinutes - avgMinutes) / avgMinutes;
                    if (deviation > 0.5)
                    {
                        _logger.LogInformation(
                            "Unusual session duration detected: UserId={UserId}. Current={Current:F1}min, Average={Average:F1}min", // 영문 로그
                            userId, currentMinutes, avgMinutes);
                        await _metricsService.IncrementAsync($"{METRICS_PREFIX}.duration.anomaly", cancellationToken: cancellationToken);
                    }
                    var newAvg = (avgMinutes * 0.9) + (currentMinutes * 0.1);
                    await _cacheService.SetStringAsync(avgDurationKey, newAvg.ToString("F2"), TimeSpan.FromDays(30), cancellationToken);
                }
                else
                {
                    await _cacheService.SetStringAsync(avgDurationKey, currentMinutes.ToString("F2"), TimeSpan.FromDays(30), cancellationToken);
                }
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze session expiration pattern: UserId={UserId}", userId); // 영문 로그
            }
        }


        #endregion

        #region 알림 (Notifications)

        /// <summary>
        /// 강제 로그아웃 알림을 사용자에게 발송합니다.
        /// </summary>
        private async Task SendForcedLogoutNotificationAsync(Guid targetUserId, Guid forcedByConnectedId, string reason, CancellationToken cancellationToken)
        {
            if (targetUserId == Guid.Empty) return;
            try
            {
                // GetByIdAsync 사용
                var user = await _userRepository.GetByIdAsync(targetUserId, cancellationToken);
                if (user == null || string.IsNullOrEmpty(user.Email))
                {
                    _logger.LogWarning("Cannot send forced logout notification: User not found or no email (UserId: {UserId})", targetUserId); // 영문 로그
                    return;
                }

                // GetByIdAsync 사용
                var forcedByConn = await _connectedIdRepository.GetByIdAsync(forcedByConnectedId, cancellationToken);
                // GetByIdAsync 사용 및 null-forgiving operator 사용
                var forcedByUser = forcedByConn != null ? await _userRepository.GetByIdAsync(forcedByConn.UserId!.Value, cancellationToken) : null;
                var forcedByName = forcedByUser?.DisplayName ?? forcedByConn?.Id.ToString() ?? "System Administrator";

                // 인앱/푸시 알림
                await _notificationService.SendSecurityAlertAsync(
                   targetUserId,
                   "Session Terminated", // 영문 제목
                   $"Your session was terminated by {forcedByName}. Reason: {reason}. If you have questions, please contact your administrator.", // 영문 내용
                   cancellationToken);

                // 이메일 알림
                var details = new Dictionary<string, string>
                {
                    ["Reason"] = reason,
                    ["ForcedBy"] = forcedByName,
                    ["ForcedAt"] = _dateTimeProvider.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC")
                };
                // SecurityAlertType.AccountAction 사용 (Enum 수정 전까지 임시)
                await _emailService.SendSecurityAlertEmailAsync(
                   user.Email,
                   SecurityAlertType.ForcedLogout, // Enum 수정 또는 적절한 타입 선택
                   details,
                   targetUserId,
                   cancellationToken);

                _logger.LogInformation("Forced logout notification sent successfully: UserId={UserId}", targetUserId); // 영문 로그
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send forced logout notification: UserId={UserId}", targetUserId); // 영문 로그
            }
        }


        /// <summary>
        /// 모든 디바이스 로그아웃 알림을 발송합니다.
        /// </summary>
        private async Task SendLogoutAllDevicesNotificationAsync(Guid userId, string reason, int sessionCount, CancellationToken cancellationToken)
        {
             if (userId == Guid.Empty) return;
            try
            {
                // GetByIdAsync 사용
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null || string.IsNullOrEmpty(user.Email))
                {
                     _logger.LogWarning("Cannot send logout all devices notification: User not found or no email (UserId: {UserId})", userId); // 영문 로그
                    return;
                }

                 // 인앱/푸시 알림
                 await _notificationService.SendSecurityAlertAsync(
                    userId,
                    "All Sessions Terminated", // 영문 제목
                    $"All your active sessions ({sessionCount}) have been terminated. Reason: {reason}. You will need to sign in again on all your devices.", // 영문 내용
                    cancellationToken);

                 // 이메일 알림
                 var details = new Dictionary<string, string>
                {
                    ["SessionCount"] = sessionCount.ToString(),
                    ["Reason"] = reason,
                    ["LogoutAt"] = _dateTimeProvider.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                    ["Action"] = "All devices have been logged out"
                };
                 // SecurityAlertType.AccountAction 사용 (Enum 수정 전까지 임시)
                await _emailService.SendSecurityAlertEmailAsync(
                    user.Email,
                    SecurityAlertType.ForcedLogout, // Enum 수정 또는 적절한 타입 선택
                    details,
                    userId,
                    cancellationToken);

                 _logger.LogInformation("Logout all devices notification sent successfully: UserId={UserId}", userId); // 영문 로그
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send logout all devices notification: UserId={UserId}", userId); // 영문 로그
            }
        }


        #endregion

        #region 보안 관련 헬퍼 (Security Helper Methods)

        /// <summary>
        /// 보안 이벤트를 기록합니다 (감사 로그 활용).
        /// </summary>
        private async Task RecordSecurityEventAsync(Guid userId, string eventType, string description, SecuritySeverity severity, CancellationToken cancellationToken)
        {
            if (userId == Guid.Empty) return;
            try
            {
                // 감사 로그를 보안 이벤트 기록용으로 사용
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Security,
                    action: eventType,
                    connectedId: Guid.Empty, // 시스템 또는 관련 ConnectedId (여기서는 UserId로 대체)
                    resourceType: "UserSecurity",
                    resourceId: userId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        ["Description"] = description,
                        ["Severity"] = severity.ToString()
                    },
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Security event recorded: Type={EventType}, UserId={UserId}, Severity={Severity}", eventType, userId, severity); // 영문 로그
            }
            catch (OperationCanceledException) { /* 무시 */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record security event: Type={EventType}, UserId={UserId}", eventType, userId); // 영문 로그
            }
        }

        // SecuritySeverity 매핑 메서드 (현재 LogAuditAsync에서 사용 안함)
        // private AuditEventSeverity MapSecuritySeverityToAuditEventSeverity(SecuritySeverity severity) { ... }

        #endregion

        #region 유틸리티 메서드 (Utility Methods)

        /// <summary>
        /// 메트릭 레이블로 사용하기 안전한 문자열로 변환합니다.
        /// </summary>
        private string SanitizeMetricLabel(string? label)
        {
            if (string.IsNullOrWhiteSpace(label)) return "unknown";
            var sanitized = System.Text.RegularExpressions.Regex.Replace(label.ToLowerInvariant(), @"[^a-z0-9_]+", "_");
            return sanitized.Trim('_');
        }

        #endregion

        #region 사용자 정의 JSON 직렬화 옵션 (Utility Methods)

        private static class DefaultJsonSerializerOptions
        {
            public static JsonSerializerOptions Options { get; } = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
            };
        }

        #endregion

        #region IConnectedIdRepository 의존성 (필요한 메서드)

        /// <summary>
        /// 사용자의 (선택적으로 활성) ConnectedId 목록을 가져옵니다. (Repository 호출 래핑)
        /// </summary>
        private async Task<IEnumerable<Guid>> GetConnectedIdsForUserAsync(Guid userId, bool activeOnly, CancellationToken cancellationToken)
        {
             if (userId == Guid.Empty) return Enumerable.Empty<Guid>();
             try
             {
                 var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                 // TODO: 활성 필터링 추가 (ConnectedIdEntity에 Status 가정)
                 // if (activeOnly) { connectedIds = connectedIds.Where(c => c.Status == ConnectedIdStatus.Active); }
                 return connectedIds?.Select(c => c.Id) ?? Enumerable.Empty<Guid>();
             }
             catch (Exception ex)
             {
                  _logger.LogError(ex, "Failed to get ConnectedIds for user: UserId={UserId}", userId); // 영문 로그
                  return Enumerable.Empty<Guid>();
             }
        }

        #endregion
    }
}


