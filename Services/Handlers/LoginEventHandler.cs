using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
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
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Auth.Services.Authentication;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.User.Events;
using AuthHive.Core.Models.Auth.Session.Events;
using AuthHive.Core.Models.User.Events.Lifecycle;

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 로그인 이벤트 핸들러 구현 - AuthHive v15
    /// 로그인 관련 모든 이벤트를 처리하고 감사 로그, 알림, 보안 분석, 캐시 관리 등을 수행합니다.
    /// SessionService, AuthenticationAttemptService와 긴밀하게 연동됩니다.
    /// </summary>
    public class LoginEventHandler : ILoginEventHandler
    {
        #region Dependencies

        private readonly ILogger<LoginEventHandler> _logger;
        private readonly IAuditLogRepository _auditRepository;
        private readonly IUserRepository _userRepository;
        private readonly IUserActivityLogRepository _activityLogRepository;
        private readonly IAuthenticationAttemptLogRepository _authAttemptRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionService _sessionService;
        private readonly IAuthenticationAttemptService _authAttemptService;
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

        private const string CACHE_KEY_PREFIX = "login";
        private const string METRICS_PREFIX = "auth.login";
        private const string LOCATION_CACHE_KEY = "auth:locations";
        private const string DEVICE_CACHE_KEY = "auth:devices";
        private const string SESSION_CACHE_KEY = "auth:sessions";
        private const int MAX_CONCURRENT_SESSIONS = 5;
        private const int LOCATION_CACHE_DAYS = 30;
        private const int DEVICE_CACHE_DAYS = 90;

        #endregion

        #region Constructor

        public LoginEventHandler(
            ILogger<LoginEventHandler> logger,
            IAuditLogRepository auditRepository,
            IUserRepository userRepository,
            IUserActivityLogRepository activityLogRepository,
            IAuthenticationAttemptLogRepository authAttemptRepository,
            ISessionRepository sessionRepository,
            ISessionService sessionService,
            IAuthenticationAttemptService authAttemptService,
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
            _authAttemptRepository = authAttemptRepository ?? throw new ArgumentNullException(nameof(authAttemptRepository));
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _authAttemptService = authAttemptService ?? throw new ArgumentNullException(nameof(authAttemptService));
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

        #region ILoginEventHandler Implementation

        /// <inheritdoc />
        public async Task HandlePreLoginAsync(PreLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Pre-login attempt for {Username} via {LoginMethod} from {IpAddress}",
                    eventData.Username, eventData.LoginMethod, eventData.IpAddress);

                // 1. AuthenticationAttemptService를 통한 IP 위협 평가
                var ipRiskAssessment = await _authAttemptService.AssessIpRiskAsync(eventData.IpAddress, cancellationToken);
                if (ipRiskAssessment.IsSuccess && ipRiskAssessment.Data?.RiskScore >= 0.8)
                {
                    _logger.LogWarning("High risk IP detected: {IpAddress}", eventData.IpAddress);
                    await RecordBlockedAttemptAsync(eventData, cancellationToken);
                    return;
                }

                // 2. 무차별 대입 공격 감지
                var bruteForceDetected = await _authAttemptService.DetectBruteForceAttackAsync(
                    eventData.Username,
                    eventData.IpAddress,
                    cancellationToken);
                if (bruteForceDetected.IsSuccess && bruteForceDetected.Data == true)
                {
                    _logger.LogWarning("Brute force attack detected from {IpAddress}", eventData.IpAddress);
                    await _authAttemptService.BlockIpAddressAsync(
        ipAddress: eventData.IpAddress,
        duration: TimeSpan.FromHours(1),
        reason: "Brute force attack detected",
        organizationId: null,
        cancellationToken: cancellationToken);
                    return;
                }

                // 3. AuthenticationRequest 생성 및 로깅
                var authRequest = new AuthenticationRequest
                {
                    Username = eventData.Username,
                    Method = ParseAuthenticationMethod(eventData.LoginMethod),
                    IpAddress = eventData.IpAddress,
                    UserAgent = eventData.UserAgent,
                    DeviceInfo = !string.IsNullOrEmpty(eventData.UserAgent)
                        ? new DeviceInfo { UserAgent = eventData.UserAgent }
                        : null
                };

                await _authAttemptService.LogAuthenticationAttemptAsync(authRequest, cancellationToken);

                // 4. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "LOGIN_ATTEMPT",
                    $"Login attempt initiated for {eventData.Username}",
                    null,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["LoginMethod"] = eventData.LoginMethod,
                        ["IpAddress"] = eventData.IpAddress,
                        ["UserAgent"] = eventData.UserAgent ?? "Unknown"
                    },
                    cancellationToken);

                // 5. 메트릭 기록
                // Specify which parameter gets which value
                // Pass '1' for the value, then the cancellationToken
                // This matches the interface definition you provided.
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.attempt.{eventData.LoginMethod.ToLower()}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle pre-login event for {Username}", eventData.Username);
            }
        }

        /// <inheritdoc />
        public async Task HandleLoginSuccessAsync(LoginSuccessEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Login successful for User {UserId} (Session: {SessionId}) via {LoginMethod} from {IpAddress}",
                    eventData.UserId, eventData.SessionId, eventData.LoginMethod, eventData.IpAddress);

                // 1. 사용자 정보 업데이트
                var user = await _userRepository.GetByIdAsync(eventData.UserId, cancellationToken);
                if (user != null)
                {
                    user.LastLoginAt = eventData.OccurredAt;
                    user.LastLoginIp = eventData.IpAddress;
                    user.LoginCount = (user.LoginCount ?? 0) + 1;
                    user.UpdatedAt = _dateTimeProvider.UtcNow;

                    await _userRepository.UpdateAsync(user, cancellationToken);
                }

                // 2. AuthenticationAttemptService를 통한 성공 기록
                await _authAttemptService.LogSuccessfulAuthenticationAsync(
                    eventData.UserId,
                    eventData.ConnectedId,
                    ParseAuthenticationMethod(eventData.LoginMethod),
                    eventData.IpAddress,
                    eventData.Device,
                    cancellationToken);

                // 3. SessionService를 통한 세션 생성
                if (eventData.ConnectedId.HasValue)
                {
                    var createSessionRequest = new CreateSessionRequest
                    {
                        ConnectedId = eventData.ConnectedId.Value,
                        OrganizationId = user?.OrganizationId ?? Guid.Empty,
                        SessionType = SessionType.Web,
                        IpAddress = eventData.IpAddress,
                        UserAgent = eventData.Device ?? string.Empty,
                        InitialStatus = SessionStatus.Active,
                        ExpiresAt = DateTime.UtcNow.AddMinutes(AuthConstants.Session.GlobalSessionTimeoutMinutes),
                        InitialRiskScore = 0,
                        EnableGrpc = false,
                        EnablePubSubNotifications = true,
                        EnablePermissionCache = true
                    };

                    var sessionResult = await _sessionService.CreateSessionAsync(createSessionRequest, cancellationToken);
                    if (sessionResult.IsSuccess && sessionResult.Data != null)
                    {
                        eventData.SessionId = sessionResult.Data.SessionId ?? Guid.NewGuid();
                    }
                }

                // 4. 활동 로그 기록
                await LogUserActivityAsync(
                    eventData.ConnectedId ?? Guid.Empty,
                    UserActivityType.Login,
                    true,
                    new
                    {
                        SessionId = eventData.SessionId,
                        LoginMethod = eventData.LoginMethod,
                        IpAddress = eventData.IpAddress,
                        Location = eventData.Location,
                        Device = eventData.Device
                    },
                    cancellationToken);

                // 5. 보안 분석
                var anomalyResult = await _securityAnalyzer.DetectLoginAnomalyAsync(
                    eventData.UserId,
                    eventData.IpAddress,
                    eventData.Device ?? "Unknown",
                    eventData.OccurredAt,
                    cancellationToken);

                double anomalyScore = anomalyResult.AnomalyScore;
                bool anomalyDetected = anomalyResult.AnomalyDetected;
                bool requireAdditionalVerification = anomalyResult.RequireAdditionalVerification;

                if (anomalyDetected && anomalyScore > 0.7)
                {
                    await HandleSuspiciousLoginAsync(eventData, anomalyScore, requireAdditionalVerification, cancellationToken);
                }

                // 6. 지리적 이상 징후 탐지 (AuthenticationAttemptService 활용)
                if (!string.IsNullOrEmpty(eventData.Location))
                {
                    var geoAnomalyDetected = await _authAttemptService.DetectGeographicalAnomalyAsync(
                        eventData.UserId,
                        eventData.Location,
                        cancellationToken);

                    if (geoAnomalyDetected.IsSuccess && geoAnomalyDetected.Data == true)
                    {
                        await SendNewLocationAlertAsync(eventData, cancellationToken);
                    }
                }

                // 7. 감사 로그
                await LogAuditAsync(
                    eventData.ConnectedId ?? Guid.Empty,
                    "LOGIN_SUCCESS",
                    $"User logged in successfully via {eventData.LoginMethod}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["SessionId"] = eventData.SessionId?.ToString() ?? "N/A",
                        ["LoginMethod"] = eventData.LoginMethod,
                        ["IpAddress"] = eventData.IpAddress,
                        ["Location"] = eventData.Location ?? "Unknown",
                        ["Device"] = eventData.Device ?? "Unknown",
                        ["AnomalyScore"] = anomalyScore
                    },
                    cancellationToken);

                // 8. 메트릭 기록 (수정된 부분)
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.success.{eventData.LoginMethod.ToLower()}");
                await _metricsService.RecordHistogramAsync($"{METRICS_PREFIX}.anomaly_score", anomalyScore, cancellationToken);

                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle login success event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleLoginFailureAsync(LoginFailureEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning(
                    "Login failed for {Username} via {LoginMethod} from {IpAddress}. Reason: {Reason}, Attempts: {Attempts}",
                    eventData.Username, eventData.LoginMethod, eventData.IpAddress,
                    eventData.FailureReason, eventData.FailedAttempts);

                // 1. AuthenticationAttemptService를 통한 실패 기록
                await _authAttemptService.LogFailedAuthenticationAsync(
                    identifier: eventData.Username,
                    method: ParseAuthenticationMethod(eventData.LoginMethod),
                    reason: ParseAuthenticationResult(eventData.FailureReason),
                    ipAddress: eventData.IpAddress,
                    userAgent: eventData.UserAgent,
                    cancellationToken: cancellationToken);

                // 2. 계정 잠금 확인 및 처리
                // [FIX] CS1061: GetByUsernameAsync -> FindByUsernameAsync 메서드 이름 변경
                var user = await _userRepository.FindByUsernameAsync(eventData.Username, includeDeleted: false, cancellationToken);
                if (user != null)
                {
                    var lockStatus = await _authAttemptService.CheckAccountLockStatusAsync(user.Id, cancellationToken);
                    if (lockStatus.IsSuccess && lockStatus.Data?.IsLocked == true)
                    {
                        eventData.IsAccountLocked = true;
                        await HandleAccountLockAsync(user.Id, eventData.FailureReason, cancellationToken);
                    }
                }

                // 3. 의심스러운 활동 알림
                if (eventData.FailedAttempts >= 5 && user != null)
                {
                    await _authAttemptService.NotifySuspiciousActivityAsync(
                        user.Id,
                        $"Multiple failed login attempts: {eventData.FailedAttempts}",
                        cancellationToken);
                }

                // 4. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "LOGIN_FAILURE",
                    $"Login failed: {eventData.FailureReason}",
                    user?.Id,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["LoginMethod"] = eventData.LoginMethod,
                        ["IpAddress"] = eventData.IpAddress,
                        ["FailureReason"] = eventData.FailureReason,
                        ["FailedAttempts"] = eventData.FailedAttempts,
                        ["IsAccountLocked"] = eventData.IsAccountLocked
                    },
                    cancellationToken);

                // 5. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.failure.{eventData.LoginMethod.ToLower()}");

                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle login failure event for {Username}", eventData.Username);
            }
        }

        /// <inheritdoc />
        public async Task HandleFirstLoginAsync(FirstLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "First login detected for User {UserId} ({Username}) from {RegistrationSource}",
                    eventData.UserId, eventData.Username, eventData.RegistrationSource);

                // 1. 사용자 정보 업데이트
                var user = await _userRepository.GetByIdAsync(eventData.UserId, cancellationToken);
                if (user != null && !user.FirstLoginAt.HasValue)
                {
                    user.FirstLoginAt = eventData.OccurredAt;
                    user.UpdatedAt = _dateTimeProvider.UtcNow;
                    await _userRepository.UpdateAsync(user, cancellationToken);
                }

                // 2. 활동 로그 기록
                await LogUserActivityAsync(
                    Guid.Empty,
                    UserActivityType.FirstLogin,
                    true,
                    new
                    {
                        Username = eventData.Username,
                        RegistrationSource = eventData.RegistrationSource
                    },
                    cancellationToken);

                // 3. 환영 이메일 발송
                await SendWelcomeEmailAsync(eventData.UserId, eventData.Username, cancellationToken);

                // 4. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "FIRST_LOGIN",
                    $"First login completed for user {eventData.Username}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["RegistrationSource"] = eventData.RegistrationSource,
                        ["FirstLoginAt"] = eventData.OccurredAt
                    },
                    cancellationToken);

                // 5. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.first_login");

                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle first login event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleNewDeviceLoginAsync(NewDeviceLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "New device login detected for User {UserId}. Device: {DeviceType} ({DeviceName}) from {IpAddress}",
                    eventData.AggregateId, // BaseEvent에서 상속받은 AggregateId를 사용 (생성자에서 userId로 설정됨)
                    eventData.DeviceType,
                    eventData.DeviceName,
                    eventData.IpAddress);

                // 1. AuthenticationAttemptService를 통한 새 디바이스 알림
                await _authAttemptService.NotifyNewDeviceLoginAsync(
                    eventData.AggregateId,
                    $"{eventData.DeviceType}: {eventData.DeviceName}",
                    eventData.IpAddress,
                    cancellationToken);

                // 2. 활동 로그 기록
                await LogUserActivityAsync(
                    Guid.Empty, // 이 이벤트는 특정 ConnectedId와 직접 연관되지 않을 수 있음
                    UserActivityType.NewDeviceLogin,
                    true,
                    new
                    {
                        eventData.DeviceId,
                        eventData.DeviceType,
                        eventData.DeviceName,
                        eventData.IpAddress
                    },
                    cancellationToken);

                // 3. 디바이스 캐싱
                await UpdateDeviceCacheAsync(eventData.AggregateId, $"{eventData.DeviceType}:{eventData.DeviceName}", cancellationToken);

                // 4. 감사 로그 (✅ FIX: 명명된 인수를 사용하여 CancellationToken을 올바르게 전달)
                await LogAuditAsync(
                    performedByConnectedId: Guid.Empty,
                    action: "NEW_DEVICE_LOGIN",
                    description: $"Login from new device: {eventData.DeviceType} ({eventData.DeviceName})",
                    userId: eventData.AggregateId,
                    severity: AuditEventSeverity.Warning,
                    metadata: new Dictionary<string, object>
                    {
                        ["DeviceId"] = eventData.DeviceId,
                        ["DeviceType"] = eventData.DeviceType,
                        ["DeviceName"] = eventData.DeviceName,
                        ["IpAddress"] = eventData.IpAddress,
                        ["LoginAt"] = eventData.LoginAt
                    },
                    cancellationToken: cancellationToken);

                // 5. 메트릭 기록 (✅ FIX: CancellationToken 인수 제거)
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.new_device");

                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle new device login event for User {UserId}", eventData.AggregateId);
            }
        }

        /// <inheritdoc />
        public async Task HandleConcurrentLoginAsync(ConcurrentLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning(
                    "Concurrent login detected for User {UserId}. Active sessions: {ActiveSessionCount}, Exceeds limit: {ExceedsLimit}",
                    eventData.UserId, eventData.ActiveSessions.Count, eventData.ExceedsLimit);

                // 1. SessionRepository를 통한 동시 세션 수 확인
                var concurrentCount = await _sessionRepository.GetConcurrentSessionCountAsync(
                    eventData.UserId,
                    SessionLevel.Global,
                    cancellationToken);

                // 2. 세션 제한 초과 처리
                if (eventData.ExceedsLimit || concurrentCount > MAX_CONCURRENT_SESSIONS)
                {
                    // SessionService를 통해 다른 디바이스 세션 종료
                    Guid currentSessionId;
                    if (!Guid.TryParse(eventData.NewSessionId, out currentSessionId))
                    {
                        currentSessionId = Guid.NewGuid();
                    }

                    // ConnectedId 찾기
                    var connectedIds = await _connectedIdRepository.GetByUserIdAsync(eventData.UserId, cancellationToken);
                    if (connectedIds.Any())
                    {
                        var primaryConnectedId = connectedIds.First().Id;
                        var endedCountResult = await _sessionService.EndOtherDeviceSessionsAsync(
                            primaryConnectedId,
                            currentSessionId,
                            cancellationToken);

                        _logger.LogInformation(
                            "Ended {Count} other device sessions for User {UserId}",
                            endedCountResult.Data, eventData.UserId);
                    }
                }

                // 3. 이상 패턴 탐지
                if (eventData.ActiveSessions.Count > 3)
                {
                    var deviceFingerprints = eventData.ActiveSessions
                        .Select(s => s.Device)
                        .Distinct()
                        .ToList();

                    foreach (var fingerprint in deviceFingerprints)
                    {
                        await _authAttemptService.DetectAnomalousPatternAsync(
                            eventData.UserId,
                            eventData.ActiveSessions.First().IpAddress,
                            fingerprint,
                            cancellationToken);
                    }
                }

                // 4. 활동 로그 기록
                await LogUserActivityAsync(
                    Guid.Empty,
                    UserActivityType.ConcurrentLogin,
                    !eventData.ExceedsLimit,
                    new
                    {
                        ActiveSessionCount = eventData.ActiveSessions.Count,
                        NewSessionId = eventData.NewSessionId,
                        ExceedsLimit = eventData.ExceedsLimit
                    },
                    cancellationToken);

                // 5. 감사 로그
                var severity = eventData.ExceedsLimit ? AuditEventSeverity.Warning : AuditEventSeverity.Info;
                await LogAuditAsync(
                    Guid.Empty,
                    "CONCURRENT_LOGIN",
                    $"Concurrent login detected. Active sessions: {eventData.ActiveSessions.Count}",
                    eventData.UserId,
                    severity,
                    new Dictionary<string, object>
                    {
                        ["ActiveSessionCount"] = eventData.ActiveSessions.Count,
                        ["NewSessionId"] = eventData.NewSessionId,
                        ["ExceedsLimit"] = eventData.ExceedsLimit,
                        ["ConcurrentCountFromRepo"] = concurrentCount
                    },
                    cancellationToken);

                // 6. 메트릭 기록 (수정된 부분)
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.concurrent");
                await _metricsService.SetGaugeAsync($"{METRICS_PREFIX}.concurrent.sessions", concurrentCount);

                // 7. 알림
                if (eventData.ExceedsLimit || concurrentCount > 3)
                {
                    await SendConcurrentLoginAlertAsync(eventData, cancellationToken);
                }

                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle concurrent login event for User {UserId}", eventData.UserId);
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task UpdateDeviceCacheAsync(Guid userId, string? device, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(device))
                return;

            var key = $"{DEVICE_CACHE_KEY}:{userId}";
            var devicesJson = await _distributedCache.GetStringAsync(key, cancellationToken);

            var devices = string.IsNullOrEmpty(devicesJson)
                ? new HashSet<string>()
                : JsonSerializer.Deserialize<HashSet<string>>(devicesJson) ?? new HashSet<string>();

            devices.Add(device);

            await _distributedCache.SetStringAsync(
                key,
                JsonSerializer.Serialize(devices),
                new DistributedCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromDays(DEVICE_CACHE_DAYS)
                },
                cancellationToken);
        }

        private async Task HandleAccountLockAsync(Guid userId, string reason, CancellationToken cancellationToken = default)
        {
            // AuthenticationAttemptService를 통한 계정 잠금 처리
            await _authAttemptService.LockAccountAsync(
                userId,
                TimeSpan.FromMinutes(AuthConstants.Security.AccountLockoutDurationMinutes),
                reason,
                cancellationToken);

            // SessionService를 통한 모든 세션 종료
            var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
            foreach (var connectedId in connectedIds)
            {
                await _sessionService.EndAllSessionsAsync(connectedId.Id, SessionEndReason.SecurityViolation);
            }
        }

        private async Task HandleSuspiciousLoginAsync(LoginSuccessEvent eventData, double anomalyScore, bool requireAdditionalVerification, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning(
                "Suspicious login detected for User {UserId} from {IpAddress}. Anomaly score: {Score}",
                eventData.UserId, eventData.IpAddress, anomalyScore);

            // SessionService를 통한 위험도 업데이트
            if (eventData.SessionId.HasValue)
            {
                await _sessionService.UpdateRiskScoreAsync(
                    eventData.SessionId.Value,
                    (int)(anomalyScore * 10),
                    "Suspicious login pattern detected",
                    cancellationToken);
            }

            if (requireAdditionalVerification)
            {
                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "Suspicious Login Detected",
                    $"A login from {eventData.IpAddress} was flagged as suspicious. Please verify this was you.",
                    cancellationToken);
            }
        }

        private AuthenticationMethod ParseAuthenticationMethod(string method)
        {
            return Enum.TryParse<AuthenticationMethod>(method, true, out var result)
                ? result
                : AuthenticationMethod.Password;
        }

        private AuthenticationResult ParseAuthenticationResult(string reason)
        {
            return reason?.ToLower() switch
            {
                "invalid credentials" => AuthenticationResult.InvalidCredentials,
                "account locked" => AuthenticationResult.AccountLocked,
                "two factor required" => AuthenticationResult.MfaRequired,
                "mfa required" => AuthenticationResult.MfaRequired,
                "account disabled" => AuthenticationResult.AccountDisabled,
                "account expired" => AuthenticationResult.AccountExpired,
                "mfa failed" => AuthenticationResult.MfaFailed,
                "password expired" => AuthenticationResult.PasswordExpired,
                "too many attempts" => AuthenticationResult.TooManyAttempts,
                "ip blocked" => AuthenticationResult.IPBlocked,
                "organization access denied" => AuthenticationResult.OrganizationAccessDenied,
                "application access denied" => AuthenticationResult.ApplicationAccessDenied,
                "session limit exceeded" => AuthenticationResult.SessionLimitExceeded,
                "system error" => AuthenticationResult.SystemError,
                _ => AuthenticationResult.Other
            };
        }

        private async Task LogUserActivityAsync(Guid connectedId, UserActivityType activityType, bool isSuccessful, object? metadata = null, CancellationToken cancellationToken = default)
        {
            try
            {
                // ConnectedId가 없으면 조회 또는 생성
                if (connectedId == Guid.Empty)
                {
                    connectedId = await GetOrCreateConnectedIdAsync(Guid.Empty, cancellationToken);
                }

                var activity = new UserActivityLog
                {
                    Id = Guid.NewGuid(),
                    ConnectedId = connectedId,
                    ActivityType = activityType,
                    IsSuccessful = isSuccessful,
                    Timestamp = _dateTimeProvider.UtcNow,
                    IpAddress = "System",
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    CreatedAt = _dateTimeProvider.UtcNow
                };

                await _activityLogRepository.AddAsync(activity, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log user activity");
            }
        }

        private async Task<Guid> GetOrCreateConnectedIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            if (userId != Guid.Empty)
            {
                var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                if (connectedIds.Any())
                {
                    return connectedIds.First().Id;
                }
            }

            return Guid.NewGuid();
        }

        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? userId,
            AuditEventSeverity severity,
            Dictionary<string, object>? metadata = null,
            CancellationToken cancellationToken = default)
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
                    ResourceType = "Login",
                    ResourceId = userId?.ToString(),
                    Success = !action.Contains("FAILURE") && !action.Contains("BLOCKED"),
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    Severity = severity,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = performedByConnectedId
                };

                await _auditRepository.AddAsync(auditLog, cancellationToken);
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
                "LOGIN_ATTEMPT" => AuditActionType.LoginAttempt,
                "LOGIN_SUCCESS" => AuditActionType.Login,
                "LOGIN_FAILURE" => AuditActionType.FailedLogin,
                "FIRST_LOGIN" => AuditActionType.Login,
                "NEW_DEVICE_LOGIN" => AuditActionType.Login,
                "CONCURRENT_LOGIN" => AuditActionType.Login,
                "LOGIN_BLOCKED" => AuditActionType.Blocked,
                _ => AuditActionType.Others
            };
        }

        private async Task RecordBlockedAttemptAsync(PreLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            await LogAuditAsync(
                Guid.Empty,
                "LOGIN_BLOCKED",
                $"Login attempt blocked from IP: {eventData.IpAddress}",
                null,
                AuditEventSeverity.Critical,
                new Dictionary<string, object>
                {
                    ["Username"] = eventData.Username,
                    ["IpAddress"] = eventData.IpAddress,
                    ["Reason"] = "High Risk IP"
                },
                cancellationToken);
        }

        #endregion

        #region Email Notifications

        private async Task SendWelcomeEmailAsync(Guid userId, string username, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user != null && !string.IsNullOrEmpty(user.Email))
                {
                    await _emailService.SendWelcomeEmailAsync(
        email: user.Email,
        userName: user.DisplayName ?? username,
        organizationId: user.OrganizationId ?? Guid.Empty,
        cancellationToken: cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send welcome email for User {UserId}", userId);
            }
        }

        private async Task SendNewLocationAlertAsync(LoginSuccessEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "New Login Location",
                    $"Your account was accessed from a new location: {eventData.Location ?? eventData.IpAddress}. " +
                    $"Device: {eventData.Device ?? "Unknown"}. If this wasn't you, please secure your account immediately.",
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send new location alert for User {UserId}", eventData.UserId);
            }
        }

        private async Task SendConcurrentLoginAlertAsync(ConcurrentLoginEvent eventData, CancellationToken cancellationToken = default)
        {
            try
            {
                var message = eventData.ExceedsLimit
                    ? $"Your account has exceeded the maximum number of concurrent sessions ({MAX_CONCURRENT_SESSIONS}). " +
                      $"Some sessions have been terminated for security."
                    : $"Multiple active sessions detected for your account ({eventData.ActiveSessions.Count} sessions). " +
                      $"Please review your active sessions if you don't recognize all of them.";

                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "Multiple Active Sessions",
                    message,
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send concurrent login alert for User {UserId}", eventData.UserId);
            }
        }

        #endregion
    }
}