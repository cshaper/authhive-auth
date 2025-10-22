using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Interfaces.Infra.Monitoring;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Events;
using System.Threading; // CancellationToken 사용을 위해 추가

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 인증 이벤트 핸들러 구현 - AuthHive v16 (확장됨)
    /// 인증 관련 모든 이벤트를 처리하고 감사 로그, 알림, 캐시 무효화 등을 수행합니다.
    /// ✨ v16: 인증 시도 추적, 위험 평가, 이상 징후 감지 기능 추가, CancellationToken 적용
    /// </summary>
    public class AuthEventHandler : IAuthEventHandler
    {
        private readonly ILogger<AuthEventHandler> _logger;
        private readonly IAuditLogRepository _auditRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly INotificationService _notificationService;
        private readonly ICacheService _cacheService;
        private readonly IMetricsService _metricsService;

        private const string CACHE_KEY_PREFIX = "auth:session";
        private const string METRICS_PREFIX = "auth.events";

        public AuthEventHandler(
            ILogger<AuthEventHandler> logger,
            IAuditLogRepository auditRepository,
            IDateTimeProvider dateTimeProvider,
            INotificationService notificationService,
            ICacheService cacheService,
            IMetricsService metricsService)
        {
            _logger = logger;
            _auditRepository = auditRepository;
            _dateTimeProvider = dateTimeProvider;
            _notificationService = notificationService;
            _cacheService = cacheService;
            _metricsService = metricsService;
        }

        #region 기존 메서드들 (v15) - CancellationToken 추가

        /// <inheritdoc />
        public async Task HandleAuthenticationSuccessAsync(AuthenticationSuccessEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "Authentication success for User {UserId} via {AuthMethod} from {IpAddress}",
                    eventData.UserId, eventData.AuthMethod, eventData.ClientIpAddress);

                await LogAuditAsync(
                    eventData.ConnectedId ?? Guid.Empty,
                    "AUTH_SUCCESS",
                    $"User authenticated successfully via {eventData.AuthMethod}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["AuthMethod"] = eventData.AuthMethod,
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown",
                        ["UserAgent"] = eventData.UserAgent ?? "Unknown",
                        ["Username"] = eventData.Username ?? "Unknown", // Username 추가됨
                        ["AdditionalData"] = eventData.AdditionalData ?? new Dictionary<string, object>()
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.success.{eventData.AuthMethod.ToLower()}", 1, cancellationToken);

                var cacheKey = $"{CACHE_KEY_PREFIX}:{eventData.UserId}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken); // CancellationToken 전달

                if (await IsNewLocationAsync(eventData.UserId, eventData.ClientIpAddress, cancellationToken)) // CancellationToken 전달
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId,
                        "New Login Location",
                        $"Your account was accessed from a new location: {eventData.ClientIpAddress}",
                        cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication success event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAuthenticationFailureAsync(AuthenticationFailureEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogWarning(
                    "Authentication failure for {Username} via {AuthMethod} from {IpAddress}. Reason: {Reason}. Attempt: {AttemptCount}",
                    eventData.Username ?? "Unknown", eventData.AuthMethod, eventData.ClientIpAddress, // ClientIp -> ClientIpAddress
                    eventData.FailureReason, eventData.AttemptCount);

                await LogAuditAsync(
                    Guid.Empty,
                    "AUTH_FAILURE",
                    $"Authentication failed: {eventData.FailureReason}",
                    null, // UserId가 없을 수 있음
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username ?? "Unknown", // UserIdentifier -> Username
                        ["AuthMethod"] = eventData.AuthMethod,
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown", // ClientIp -> ClientIpAddress
                        ["AttemptCount"] = eventData.AttemptCount,
                        ["FailureReason"] = eventData.FailureReason
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.failure.{eventData.AuthMethod.ToLower()}", 1, cancellationToken); // CancellationToken 전달

                if (eventData.AttemptCount >= 3)
                {
                    await HandleRepeatedFailuresAsync(eventData, cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication failure event");
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenIssuedAsync(TokenIssuedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "Token issued for User {UserId}. Type: {TokenType}, Expires: {ExpiresAt}", // TokenId 제거 (BaseEvent.AggregateId 사용)
                    eventData.UserId, eventData.TokenType, eventData.ExpiresAt);

                await LogAuditAsync(
                    Guid.Empty, // 토큰 발급은 시스템 행위로 간주
                    "TOKEN_ISSUED",
                    $"{eventData.TokenType} token issued",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["TokenType"] = eventData.TokenType,
                        ["TokenId"] = eventData.AggregateId, // TokenId -> AggregateId
                        ["ExpiresAt"] = eventData.ExpiresAt!,
                        ["Scopes"] = eventData.Scopes ?? new List<string>()
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.issued.{eventData.TokenType.ToLower()}", 1, cancellationToken); // CancellationToken 전달

                var cacheKey = $"token:{eventData.AggregateId}"; // TokenId -> AggregateId
                var cacheData = new
                {
                    UserId = eventData.UserId,
                    Type = eventData.TokenType,
                    ExpiresAt = eventData.ExpiresAt,
                    Scopes = eventData.Scopes
                };
                var ttl = eventData.ExpiresAt - _dateTimeProvider.UtcNow;
                if (ttl > TimeSpan.Zero)
                {
                    await _cacheService.SetAsync(cacheKey, JsonSerializer.Serialize(cacheData), ttl, cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token issued event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenRefreshedAsync(TokenRefreshedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "Token refreshed for User {UserId}. Old: {OldTokenId}, New: {NewTokenId}",
                    eventData.UserId, eventData.OldTokenId, eventData.NewTokenId);

                await LogAuditAsync(
                    Guid.Empty,
                    "TOKEN_REFRESHED",
                    "Token refreshed successfully",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["OldTokenId"] = eventData.OldTokenId,
                        ["NewTokenId"] = eventData.NewTokenId
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.refreshed", 1, cancellationToken); // CancellationToken 전달

                var oldCacheKey = $"token:{eventData.OldTokenId}";
                await _cacheService.RemoveAsync(oldCacheKey, cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token refreshed event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenRevokedAsync(TokenRevokedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "Token revoked for User {UserId}. TokenId: {TokenId}, Reason: {Reason}",
                    eventData.UserId, eventData.TokenId, eventData.RevokeReason);

                await LogAuditAsync(
                    Guid.Empty,
                    "TOKEN_REVOKED",
                    $"Token revoked: {eventData.RevokeReason}",
                    eventData.UserId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["TokenId"] = eventData.TokenId,
                        ["RevokeReason"] = eventData.RevokeReason
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.revoked", 1, cancellationToken); // CancellationToken 전달

                var cacheKey = $"token:{eventData.TokenId}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken); // CancellationToken 전달

                if (IsSuspiciousRevocation(eventData.RevokeReason))
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId,
                        "Token Revoked",
                        $"A token was revoked for security reasons: {eventData.RevokeReason}",
                        cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token revoked event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleMfaRequiredAsync(MfaRequiredEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "MFA required for User {UserId}. Method: {MfaMethod}",
                    eventData.UserId, eventData.MfaMethod);

                await LogAuditAsync(
                    Guid.Empty,
                    "MFA_REQUIRED",
                    $"MFA verification required via {eventData.MfaMethod}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["MfaMethod"] = eventData.MfaMethod
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.mfa.required.{eventData.MfaMethod.ToLower()}", 1, cancellationToken); // CancellationToken 전달

                if (eventData.MfaMethod == "SMS" || eventData.MfaMethod == "Email")
                {
                    // MFA 코드 발송은 중요하므로 취소되지 않도록 별도 Task로 실행하거나,
                    // CancellationToken.None을 전달하는 것을 고려할 수 있습니다.
                    await _notificationService.SendMfaCodeAsync(eventData.UserId, eventData.MfaMethod, CancellationToken.None); // 또는 cancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle MFA required event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleMfaSuccessAsync(MfaSuccessEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "MFA verification successful for User {UserId}. Method: {MfaMethod}",
                    eventData.UserId, eventData.MfaMethod);

                await LogAuditAsync(
                    Guid.Empty,
                    "MFA_SUCCESS",
                    $"MFA verification successful via {eventData.MfaMethod}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["MfaMethod"] = eventData.MfaMethod
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.mfa.success.{eventData.MfaMethod.ToLower()}", 1, cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle MFA success event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAccountLockedAsync(AccountLockedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogWarning(
                    "Account locked for User {UserId}. Reason: {Reason}, Until: {LockedUntil}",
                    eventData.UserId, eventData.Reason, eventData.LockedUntil);

                await LogAuditAsync(
                    Guid.Empty,
                    "ACCOUNT_LOCKED",
                    $"Account locked: {eventData.Reason}",
                    eventData.UserId,
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["LockReason"] = eventData.Reason,
                        ["LockedUntil"] = eventData.LockedUntil.ToString()!
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.locked", 1, cancellationToken); // CancellationToken 전달

                // 계정 잠금 시 관련 캐시(세션 등) 일괄 삭제
                var sessionPattern = $"{CACHE_KEY_PREFIX}:{eventData.UserId}:*";
                await _cacheService.RemoveByPatternAsync(sessionPattern, cancellationToken); // CancellationToken 전달

                await _notificationService.SendAccountLockedNotificationAsync(
                    eventData.UserId,
                    eventData.Reason,
                    eventData.LockedUntil,
                    cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle account locked event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAccountUnlockedAsync(AccountUnlockedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogInformation(
                    "Account unlocked for User {UserId}. Reason: {Reason}",
                    eventData.UserId, eventData.UnlockReason);

                await LogAuditAsync(
                    Guid.Empty,
                    "ACCOUNT_UNLOCKED",
                    $"Account unlocked: {eventData.UnlockReason}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["UnlockReason"] = eventData.UnlockReason!
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.unlocked", 1, cancellationToken); // CancellationToken 전달

                await _notificationService.SendAccountUnlockedNotificationAsync(
                    eventData.UserId,
                    eventData.UnlockReason ?? "Your account has been unlocked.",
                    cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle account unlocked event for User {UserId}", eventData.UserId);
            }
        }

        #endregion

        #region 신규 메서드들 (v16) - CancellationToken 추가

        /// <inheritdoc />
        public async Task HandleAuthenticationAttemptedAsync(AuthenticationAttemptedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                var logLevel = eventData.IsSuccess ? LogLevel.Information : LogLevel.Warning;
                _logger.Log(
                    logLevel,
                    "Authentication attempt for User {Username} via {Method} from {IpAddress}. Success: {Success}",
                    eventData.Username, eventData.Method, eventData.ClientIpAddress, eventData.IsSuccess); // IpAddress -> ClientIpAddress

                await LogAuditAsync(
                    eventData.ConnectedId ?? Guid.Empty,
                    eventData.IsSuccess ? "AUTH_ATTEMPT_SUCCESS" : "AUTH_ATTEMPT_FAILURE",
                    $"Authentication attempt via {eventData.Method}: {(eventData.IsSuccess ? "Success" : $"Failed - {eventData.FailureReason}")}",
                    eventData.UserId,
                    eventData.IsSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["Method"] = eventData.Method.ToString(),
                        ["IsSuccess"] = eventData.IsSuccess,
                        ["FailureReason"] = eventData.FailureReason?.ToString() ?? "N/A",
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown",
                        ["UserAgent"] = eventData.UserAgent ?? "Unknown",
                        ["ApplicationId"] = eventData.ApplicationId?.ToString() ?? "N/A"
                    },
                    cancellationToken); // CancellationToken 전달

                var metricKey = eventData.IsSuccess
                    ? $"{METRICS_PREFIX}.attempt.success.{eventData.Method.ToString().ToLower()}"
                    : $"{METRICS_PREFIX}.attempt.failure.{eventData.Method.ToString().ToLower()}";
                await _metricsService.IncrementAsync(metricKey, 1, cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication attempted event");
            }
        }

        /// <inheritdoc />
        public async Task HandleHighRiskAuthenticationAsync(HighRiskAuthenticationEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogWarning(
                    "High-risk authentication for User {Username} from {IpAddress}. Risk Score: {RiskScore}, Level: {RiskLevel}",
                    eventData.Username, eventData.ClientIpAddress, eventData.RiskScore, eventData.RiskLevel); // IpAddress -> ClientIpAddress

                await LogAuditAsync(
                    eventData.UserId ?? Guid.Empty, // ConnectedId 대신 UserId 사용 (없을 수 있음)
                    "HIGH_RISK_AUTH",
                    $"High-risk authentication detected: {eventData.RiskLevel} (Score: {eventData.RiskScore})",
                    eventData.UserId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown",
                        ["RiskScore"] = eventData.RiskScore,
                        ["RiskLevel"] = eventData.RiskLevel,
                        ["RiskFactors"] = eventData.RiskFactors,
                        ["RequiresMfa"] = eventData.RequiresMfa,
                        ["RequiresAdditionalVerification"] = eventData.RequiresAdditionalVerification
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.high_risk", 1, cancellationToken); // CancellationToken 전달

                // 고위험 인증 시 보안팀에 알림
                if (eventData.RiskScore >= 0.8)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId ?? Guid.Empty,
                        "High-Risk Authentication Detected",
                        $"A high-risk authentication was detected for {eventData.Username} from {eventData.ClientIpAddress}. " + // IpAddress -> ClientIpAddress
                        $"Risk Score: {eventData.RiskScore:P0}. Factors: {string.Join(", ", eventData.RiskFactors)}",
                        cancellationToken); // CancellationToken 전달
                }

                // MFA 요구 시 사용자에게 알림
                if (eventData.RequiresMfa && eventData.UserId.HasValue)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId.Value,
                        "MFA Required for Security",
                        "Due to unusual activity, multi-factor authentication is now required.",
                        cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle high-risk authentication event");
            }
        }

        /// <inheritdoc />
        public async Task HandleSuspiciousLoginActivityAsync(SuspiciousLoginActivityEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogWarning(
                    "Suspicious login activity detected for {Username} from {IpAddress}. Risk Score: {RiskScore}. Patterns: {Patterns}",
                    eventData.Username, eventData.ClientIpAddress, eventData.RiskScore, // IpAddress -> ClientIpAddress
                    string.Join(", ", eventData.DetectedPatterns));

                await LogAuditAsync(
                    Guid.Empty, // 특정 ConnectedId 특정 어려움
                    "SUSPICIOUS_LOGIN",
                    $"Suspicious login activity detected. Patterns: {string.Join(", ", eventData.DetectedPatterns)}",
                    null, // UserId 특정 어려움
                    eventData.RiskScore >= 80 ? AuditEventSeverity.Critical : AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown",
                        ["DeviceFingerprint"] = eventData.DeviceFingerprint ?? "Unknown",
                        ["RiskScore"] = eventData.RiskScore,
                        ["DetectedPatterns"] = eventData.DetectedPatterns
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.suspicious_login", 1, cancellationToken); // CancellationToken 전달

                // 임시 IP 차단 (고위험 시)
                if (eventData.RiskScore >= 80 && !string.IsNullOrEmpty(eventData.ClientIpAddress)) // IpAddress -> ClientIpAddress
                {
                    var blockKey = $"auth:blocked:ip:{eventData.ClientIpAddress}"; // IpAddress -> ClientIpAddress
                    await _cacheService.SetAsync(blockKey, "suspicious_activity", TimeSpan.FromMinutes(30), cancellationToken); // CancellationToken 전달

                    _logger.LogWarning("Temporarily blocked IP {IpAddress} due to suspicious activity", eventData.ClientIpAddress); // IpAddress -> ClientIpAddress
                }

                // 보안 알림 발송 (UserId 특정 어려움)
                _logger.LogWarning(
                    "Sending security alert for suspicious login: {Username} from {IpAddress}",
                    eventData.Username, eventData.ClientIpAddress); // IpAddress -> ClientIpAddress
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle suspicious login activity event");
            }
        }

        /// <inheritdoc />
        public async Task HandleGeographicalAnomalyAsync(GeographicalAnomalyDetectedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogWarning(
                    "Geographical anomaly detected for User {UserId}. New location: {NewLocation}. Previous: {PreviousLocations}",
                    eventData.TriggeredBy, eventData.NewLocation, string.Join(", ", eventData.PreviousLocations));

                await LogAuditAsync(
                    eventData.TriggeredBy ?? Guid.Empty, // 로그인 주체
                    "GEO_ANOMALY",
                    $"Geographical anomaly detected. New location: {eventData.NewLocation}",
                    eventData.TriggeredBy, // 이벤트 대상 사용자
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["NewLocation"] = eventData.NewLocation,
                        ["PreviousLocations"] = eventData.PreviousLocations,
                        ["RiskScore"] = eventData.RiskScore,
                        ["IpAddress"] = eventData.ClientIpAddress ?? "Unknown" // BaseEvent에서 가져옴
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.geo_anomaly", 1, cancellationToken); // CancellationToken 전달

                // 사용자에게 위치 확인 요청
                if (eventData.TriggeredBy.HasValue)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.TriggeredBy.Value,
                        "New Login Location Detected",
                        $"We detected a login from a new location: {eventData.NewLocation}. " +
                        $"If this wasn't you, please secure your account immediately.",
                        cancellationToken); // CancellationToken 전달
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle geographical anomaly event");
            }
        }

        /// <inheritdoc />
        public async Task HandleBruteForceAttackAsync(BruteForceAttackDetectedEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                _logger.LogCritical(
                    "BRUTE FORCE ATTACK detected from IP {IpAddress}. {AttemptsCount} attempts in {TimeWindow} minutes. Affected users: {Users}",
                    eventData.IpAddress, eventData.AttemptsCount, eventData.TimeWindow.TotalMinutes,
                    string.Join(", ", eventData.AffectedUsers));

                await LogAuditAsync(
                    Guid.Empty, // 시스템 감지
                    "BRUTE_FORCE_ATTACK",
                    $"Brute force attack detected from {eventData.IpAddress}. {eventData.AttemptsCount} attempts",
                    null, // 특정 사용자 없음
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["IpAddress"] = eventData.IpAddress,
                        ["AttemptsCount"] = eventData.AttemptsCount,
                        ["TimeWindow"] = eventData.TimeWindow.TotalMinutes,
                        ["ActionTaken"] = eventData.ActionTaken,
                        ["AffectedUsers"] = eventData.AffectedUsers
                    },
                    cancellationToken); // CancellationToken 전달

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.brute_force_attack", 1, cancellationToken); // CancellationToken 전달

                // IP 영구 차단 (24시간)
                if (!string.IsNullOrEmpty(eventData.IpAddress))
                {
                     var blockKey = $"auth:blocked:ip:{eventData.IpAddress}";
                    await _cacheService.SetAsync(blockKey, "brute_force_attack", TimeSpan.FromHours(24), cancellationToken); // CancellationToken 전달

                    _logger.LogCritical("IP {IpAddress} blocked for 24 hours due to brute force attack", eventData.IpAddress);
                }

                // 보안팀에 긴급 알림 (TODO: 실제 보안팀 알림 시스템 구현 필요)
                _logger.LogCritical(
                    "CRITICAL SECURITY ALERT: Brute Force Attack Detected. " +
                    "IP: {IpAddress}, Attempts: {AttemptsCount}, TimeWindow: {TimeWindow} minutes, " +
                    "Action: {ActionTaken}, AffectedUsers: {Users}",
                    eventData.IpAddress, eventData.AttemptsCount, eventData.TimeWindow.TotalMinutes,
                    eventData.ActionTaken, string.Join(", ", eventData.AffectedUsers));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle brute force attack event");
            }
        }

        #endregion

        #region Private Helper Methods - CancellationToken 추가

        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? userId,
            AuditEventSeverity severity,
            Dictionary<string, object>? metadata = null,
            CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = performedByConnectedId == Guid.Empty ? null : performedByConnectedId, // Empty 대신 null 사용 고려
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = DetermineActionType(action),
                    Action = action,
                    ResourceType = "Authentication", // 필요 시 더 구체화
                    ResourceId = userId?.ToString(),
                    Success = !action.Contains("FAILURE") && !action.Contains("LOCKED") && !action.Contains("ATTACK"), // Success 조건 명확화
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    Severity = severity,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = performedByConnectedId == Guid.Empty ? null : performedByConnectedId
                };

                await _auditRepository.AddAsync(auditLog, cancellationToken); // CancellationToken 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for action {Action}", action);
            }
        }

        private AuditActionType DetermineActionType(string action)
        {
            // ... (기존 switch 문 유지) ...
             return action switch
             {
                 "AUTH_SUCCESS" => AuditActionType.Login,
                 "AUTH_FAILURE" => AuditActionType.LoginAttempt,
                 "AUTH_ATTEMPT_SUCCESS" => AuditActionType.Login,
                 "AUTH_ATTEMPT_FAILURE" => AuditActionType.LoginAttempt,
                 "TOKEN_ISSUED" => AuditActionType.Create,
                 "TOKEN_REFRESHED" => AuditActionType.Update,
                 "TOKEN_REVOKED" => AuditActionType.Delete,
                 "MFA_REQUIRED" => AuditActionType.Read, // or LoginAttempt
                 "MFA_SUCCESS" => AuditActionType.Update, // or Login
                 "ACCOUNT_LOCKED" => AuditActionType.Update,
                 "ACCOUNT_UNLOCKED" => AuditActionType.Update,
                 "HIGH_RISK_AUTH" => AuditActionType.LoginAttempt,
                 "SUSPICIOUS_LOGIN" => AuditActionType.LoginAttempt,
                 "GEO_ANOMALY" => AuditActionType.LoginAttempt,
                 "BRUTE_FORCE_ATTACK" => AuditActionType.LoginAttempt,
                 _ => AuditActionType.Others
             };
        }

        private async Task<bool> IsNewLocationAsync(Guid userId, string? ipAddress, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                var recentLocationsKey = $"auth:locations:{userId}";
                // GetAsync에 CancellationToken 전달
                var recentLocationsJson = await _cacheService.GetAsync<string>(recentLocationsKey, cancellationToken);

                List<string>? recentLocations = null;
                if (!string.IsNullOrEmpty(recentLocationsJson))
                {
                     try { recentLocations = JsonSerializer.Deserialize<List<string>>(recentLocationsJson); }
                     catch { /* 파싱 실패 시 새 위치로 간주 */ }
                }

                bool isNew = recentLocations == null || !recentLocations.Contains(ipAddress);

                // 새 위치면 캐시 업데이트
                if(isNew)
                {
                    recentLocations ??= new List<string>();
                    recentLocations.Add(ipAddress);
                    // 최근 5개 위치만 저장 (예시)
                    if(recentLocations.Count > 5) recentLocations.RemoveAt(0);
                    // SetAsync에 CancellationToken 전달
                    await _cacheService.SetAsync(recentLocationsKey, JsonSerializer.Serialize(recentLocations), TimeSpan.FromDays(30), cancellationToken);
                }

                return isNew;
            }
            catch(OperationCanceledException) { throw; } // 취소 예외는 다시 던짐
            catch(Exception ex)
            {
                 _logger.LogError(ex, "Failed to check for new location for User {UserId}", userId);
                return false; // 오류 발생 시 새 위치 아님으로 간주 (안전)
            }
        }

        private async Task HandleRepeatedFailuresAsync(AuthenticationFailureEvent eventData, CancellationToken cancellationToken = default) // CancellationToken 추가
        {
            try
            {
                if (eventData.AttemptCount >= 5) // 임계값 설정
                {
                    _logger.LogWarning(
                        "Repeated authentication failures detected for {Username} from {IpAddress}. Implementing temporary block.",
                        eventData.Username, eventData.ClientIpAddress);

                    if (!string.IsNullOrEmpty(eventData.ClientIpAddress))
                    {
                        var blockKey = $"auth:blocked:ip:{eventData.ClientIpAddress}";
                        // SetAsync에 CancellationToken 전달
                        await _cacheService.SetAsync(blockKey, "blocked_repeated_failures", TimeSpan.FromMinutes(15), cancellationToken);
                    }

                    // IncrementAsync에 CancellationToken 전달
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.repeated_failures", 1, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle repeated failures");
            }
        }

        private bool IsSuspiciousRevocation(string revokeReason)
        {
            // ... (기존 로직 유지) ...
             var suspiciousReasons = new[]
             {
                 "security", "breach", "suspicious", "unauthorized", "compromised", "stolen"
             };

             var lowerReason = revokeReason?.ToLowerInvariant() ?? string.Empty;
             return Array.Exists(suspiciousReasons, reason => lowerReason.Contains(reason));
        }

        #endregion
    }
}