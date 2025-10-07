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

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 인증 이벤트 핸들러 구현 - AuthHive v16 (확장됨)
    /// 인증 관련 모든 이벤트를 처리하고 감사 로그, 알림, 캐시 무효화 등을 수행합니다.
    /// ✨ v16: 인증 시도 추적, 위험 평가, 이상 징후 감지 기능 추가
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

        #region 기존 메서드들 (v15)

        /// <inheritdoc />
        public async Task HandleAuthenticationSuccessAsync(AuthenticationSuccessEvent eventData)
        {
            try
            {
                _logger.LogInformation(
                    "Authentication success for User {UserId} via {AuthMethod} from {IpAddress}",
                    eventData.UserId, eventData.AuthMethod, eventData.IpAddress);

                await LogAuditAsync(
                    eventData.ConnectedId ?? Guid.Empty,
                    "AUTH_SUCCESS",
                    $"User authenticated successfully via {eventData.AuthMethod}",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["AuthMethod"] = eventData.AuthMethod,
                        ["IpAddress"] = eventData.IpAddress ?? "Unknown",
                        ["UserAgent"] = eventData.UserAgent ?? "Unknown",
                        ["AdditionalData"] = eventData.AdditionalData ?? new Dictionary<string, object>()
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.success.{eventData.AuthMethod.ToLower()}");

                var cacheKey = $"{CACHE_KEY_PREFIX}:{eventData.UserId}";
                await _cacheService.RemoveAsync(cacheKey);

                if (await IsNewLocationAsync(eventData.UserId, eventData.IpAddress))
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId,
                        "New Login Location",
                        $"Your account was accessed from a new location: {eventData.IpAddress}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication success event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAuthenticationFailureAsync(AuthenticationFailureEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "Authentication failure for {Username} via {AuthMethod} from {IpAddress}. Reason: {Reason}. Attempt: {AttemptCount}",
                    eventData.Username ?? "Unknown", eventData.AuthMethod, eventData.IpAddress,
                    eventData.FailureReason, eventData.AttemptCount);

                await LogAuditAsync(
                    Guid.Empty,
                    "AUTH_FAILURE",
                    $"Authentication failed: {eventData.FailureReason}",
                    null,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username ?? "Unknown",
                        ["AuthMethod"] = eventData.AuthMethod,
                        ["IpAddress"] = eventData.IpAddress ?? "Unknown",
                        ["AttemptCount"] = eventData.AttemptCount,
                        ["FailureReason"] = eventData.FailureReason
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.failure.{eventData.AuthMethod.ToLower()}");

                if (eventData.AttemptCount >= 3)
                {
                    await HandleRepeatedFailuresAsync(eventData);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication failure event");
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenIssuedAsync(TokenIssuedEvent eventData)
        {
            try
            {
                _logger.LogInformation(
                    "Token issued for User {UserId}. Type: {TokenType}, ID: {TokenId}, Expires: {ExpiresAt}",
                    eventData.UserId, eventData.TokenType, eventData.TokenId, eventData.ExpiresAt);

                await LogAuditAsync(
                    Guid.Empty,
                    "TOKEN_ISSUED",
                    $"{eventData.TokenType} token issued",
                    eventData.UserId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["TokenType"] = eventData.TokenType,
                        ["TokenId"] = eventData.TokenId,
                        ["ExpiresAt"] = eventData.ExpiresAt,
                        ["Scopes"] = eventData.Scopes ?? new List<string>()
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.issued.{eventData.TokenType.ToLower()}");

                var cacheKey = $"token:{eventData.TokenId}";
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
                    await _cacheService.SetAsync(cacheKey, JsonSerializer.Serialize(cacheData), ttl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token issued event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenRefreshedAsync(TokenRefreshedEvent eventData)
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
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.refreshed");

                var oldCacheKey = $"token:{eventData.OldTokenId}";
                await _cacheService.RemoveAsync(oldCacheKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token refreshed event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleTokenRevokedAsync(TokenRevokedEvent eventData)
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
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.revoked");

                var cacheKey = $"token:{eventData.TokenId}";
                await _cacheService.RemoveAsync(cacheKey);

                if (IsSuspiciousRevocation(eventData.RevokeReason))
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId,
                        "Token Revoked",
                        $"A token was revoked for security reasons: {eventData.RevokeReason}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle token revoked event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleMfaRequiredAsync(MfaRequiredEvent eventData)
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
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.mfa.required.{eventData.MfaMethod.ToLower()}");

                if (eventData.MfaMethod == "SMS" || eventData.MfaMethod == "Email")
                {
                    await _notificationService.SendMfaCodeAsync(eventData.UserId, eventData.MfaMethod);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle MFA required event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleMfaSuccessAsync(MfaSuccessEvent eventData)
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
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.mfa.success.{eventData.MfaMethod.ToLower()}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle MFA success event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAccountLockedAsync(AccountLockedEvent eventData)
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
                        ["LockedUntil"] = eventData.LockedUntil.ToString()
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.locked");

                var sessionPattern = $"{CACHE_KEY_PREFIX}:{eventData.UserId}:*";
                await _cacheService.RemoveByPatternAsync(sessionPattern);

                await _notificationService.SendAccountLockedNotificationAsync(
                    eventData.UserId,
                    eventData.Reason,
                    eventData.LockedUntil);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle account locked event for User {UserId}", eventData.UserId);
            }
        }

        /// <inheritdoc />
        public async Task HandleAccountUnlockedAsync(AccountUnlockedEvent eventData)
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
                        ["UnlockReason"] = eventData.UnlockReason
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.unlocked");

                await _notificationService.SendAccountUnlockedNotificationAsync(
                    eventData.UserId,
                    eventData.UnlockReason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle account unlocked event for User {UserId}", eventData.UserId);
            }
        }

        #endregion

        #region 신규 메서드들 (v16)

        /// <inheritdoc />
        public async Task HandleAuthenticationAttemptedAsync(AuthenticationAttemptedEvent eventData)
        {
            try
            {
                var logLevel = eventData.IsSuccess ? LogLevel.Information : LogLevel.Warning;
                _logger.Log(
                    logLevel,
                    "Authentication attempt for User {Username} via {Method} from {IpAddress}. Success: {Success}",
                    eventData.Username, eventData.Method, eventData.IpAddress, eventData.IsSuccess);

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
                        ["IpAddress"] = eventData.IpAddress,
                        ["UserAgent"] = eventData.UserAgent ?? "Unknown",
                        ["ApplicationId"] = eventData.ApplicationId?.ToString() ?? "N/A"
                    });

                var metricKey = eventData.IsSuccess 
                    ? $"{METRICS_PREFIX}.attempt.success.{eventData.Method.ToString().ToLower()}"
                    : $"{METRICS_PREFIX}.attempt.failure.{eventData.Method.ToString().ToLower()}";
                await _metricsService.IncrementAsync(metricKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle authentication attempted event");
            }
        }

        /// <inheritdoc />
        public async Task HandleHighRiskAuthenticationAsync(HighRiskAuthenticationEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "High-risk authentication for User {Username} from {IpAddress}. Risk Score: {RiskScore}, Level: {RiskLevel}",
                    eventData.Username, eventData.IpAddress, eventData.RiskScore, eventData.RiskLevel);

                await LogAuditAsync(
                    eventData.UserId ?? Guid.Empty,
                    "HIGH_RISK_AUTH",
                    $"High-risk authentication detected: {eventData.RiskLevel} (Score: {eventData.RiskScore})",
                    eventData.UserId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["IpAddress"] = eventData.IpAddress,
                        ["RiskScore"] = eventData.RiskScore,
                        ["RiskLevel"] = eventData.RiskLevel,
                        ["RiskFactors"] = eventData.RiskFactors,
                        ["RequiresMfa"] = eventData.RequiresMfa,
                        ["RequiresAdditionalVerification"] = eventData.RequiresAdditionalVerification
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.high_risk");

                // 고위험 인증 시 보안팀에 알림
                if (eventData.RiskScore >= 0.8)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId ?? Guid.Empty,
                        "High-Risk Authentication Detected",
                        $"A high-risk authentication was detected for {eventData.Username} from {eventData.IpAddress}. " +
                        $"Risk Score: {eventData.RiskScore:P0}. Factors: {string.Join(", ", eventData.RiskFactors)}");
                }

                // MFA 요구 시 사용자에게 알림
                if (eventData.RequiresMfa && eventData.UserId.HasValue)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.UserId.Value,
                        "MFA Required for Security",
                        "Due to unusual activity, multi-factor authentication is now required.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle high-risk authentication event");
            }
        }

        /// <inheritdoc />
        public async Task HandleSuspiciousLoginActivityAsync(SuspiciousLoginActivityEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "Suspicious login activity detected for {Username} from {IpAddress}. Risk Score: {RiskScore}. Patterns: {Patterns}",
                    eventData.Username, eventData.IpAddress, eventData.RiskScore, 
                    string.Join(", ", eventData.DetectedPatterns));

                await LogAuditAsync(
                    Guid.Empty,
                    "SUSPICIOUS_LOGIN",
                    $"Suspicious login activity detected. Patterns: {string.Join(", ", eventData.DetectedPatterns)}",
                    null,
                    eventData.RiskScore >= 80 ? AuditEventSeverity.Critical : AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Username"] = eventData.Username,
                        ["IpAddress"] = eventData.IpAddress,
                        ["DeviceFingerprint"] = eventData.DeviceFingerprint ?? "Unknown",
                        ["RiskScore"] = eventData.RiskScore,
                        ["DetectedPatterns"] = eventData.DetectedPatterns
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.suspicious_login");

                // 임시 IP 차단 (고위험 시)
                if (eventData.RiskScore >= 80)
                {
                    var blockKey = $"auth:blocked:ip:{eventData.IpAddress}";
                    await _cacheService.SetAsync(blockKey, "suspicious_activity", TimeSpan.FromMinutes(30));

                    _logger.LogWarning("Temporarily blocked IP {IpAddress} due to suspicious activity", eventData.IpAddress);
                }

                // 보안 알림 발송
                // Note: Username으로 실제 UserId를 찾아야 하지만, 여기서는 보안팀에 알림으로 대체
                _logger.LogWarning(
                    "Sending security alert for suspicious login: {Username} from {IpAddress}",
                    eventData.Username, eventData.IpAddress);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle suspicious login activity event");
            }
        }

        /// <inheritdoc />
        public async Task HandleGeographicalAnomalyAsync(GeographicalAnomalyDetectedEvent eventData)
        {
            try
            {
                _logger.LogWarning(
                    "Geographical anomaly detected for User {UserId}. New location: {NewLocation}. Previous: {PreviousLocations}",
                    eventData.TriggeredBy, eventData.NewLocation, string.Join(", ", eventData.PreviousLocations));

                await LogAuditAsync(
                    eventData.TriggeredBy ?? Guid.Empty,
                    "GEO_ANOMALY",
                    $"Geographical anomaly detected. New location: {eventData.NewLocation}",
                    eventData.TriggeredBy,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["NewLocation"] = eventData.NewLocation,
                        ["PreviousLocations"] = eventData.PreviousLocations,
                        ["RiskScore"] = eventData.RiskScore
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.geo_anomaly");

                // 사용자에게 위치 확인 요청
                if (eventData.TriggeredBy.HasValue)
                {
                    await _notificationService.SendSecurityAlertAsync(
                        eventData.TriggeredBy.Value,
                        "New Login Location Detected",
                        $"We detected a login from a new location: {eventData.NewLocation}. " +
                        $"If this wasn't you, please secure your account immediately.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle geographical anomaly event");
            }
        }

        /// <inheritdoc />
        public async Task HandleBruteForceAttackAsync(BruteForceAttackDetectedEvent eventData)
        {
            try
            {
                _logger.LogCritical(
                    "BRUTE FORCE ATTACK detected from IP {IpAddress}. {AttemptsCount} attempts in {TimeWindow} minutes. Affected users: {Users}",
                    eventData.IpAddress, eventData.AttemptsCount, eventData.TimeWindow.TotalMinutes,
                    string.Join(", ", eventData.AffectedUsers));

                await LogAuditAsync(
                    Guid.Empty,
                    "BRUTE_FORCE_ATTACK",
                    $"Brute force attack detected from {eventData.IpAddress}. {eventData.AttemptsCount} attempts",
                    null,
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["IpAddress"] = eventData.IpAddress,
                        ["AttemptsCount"] = eventData.AttemptsCount,
                        ["TimeWindow"] = eventData.TimeWindow.TotalMinutes,
                        ["ActionTaken"] = eventData.ActionTaken,
                        ["AffectedUsers"] = eventData.AffectedUsers
                    });

                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.brute_force_attack");

                // IP 영구 차단 (24시간)
                var blockKey = $"auth:blocked:ip:{eventData.IpAddress}";
                await _cacheService.SetAsync(blockKey, "brute_force_attack", TimeSpan.FromHours(24));

                _logger.LogCritical("IP {IpAddress} blocked for 24 hours due to brute force attack", eventData.IpAddress);

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

        #region Private Helper Methods

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
                    ResourceType = "Authentication",
                    ResourceId = userId?.ToString(),
                    Success = !action.Contains("FAILURE") && !action.Contains("LOCKED"),
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
                "AUTH_SUCCESS" => AuditActionType.Login,
                "AUTH_FAILURE" => AuditActionType.LoginAttempt,
                "AUTH_ATTEMPT_SUCCESS" => AuditActionType.Login,
                "AUTH_ATTEMPT_FAILURE" => AuditActionType.LoginAttempt,
                "TOKEN_ISSUED" => AuditActionType.Create,
                "TOKEN_REFRESHED" => AuditActionType.Update,
                "TOKEN_REVOKED" => AuditActionType.Delete,
                "MFA_REQUIRED" => AuditActionType.Read,
                "MFA_SUCCESS" => AuditActionType.Update,
                "ACCOUNT_LOCKED" => AuditActionType.Update,
                "ACCOUNT_UNLOCKED" => AuditActionType.Update,
                "HIGH_RISK_AUTH" => AuditActionType.LoginAttempt,
                "SUSPICIOUS_LOGIN" => AuditActionType.LoginAttempt,
                "GEO_ANOMALY" => AuditActionType.LoginAttempt,
                "BRUTE_FORCE_ATTACK" => AuditActionType.LoginAttempt,
                _ => AuditActionType.Others
            };
        }

        private async Task<bool> IsNewLocationAsync(Guid userId, string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                var recentLocationsKey = $"auth:locations:{userId}";
                var recentLocationsJson = await _cacheService.GetAsync<string>(recentLocationsKey);

                if (string.IsNullOrEmpty(recentLocationsJson))
                    return true;

                var recentLocations = JsonSerializer.Deserialize<List<string>>(recentLocationsJson);
                return !recentLocations?.Contains(ipAddress) ?? true;
            }
            catch
            {
                return false;
            }
        }

        private async Task HandleRepeatedFailuresAsync(AuthenticationFailureEvent eventData)
        {
            try
            {
                if (eventData.AttemptCount >= 5)
                {
                    _logger.LogWarning(
                        "Repeated authentication failures detected for {Username} from {IpAddress}. Implementing temporary block.",
                        eventData.Username, eventData.IpAddress);

                    if (!string.IsNullOrEmpty(eventData.IpAddress))
                    {
                        var blockKey = $"auth:blocked:ip:{eventData.IpAddress}";
                        await _cacheService.SetAsync(blockKey, "blocked", TimeSpan.FromMinutes(15));
                    }

                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.security.repeated_failures");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle repeated failures");
            }
        }

        private bool IsSuspiciousRevocation(string revokeReason)
        {
            var suspiciousReasons = new[]
            {
                "security",
                "breach",
                "suspicious",
                "unauthorized",
                "compromised",
                "stolen"
            };

            var lowerReason = revokeReason.ToLower();
            return Array.Exists(suspiciousReasons, reason => lowerReason.Contains(reason));
        }

        #endregion
    }
}