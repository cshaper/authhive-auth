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

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 인증 이벤트 핸들러 구현 - AuthHive v15
    /// 인증 관련 모든 이벤트를 처리하고 감사 로그, 알림, 캐시 무효화 등을 수행합니다.
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

        /// <inheritdoc />
        public async Task HandleAuthenticationSuccessAsync(AuthenticationSuccessEvent eventData)
        {
            try
            {
                _logger.LogInformation(
                    "Authentication success for User {UserId} via {AuthMethod} from {IpAddress}",
                    eventData.UserId, eventData.AuthMethod, eventData.IpAddress);

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.success.{eventData.AuthMethod.ToLower()}");

                // 3. 캐시 무효화 (이전 세션 데이터)
                var cacheKey = $"{CACHE_KEY_PREFIX}:{eventData.UserId}";
                await _cacheService.RemoveAsync(cacheKey);

                // 4. 성공 알림 (선택적 - 새로운 위치에서 로그인 시)
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
                // 이벤트 처리 실패는 인증 자체를 실패시키지 않음
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.failure.{eventData.AuthMethod.ToLower()}");
                
                // 3. 반복 실패 감지 및 대응
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.issued.{eventData.TokenType.ToLower()}");

                // 3. 토큰 정보 캐싱 (빠른 검증을 위해)
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.refreshed");

                // 3. 이전 토큰 캐시 무효화
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.token.revoked");

                // 3. 토큰 캐시 즉시 무효화
                var cacheKey = $"token:{eventData.TokenId}";
                await _cacheService.RemoveAsync(cacheKey);

                // 4. 보안 알림 (의심스러운 활동인 경우)
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.mfa.required.{eventData.MfaMethod.ToLower()}");

                // 3. MFA 알림 발송 (SMS, Email 등)
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
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
                    eventData.UserId, eventData.LockReason, eventData.LockedUntil);

                // 1. 감사 로그 기록
                await LogAuditAsync(
                    Guid.Empty,
                    "ACCOUNT_LOCKED",
                    $"Account locked: {eventData.LockReason}",
                    eventData.UserId,
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["LockReason"] = eventData.LockReason,
                        ["LockedUntil"] = eventData.LockedUntil?.ToString() ?? "Indefinite"
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.locked");

                // 3. 모든 활성 세션 무효화
                var sessionPattern = $"{CACHE_KEY_PREFIX}:{eventData.UserId}:*";
                await _cacheService.RemoveByPatternAsync(sessionPattern);

                // 4. 계정 잠금 알림 발송
                await _notificationService.SendAccountLockedNotificationAsync(
                    eventData.UserId,
                    eventData.LockReason,
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

                // 1. 감사 로그 기록
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

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.account.unlocked");

                // 3. 계정 잠금 해제 알림 발송
                await _notificationService.SendAccountUnlockedNotificationAsync(
                    eventData.UserId,
                    eventData.UnlockReason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle account unlocked event for User {UserId}", eventData.UserId);
            }
        }

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
                "TOKEN_ISSUED" => AuditActionType.Create,
                "TOKEN_REFRESHED" => AuditActionType.Update,
                "TOKEN_REVOKED" => AuditActionType.Delete,
                "MFA_REQUIRED" => AuditActionType.Read,
                "MFA_SUCCESS" => AuditActionType.Update,
                "ACCOUNT_LOCKED" => AuditActionType.Update,
                "ACCOUNT_UNLOCKED" => AuditActionType.Update,
                _ => AuditActionType.Others
            };
        }

        private async Task<bool> IsNewLocationAsync(Guid userId, string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                // 캐시에서 최근 로그인 위치 확인
                var recentLocationsKey = $"auth:locations:{userId}";
                var recentLocationsJson = await _cacheService.GetAsync<string>(recentLocationsKey);
                
                if (string.IsNullOrEmpty(recentLocationsJson))
                    return true; // 첫 로그인

                var recentLocations = JsonSerializer.Deserialize<List<string>>(recentLocationsJson);
                return !recentLocations?.Contains(ipAddress) ?? true;
            }
            catch
            {
                return false; // 오류 시 새 위치로 간주하지 않음
            }
        }

        private async Task HandleRepeatedFailuresAsync(AuthenticationFailureEvent eventData)
        {
            try
            {
                // 5번 이상 실패 시 임시 차단
                if (eventData.AttemptCount >= 5)
                {
                    _logger.LogWarning(
                        "Repeated authentication failures detected for {Username} from {IpAddress}. Implementing temporary block.",
                        eventData.Username, eventData.IpAddress);

                    // IP 기반 임시 차단 (15분)
                    if (!string.IsNullOrEmpty(eventData.IpAddress))
                    {
                        var blockKey = $"auth:blocked:ip:{eventData.IpAddress}";
                        await _cacheService.SetAsync(blockKey, "blocked", TimeSpan.FromMinutes(15));
                    }

                    // 메트릭 기록
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