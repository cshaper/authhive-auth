using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Core.UserEnums;
using UserEntity = AuthHive.Core.Entities.User.User;
using Newtonsoft.Json;
using AuthHive.Core.Models.Auth.Settings;
using AuthHive.Core.Models.User.Events;
using AuthHive.Core.Models.Auth.Events;

namespace AuthHive.Auth.Services.User
{
    /// <summary>
    /// 사용자 인증 방법 서비스 구현체 - AuthHive v15
    /// </summary>
    public class UserAuthenticationMethodService : IUserAuthenticationMethodService
    {
        #region Dependencies

        private readonly IUserRepository _userRepository;
        private readonly IUserActivityLogRepository _activityLogRepository;
        private readonly IAuthenticationAttemptLogRepository _authAttemptRepository;
        private readonly IMfaService _mfaService;
        private readonly IMfaBypassTokenRepository _mfaBypassRepository;
        private readonly IEmailService _emailService;
        private readonly IDistributedCache _distributedCache;
        private readonly IMemoryCache _memoryCache;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserAuthenticationMethodService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly AuthenticationSettings _settings;
        private readonly ISecurityAnalyzer _securityAnalyzer;
        private readonly IAuditService _auditService;
        private readonly IEventHandler<UserEmailVerifiedEvent> _emailVerifiedEventHandler;
        private readonly IEventHandler<TwoFactorStatusChangedEvent> _twoFactorEventHandler;
        private readonly IEventHandler<UserLoggedInEvent> _loginEventHandler;

        #endregion

        #region Constructor

        public UserAuthenticationMethodService(
            IUserRepository userRepository,
            IUserActivityLogRepository activityLogRepository,
            IAuthenticationAttemptLogRepository authAttemptRepository,
            IMfaService mfaService,
            IMfaBypassTokenRepository mfaBypassRepository,
            IEmailService emailService,
            IDistributedCache distributedCache,
            IMemoryCache memoryCache,
            IUnitOfWork unitOfWork,
            ILogger<UserAuthenticationMethodService> logger,
            IHttpContextAccessor httpContextAccessor,
            IOptions<AuthenticationSettings> settings,
            ISecurityAnalyzer securityAnalyzer,
            IAuditService auditService,
            IEventHandler<UserEmailVerifiedEvent> emailVerifiedEventHandler,
            IEventHandler<TwoFactorStatusChangedEvent> twoFactorEventHandler,
            IEventHandler<UserLoggedInEvent> loginEventHandler)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _activityLogRepository = activityLogRepository ?? throw new ArgumentNullException(nameof(activityLogRepository));
            _authAttemptRepository = authAttemptRepository ?? throw new ArgumentNullException(nameof(authAttemptRepository));
            _mfaService = mfaService ?? throw new ArgumentNullException(nameof(mfaService));
            _mfaBypassRepository = mfaBypassRepository ?? throw new ArgumentNullException(nameof(mfaBypassRepository));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
            _settings = settings?.Value ?? throw new ArgumentNullException(nameof(settings));
            _securityAnalyzer = securityAnalyzer ?? throw new ArgumentNullException(nameof(securityAnalyzer));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _emailVerifiedEventHandler = emailVerifiedEventHandler ?? throw new ArgumentNullException(nameof(emailVerifiedEventHandler));
            _twoFactorEventHandler = twoFactorEventHandler ?? throw new ArgumentNullException(nameof(twoFactorEventHandler));
            _loginEventHandler = loginEventHandler ?? throw new ArgumentNullException(nameof(loginEventHandler));
        }

        #endregion

        #region Email Verification

        /// <summary>
        /// 이메일 주소 인증 처리
        /// </summary>
        public async Task<ServiceResult> VerifyEmailAsync(Guid id, string verificationToken)
        {
            try
            {
                // 1. 입력 검증
                if (id == Guid.Empty)
                {
                    return ServiceResult.Failure("Invalid user ID", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                if (string.IsNullOrWhiteSpace(verificationToken))
                {
                    return ServiceResult.Failure("Invalid verification token", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 2. Rate Limiting 체크
                var rateLimitKey = string.Format(AuthConstants.CacheKeys.FailedAttemptsPattern, $"email_verify:{id}");
                var attempts = await GetRateLimitCountAsync(rateLimitKey);
                if (attempts > AuthConstants.Security.MaxFailedLoginAttempts)
                {
                    await _auditService.LogSecurityEventAsync(
                        "EMAIL_VERIFICATION_RATE_LIMIT_EXCEEDED",
                        AuditEventSeverity.Warning,
                        "Too many verification attempts",
                        id,
                        new Dictionary<string, object> { ["attempts"] = attempts, ["ipAddress"] = GetClientIpAddress() });

                    return ServiceResult.Failure(
                        "Too many verification attempts. Please try again later.",
                        AuthConstants.ErrorCodes.RateLimitExceeded);
                }

                // 3. 사용자 조회
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    await IncrementRateLimitAsync(rateLimitKey);
                    return ServiceResult.Failure("User not found", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 4. 이미 인증된 경우 처리
                if (user.IsEmailVerified)
                {
                    return ServiceResult.Success("Email already verified");
                }

                // 5. 토큰 검증
                var expectedToken = await GetCachedVerificationTokenAsync(id);
                if (expectedToken == null || !SecureCompare(expectedToken, verificationToken))
                {
                    await IncrementRateLimitAsync(rateLimitKey);
                    await RecordFailedVerificationAttemptAsync(user, "Invalid token");

                    return ServiceResult.Failure(
                        "Invalid or expired verification token",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 6. 토큰 만료 시간 체크
                var tokenExpiry = await GetCachedTokenExpiryAsync(id);
                if (!tokenExpiry.HasValue || tokenExpiry < DateTime.UtcNow)
                {
                    await RemoveCachedVerificationTokenAsync(id);
                    return ServiceResult.Failure(
                        "Verification token has expired",
                        AuthConstants.ErrorCodes.SessionExpired);
                }

                // 7. 이메일 인증 처리
                user.IsEmailVerified = true;
                user.EmailVerifiedAt = DateTime.UtcNow;
                user.UpdatedAt = DateTime.UtcNow;

                // 8. 상태 변경 (Pending -> Active)
                if (user.Status == UserStatus.PendingVerification)
                {
                    user.Status = UserStatus.Active;
                }

                // 9. 데이터베이스 업데이트
                await _userRepository.UpdateAsync(user);
                await _unitOfWork.SaveChangesAsync();

                // 10. 캐시 정리
                await RemoveCachedVerificationTokenAsync(id);
                await ClearRateLimitAsync(rateLimitKey);

                // 11. 활동 로그 기록
                await LogUserActivityAsync(user.Id, "EmailVerified", true);

                // 12. 감사 로그
                await _auditService.LogActionAsync(
                    user.Id,
                    "EmailVerified",
                    AuditActionType.Update,
                    "User",
                    user.Id.ToString(),
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        email = user.Email,
                        verifiedAt = user.EmailVerifiedAt,
                        ipAddress = GetClientIpAddress(),
                        userAgent = GetUserAgent()
                    }));

                // 13. 이벤트 발행
                await _emailVerifiedEventHandler.HandleAsync(new UserEmailVerifiedEvent
                {
                    UserId = user.Id,
                    Email = user.Email,
                    VerifiedAt = user.EmailVerifiedAt.Value
                });

                // 14. 환영 이메일 발송
                await SendWelcomeEmailAsync(user);

                return ServiceResult.Success("Email successfully verified");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying email for user {UserId}", id);
                return ServiceResult.Failure(
                    "An error occurred while verifying your email",
                    "INTERNAL_ERROR");
            }
        }

        /// <summary>
        /// 이메일 인증 재전송
        /// </summary>
        public async Task<ServiceResult> ResendEmailVerificationAsync(Guid id)
        {
            try
            {
                // 1. 입력 검증
                if (id == Guid.Empty)
                {
                    return ServiceResult.Failure("Invalid user ID", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 2. Rate Limiting - 스팸 방지
                var lastResend = await GetLastResendTimeAsync(id);
                if (lastResend.HasValue && (DateTime.UtcNow - lastResend.Value).TotalMinutes < _settings.MinResendIntervalMinutes)
                {
                    var remainingMinutes = _settings.MinResendIntervalMinutes - (DateTime.UtcNow - lastResend.Value).TotalMinutes;
                    return ServiceResult.Failure(
                        $"Please wait {Math.Ceiling(remainingMinutes)} minutes before requesting another verification email",
                        AuthConstants.ErrorCodes.RateLimitExceeded);
                }

                // 3. 일일 재전송 한도 체크
                var dailyCount = await GetDailyResendCountAsync(id);
                if (dailyCount >= _settings.MaxDailyResends)
                {
                    return ServiceResult.Failure(
                        "Daily resend limit exceeded. Please try again tomorrow.",
                        AuthConstants.ErrorCodes.RateLimitExceeded);
                }

                // 4. 사용자 조회
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 5. 이미 인증된 경우
                if (user.IsEmailVerified)
                {
                    return ServiceResult.Success("Email is already verified");
                }

                // 6. 새 토큰 생성
                var newToken = GenerateSecureToken();
                var hashedToken = HashToken(newToken);
                var expiry = DateTime.UtcNow.AddHours(_settings.EmailVerificationTokenExpiryHours);

                // 7. 캐시에 토큰 저장
                await SetCachedVerificationTokenAsync(id, hashedToken, expiry);

                // 8. 이메일 발송 - SendVerificationEmailAsync 사용
                var emailResult = await _emailService.SendVerificationEmailAsync(
                    user.Email,
                    newToken,  // verificationCode
                    user.OrganizationId,  // organizationId
                    user.DisplayName ?? user.Email,  // userName
                    (int)(_settings.EmailVerificationTokenExpiryHours * 60)  // expirationMinutes
                );

                if (!emailResult.IsSuccess)
                {
                    return ServiceResult.Failure(
                        "Failed to send verification email",
                        "EMAIL_SEND_FAILED");
                }

                // 9. 재전송 시간 및 카운트 업데이트
                await SetLastResendTimeAsync(id);
                await IncrementDailyResendCountAsync(id);

                // 10. 활동 로그
                await LogUserActivityAsync(user.Id, "EmailVerificationResent", true);

                // 11. 감사 로그
                await _auditService.LogSecurityEventAsync(
                    "EmailVerificationResent",
                    AuditEventSeverity.Info,
                    $"Verification email resent to {user.Email}",
                    user.Id,
                    new Dictionary<string, object> { ["email"] = user.Email, ["expiry"] = expiry });

                return ServiceResult.Success($"Verification email sent to {user.Email}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resending verification email for user {UserId}", id);
                return ServiceResult.Failure(
                    "Failed to resend verification email",
                    "INTERNAL_ERROR");
            }
        }

        #endregion

        #region Two-Factor Authentication

        /// <summary>
        /// 2단계 인증 활성화/비활성화
        /// </summary>
        public async Task<ServiceResult> SetTwoFactorEnabledAsync(Guid id, bool enabled, string? verificationCode = null)
        {
            try
            {
                // 1. 입력 검증
                if (id == Guid.Empty)
                {
                    return ServiceResult.Failure("Invalid user ID", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 2. 사용자 조회
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 3. 이메일 인증 확인
                if (!user.IsEmailVerified)
                {
                    return ServiceResult.Failure(
                        "Please verify your email before enabling two-factor authentication",
                        "EMAIL_NOT_VERIFIED");
                }

                ServiceResult result;

                // 4. 활성화 처리
                if (enabled)
                {
                    // 이미 활성화된 경우
                    if (user.IsTwoFactorEnabled)
                    {
                        return ServiceResult.Success("Two-factor authentication is already enabled");
                    }

                    // 인증 코드 필수 확인
                    if (string.IsNullOrWhiteSpace(verificationCode))
                    {
                        return ServiceResult.Failure(
                            "Verification code is required to enable two-factor authentication",
                            AuthConstants.ErrorCodes.TwoFactorRequired);
                    }

                    // MFA 설정 생성
                    var mfaSetupResult = await _mfaService.EnableMfaAsync(
                        user.Id,
                        MfaMethod.Totp,
                        user.OrganizationId,
                        GetUserAgent());

                    if (!mfaSetupResult.IsSuccess || mfaSetupResult.Data == null)
                    {
                        await RecordFailedMfaAttemptAsync(user, "Failed to setup MFA");
                        return ServiceResult.Failure("Failed to enable two-factor authentication");
                    }

                    // MfaSetupResponse 활용
                    var setupData = mfaSetupResult.Data;

                    // 백업 코드 생성
                    var backupCodesResult = await _mfaService.GenerateBackupCodesAsync(user.Id, 10, false);
                    List<string> backupCodes = new();

                    if (backupCodesResult.IsSuccess && backupCodesResult.Data != null)
                    {
                        backupCodes = backupCodesResult.Data.Codes;
                        user.BackupCodes = backupCodes.Select(HashToken).ToList();
                    }

                    user.IsTwoFactorEnabled = true;
                    user.TwoFactorEnabledAt = DateTime.UtcNow;
                    user.TwoFactorMethod = "TOTP";

                    // 백업 코드를 반환 데이터에 포함
                    result = ServiceResult.Success("Two-factor authentication enabled successfully");
                    result.Metadata = new Dictionary<string, object>
                    {
                        ["backupCodes"] = backupCodes,
                        ["qrCodeUrl"] = setupData.QrCodeUrl ?? "",
                        ["warning"] = "Save these backup codes in a secure location. They will not be shown again."
                    };

                    // 보안 알림 이메일 발송
                    await SendSecurityAlertEmailAsync(user, SecurityAlertType.UnusualLogin, "Two-factor authentication enabled");
                }
                else
                {
                    // 비활성화 처리
                    if (!user.IsTwoFactorEnabled)
                    {
                        return ServiceResult.Success("Two-factor authentication is already disabled");
                    }

                    // 비활성화도 인증 코드 확인
                    if (string.IsNullOrWhiteSpace(verificationCode))
                    {
                        return ServiceResult.Failure(
                            "Verification code is required to disable two-factor authentication",
                            AuthConstants.ErrorCodes.TwoFactorRequired);
                    }

                    // MFA 코드 검증
                    var verifyResult = await _mfaService.VerifyMfaCodeAsync(
                        user.Id,
                        verificationCode,
                        MfaMethod.Totp);

                    if (!verifyResult.IsSuccess)
                    {
                        await RecordFailedMfaAttemptAsync(user, "Invalid verification code for disable");
                        return ServiceResult.Failure("Invalid verification code");
                    }

                    // MFA 비활성화
                    user.IsTwoFactorEnabled = false;
                    user.TwoFactorMethod = null;
                    user.BackupCodes.Clear();

                    await _mfaService.DisableMfaAsync(user.Id, MfaMethod.Totp, verificationCode);

                    // 보안 알림 이메일 발송
                    await SendSecurityAlertEmailAsync(user, SecurityAlertType.AccountLocked, "Two-factor authentication disabled");

                    result = ServiceResult.Success("Two-factor authentication disabled successfully");
                }

                // 5. 데이터베이스 업데이트
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(user);
                await _unitOfWork.SaveChangesAsync();

                // 6. 캐시 무효화
                await InvalidateUserCacheAsync(user.Id);

                // 7. 활동 로그
                await LogUserActivityAsync(
                    user.Id,
                    enabled ? "TwoFactorEnabled" : "TwoFactorDisabled",
                    true);

                // 8. 감사 로그
                await _auditService.LogSecurityEventAsync(
                    enabled ? "TWO_FACTOR_ENABLED" : "TWO_FACTOR_DISABLED",
                    AuditEventSeverity.Warning,
                    $"Two-factor authentication {(enabled ? "enabled" : "disabled")} for user",
                    user.Id,
                    new Dictionary<string, object> { ["ipAddress"] = GetClientIpAddress(), ["userAgent"] = GetUserAgent() });

                // 9. 이벤트 발행
                await _twoFactorEventHandler.HandleAsync(new TwoFactorStatusChangedEvent
                {
                    UserId = user.Id,
                    Enabled = enabled,
                    ChangedAt = DateTime.UtcNow
                });

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting two-factor authentication for user {UserId}", id);
                return ServiceResult.Failure(
                    "Failed to update two-factor authentication settings",
                    "INTERNAL_ERROR");
            }
        }

        #endregion

        #region Login Recording

        /// <summary>
        /// 로그인 기록
        /// </summary>
        public async Task<ServiceResult> RecordLoginAsync(Guid id, LoginInfoRequest loginInfo)
        {
            try
            {
                // 1. 입력 검증
                if (id == Guid.Empty)
                {
                    return ServiceResult.Failure("Invalid user ID", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                if (loginInfo == null)
                {
                    return ServiceResult.Failure("Login info is required", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 2. 사용자 조회
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found", AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 3. IP 주소 보완
                var ipAddress = !string.IsNullOrWhiteSpace(loginInfo.IpAddress)
                    ? loginInfo.IpAddress
                    : GetClientIpAddress();

                // 4. User Agent 보완
                var userAgent = !string.IsNullOrWhiteSpace(loginInfo.UserAgent)
                    ? loginInfo.UserAgent
                    : GetUserAgent();

                // 5. 보안 이상 징후 감지
                var anomalyResult = await _securityAnalyzer.DetectLoginAnomalyAsync(
                    user.Id,
                    ipAddress,
                    userAgent,
                    loginInfo.LoginTime);

                if (anomalyResult.AnomalyDetected && anomalyResult.AnomalyScore > 0.7)
                {
                    // 고위험 감지 시 추가 인증 요구
                    await _auditService.LogSecurityEventAsync(
                        "HIGH_RISK_LOGIN_DETECTED",
                        AuditEventSeverity.Warning,
                        "Suspicious login detected",
                        user.Id,
                        new Dictionary<string, object>
                        {
                            ["ipAddress"] = ipAddress,
                            ["userAgent"] = userAgent,
                            ["anomalyScore"] = anomalyResult.AnomalyScore,
                            ["confidenceScore"] = anomalyResult.ConfidenceScore
                        });

                    // MFA 요구 여부 확인
                    var requiresMfa = await _securityAnalyzer.RequiresMfaAsync(
                        user.Id,
                        ipAddress,
                        (int)(anomalyResult.AnomalyScore * 100));

                    if (requiresMfa || anomalyResult.RequireAdditionalVerification)
                    {
                        return ServiceResult.Failure(
                            "Additional verification required due to unusual activity",
                            AuthConstants.ErrorCodes.TwoFactorRequired);
                    }
                }

                // 6. 인증 시도 기록
                var authAttempt = new AuthenticationAttemptLog
                {
                    UserId = user.Id,
                    Method = AuthenticationMethod.Password,
                    IsSuccess = true,
                    AttemptedAt = loginInfo.LoginTime,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    RiskScore = (int)(anomalyResult.AnomalyScore * 100),
                    SessionId = Guid.NewGuid(),
                    Location = await GetLocationFromIpAsync(ipAddress),  // Location 속성 직접 설정
                    DeviceId = await GenerateDeviceFingerprintAsync(userAgent, ipAddress)  // DeviceId에 fingerprint 저장
                };

                await _authAttemptRepository.AddAsync(authAttempt);

                // 7. 사용자 정보 업데이트
                user.LastLoginAt = loginInfo.LoginTime;
                user.LastLoginIp = ipAddress;
                user.LastActivity = loginInfo.LoginTime;
                user.LoginCount = (user.LoginCount ?? 0) + 1;

                // 8. 첫 로그인 기록
                if (!user.FirstLoginAt.HasValue)
                {
                    user.FirstLoginAt = loginInfo.LoginTime;
                }

                // 9. 연속 로그인 일수 계산
                await UpdateConsecutiveLoginDaysAsync(user);

                // 10. 데이터베이스 업데이트
                await _userRepository.UpdateAsync(user);
                await _unitOfWork.SaveChangesAsync();

                // 11. 활동 로그 기록
                await LogUserActivityAsync(user.Id, "Login", true, new
                {
                    ipAddress,
                    userAgent,
                    anomalyScore = anomalyResult.AnomalyScore
                });

                // 12. 로그인 통계 업데이트
                await UpdateLoginStatisticsAsync(user.Id, ipAddress);

                // 13. 새 위치에서의 로그인 알림
                if (await IsNewLocationAsync(user.Id, ipAddress))
                {
                    await SendNewLocationAlertAsync(user, ipAddress);
                }

                // 14. 이벤트 발행
                await _loginEventHandler.HandleAsync(new UserLoggedInEvent
                {
                    UserId = user.Id,
                    LoggedInAt = loginInfo.LoginTime,
                    IPAddress = ipAddress,
                    UserAgent = userAgent,
                    IsFirstLogin = user.LoginCount == 1
                });

                return ServiceResult.Success("Login recorded successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recording login for user {UserId}", id);
                return ServiceResult.Failure(
                    "Failed to record login",
                    "INTERNAL_ERROR");
            }
        }

        #endregion

        #region Helper Methods

        private bool SecureCompare(string a, string b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            uint diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        private string GenerateSecureToken()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private string GetClientIpAddress()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
                return "127.0.0.1";

            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(realIp))
            {
                return realIp;
            }

            return httpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        }

        private string GetUserAgent()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            return httpContext?.Request.Headers["User-Agent"].FirstOrDefault() ?? "Unknown";
        }

        private async Task LogUserActivityAsync(Guid userId, string activityType, bool isSuccessful, object? additionalData = null)
        {
            try
            {
                var connectedId = await GetOrCreateConnectedIdAsync(userId);

                var activity = new UserActivityLog
                {
                    ConnectedId = connectedId,
                    ActivityType = ParseActivityType(activityType),
                    IsSuccessful = isSuccessful,
                    Timestamp = DateTime.UtcNow,
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    Metadata = additionalData != null ? JsonConvert.SerializeObject(additionalData) : null
                };

                await _activityLogRepository.AddAsync(activity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log user activity for user {UserId}", userId);
            }
        }

        private UserActivityType ParseActivityType(string activityType)
        {
            return activityType switch
            {
                "Login" => UserActivityType.Login,
                "EmailVerified" => UserActivityType.DataModification,
                "EmailVerificationResent" => UserActivityType.DataModification,
                "TwoFactorEnabled" => UserActivityType.SettingsChange,
                "TwoFactorDisabled" => UserActivityType.SettingsChange,
                _ => UserActivityType.ApiCall
            };
        }

        private async Task<Guid> GetOrCreateConnectedIdAsync(Guid userId)
        {
            // 실제 구현에서는 ConnectedId 서비스를 통해 가져와야 함
            return await Task.FromResult(userId);
        }

        private async Task<string> GenerateDeviceFingerprintAsync(string userAgent, string ipAddress)
        {
            var fingerprint = $"{userAgent}:{ipAddress}";
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(fingerprint);
            var hash = sha256.ComputeHash(bytes);
            return await Task.FromResult(Convert.ToBase64String(hash));
        }

        private async Task<string> GetLocationFromIpAsync(string ipAddress)
        {
            return await Task.FromResult("Unknown Location");
        }

        private async Task UpdateConsecutiveLoginDaysAsync(UserEntity user)
        {
            var lastLoginDate = user.LastLoginAt?.Date ?? DateTime.MinValue;
            var todayDate = DateTime.UtcNow.Date;

            if (lastLoginDate == todayDate.AddDays(-1))
            {
                user.ConsecutiveLoginDays = (user.ConsecutiveLoginDays ?? 0) + 1;
            }
            else if (lastLoginDate < todayDate.AddDays(-1))
            {
                user.ConsecutiveLoginDays = 1;
            }

            await Task.CompletedTask;
        }

        private async Task<bool> IsNewLocationAsync(Guid userId, string ipAddress)
        {
            var cacheKey = $"user:locations:{userId}";
            var locations = await _distributedCache.GetStringAsync(cacheKey);

            if (string.IsNullOrEmpty(locations))
            {
                var locationList = new List<string> { ipAddress };
                await _distributedCache.SetStringAsync(cacheKey, JsonConvert.SerializeObject(locationList),
                    new DistributedCacheEntryOptions
                    {
                        SlidingExpiration = TimeSpan.FromDays(30)
                    });
                return true;
            }

            var existingLocations = JsonConvert.DeserializeObject<List<string>>(locations);
            if (existingLocations != null && !existingLocations.Contains(ipAddress))
            {
                existingLocations.Add(ipAddress);
                await _distributedCache.SetStringAsync(cacheKey, JsonConvert.SerializeObject(existingLocations),
                    new DistributedCacheEntryOptions
                    {
                        SlidingExpiration = TimeSpan.FromDays(30)
                    });
                return true;
            }

            return false;
        }

        private async Task UpdateLoginStatisticsAsync(Guid userId, string ipAddress)
        {
            var hour = DateTime.UtcNow.Hour;
            var statKey = $"security:stats:{userId}:hour:{hour}";

            var count = await GetRateLimitCountAsync(statKey);
            await _distributedCache.SetStringAsync(statKey, (count + 1).ToString(),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24)
                });
        }

        #endregion

        #region Cache Management

        private async Task<string?> GetCachedVerificationTokenAsync(Guid userId)
        {
            var key = $"2fa:verify:{userId}";
            return await _distributedCache.GetStringAsync(key);
        }

        private async Task SetCachedVerificationTokenAsync(Guid userId, string token, DateTime expiry)
        {
            var key = $"2fa:verify:{userId}";
            var expiryKey = $"2fa:verify_expiry:{userId}";

            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = expiry,
                SlidingExpiration = TimeSpan.FromSeconds(300)
            };

            await _distributedCache.SetStringAsync(key, token, options);
            await _distributedCache.SetStringAsync(expiryKey, expiry.ToString("O"), options);
        }

        private async Task<DateTime?> GetCachedTokenExpiryAsync(Guid userId)
        {
            var key = $"2fa:verify_expiry:{userId}";
            var value = await _distributedCache.GetStringAsync(key);

            if (DateTime.TryParse(value, out var expiry))
                return expiry;

            return null;
        }

        private async Task RemoveCachedVerificationTokenAsync(Guid userId)
        {
            await _distributedCache.RemoveAsync($"2fa:verify:{userId}");
            await _distributedCache.RemoveAsync($"2fa:verify_expiry:{userId}");
        }

        private async Task InvalidateUserCacheAsync(Guid userId)
        {
            var keys = new[]
            {
                $"user:{userId}",
                $"user:profile:{userId}",
                $"permissions:{userId}",
                $"roles:{userId}"
            };

            foreach (var key in keys)
            {
                await _distributedCache.RemoveAsync(key);
            }
        }

        #endregion

        #region Rate Limiting

        private async Task<int> GetRateLimitCountAsync(string key)
        {
            var value = await _distributedCache.GetStringAsync(key);
            return int.TryParse(value, out var count) ? count : 0;
        }

        private async Task IncrementRateLimitAsync(string key)
        {
            var count = await GetRateLimitCountAsync(key);
            await _distributedCache.SetStringAsync(key, (count + 1).ToString(),
                new DistributedCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromMinutes(15)
                });
        }

        private async Task ClearRateLimitAsync(string key)
        {
            await _distributedCache.RemoveAsync(key);
        }

        private async Task<DateTime?> GetLastResendTimeAsync(Guid userId)
        {
            var key = $"security:last_resend:{userId}";
            var value = await _distributedCache.GetStringAsync(key);

            if (DateTime.TryParse(value, out var time))
                return time;

            return null;
        }

        private async Task SetLastResendTimeAsync(Guid userId)
        {
            var key = $"security:last_resend:{userId}";
            await _distributedCache.SetStringAsync(key, DateTime.UtcNow.ToString("O"),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24)
                });
        }

        private async Task<int> GetDailyResendCountAsync(Guid userId)
        {
            var key = $"security:daily_resend:{userId}:{DateTime.UtcNow:yyyy-MM-dd}";
            var value = await _distributedCache.GetStringAsync(key);
            return int.TryParse(value, out var count) ? count : 0;
        }

        private async Task IncrementDailyResendCountAsync(Guid userId)
        {
            var key = $"security:daily_resend:{userId}:{DateTime.UtcNow:yyyy-MM-dd}";
            var count = await GetDailyResendCountAsync(userId);
            await _distributedCache.SetStringAsync(key, (count + 1).ToString(),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1)
                });
        }

        #endregion

        #region Email Notifications

        private async Task SendWelcomeEmailAsync(UserEntity user)
        {
            try
            {
                var result = await _emailService.SendWelcomeEmailAsync(
                    user.Email,
                    user.DisplayName ?? user.Email,
                    user.OrganizationId ?? Guid.Empty);

                if (!result.IsSuccess)
                {
                    _logger.LogWarning("Failed to send welcome email: {Error}", result.Message);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email);
            }
        }

        private async Task SendSecurityAlertEmailAsync(UserEntity user, SecurityAlertType alertType, string action)
        {
            try
            {
                var result = await _emailService.SendSecurityAlertEmailAsync(
                    user.Email,
                    alertType,
                    new Dictionary<string, string>
                    {
                        ["action"] = action,
                        ["timestamp"] = DateTime.UtcNow.ToString("f"),
                        ["ipAddress"] = GetClientIpAddress(),
                        ["userAgent"] = GetUserAgent()
                    },
                    user.Id);

                if (!result.IsSuccess)
                {
                    _logger.LogWarning("Failed to send security alert: {Error}", result.Message);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send security alert email to {Email}", user.Email);
            }
        }

        private async Task SendNewLocationAlertAsync(UserEntity user, string ipAddress)
        {
            try
            {
                var result = await _emailService.SendSecurityAlertEmailAsync(
                    user.Email,
                    SecurityAlertType.NewDeviceLogin,
                    new Dictionary<string, string>
                    {
                        ["location"] = await GetLocationFromIpAsync(ipAddress),
                        ["ipAddress"] = ipAddress,
                        ["timestamp"] = DateTime.UtcNow.ToString("f"),
                        ["device"] = GetUserAgent()
                    },
                    user.Id);

                if (!result.IsSuccess)
                {
                    _logger.LogWarning("Failed to send new location alert: {Error}", result.Message);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send new location alert to {Email}", user.Email);
            }
        }

        #endregion

        #region Failed Attempt Recording

        private async Task RecordFailedVerificationAttemptAsync(UserEntity user, string reason)
        {
            var attempt = new AuthenticationAttemptLog
            {
                UserId = user.Id,
                Method = AuthenticationMethod.Password,
                IsSuccess = false,
                FailureReason = AuthenticationResult.InvalidCredentials,  // 이메일 인증 실패
                AttemptedAt = DateTime.UtcNow,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };

            await _authAttemptRepository.AddAsync(attempt);
        }

        private async Task RecordFailedMfaAttemptAsync(UserEntity user, string reason)
        {
            var attempt = new AuthenticationAttemptLog
            {
                UserId = user.Id,
                Method = AuthenticationMethod.TwoFactor,
                IsSuccess = false,
                FailureReason = AuthenticationResult.MfaFailed,  // MFA 실패에 적합한 값
                AttemptedAt = DateTime.UtcNow,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };

            await _authAttemptRepository.AddAsync(attempt);
        }

        #endregion
    }

    #region Supporting Classes



    #endregion

    #region Extension Methods for AuthenticationAttemptLog


    #endregion
}