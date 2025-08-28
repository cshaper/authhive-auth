// Path: AuthHive.Auth/Services/Authentication/AuthenticationAttemptService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.User.Repository;
using Org.BouncyCastle.Crypto.Generators;
using BCrypt.Net;
using UserEntity = AuthHive.Core.Entities.User.User;
using static AuthHive.Core.Enums.Auth.SessionEnums;
namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 시도 관리 서비스 구현 - AuthHive v15
    /// </summary>
    public class AuthenticationAttemptService : IAuthenticationAttemptService
    {
        private readonly IAuthenticationAttemptLogRepository _attemptLogRepository;
        private readonly IUserRepository _userRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationAttemptService> _logger;

        // 설정값
        private readonly int _maxFailedAttempts;
        private readonly int _lockoutDurationMinutes;
        private readonly int _bruteForceThreshold;
        private readonly int _riskScoreThreshold;

        // 캐시 키
        private const string BLOCKED_IP_PREFIX = "blocked_ip:";
        private const string TRUSTED_IP_PREFIX = "trusted_ip:";
        private const string USER_LOCK_PREFIX = "user_lock:";

        public AuthenticationAttemptService(
            IAuthenticationAttemptLogRepository attemptLogRepository,
            IUserRepository userRepository,
            ISessionRepository sessionRepository,
            IMemoryCache cache,
            IConfiguration configuration,
            ILogger<AuthenticationAttemptService> logger)
        {
            _attemptLogRepository = attemptLogRepository;
            _userRepository = userRepository;
            _sessionRepository = sessionRepository;
            _cache = cache;
            _configuration = configuration;
            _logger = logger;

            // 설정 로드
            _maxFailedAttempts = configuration.GetValue<int>("Auth:Security:MaxFailedAttempts", 5);
            _lockoutDurationMinutes = configuration.GetValue<int>("Auth:Security:LockoutDurationMinutes", 30);
            _bruteForceThreshold = configuration.GetValue<int>("Auth:Security:BruteForceThreshold", 10);
            _riskScoreThreshold = configuration.GetValue<int>("Auth:Security:RiskScoreThreshold", 70);
        }

        #region 인증 시도 기록

        /// <summary>
        /// 인증 시도 기록
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> LogAuthenticationAttemptAsync(
            AuthenticationRequest request)
        {
            try
            {
                // IP 차단 확인
                if (IsIpBlocked(request.IpAddress))
                {
                    return ServiceResult<AuthenticationResponse>.Failure("IP address is blocked");
                }

                var attemptLog = new AuthenticationAttemptLog
                {
                    Username = request.Username,
                    Method = request.Method,
                    ApplicationId = request.ApplicationId,
                    OrganizationId = request.OrganizationId ?? Guid.Empty,
                    IpAddress = request.IpAddress ?? "unknown",
                    UserAgent = request.UserAgent,
                    AttemptedAt = DateTime.UtcNow,
                    Provider = request.Provider,
                    DeviceId = request.DeviceInfo?.DeviceId,
                    DeviceType = request.DeviceInfo?.DeviceType,
                    Location = request.DeviceInfo?.Location
                };

                // 기본적인 인증 로직은 다른 서비스에서 처리한다고 가정
                // 여기서는 로그 기록만 담당

                await _attemptLogRepository.AddAsync(attemptLog);

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = attemptLog.IsSuccess,
                    UserId = attemptLog.UserId,
                    ConnectedId = attemptLog.ConnectedId
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging authentication attempt");
                return ServiceResult<AuthenticationResponse>.Failure("Failed to log authentication attempt");
            }
        }

        /// <summary>
        /// 성공한 인증 기록
        /// </summary>
        public async Task<ServiceResult> LogSuccessfulAuthenticationAsync(
            Guid userId,
            Guid? connectedId,
            AuthenticationMethod method,
            string ipAddress,
            string? userAgent = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found");
                }

                var attemptLog = new AuthenticationAttemptLog
                {
                    UserId = userId,
                    ConnectedId = connectedId,
                    Username = user.Username,
                    Method = method,
                    IsSuccess = true,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty
                };

                await _attemptLogRepository.AddAsync(attemptLog);

                // 연속 실패 카운터 리셋
                ClearFailureCounter(userId);

                _logger.LogInformation("Successful authentication logged for user {UserId}", userId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging successful authentication for user {UserId}", userId);
                return ServiceResult.Failure("Failed to log successful authentication");
            }
        }

        /// <summary>
        /// 실패한 인증 기록
        /// </summary>
        public async Task<ServiceResult> LogFailedAuthenticationAsync(
            string identifier,
            AuthenticationMethod method,
            AuthenticationResult reason,
            string ipAddress,
            string? userAgent = null)
        {
            try
            {
                // 사용자 찾기 (선택적)
                // 1. userId 변수 선언
                Guid? userId = await _userRepository.FindByUsernameOrEmailAsync(identifier);
                UserEntity? user = null;
                // 2. userId가 있으면 user 조회
                if (userId.HasValue)
                {
                    user = await _userRepository.GetByIdAsync(userId.Value);
                }
                var attemptLog = new AuthenticationAttemptLog
                {
                    UserId = userId,
                    Username = identifier,
                    Method = method,
                    IsSuccess = false,
                    FailureReason = reason,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user?.OrganizationId ?? Guid.Empty
                };

                // 연속 실패 횟수 계산
                if (user != null)
                {
                    attemptLog.ConsecutiveFailures = await _attemptLogRepository.GetConsecutiveFailureCountAsync(user.Id) + 1;

                    // 계정 잠금 체크
                    if (attemptLog.ConsecutiveFailures >= _maxFailedAttempts)
                    {
                        attemptLog.TriggeredAccountLock = true;
                        await LockAccountAsync(user.Id, TimeSpan.FromMinutes(_lockoutDurationMinutes), "Too many failed attempts");
                    }
                }

                // 위험도 평가
                attemptLog.RiskScore = await CalculateRiskScoreAsync(ipAddress, user?.Id);
                attemptLog.IsSuspicious = attemptLog.RiskScore > _riskScoreThreshold;

                await _attemptLogRepository.AddAsync(attemptLog);

                _logger.LogWarning("Failed authentication attempt for {Identifier} from {IpAddress}", identifier, ipAddress);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging failed authentication");
                return ServiceResult.Failure("Failed to log failed authentication");
            }
        }

        /// <summary>
        /// MFA 인증 시도 기록
        /// </summary>
        public async Task<ServiceResult<MfaChallengeResponse>> LogMfaAttemptAsync(
            Guid userId,
            TwoFactorMethod method,
            bool isSuccess,
            string? failureReason = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<MfaChallengeResponse>.Failure("User not found");
                }

                var attemptLog = new AuthenticationAttemptLog
                {
                    UserId = userId,
                    Username = user.Username,
                    Method = AuthenticationMethod.TwoFactor,
                    IsSuccess = isSuccess,
                    MfaRequired = true,
                    MfaCompleted = isSuccess,
                    FailureMessage = failureReason,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty
                };

                await _attemptLogRepository.AddAsync(attemptLog);

                var response = new MfaChallengeResponse
                {
                    ChallengeId = Guid.NewGuid(),
                    Method = method.ToString(),
                    ChallengeType = isSuccess ? "completed" : "failed",
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                    AttemptsRemaining = _maxFailedAttempts - (attemptLog?.ConsecutiveFailures ?? 0)
                };

                return ServiceResult<MfaChallengeResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging MFA attempt for user {UserId}", userId);
                return ServiceResult<MfaChallengeResponse>.Failure("Failed to log MFA attempt");
            }
        }

        #endregion

        #region 계정 잠금 관리

        /// <summary>
        /// 계정 잠금 상태 확인
        /// </summary>
        public async Task<ServiceResult<AccountLockStatus>> CheckAccountLockStatusAsync(Guid userId)
        {
            try
            {
                var cacheKey = $"{USER_LOCK_PREFIX}{userId}";
                if (_cache.TryGetValue<AccountLockInfo>(cacheKey, out var lockInfo) && lockInfo != null)
                {
                    return ServiceResult<AccountLockStatus>.Success(new AccountLockStatus
                    {
                        IsLocked = true,
                        LockReason = lockInfo.Reason,
                        LockedAt = lockInfo.LockedAt,
                        LockedUntil = lockInfo.LockedUntil,
                        FailedAttempts = lockInfo.FailedAttempts,
                        MaxFailedAttempts = _maxFailedAttempts
                    });
                }

                // 데이터베이스에서 실패 횟수 확인
                var recentFailures = await _attemptLogRepository.GetFailedAttemptCountAsync(
                    userId,
                    DateTime.UtcNow.AddMinutes(-30));

                return ServiceResult<AccountLockStatus>.Success(new AccountLockStatus
                {
                    IsLocked = false,
                    FailedAttempts = recentFailures,
                    MaxFailedAttempts = _maxFailedAttempts
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking account lock status for user {UserId}", userId);
                return ServiceResult<AccountLockStatus>.Failure("Failed to check account lock status");
            }
        }

        /// <summary>
        /// 계정 잠금
        /// </summary>
        public async Task<ServiceResult> LockAccountAsync(
            Guid userId,
            TimeSpan duration,
            string reason)
        {
            try
            {
                var lockInfo = new AccountLockInfo
                {
                    UserId = userId,
                    Reason = reason,
                    LockedAt = DateTime.UtcNow,
                    LockedUntil = DateTime.UtcNow.Add(duration),
                    FailedAttempts = await _attemptLogRepository.GetConsecutiveFailureCountAsync(userId)
                };

                var cacheKey = $"{USER_LOCK_PREFIX}{userId}";
                _cache.Set(cacheKey, lockInfo, duration);

                // 사용자 엔티티 업데이트
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    user.IsAccountLocked = true;
                    user.AccountLockedUntil = lockInfo.LockedUntil;
                    await _userRepository.UpdateAsync(user);
                }

                // 활성 세션 종료
                var sessions = await _sessionRepository.GetActiveSessionsByUserAsync(userId);
                foreach (var session in sessions)
                {
                    session.Status = SessionStatus.Terminated;
                    session.EndReason = SessionEndReason.SecurityViolation;
                    await _sessionRepository.UpdateAsync(session);
                }

                _logger.LogWarning("Account locked for user {UserId}: {Reason}", userId, reason);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error locking account for user {UserId}", userId);
                return ServiceResult.Failure("Failed to lock account");
            }
        }

        /// <summary>
        /// 계정 잠금 해제
        /// </summary>
        public async Task<ServiceResult> UnlockAccountAsync(Guid userId)
        {
            try
            {
                var cacheKey = $"{USER_LOCK_PREFIX}{userId}";
                _cache.Remove(cacheKey);

                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    user.IsAccountLocked = false;
                    user.AccountLockedUntil = null;
                    await _userRepository.UpdateAsync(user);
                }

                ClearFailureCounter(userId);

                _logger.LogInformation("Account unlocked for user {UserId}", userId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking account for user {UserId}", userId);
                return ServiceResult.Failure("Failed to unlock account");
            }
        }

        /// <summary>
        /// 자동 잠금 정책 확인 및 적용
        /// </summary>
        public async Task<ServiceResult<bool>> CheckAndApplyLockPolicyAsync(Guid userId)
        {
            try
            {
                var consecutiveFailures = await _attemptLogRepository.GetConsecutiveFailureCountAsync(userId);

                if (consecutiveFailures >= _maxFailedAttempts)
                {
                    await LockAccountAsync(userId, TimeSpan.FromMinutes(_lockoutDurationMinutes), "Auto-lock policy triggered");
                    return ServiceResult<bool>.Success(true);
                }

                return ServiceResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking lock policy for user {UserId}", userId);
                return ServiceResult<bool>.Failure("Failed to check lock policy");
            }
        }

        #endregion

        #region 보안 위협 탐지

        /// <summary>
        /// 무차별 대입 공격 탐지
        /// </summary>
        public async Task<ServiceResult<bool>> DetectBruteForceAttackAsync(
            string identifier,
            string ipAddress)
        {
            try
            {
                var recentAttempts = await _attemptLogRepository.DetectBruteForceAttacksAsync(
                    DateTime.UtcNow.AddMinutes(-10),
                    _bruteForceThreshold);

                var isBruteForce = recentAttempts.Any(x =>
                    x.IpAddress == ipAddress || x.Username == identifier);

                if (isBruteForce)
                {
                    _logger.LogWarning("Brute force attack detected from IP {IpAddress} for {Identifier}",
                        ipAddress, identifier);

                    // IP 자동 차단
                    await BlockIpAddressAsync(ipAddress, TimeSpan.FromHours(1), "Brute force attack detected");
                }

                return ServiceResult<bool>.Success(isBruteForce);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting brute force attack");
                return ServiceResult<bool>.Failure("Failed to detect brute force attack");
            }
        }

        /// <summary>
        /// IP 기반 위협 평가
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessIpRiskAsync(string ipAddress)
        {
            try
            {
                var assessment = new RiskAssessment
                {
                    AssessmentId = Guid.NewGuid(),
                    AssessedAt = DateTime.UtcNow,
                    RiskFactors = new List<RiskFactor>()
                };

                // 신뢰할 수 있는 IP인지 확인
                if (IsTrustedIp(ipAddress))
                {
                    assessment.RiskScore = 0;
                    assessment.RiskLevel = "Low";
                    return ServiceResult<RiskAssessment>.Success(assessment);
                }

                // 차단된 IP인지 확인
                if (IsIpBlocked(ipAddress))
                {
                    assessment.RiskScore = 1.0;
                    assessment.RiskLevel = "Critical";
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        FactorType = "BlockedIP",
                        Description = "IP is currently blocked",
                        Weight = 1.0,
                        Severity = "Critical"
                    });
                    return ServiceResult<RiskAssessment>.Success(assessment);
                }

                // 최근 실패 횟수 확인
                var recentFailures = await _attemptLogRepository.GetByIpAddressAsync(ipAddress, DateTime.UtcNow.AddHours(-1));
                var failureCount = recentFailures.Count(x => !x.IsSuccess);

                if (failureCount > 5)
                {
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        FactorType = "HighFailureRate",
                        Description = $"High failure rate: {failureCount} failures in last hour",
                        Weight = 0.3,
                        Severity = "High"
                    });
                }

                // 여러 계정 접근 시도
                var uniqueUsers = recentFailures.Select(x => x.UserId).Distinct().Count();
                if (uniqueUsers > 3)
                {
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        FactorType = "MultipleAccountAccess",
                        Description = $"Attempted access to {uniqueUsers} different accounts",
                        Weight = 0.4,
                        Severity = "High"
                    });
                }

                // 위험도 점수 계산
                assessment.RiskScore = Math.Min(assessment.RiskFactors.Sum(x => x.Weight), 1.0);

                // 위험 수준 결정
                assessment.RiskLevel = assessment.RiskScore switch
                {
                    >= 0.8 => "Critical",
                    >= 0.6 => "High",
                    >= 0.4 => "Medium",
                    _ => "Low"
                };

                // 권장 조치
                if (assessment.RiskScore >= 0.6)
                {
                    assessment.RequiresMfa = true;
                    assessment.RecommendedActions.Add("Require MFA");
                }
                if (assessment.RiskScore >= 0.8)
                {
                    assessment.RequiresAdditionalVerification = true;
                    assessment.RecommendedActions.Add("Block IP temporarily");
                }

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing IP risk for {IpAddress}", ipAddress);
                return ServiceResult<RiskAssessment>.Failure("Failed to assess IP risk");
            }
        }

        /// <summary>
        /// 이상 패턴 탐지
        /// </summary>
        public async Task<ServiceResult<bool>> DetectAnomalousPatternAsync(
            Guid userId,
            string ipAddress,
            string? deviceFingerprint = null)
        {
            try
            {
                var anomalies = await _attemptLogRepository.DetectAnomaliesAsync(userId, DateTime.UtcNow.AddDays(-7));

                return ServiceResult<bool>.Success(anomalies.Any());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting anomalous pattern");
                return ServiceResult<bool>.Failure("Failed to detect anomalous pattern");
            }
        }

        /// <summary>
        /// 지리적 이상 징후 탐지
        /// </summary>
        public async Task<ServiceResult<bool>> DetectGeographicalAnomalyAsync(
            Guid userId,
            string currentLocation)
        {
            try
            {
                // 최근 로그인 위치들 조회
                var recentAttempts = await _attemptLogRepository.GetRecentAttemptsAsync(userId, 10);
                var locations = recentAttempts
                    .Where(x => x.IsSuccess && !string.IsNullOrEmpty(x.Location))
                    .Select(x => x.Location)
                    .Distinct()
                    .ToList();

                // 간단한 구현: 새로운 위치인지 확인
                var isNewLocation = !locations.Contains(currentLocation);

                if (isNewLocation)
                {
                    _logger.LogWarning("Geographical anomaly detected for user {UserId}: New location {Location}",
                        userId, currentLocation);
                }

                return ServiceResult<bool>.Success(isNewLocation);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting geographical anomaly");
                return ServiceResult<bool>.Failure("Failed to detect geographical anomaly");
            }
        }

        #endregion

        #region IP 관리

        /// <summary>
        /// IP 차단
        /// </summary>
        public async Task<ServiceResult> BlockIpAddressAsync(
            string ipAddress,
            TimeSpan duration,
            string reason)
        {
            try
            {
                var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
                _cache.Set(cacheKey, new BlockedIpInfo
                {
                    IpAddress = ipAddress,
                    Reason = reason,
                    BlockedAt = DateTime.UtcNow,
                    BlockedUntil = DateTime.UtcNow.Add(duration)
                }, duration);

                _logger.LogWarning("IP {IpAddress} blocked: {Reason}", ipAddress, reason);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking IP {IpAddress}", ipAddress);
                return ServiceResult.Failure("Failed to block IP");
            }
        }

        /// <summary>
        /// IP 차단 해제
        /// </summary>
        public async Task<ServiceResult> UnblockIpAddressAsync(string ipAddress)
        {
            try
            {
                var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
                _cache.Remove(cacheKey);

                _logger.LogInformation("IP {IpAddress} unblocked", ipAddress);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking IP {IpAddress}", ipAddress);
                return ServiceResult.Failure("Failed to unblock IP");
            }
        }

        /// <summary>
        /// 차단된 IP 목록 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<string>>> GetBlockedIpAddressesAsync()
        {
            try
            {
                // 캐시에서 차단된 IP 목록 조회
                // 실제로는 더 정교한 구현이 필요
                var blockedIps = new List<string>();

                return await Task.FromResult(ServiceResult<IEnumerable<string>>.Success(blockedIps));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting blocked IPs");
                return ServiceResult<IEnumerable<string>>.Failure("Failed to get blocked IPs");
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 IP 추가
        /// </summary>
        public async Task<ServiceResult> AddTrustedIpAddressAsync(
            Guid organizationId,
            string ipAddress)
        {
            try
            {
                var cacheKey = $"{TRUSTED_IP_PREFIX}{organizationId}:{ipAddress}";
                _cache.Set(cacheKey, true, TimeSpan.FromDays(365));

                _logger.LogInformation("Trusted IP {IpAddress} added for organization {OrganizationId}",
                    ipAddress, organizationId);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding trusted IP");
                return ServiceResult.Failure("Failed to add trusted IP");
            }
        }

        #endregion

        #region 비밀번호 정책

        /// <summary>
        /// 비밀번호 정책 검증
        /// </summary>
        public async Task<ServiceResult<PasswordValidationResult>> ValidatePasswordAsync(
            string password,
            PasswordPolicy policy)
        {
            try
            {
                var result = new PasswordValidationResult();
                var errors = new List<string>();

                // 길이 검증
                if (password.Length < policy.MinimumLength)
                    errors.Add($"Password must be at least {policy.MinimumLength} characters long");

                if (password.Length > policy.MaximumLength)
                    errors.Add($"Password must not exceed {policy.MaximumLength} characters");

                // 대문자 검증
                if (policy.RequireUppercase && !password.Any(char.IsUpper))
                    errors.Add("Password must contain at least one uppercase letter");

                // 소문자 검증
                if (policy.RequireLowercase && !password.Any(char.IsLower))
                    errors.Add("Password must contain at least one lowercase letter");

                // 숫자 검증
                if (policy.RequireNumbers && !password.Any(char.IsDigit))
                    errors.Add("Password must contain at least one number");

                // 특수문자 검증
                if (policy.RequireSpecialCharacters && !password.Any(c => !char.IsLetterOrDigit(c)))
                    errors.Add("Password must contain at least one special character");

                // 고유 문자 수 검증
                var uniqueChars = password.Distinct().Count();
                if (uniqueChars < policy.MinimumUniqueCharacters)
                    errors.Add($"Password must contain at least {policy.MinimumUniqueCharacters} unique characters");

                result.IsValid = !errors.Any();
                result.Errors = errors;

                // 강도 점수 계산
                result.StrengthScore = CalculatePasswordStrength(password);
                result.StrengthLevel = result.StrengthScore switch
                {
                    >= 80 => "VeryStrong",
                    >= 60 => "Strong",
                    >= 40 => "Good",
                    >= 20 => "Fair",
                    _ => "Weak"
                };

                // 개선 제안
                if (!result.IsValid || result.StrengthScore < 60)
                {
                    result.Suggestions = GeneratePasswordSuggestions(password, policy);
                }

                return await Task.FromResult(ServiceResult<PasswordValidationResult>.Success(result));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating password");
                return ServiceResult<PasswordValidationResult>.Failure("Failed to validate password");
            }
        }

        /// <summary>
        /// 비밀번호 이력 확인
        /// </summary>
        public async Task<ServiceResult<bool>> CheckPasswordHistoryAsync(
            Guid userId,
            string passwordHash)
        {
            try
            {
                // TODO: 비밀번호 이력 저장소 구현 필요
                // 여기서는 간단한 구현
                var cacheKey = $"pwd_history:{userId}";
                if (_cache.TryGetValue<List<string>>(cacheKey, out var history))
                {
                    var isReused = history?.Contains(passwordHash) ?? false;
                    return ServiceResult<bool>.Success(isReused);
                }

                return await Task.FromResult(ServiceResult<bool>.Success(false));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking password history");
                return ServiceResult<bool>.Failure("Failed to check password history");
            }
        }

        /// <summary>
        /// 비밀번호 만료 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsPasswordExpiredAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<bool>.Failure("User not found");
                }

                var expirationDays = _configuration.GetValue<int>("Auth:Password:ExpirationDays", 90);

                // 명시적으로 처리
                if (user.PasswordChangedAt == null)
                {
                    return ServiceResult<bool>.Success(false); // 비밀번호 변경 기록이 없으면 만료되지 않음
                }

                var isExpired = user.PasswordChangedAt.Value.AddDays(expirationDays) < DateTime.UtcNow;
                return ServiceResult<bool>.Success(isExpired);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking password expiration");
                return ServiceResult<bool>.Failure("Failed to check password expiration");
            }
        }

        /// <summary>
        /// 비밀번호 재설정 토큰 생성
        /// </summary>
        public async Task<ServiceResult<PasswordResetToken>> CreatePasswordResetTokenAsync(
            string identifier)
        {
            try
            {
                // FindByUsernameOrEmailAsync가 Guid?를 반환
                var userId = await _userRepository.FindByUsernameOrEmailAsync(identifier);
                if (!userId.HasValue)
                {
                    // 보안상 사용자가 존재하지 않아도 성공으로 반환
                    return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken
                    {
                        Message = "If the account exists, a reset email has been sent"
                    });
                }

                // userId로 사용자 조회
                var user = await _userRepository.GetByIdAsync(userId.Value);
                if (user == null)
                {
                    return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken
                    {
                        Message = "If the account exists, a reset email has been sent"
                    });
                }

                var token = GenerateSecureToken();
                var resetToken = new PasswordResetToken
                {
                    Token = token,
                    UserId = user.Id,  // user는 UserEntity 타입
                    Email = user.Email ?? string.Empty,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    RequiresMfa = user.TwoFactorEnabled,  // 또는 user.IsTwoFactorEnabled
                    ResetUrl = $"{_configuration["App:BaseUrl"]}/reset-password?token={token}",
                    Message = "Password reset token created successfully"
                };

                // 토큰 캐시에 저장
                var cacheKey = $"pwd_reset:{token}";
                _cache.Set(cacheKey, resetToken, TimeSpan.FromHours(1));

                _logger.LogInformation("Password reset token created for user {UserId}", user.Id);

                return ServiceResult<PasswordResetToken>.Success(resetToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating password reset token");
                return ServiceResult<PasswordResetToken>.Failure("Failed to create password reset token");
            }
        }
        /// <summary>
        /// 비밀번호 재설정
        /// </summary>
        public async Task<ServiceResult> ResetPasswordAsync(
            string token,
            string newPassword)
        {
            try
            {
                var cacheKey = $"pwd_reset:{token}";
                if (!_cache.TryGetValue<PasswordResetToken>(cacheKey, out var resetToken) || resetToken == null)
                {
                    return ServiceResult.Failure("Invalid or expired token");
                }

                if (resetToken.ExpiresAt < DateTime.UtcNow)
                {
                    return ServiceResult.Failure("Token has expired");
                }

                var user = await _userRepository.GetByIdAsync(resetToken.UserId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found");
                }

                // 비밀번호 정책 검증
                var policy = new PasswordPolicy(); // 기본 정책 사용
                var validationResult = await ValidatePasswordAsync(newPassword, policy);
                if (!validationResult.Data?.IsValid ?? false)
                {
                    return ServiceResult.Failure("Password does not meet requirements");
                }

                // 비밀번호 해시 생성 (실제 구현에서는 암호화 서비스 사용)
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);

                // 비밀번호 이력 체크
                var isReused = await CheckPasswordHistoryAsync(user.Id, passwordHash);
                if (isReused.Data)
                {
                    return ServiceResult.Failure("Password has been used recently");
                }

                // 비밀번호 업데이트
                user.PasswordHash = passwordHash;
                user.PasswordChangedAt = DateTime.UtcNow;
                user.RequiresPasswordChange = false;
                await _userRepository.UpdateAsync(user);

                // 토큰 무효화
                _cache.Remove(cacheKey);

                // 계정 잠금 해제
                await UnlockAccountAsync(user.Id);

                _logger.LogInformation("Password reset successfully for user {UserId}", user.Id);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return ServiceResult.Failure("Failed to reset password");
            }
        }

        #endregion

        #region 인증 이력 조회

        /// <summary>
        /// 사용자 인증 이력 조회
        /// </summary>
        public async Task<ServiceResult<AuthenticationHistory>> GetAuthenticationHistoryAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var attempts = await _attemptLogRepository.GetRecentAttemptsAsync(userId, 100);

                if (startDate.HasValue)
                    attempts = attempts.Where(x => x.AttemptedAt >= startDate.Value);

                if (endDate.HasValue)
                    attempts = attempts.Where(x => x.AttemptedAt <= endDate.Value);

                var successfulAttempt = attempts.FirstOrDefault(x => x.IsSuccess);
                if (successfulAttempt != null)
                {
                    var history = new AuthenticationHistory
                    {
                        Id = successfulAttempt.Id,
                        UserId = userId,
                        ConnectedId = successfulAttempt.ConnectedId,
                        Method = successfulAttempt.Method.ToString(),
                        Success = true,
                        AuthenticatedAt = successfulAttempt.AttemptedAt,
                        IpAddress = successfulAttempt.IpAddress,
                        Location = successfulAttempt.Location,
                        DeviceName = successfulAttempt.DeviceId ?? "Unknown",
                        DeviceType = successfulAttempt.DeviceType ?? "Unknown",
                        SessionId = successfulAttempt.SessionId
                    };

                    return ServiceResult<AuthenticationHistory>.Success(history);
                }

                return ServiceResult<AuthenticationHistory>.Failure("No authentication history found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication history");
                return ServiceResult<AuthenticationHistory>.Failure("Failed to get authentication history");
            }
        }

        /// <summary>
        /// 최근 인증 시도 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<AuthenticationAttempts>>> GetRecentAttemptsAsync(
            Guid userId,
            int count = 10)
        {
            try
            {
                var attempts = await _attemptLogRepository.GetRecentAttemptsAsync(userId, count);

                var result = attempts.Select(x => new AuthenticationAttempts
                {
                    UserId = x.UserId,
                    ConnectedId = x.ConnectedId,
                    Method = x.Method.ToString(),
                    Success = x.IsSuccess,
                    FailureReason = x.FailureReason?.ToString(),
                    IpAddress = x.IpAddress,
                    UserAgent = x.UserAgent ?? string.Empty,
                    AttemptedAt = x.AttemptedAt,
                    OrganizationId = x.OrganizationId,
                    ApplicationId = x.ApplicationId
                });

                return ServiceResult<IEnumerable<AuthenticationAttempts>>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting recent attempts");
                return ServiceResult<IEnumerable<AuthenticationAttempts>>.Failure("Failed to get recent attempts");
            }
        }

        /// <summary>
        /// 실패한 인증 시도 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<AuthenticationFailure>>> GetFailedAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null)
        {
            try
            {
                var attempts = await _attemptLogRepository.GetFailedAttemptsAsync(userId, since);

                var failures = attempts.Select(x => new AuthenticationFailure
                {
                    Id = x.Id,
                    UserId = x.UserId,
                    Username = x.Username ?? string.Empty,
                    Method = x.Method.ToString(),
                    FailureReason = x.FailureReason?.ToString() ?? "Unknown",
                    FailureCode = x.ErrorCode ?? string.Empty,
                    FailedAt = x.AttemptedAt,
                    IpAddress = x.IpAddress,
                    UserAgent = x.UserAgent ?? string.Empty,
                    ConsecutiveFailures = x.ConsecutiveFailures,
                    AccountLocked = x.TriggeredAccountLock
                });

                return ServiceResult<IEnumerable<AuthenticationFailure>>.Success(failures);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting failed attempts");
                return ServiceResult<IEnumerable<AuthenticationFailure>>.Failure("Failed to get failed attempts");
            }
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 인증 성공률 계산
        /// </summary>
        public async Task<ServiceResult<double>> CalculateSuccessRateAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            try
            {
                var stats = await _attemptLogRepository.GetStatisticsAsync(startDate, endDate, organizationId);

                return ServiceResult<double>.Success(stats.SuccessRate);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating success rate");
                return ServiceResult<double>.Failure("Failed to calculate success rate");
            }
        }

        /// <summary>
        /// 인증 방법별 통계
        /// </summary>
        public async Task<ServiceResult<Dictionary<AuthenticationMethod, int>>> GetMethodStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null)
        {
            try
            {
                var from = startDate ?? DateTime.UtcNow.AddMonths(-1);
                var to = DateTime.UtcNow;

                var stats = await _attemptLogRepository.GetStatisticsAsync(from, to, organizationId);

                return ServiceResult<Dictionary<AuthenticationMethod, int>>.Success(stats.AttemptsByMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting method statistics");
                return ServiceResult<Dictionary<AuthenticationMethod, int>>.Failure("Failed to get method statistics");
            }
        }

        /// <summary>
        /// 실패 원인 분석
        /// </summary>
        public async Task<ServiceResult<Dictionary<AuthenticationResult, int>>> AnalyzeFailureReasonsAsync(
            Guid organizationId,
            int periodDays = 30)
        {
            try
            {
                var from = DateTime.UtcNow.AddDays(-periodDays);
                var to = DateTime.UtcNow;

                var stats = await _attemptLogRepository.GetStatisticsAsync(from, to, organizationId);

                return ServiceResult<Dictionary<AuthenticationResult, int>>.Success(stats.FailureReasons);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing failure reasons");
                return ServiceResult<Dictionary<AuthenticationResult, int>>.Failure("Failed to analyze failure reasons");
            }
        }

        #endregion

        #region 알림

        /// <summary>
        /// 의심스러운 활동 알림
        /// </summary>
        public async Task<ServiceResult> NotifySuspiciousActivityAsync(
            Guid userId,
            string activityDescription)
        {
            try
            {
                // TODO: 알림 서비스 구현
                _logger.LogWarning("Suspicious activity for user {UserId}: {Description}",
                    userId, activityDescription);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying suspicious activity");
                return ServiceResult.Failure("Failed to notify suspicious activity");
            }
        }

        /// <summary>
        /// 새 디바이스 로그인 알림
        /// </summary>
        public async Task<ServiceResult> NotifyNewDeviceLoginAsync(
            Guid userId,
            string deviceInfo,
            string location)
        {
            try
            {
                // TODO: 알림 서비스 구현
                _logger.LogInformation("New device login for user {UserId}: {Device} from {Location}",
                    userId, deviceInfo, location);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying new device login");
                return ServiceResult.Failure("Failed to notify new device login");
            }
        }

        /// <summary>
        /// 계정 잠금 알림
        /// </summary>
        public async Task<ServiceResult> NotifyAccountLockAsync(
            Guid userId,
            string reason)
        {
            try
            {
                // TODO: 알림 서비스 구현
                _logger.LogWarning("Account locked for user {UserId}: {Reason}", userId, reason);

                return await Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying account lock");
                return ServiceResult.Failure("Failed to notify account lock");
            }
        }

        #endregion

        #region 데이터 관리

        /// <summary>
        /// 오래된 로그 정리
        /// </summary>
        public async Task<ServiceResult<int>> CleanupOldLogsAsync(
            int olderThanDays,
            bool keepFailedOnly = false)
        {
            try
            {
                var before = DateTime.UtcNow.AddDays(-olderThanDays);
                var count = await _attemptLogRepository.CleanupOldLogsAsync(before);

                _logger.LogInformation("Cleaned up {Count} old authentication logs", count);

                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up old logs");
                return ServiceResult<int>.Failure("Failed to cleanup old logs");
            }
        }

        /// <summary>
        /// 인증 로그 아카이빙
        /// </summary>
        public async Task<ServiceResult<int>> ArchiveLogsAsync(
            Guid organizationId,
            DateTime beforeDate)
        {
            try
            {
                var archiveLocation = _configuration["Storage:ArchiveLocation"] ?? "archive";
                var count = await _attemptLogRepository.ArchiveSuccessfulLogsAsync(beforeDate, archiveLocation);

                _logger.LogInformation("Archived {Count} authentication logs for organization {OrganizationId}",
                    count, organizationId);

                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving logs");
                return ServiceResult<int>.Failure("Failed to archive logs");
            }
        }

        #endregion

        #region Private Helper Methods

        private bool IsIpBlocked(string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;

            var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
            return _cache.TryGetValue<BlockedIpInfo>(cacheKey, out _);
        }

        private bool IsTrustedIp(string ipAddress)
        {
            // 간단한 구현 - 실제로는 조직별 신뢰 IP 확인
            return ipAddress.StartsWith("192.168.") || ipAddress == "::1" || ipAddress == "127.0.0.1";
        }

        private void ClearFailureCounter(Guid userId)
        {
            // 실패 카운터 초기화 로직
            var cacheKey = $"fail_count:{userId}";
            _cache.Remove(cacheKey);
        }

        private async Task<int> CalculateRiskScoreAsync(string ipAddress, Guid? userId)
        {
            var score = 0;

            // IP 기반 위험도
            var ipRisk = await AssessIpRiskAsync(ipAddress);
            if (ipRisk.IsSuccess && ipRisk.Data != null)
            {
                score += (int)(ipRisk.Data.RiskScore * 50);
            }

            // 사용자 기반 위험도
            if (userId.HasValue)
            {
                var recentFailures = await _attemptLogRepository.GetFailedAttemptCountAsync(
                    userId.Value, DateTime.UtcNow.AddHours(-1));
                score += recentFailures * 10;
            }

            return Math.Min(score, 100);
        }

        private int CalculatePasswordStrength(string password)
        {
            var score = 0;

            // 길이 점수
            score += Math.Min(password.Length * 4, 40);

            // 대문자
            if (password.Any(char.IsUpper)) score += 10;

            // 소문자
            if (password.Any(char.IsLower)) score += 10;

            // 숫자
            if (password.Any(char.IsDigit)) score += 10;

            // 특수문자
            if (password.Any(c => !char.IsLetterOrDigit(c))) score += 20;

            // 다양성
            var uniqueChars = password.Distinct().Count();
            score += Math.Min(uniqueChars * 2, 10);

            return Math.Min(score, 100);
        }

        private List<string> GeneratePasswordSuggestions(string password, PasswordPolicy policy)
        {
            var suggestions = new List<string>();

            if (password.Length < 12)
                suggestions.Add("Consider using a longer password for better security");

            if (!password.Any(c => !char.IsLetterOrDigit(c)))
                suggestions.Add("Add special characters for increased complexity");

            if (password.All(char.IsLetter))
                suggestions.Add("Mix letters with numbers and symbols");

            suggestions.Add("Consider using a passphrase instead of a password");

            return suggestions;
        }

        private string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        #endregion

        #region Helper Classes

        private class AccountLockInfo
        {
            public Guid UserId { get; set; }
            public string Reason { get; set; } = string.Empty;
            public DateTime LockedAt { get; set; }
            public DateTime LockedUntil { get; set; }
            public int FailedAttempts { get; set; }
        }

        private class BlockedIpInfo
        {
            public string IpAddress { get; set; } = string.Empty;
            public string Reason { get; set; } = string.Empty;
            public DateTime BlockedAt { get; set; }
            public DateTime BlockedUntil { get; set; }
        }

        #endregion
        public Task InitializeAsync()
        {
            // 초기화 로직이 필요하면 여기에 구현
            return Task.CompletedTask;
        }
        // IService 인터페이스 구현
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository 접근 가능 여부 확인
                await _attemptLogRepository.CountAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

    }
}
