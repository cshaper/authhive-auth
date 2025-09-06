using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.User.Repository;
using UserEntity = AuthHive.Core.Entities.User.User;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 시도 관리 서비스 구현 - AuthHive v15
    /// 메모리 캐시를 활용한 최적화 버전
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

        // 캐시 키 접두사
        private const string BLOCKED_IP_PREFIX = "blocked_ip:";
        private const string TRUSTED_IP_PREFIX = "trusted_ip:";
        private const string USER_LOCK_PREFIX = "user_lock:";
        private const string FAILURE_COUNT_PREFIX = "failure_count:";
        private const string MFA_ATTEMPTS_PREFIX = "mfa_attempts:";
        private const string RECENT_ATTEMPTS_PREFIX = "recent_attempts:";

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

        #region IService 인터페이스 구현

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository 접근 가능 여부 확인
                await _attemptLogRepository.CountAsync();
                
                // 캐시 동작 확인
                _cache.Set("health_check", true, TimeSpan.FromSeconds(1));
                _cache.Remove("health_check");
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service health check failed");
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public Task InitializeAsync()
        {
            _logger.LogInformation("AuthenticationAttemptService initialized");
            // 필요한 초기화 로직 추가
            return Task.CompletedTask;
        }

        #endregion

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
                    Id = Guid.NewGuid(),
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

                await _attemptLogRepository.AddAsync(attemptLog);
                
                // 최근 시도 캐시 업데이트
                UpdateRecentAttemptsCache(attemptLog);

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
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    ConnectedId = connectedId,
                    Username = user.Username,
                    Method = method,
                    IsSuccess = true,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty,
                    ConsecutiveFailures = 0
                };

                await _attemptLogRepository.AddAsync(attemptLog);
                
                // 캐시 초기화
                ClearUserFailureCaches(userId);
                UpdateRecentAttemptsCache(attemptLog);

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
                // 사용자 찾기
                Guid? userId = await _userRepository.FindByUsernameOrEmailAsync(identifier);
                UserEntity? user = null;
                
                if (userId.HasValue)
                {
                    user = await _userRepository.GetByIdAsync(userId.Value);
                }

                // 연속 실패 횟수 계산 (캐시 활용)
                var consecutiveFailures = 0;
                if (userId.HasValue)
                {
                    consecutiveFailures = IncrementFailureCount(userId.Value);
                }

                var attemptLog = new AuthenticationAttemptLog
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    Username = identifier,
                    Method = method,
                    IsSuccess = false,
                    FailureReason = reason,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user?.OrganizationId ?? Guid.Empty,
                    ConsecutiveFailures = consecutiveFailures
                };

                // 계정 잠금 체크
                if (userId.HasValue && consecutiveFailures >= _maxFailedAttempts)
                {
                    attemptLog.TriggeredAccountLock = true;
                    await LockAccountAsync(userId.Value, TimeSpan.FromMinutes(_lockoutDurationMinutes), 
                        $"Too many failed attempts ({consecutiveFailures})");
                }

                // 위험도 평가
                attemptLog.RiskScore = await CalculateRiskScoreAsync(ipAddress, userId);
                attemptLog.IsSuspicious = attemptLog.RiskScore > _riskScoreThreshold;

                await _attemptLogRepository.AddAsync(attemptLog);
                UpdateRecentAttemptsCache(attemptLog);

                // IP 기반 무차별 대입 공격 감지
                await CheckAndBlockSuspiciousIp(ipAddress);

                _logger.LogWarning("Failed authentication attempt for {Identifier} from {IpAddress}", 
                    identifier, ipAddress);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging failed authentication");
                return ServiceResult.Failure("Failed to log failed authentication");
            }
        }

        /// <summary>
        /// MFA 인증 시도 기록 (개선된 버전)
        /// </summary>
        public async Task<ServiceResult<MfaChallengeResponse>> LogMfaAttemptAsync(
            Guid userId,
            MfaMethod method,
            bool isSuccess,
            string? failureReason = null)
        {
            try
            {
                // 계정 잠금 상태 확인
                var lockStatus = await CheckAccountLockStatusAsync(userId);
                if (lockStatus.IsSuccess && lockStatus.Data?.IsLocked == true)
                {
                    return ServiceResult<MfaChallengeResponse>.Failure("Account is locked");
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<MfaChallengeResponse>.Failure("User not found");
                }

                // MFA 시도 횟수 관리 (캐시 활용)
                var mfaCacheKey = $"{MFA_ATTEMPTS_PREFIX}{userId}";
                var mfaAttempts = _cache.Get<MfaAttemptInfo>(mfaCacheKey) ?? new MfaAttemptInfo 
                { 
                    UserId = userId, 
                    FailedAttempts = 0,
                    FirstAttemptTime = DateTime.UtcNow
                };

                if (!isSuccess)
                {
                    mfaAttempts.FailedAttempts++;
                    mfaAttempts.LastAttemptTime = DateTime.UtcNow;
                    
                    // 30분 동안 캐시 유지
                    _cache.Set(mfaCacheKey, mfaAttempts, TimeSpan.FromMinutes(30));
                }
                else
                {
                    // 성공 시 캐시 제거
                    _cache.Remove(mfaCacheKey);
                    mfaAttempts.FailedAttempts = 0;
                }

                var attemptLog = new AuthenticationAttemptLog
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    Username = user.Username,
                    Method = AuthenticationMethod.TwoFactor,
                    IsSuccess = isSuccess,
                    MfaRequired = true,
                    MfaCompleted = isSuccess,
                    FailureMessage = failureReason,
                    AttemptedAt = DateTime.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty,
                    ConsecutiveFailures = mfaAttempts.FailedAttempts
                };

                await _attemptLogRepository.AddAsync(attemptLog);
                UpdateRecentAttemptsCache(attemptLog);

                // 최대 시도 횟수 초과 시 계정 잠금
                if (mfaAttempts.FailedAttempts >= _maxFailedAttempts)
                {
                    await LockAccountAsync(userId, TimeSpan.FromMinutes(_lockoutDurationMinutes), 
                        "Too many failed MFA attempts");
                }

                var response = new MfaChallengeResponse
                {
                    ChallengeId = Guid.NewGuid().ToString(),
                    Method = method,
                    ChallengeType = isSuccess ? "completed" : "failed",
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                    AttemptsRemaining = Math.Max(0, _maxFailedAttempts - mfaAttempts.FailedAttempts),
                    AttemptsAllowed = _maxFailedAttempts,
                    CodeSent = false,
                    Message = GetMfaResponseMessage(isSuccess, mfaAttempts.FailedAttempts, failureReason)
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

                // 캐시에서 실패 횟수 확인
                var failureCount = GetFailureCount(userId);

                await Task.CompletedTask; // async 경고 방지

                return ServiceResult<AccountLockStatus>.Success(new AccountLockStatus
                {
                    IsLocked = false,
                    FailedAttempts = failureCount,
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
                    FailedAttempts = GetFailureCount(userId)
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
                // 캐시에서 잠금 정보 제거
                var lockCacheKey = $"{USER_LOCK_PREFIX}{userId}";
                _cache.Remove(lockCacheKey);
                
                // 실패 횟수 초기화
                ClearUserFailureCaches(userId);

                // 사용자 엔티티 업데이트
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    user.IsAccountLocked = false;
                    user.AccountLockedUntil = null;
                    await _userRepository.UpdateAsync(user);
                }

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
                var failureCount = GetFailureCount(userId);

                if (failureCount >= _maxFailedAttempts)
                {
                    await LockAccountAsync(userId, TimeSpan.FromMinutes(_lockoutDurationMinutes), 
                        "Auto-lock policy triggered");
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
                // IP별 시도 횟수 확인 (캐시 활용)
                var ipAttemptsCacheKey = $"ip_attempts:{ipAddress}";
                var ipAttempts = _cache.Get<int>(ipAttemptsCacheKey);
                
                if (ipAttempts >= _bruteForceThreshold)
                {
                    _logger.LogWarning("Brute force attack detected from IP {IpAddress} for {Identifier}",
                        ipAddress, identifier);

                    // IP 자동 차단
                    await BlockIpAddressAsync(ipAddress, TimeSpan.FromHours(1), "Brute force attack detected");
                    return ServiceResult<bool>.Success(true);
                }

                return ServiceResult<bool>.Success(false);
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
                    RiskFactors = new List<RiskFactor>(),
                    RecommendedActions = new List<string>()
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

                // 캐시에서 IP 시도 횟수 확인
                var ipAttemptsCacheKey = $"ip_attempts:{ipAddress}";
                var ipAttempts = _cache.Get<int>(ipAttemptsCacheKey);
                
                if (ipAttempts > 5)
                {
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        FactorType = "HighFailureRate",
                        Description = $"High failure rate: {ipAttempts} attempts in recent period",
                        Weight = 0.3,
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

                await Task.CompletedTask; // async 경고 방지
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
                // 캐시에서 최근 시도 패턴 확인
                var recentAttempts = GetRecentAttemptsFromCache(userId);
                
                // 새로운 IP나 디바이스에서의 접근인지 확인
                var isNewIp = !recentAttempts.Any(a => a.IpAddress == ipAddress);
                var isNewDevice = !string.IsNullOrEmpty(deviceFingerprint) && 
                                 !recentAttempts.Any(a => a.DeviceId == deviceFingerprint);

                var isAnomalous = isNewIp || isNewDevice;

                if (isAnomalous)
                {
                    _logger.LogWarning("Anomalous pattern detected for user {UserId} from IP {IpAddress}",
                        userId, ipAddress);
                }

                await Task.CompletedTask; // async 경고 방지
                return ServiceResult<bool>.Success(isAnomalous);
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
                // 캐시에서 최근 위치 정보 확인
                var recentAttempts = GetRecentAttemptsFromCache(userId);
                var recentLocations = recentAttempts
                    .Where(a => !string.IsNullOrEmpty(a.Location))
                    .Select(a => a.Location)
                    .Distinct()
                    .ToList();

                var isNewLocation = !recentLocations.Contains(currentLocation);

                if (isNewLocation)
                {
                    _logger.LogWarning("Geographical anomaly detected for user {UserId}: New location {Location}",
                        userId, currentLocation);
                }

                await Task.CompletedTask; // async 경고 방지
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
        public Task<ServiceResult> BlockIpAddressAsync(
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
                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking IP {IpAddress}", ipAddress);
                return Task.FromResult(ServiceResult.Failure("Failed to block IP"));
            }
        }

        /// <summary>
        /// IP 차단 해제
        /// </summary>
        public Task<ServiceResult> UnblockIpAddressAsync(string ipAddress)
        {
            try
            {
                var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
                _cache.Remove(cacheKey);

                _logger.LogInformation("IP {IpAddress} unblocked", ipAddress);
                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking IP {IpAddress}", ipAddress);
                return Task.FromResult(ServiceResult.Failure("Failed to unblock IP"));
            }
        }

        /// <summary>
        /// 차단된 IP 목록 조회
        /// </summary>
        public Task<ServiceResult<IEnumerable<string>>> GetBlockedIpAddressesAsync()
        {
            try
            {
                // 실제 구현시에는 별도의 저장소나 더 정교한 캐시 관리가 필요
                var blockedIps = new List<string>();
                return Task.FromResult(ServiceResult<IEnumerable<string>>.Success(blockedIps));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting blocked IPs");
                return Task.FromResult(ServiceResult<IEnumerable<string>>.Failure("Failed to get blocked IPs"));
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 IP 추가
        /// </summary>
        public Task<ServiceResult> AddTrustedIpAddressAsync(
            Guid organizationId,
            string ipAddress)
        {
            try
            {
                var cacheKey = $"{TRUSTED_IP_PREFIX}{organizationId}:{ipAddress}";
                _cache.Set(cacheKey, true, TimeSpan.FromDays(365));

                _logger.LogInformation("Trusted IP {IpAddress} added for organization {OrganizationId}",
                    ipAddress, organizationId);

                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding trusted IP");
                return Task.FromResult(ServiceResult.Failure("Failed to add trusted IP"));
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
                // 캐시에서 먼저 확인
                var recentAttempts = GetRecentAttemptsFromCache(userId);
                
                if (startDate.HasValue)
                    recentAttempts = recentAttempts.Where(x => x.AttemptedAt >= startDate.Value).ToList();

                if (endDate.HasValue)
                    recentAttempts = recentAttempts.Where(x => x.AttemptedAt <= endDate.Value).ToList();

                var successfulAttempt = recentAttempts.FirstOrDefault(x => x.IsSuccess);
                
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

                // 캐시에 없으면 DB에서 조회
                var attempts = await _attemptLogRepository.GetRecentAttemptsAsync(userId, 100);
                
                if (startDate.HasValue)
                    attempts = attempts.Where(x => x.AttemptedAt >= startDate.Value);

                if (endDate.HasValue)
                    attempts = attempts.Where(x => x.AttemptedAt <= endDate.Value);

                successfulAttempt = attempts.FirstOrDefault(x => x.IsSuccess);
                
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
                // 캐시에서 먼저 확인
                var recentAttempts = GetRecentAttemptsFromCache(userId)
                    .Take(count)
                    .ToList();

                if (recentAttempts.Count < count)
                {
                    // 캐시에 충분한 데이터가 없으면 DB에서 추가 조회
                    var dbAttempts = await _attemptLogRepository.GetRecentAttemptsAsync(userId, count);
                    recentAttempts = dbAttempts.Take(count).ToList();
                }

                var result = recentAttempts.Select(x => new AuthenticationAttempts
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
        public Task<ServiceResult> NotifySuspiciousActivityAsync(
            Guid userId,
            string activityDescription)
        {
            try
            {
                // TODO: 실제 알림 서비스 구현
                _logger.LogWarning("Suspicious activity for user {UserId}: {Description}",
                    userId, activityDescription);

                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying suspicious activity");
                return Task.FromResult(ServiceResult.Failure("Failed to notify suspicious activity"));
            }
        }

        /// <summary>
        /// 새 디바이스 로그인 알림
        /// </summary>
        public Task<ServiceResult> NotifyNewDeviceLoginAsync(
            Guid userId,
            string deviceInfo,
            string location)
        {
            try
            {
                // TODO: 실제 알림 서비스 구현
                _logger.LogInformation("New device login for user {UserId}: {Device} from {Location}",
                    userId, deviceInfo, location);

                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying new device login");
                return Task.FromResult(ServiceResult.Failure("Failed to notify new device login"));
            }
        }

        /// <summary>
        /// 계정 잠금 알림
        /// </summary>
        public Task<ServiceResult> NotifyAccountLockAsync(
            Guid userId,
            string reason)
        {
            try
            {
                // TODO: 실제 알림 서비스 구현
                _logger.LogWarning("Account locked for user {UserId}: {Reason}", userId, reason);

                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying account lock");
                return Task.FromResult(ServiceResult.Failure("Failed to notify account lock"));
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

        /// <summary>
        /// IP 차단 여부 확인
        /// </summary>
        private bool IsIpBlocked(string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;

            var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
            return _cache.TryGetValue<BlockedIpInfo>(cacheKey, out _);
        }

        /// <summary>
        /// 신뢰할 수 있는 IP 여부 확인
        /// </summary>
        private bool IsTrustedIp(string ipAddress)
        {
            // 로컬 IP 확인
            if (ipAddress.StartsWith("192.168.") || ipAddress == "::1" || ipAddress == "127.0.0.1")
                return true;

            // 캐시에서 신뢰 IP 확인
            // 실제로는 조직별로 더 정교한 확인 필요
            return false;
        }

        /// <summary>
        /// 사용자 실패 횟수 증가
        /// </summary>
        private int IncrementFailureCount(Guid userId)
        {
            var cacheKey = $"{FAILURE_COUNT_PREFIX}{userId}";
            var currentCount = _cache.Get<int>(cacheKey);
            currentCount++;
            
            // 30분 동안 유지
            _cache.Set(cacheKey, currentCount, TimeSpan.FromMinutes(30));
            
            return currentCount;
        }

        /// <summary>
        /// 사용자 실패 횟수 조회
        /// </summary>
        private int GetFailureCount(Guid userId)
        {
            var cacheKey = $"{FAILURE_COUNT_PREFIX}{userId}";
            return _cache.Get<int>(cacheKey);
        }

        /// <summary>
        /// 사용자 실패 관련 캐시 초기화
        /// </summary>
        private void ClearUserFailureCaches(Guid userId)
        {
            _cache.Remove($"{FAILURE_COUNT_PREFIX}{userId}");
            _cache.Remove($"{MFA_ATTEMPTS_PREFIX}{userId}");
        }

        /// <summary>
        /// 최근 시도 캐시 업데이트
        /// </summary>
        private void UpdateRecentAttemptsCache(AuthenticationAttemptLog attemptLog)
        {
            if (attemptLog.UserId.HasValue)
            {
                var cacheKey = $"{RECENT_ATTEMPTS_PREFIX}{attemptLog.UserId}";
                var recentAttempts = _cache.Get<List<AuthenticationAttemptLog>>(cacheKey) 
                                    ?? new List<AuthenticationAttemptLog>();
                
                recentAttempts.Insert(0, attemptLog);
                
                // 최근 100개만 유지
                if (recentAttempts.Count > 100)
                {
                    recentAttempts = recentAttempts.Take(100).ToList();
                }
                
                // 1시간 동안 캐시
                _cache.Set(cacheKey, recentAttempts, TimeSpan.FromHours(1));
            }

            // IP별 시도 횟수 업데이트
            var ipCacheKey = $"ip_attempts:{attemptLog.IpAddress}";
            var ipAttempts = _cache.Get<int>(ipCacheKey);
            _cache.Set(ipCacheKey, ipAttempts + 1, TimeSpan.FromMinutes(10));
        }

        /// <summary>
        /// 캐시에서 최근 시도 조회
        /// </summary>
        private List<AuthenticationAttemptLog> GetRecentAttemptsFromCache(Guid userId)
        {
            var cacheKey = $"{RECENT_ATTEMPTS_PREFIX}{userId}";
            return _cache.Get<List<AuthenticationAttemptLog>>(cacheKey) 
                   ?? new List<AuthenticationAttemptLog>();
        }

        /// <summary>
        /// 의심스러운 IP 확인 및 차단
        /// </summary>
        private async Task CheckAndBlockSuspiciousIp(string ipAddress)
        {
            var ipCacheKey = $"ip_attempts:{ipAddress}";
            var ipAttempts = _cache.Get<int>(ipCacheKey);
            
            if (ipAttempts >= _bruteForceThreshold)
            {
                await BlockIpAddressAsync(ipAddress, TimeSpan.FromHours(1), 
                    $"Exceeded threshold with {ipAttempts} attempts");
            }
        }

        /// <summary>
        /// 위험도 점수 계산
        /// </summary>
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
                var failureCount = GetFailureCount(userId.Value);
                score += failureCount * 10;
            }

            return Math.Min(score, 100);
        }

        /// <summary>
        /// MFA 응답 메시지 생성
        /// </summary>
        private string GetMfaResponseMessage(bool isSuccess, int failedAttempts, string? failureReason)
        {
            if (isSuccess)
            {
                return "MFA authentication successful";
            }

            if (failedAttempts >= _maxFailedAttempts)
            {
                return "Maximum attempts exceeded. Account temporarily locked.";
            }

            var attemptsRemaining = _maxFailedAttempts - failedAttempts;
            return $"{failureReason ?? "Authentication failed"}. {attemptsRemaining} attempt(s) remaining.";
        }

        #endregion

        #region Helper Classes

        /// <summary>
        /// 계정 잠금 정보
        /// </summary>
        private class AccountLockInfo
        {
            public Guid UserId { get; set; }
            public string Reason { get; set; } = string.Empty;
            public DateTime LockedAt { get; set; }
            public DateTime LockedUntil { get; set; }
            public int FailedAttempts { get; set; }
        }

        /// <summary>
        /// 차단된 IP 정보
        /// </summary>
        private class BlockedIpInfo
        {
            public string IpAddress { get; set; } = string.Empty;
            public string Reason { get; set; } = string.Empty;
            public DateTime BlockedAt { get; set; }
            public DateTime BlockedUntil { get; set; }
        }

        /// <summary>
        /// MFA 시도 정보
        /// </summary>
        private class MfaAttemptInfo
        {
            public Guid UserId { get; set; }
            public int FailedAttempts { get; set; }
            public DateTime FirstAttemptTime { get; set; }
            public DateTime LastAttemptTime { get; set; }
        }

        #endregion
    }
}