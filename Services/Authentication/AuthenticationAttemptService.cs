using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Constants.Common;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.Business.Events;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using UserEntity = AuthHive.Core.Entities.User.User;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// Authentication attempt management service implementation - AuthHive v15
    /// Optimized version using memory cache with proper plan limits and events
    /// </summary>
    public class AuthenticationAttemptService : IAuthenticationAttemptService
    {
        #region Dependencies

        private readonly IAuthenticationAttemptLogRepository _attemptLogRepository;
        private readonly IUserRepository _userRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IPlanSubscriptionRepository _planSubscriptionRepository;
        private readonly ICacheService _cacheService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationAttemptService> _logger;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;

        // Plan-based configuration values - will be loaded based on subscription
        private int _maxFailedAttempts;
        private int _lockoutDurationMinutes;
        private int _bruteForceThreshold;
        private int _riskScoreThreshold;
        private int _maxConcurrentSessions;
        private int _maxIpBlocksPerOrg;

        // Cache key prefixes
        private const string BLOCKED_IP_PREFIX = "blocked_ip:";
        private const string TRUSTED_IP_PREFIX = "trusted_ip:";
        private const string USER_LOCK_PREFIX = "user_lock:";
        private const string FAILURE_COUNT_PREFIX = "failure_count:";
        private const string MFA_ATTEMPTS_PREFIX = "mfa_attempts:";
        private const string RECENT_ATTEMPTS_PREFIX = "recent_attempts:";
        private const string IP_ATTEMPTS_PREFIX = "ip_attempts:";
        private const string ORG_SETTINGS_PREFIX = "org_settings:";

        #endregion

        #region Constructor

        public AuthenticationAttemptService(
            IAuthenticationAttemptLogRepository attemptLogRepository,
            IUserRepository userRepository,
            ISessionRepository sessionRepository,
            IConnectedIdRepository connectedIdRepository,
            IPlanSubscriptionRepository planSubscriptionRepository,
            ICacheService cacheService,
            IConfiguration configuration,
            ILogger<AuthenticationAttemptService> logger,
            IEventBus eventBus,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider)
        {
            _attemptLogRepository = attemptLogRepository ?? throw new ArgumentNullException(nameof(attemptLogRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _planSubscriptionRepository = planSubscriptionRepository ?? throw new ArgumentNullException(nameof(planSubscriptionRepository));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));

            // Load default configuration (will be overridden by plan-specific settings)
            LoadDefaultConfiguration();
        }

        private void LoadDefaultConfiguration()
        {
            // Default values - will be overridden based on organization's plan
            _maxFailedAttempts = _configuration.GetValue<int>("Auth:Security:MaxFailedAttempts",
                AuthConstants.Security.MaxFailedLoginAttempts);
            _lockoutDurationMinutes = _configuration.GetValue<int>("Auth:Security:LockoutDurationMinutes",
                AuthConstants.Security.AccountLockoutDurationMinutes);
            _bruteForceThreshold = _configuration.GetValue<int>("Auth:Security:BruteForceThreshold", 10);
            _riskScoreThreshold = _configuration.GetValue<int>("Auth:Security:RiskScoreThreshold", 70);
            _maxConcurrentSessions = AuthConstants.Session.MaxConcurrentGlobalSessions;
            _maxIpBlocksPerOrg = 100; // Default limit for IP blocks per organization
        }

        #endregion

        #region IService Interface Implementation

        /// <summary>
        /// Check service health status
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 리포지토리 접근성 확인
                await _attemptLogRepository.CountAsync();

                // 캐시 동작 확인
                string healthCheckKey = "health_check";
                await _cacheService.SetStringAsync(healthCheckKey, true.ToString(), TimeSpan.FromSeconds(10));

                // Remove를 await RemoveAsync로 수정
                await _cacheService.RemoveAsync(healthCheckKey);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service health check failed");
                return false;
            }
        }

        /// <summary>
        /// Initialize service
        /// </summary>
        public Task InitializeAsync()
        {
            _logger.LogInformation("AuthenticationAttemptService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region Authentication Attempt Logging

        /// <summary>
        /// Log authentication attempt
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> LogAuthenticationAttemptAsync(
            AuthenticationRequest request)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Get organization settings and plan limits
                var orgSettings = await GetOrganizationSecuritySettingsAsync(request.OrganizationId ?? Guid.Empty);

                // Check IP blocking with plan limits
                var ipBlockResult = await CheckIpBlockingWithPlanLimitsAsync(
                    request.IpAddress,
                    request.OrganizationId,
                    request.ApplicationId);

                if (!ipBlockResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<AuthenticationResponse>.Failure(
                        ipBlockResult.ErrorMessage ?? "IP address is blocked",
                        AuthConstants.ErrorCodes.SuspiciousLogin);
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
                    AttemptedAt = _dateTimeProvider.UtcNow,
                    Provider = request.Provider,
                    DeviceId = request.DeviceInfo?.DeviceId,
                    DeviceType = request.DeviceInfo?.DeviceType,
                    Location = request.DeviceInfo?.Location
                };

                await _attemptLogRepository.AddAsync(attemptLog);

                // Update recent attempts cache
                await UpdateRecentAttemptsCacheAsync(attemptLog);

                // Check for suspicious patterns
                var suspiciousActivity = await DetectSuspiciousActivityAsync(
                    attemptLog,
                    orgSettings);

                if (suspiciousActivity)
                {
                    // 1. 먼저 이벤트 발행에 필수적인 정보가 있는지 확인합니다.
                    // string.IsNullOrEmpty를 사용하면 null과 빈 문자열("")을 모두 검사할 수 있습니다.
                    if (string.IsNullOrEmpty(request.IpAddress) || string.IsNullOrEmpty(request.Username))
                    {
                        // 2. 필수 정보가 없다면, 이벤트를 발행하는 대신 경고 로그를 남기고 종료합니다.
                        _logger.LogWarning("의심스러운 활동이 감지되었으나, IP 주소 또는 사용자 이름이 누락되어 이벤트를 발행할 수 없습니다.");
                    }
                    else
                    {
                        // 3. 모든 필수 정보가 유효할 때만 이벤트를 생성하고 발행합니다.
                        // 이 블록 안에서는 request.IpAddress와 request.Username이 null이 아님이 보장됩니다.
                        await _eventBus.PublishAsync(new SuspiciousLoginActivityEvent(
                            organizationId: request.OrganizationId ?? Guid.Empty,
                            ipAddress: request.IpAddress, // 경고 없이 안전하게 사용
                            username: request.Username    // 경고 없이 안전하게 사용
                        )
                        {
                            DeviceFingerprint = request.DeviceInfo?.DeviceId,
                            RiskScore = await CalculateRiskScoreAsync(request.IpAddress, null),
                            DetectedPatterns = new List<string> { "Unusual login pattern detected" }
                        });
                    }
                }
                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = attemptLog.IsSuccess,
                    UserId = attemptLog.UserId,
                    ConnectedId = attemptLog.ConnectedId
                });
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error logging authentication attempt");
                return ServiceResult<AuthenticationResponse>.Failure(
                    "Failed to log authentication attempt",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Log successful authentication
        /// </summary>
        public async Task<ServiceResult> LogSuccessfulAuthenticationAsync(
            Guid userId,
            Guid? connectedId,
            AuthenticationMethod method,
            string ipAddress,
            string? userAgent = null)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("User not found", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                // Check concurrent session limits based on plan
                var sessionLimitResult = await CheckSessionLimitsAsync(userId, user.OrganizationId);
                if (!sessionLimitResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return sessionLimitResult;
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
                    AttemptedAt = _dateTimeProvider.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty,
                    ConsecutiveFailures = 0
                };

                await _attemptLogRepository.AddAsync(attemptLog);

                // Clear failure caches
                ClearUserFailureCaches(userId);
                await UpdateRecentAttemptsCacheAsync(attemptLog);

                // Publish successful authentication event
                await _eventBus.PublishAsync(new UserAuthenticatedEvent(
                    // --- 생성자에 필수 값 전달 ---
                    userId: userId,
                    method: method.ToString(),
                    ipAddress: ipAddress
                )
                {
                    // --- 나머지 선택적 속성들은 여기서 초기화 ---
                    ConnectedId = connectedId,
                    DeviceInfo = userAgent,
                    OrganizationId = user.OrganizationId
                });

                _logger.LogInformation(
                    "Successful authentication logged for user {UserId} from {IpAddress}",
                    userId, ipAddress);

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error logging successful authentication for user {UserId}", userId);
                return ServiceResult.Failure(
                    "Failed to log successful authentication",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Log failed authentication
        /// </summary>
        public async Task<ServiceResult> LogFailedAuthenticationAsync(
            string identifier,
            AuthenticationMethod method,
            AuthenticationResult reason,
            string ipAddress,
            string? userAgent = null)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Find user
                Guid? userId = await _userRepository.FindByUsernameOrEmailAsync(identifier);
                UserEntity? user = null;
                Guid organizationId = Guid.Empty;

                if (userId.HasValue)
                {
                    user = await _userRepository.GetByIdAsync(userId.Value);
                    organizationId = user?.OrganizationId ?? Guid.Empty;
                }

                // Get organization security settings
                var orgSettings = await GetOrganizationSecuritySettingsAsync(organizationId);

                // Calculate consecutive failures (using cache)
                var consecutiveFailures = 0;
                if (userId.HasValue)
                {
                    var failureCount = await IncrementFailureCountAsync(userId ?? Guid.Empty);
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
                    AttemptedAt = _dateTimeProvider.UtcNow,
                    OrganizationId = organizationId,
                    ConsecutiveFailures = consecutiveFailures
                };

                // Check account lock with plan-specific limits
                if (userId.HasValue && consecutiveFailures >= orgSettings.MaxFailedAttempts)
                {
                    attemptLog.TriggeredAccountLock = true;

                    var lockDuration = TimeSpan.FromMinutes(orgSettings.LockoutDurationMinutes);
                    await LockAccountAsync(
                        userId.Value,
                        lockDuration,
                        $"Too many failed attempts ({consecutiveFailures})");

                    // Publish account locked event
                    await _eventBus.PublishAsync(new AccountLockedEvent(userId.Value)
                    {
                        OrganizationId = organizationId,
                        Reason = $"Exceeded maximum failed attempts ({orgSettings.MaxFailedAttempts})",
                        LockedUntil = _dateTimeProvider.UtcNow.Add(lockDuration),
                        FailedAttempts = consecutiveFailures,
                        IpAddress = ipAddress
                    });
                }

                // Risk assessment
                attemptLog.RiskScore = await CalculateRiskScoreAsync(ipAddress, userId);
                attemptLog.IsSuspicious = attemptLog.RiskScore > orgSettings.RiskScoreThreshold;

                await _attemptLogRepository.AddAsync(attemptLog);
                await UpdateRecentAttemptsCacheAsync(attemptLog);

                // Check for brute force attack with plan limits
                var bruteForceDetected = await CheckAndBlockSuspiciousIpAsync(
                    ipAddress,
                    organizationId,
                    orgSettings);

                if (bruteForceDetected)
                {
                    await _eventBus.PublishAsync(new BruteForceAttackDetectedEvent(organizationId)
                    {
                        IpAddress = ipAddress,
                        AttemptsCount = await GetIpAttemptsAsync(ipAddress),
                        TimeWindow = TimeSpan.FromMinutes(10),
                        ActionTaken = "IP blocked",
                        AffectedUsers = new List<string> { identifier }
                    });
                }

                _logger.LogWarning(
                    "Failed authentication attempt for {Identifier} from {IpAddress}. Consecutive failures: {Count}",
                    identifier, ipAddress, consecutiveFailures);

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error logging failed authentication");
                return ServiceResult.Failure(
                    "Failed to log failed authentication",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Log MFA authentication attempt (improved version)
        /// </summary>
        public async Task<ServiceResult<MfaChallengeResponse>> LogMfaAttemptAsync(
            Guid userId,
            MfaMethod method,
            bool isSuccess,
            string? failureReason = null)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Check account lock status
                var lockStatus = await CheckAccountLockStatusAsync(userId);
                if (lockStatus.IsSuccess && lockStatus.Data?.IsLocked == true)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<MfaChallengeResponse>.Failure(
                        "Account is locked",
                        AuthConstants.ErrorCodes.AccountLocked);
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<MfaChallengeResponse>.Failure(
                        "User not found",
                        AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                // Get organization settings
                var orgSettings = await GetOrganizationSecuritySettingsAsync(user.OrganizationId ?? Guid.Empty);

                // MFA attempt count management (cache utilization)
                var mfaCacheKey = $"{MFA_ATTEMPTS_PREFIX}{userId}";
                var mfaAttempts = await _cacheService.GetAsync<MfaAttemptInfo>(mfaCacheKey) ?? new MfaAttemptInfo
                {
                    UserId = userId,
                    FailedAttempts = 0,
                    FirstAttemptTime = _dateTimeProvider.UtcNow
                };

                if (!isSuccess)
                {
                    mfaAttempts.FailedAttempts++;
                    mfaAttempts.LastAttemptTime = _dateTimeProvider.UtcNow;

                    // Cache for 30 minutes
                    // 객체 자체를 SetAsync 메서드에 전달
                    await _cacheService.SetAsync(mfaCacheKey, mfaAttempts, TimeSpan.FromMinutes(30));
                }
                else
                {
                    // Clear cache on success
                    await _cacheService.RemoveAsync(mfaCacheKey);
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
                    AttemptedAt = _dateTimeProvider.UtcNow,
                    OrganizationId = user.OrganizationId ?? Guid.Empty,
                    ConsecutiveFailures = mfaAttempts.FailedAttempts
                };

                await _attemptLogRepository.AddAsync(attemptLog);
                await UpdateRecentAttemptsCacheAsync(attemptLog);

                // Check if max attempts exceeded
                if (mfaAttempts.FailedAttempts >= orgSettings.MaxFailedAttempts)
                {
                    var lockDuration = TimeSpan.FromMinutes(orgSettings.LockoutDurationMinutes);
                    await LockAccountAsync(userId, lockDuration, "Too many failed MFA attempts");

                    await _eventBus.PublishAsync(new MfaFailureThresholdExceededEvent(userId)
                    {
                        OrganizationId = user.OrganizationId,
                        FailedAttempts = mfaAttempts.FailedAttempts,
                        Method = method.ToString(),
                        AccountLocked = true,
                        LockedUntil = _dateTimeProvider.UtcNow.Add(lockDuration)
                    });
                }

                var response = new MfaChallengeResponse
                {
                    ChallengeId = Guid.NewGuid().ToString(),
                    Method = method,
                    ChallengeType = isSuccess ? "completed" : "failed",
                    ExpiresAt = _dateTimeProvider.UtcNow.AddMinutes(5),
                    AttemptsRemaining = Math.Max(0, orgSettings.MaxFailedAttempts - mfaAttempts.FailedAttempts),
                    AttemptsAllowed = orgSettings.MaxFailedAttempts,
                    CodeSent = false,
                    Message = GetMfaResponseMessage(
                        isSuccess,
                        mfaAttempts.FailedAttempts,
                        orgSettings.MaxFailedAttempts,
                        failureReason)
                };

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult<MfaChallengeResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error logging MFA attempt for user {UserId}", userId);
                return ServiceResult<MfaChallengeResponse>.Failure(
                    "Failed to log MFA attempt",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Account Lock Management

        /// <summary>
        /// Check account lock status
        /// </summary>
        public async Task<ServiceResult<AccountLockStatus>> CheckAccountLockStatusAsync(Guid userId)
        {
            try
            {
                var cacheKey = $"{USER_LOCK_PREFIX}{userId}";
                // 1. GetAsync를 사용해 비동기적으로 데이터를 가져옵니다.
                var lockInfo = await _cacheService.GetAsync<AccountLockInfo>(cacheKey);

                // 2. 가져온 데이터가 null이 아닌지 확인합니다.
                if (lockInfo != null)
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

                // Check failure count from cache
                var failureCount = await GetFailureCountAsync(userId);

                await Task.CompletedTask; // Avoid async warning

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
                return ServiceResult<AccountLockStatus>.Failure(
                    "Failed to check account lock status",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Lock user account
        /// </summary>
        public async Task<ServiceResult> LockAccountAsync(
            Guid userId,
            TimeSpan duration,
            string reason)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                var lockInfo = new AccountLockInfo
                {
                    UserId = userId,
                    Reason = reason,
                    LockedAt = _dateTimeProvider.UtcNow,
                    LockedUntil = _dateTimeProvider.UtcNow.Add(duration),
                    FailedAttempts = await GetFailureCountAsync(userId)
                };

                var cacheKey = $"{USER_LOCK_PREFIX}{userId}";
                // 객체 저장을 위한 제네릭 메서드 SetAsync 사용
                await _cacheService.SetAsync(cacheKey, lockInfo, TimeSpan.FromMinutes(_lockoutDurationMinutes));

                // Update user entity
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    user.IsAccountLocked = true;
                    user.AccountLockedUntil = lockInfo.LockedUntil;
                    await _userRepository.UpdateAsync(user);
                }

                // Terminate active sessions
                var sessions = await _sessionRepository.GetActiveSessionsByUserAsync(userId);
                foreach (var session in sessions)
                {
                    session.Status = SessionStatus.Terminated;
                    session.EndReason = SessionEndReason.SecurityViolation;
                    await _sessionRepository.UpdateAsync(session);
                }

                _logger.LogWarning("Account locked for user {UserId}: {Reason}", userId, reason);

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error locking account for user {UserId}", userId);
                return ServiceResult.Failure(
                    "Failed to lock account",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Unlock user account
        /// </summary>
        public async Task<ServiceResult> UnlockAccountAsync(Guid userId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Remove lock info from cache
                var lockCacheKey = $"{USER_LOCK_PREFIX}{userId}";
                await _cacheService.RemoveAsync(lockCacheKey);

                // Clear failure counts
                ClearUserFailureCaches(userId);

                // Update user entity
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    user.IsAccountLocked = false;
                    user.AccountLockedUntil = null;
                    await _userRepository.UpdateAsync(user);
                }

                _logger.LogInformation("Account unlocked for user {UserId}", userId);

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error unlocking account for user {UserId}", userId);
                return ServiceResult.Failure(
                    "Failed to unlock account",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Check and apply automatic lock policy
        /// </summary>
        public async Task<ServiceResult<bool>> CheckAndApplyLockPolicyAsync(Guid userId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<bool>.Failure(
                        "User not found",
                        AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                var orgSettings = await GetOrganizationSecuritySettingsAsync(user.OrganizationId ?? Guid.Empty);
                var failureCount = await GetFailureCountAsync(userId);

                if (failureCount >= orgSettings.MaxFailedAttempts)
                {
                    var lockDuration = TimeSpan.FromMinutes(orgSettings.LockoutDurationMinutes);
                    await LockAccountAsync(userId, lockDuration, "Auto-lock policy triggered");

                    await _unitOfWork.CommitTransactionAsync();
                    return ServiceResult<bool>.Success(true);
                }

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error checking lock policy for user {UserId}", userId);
                return ServiceResult<bool>.Failure(
                    "Failed to check lock policy",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Security Threat Detection

        /// <summary>
        /// Detect brute force attack
        /// </summary>
        public async Task<ServiceResult<bool>> DetectBruteForceAttackAsync(
            string identifier,
            string ipAddress)
        {
            try
            {
                // Get organization ID from identifier
                var userId = await _userRepository.FindByUsernameOrEmailAsync(identifier);
                var organizationId = Guid.Empty;

                if (userId.HasValue)
                {
                    var user = await _userRepository.GetByIdAsync(userId.Value);
                    organizationId = user?.OrganizationId ?? Guid.Empty;
                }

                var orgSettings = await GetOrganizationSecuritySettingsAsync(organizationId);

                // Check IP attempt count (cache utilization)
                var ipAttempts = await GetIpAttemptsAsync(ipAddress);

                if (ipAttempts >= orgSettings.BruteForceThreshold)
                {
                    _logger.LogWarning(
                        "Brute force attack detected from IP {IpAddress} for {Identifier}. Attempts: {Count}",
                        ipAddress, identifier, ipAttempts);

                    // Auto-block IP
                    await BlockIpAddressAsync(
                        ipAddress,
                        TimeSpan.FromHours(1),
                        "Brute force attack detected",
                        organizationId);

                    // Publish event
                    await _eventBus.PublishAsync(new BruteForceAttackDetectedEvent(organizationId)
                    {
                        IpAddress = ipAddress,
                        AttemptsCount = ipAttempts,
                        TimeWindow = TimeSpan.FromMinutes(10),
                        ActionTaken = "IP blocked for 1 hour",
                        AffectedUsers = new List<string> { identifier }
                    });

                    return ServiceResult<bool>.Success(true);
                }

                return ServiceResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting brute force attack");
                return ServiceResult<bool>.Failure(
                    "Failed to detect brute force attack",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Assess IP-based risk
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessIpRiskAsync(string ipAddress)
        {
            try
            {
                var assessment = new RiskAssessment
                {
                    AssessmentId = Guid.NewGuid(),
                    AssessedAt = _dateTimeProvider.UtcNow,
                    RiskFactors = new List<RiskFactor>(),
                    RecommendedActions = new List<string>()
                };

                // Check if trusted IP
                if (IsTrustedIp(ipAddress))
                {
                    assessment.RiskScore = 0;
                    assessment.RiskLevel = "Low";
                    return ServiceResult<RiskAssessment>.Success(assessment);
                }
                // Check if blocked IP
                if (await IsIpBlockedAsync(ipAddress))
                {
                    assessment.RiskScore = 1.0;
                    assessment.RiskLevel = "Critical";
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        Name = "BlockedIP",
                        Description = "IP is currently blocked",
                        Weight = 1.0,
                        Impact = 100,
                        Category = "Network"
                    });
                    return ServiceResult<RiskAssessment>.Success(assessment);
                }

                // Check IP attempt count from cache
                var ipAttempts = await GetIpAttemptsAsync(ipAddress);
                if (ipAttempts > 5)
                {
                    assessment.RiskFactors.Add(new RiskFactor
                    {
                        Name = "HighFailureRate",
                        Description = $"High failure rate: {ipAttempts} attempts in recent period",
                        Weight = 0.3,
                        Impact = 80,
                        Category = "Authentication"
                    });
                }

                // Calculate risk score
                assessment.RiskScore = Math.Min(assessment.RiskFactors.Sum(x => x.Weight), 1.0);

                // Determine risk level
                assessment.RiskLevel = assessment.RiskScore switch
                {
                    >= 0.8 => "Critical",
                    >= 0.6 => "High",
                    >= 0.4 => "Medium",
                    _ => "Low"
                };

                // Recommended actions
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

                await Task.CompletedTask; // Avoid async warning
                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing IP risk for {IpAddress}", ipAddress);
                return ServiceResult<RiskAssessment>.Failure(
                    "Failed to assess IP risk",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Detect anomalous pattern
        /// </summary>
        public async Task<ServiceResult<bool>> DetectAnomalousPatternAsync(
            Guid userId,
            string ipAddress,
            string? deviceFingerprint = null)
        {
            try
            {
                // Get recent attempts from cache
                var recentAttempts = await GetRecentAttemptsFromCacheAsync(userId);
                var isNewIp = !recentAttempts.Any(a => a.IpAddress == ipAddress);
                var isNewDevice = !string.IsNullOrEmpty(deviceFingerprint) &&
                                 !recentAttempts.Any(a => a.DeviceId == deviceFingerprint);

                var isAnomalous = isNewIp || isNewDevice;

                if (isAnomalous)
                {
                    _logger.LogWarning(
                        "Anomalous pattern detected for user {UserId} from IP {IpAddress}. New IP: {NewIp}, New Device: {NewDevice}",
                        userId, ipAddress, isNewIp, isNewDevice);

                    // Publish suspicious activity event
                    var user = await _userRepository.GetByIdAsync(userId);
                    if (user != null)
                    {
                        await _eventBus.PublishAsync(new AnomalousLoginPatternDetectedEvent(userId)
                        {
                            OrganizationId = user.OrganizationId,
                            IpAddress = ipAddress,
                            DeviceFingerprint = deviceFingerprint,
                            IsNewLocation = isNewIp,
                            IsNewDevice = isNewDevice,
                            RiskScore = isNewIp && isNewDevice ? 80 : 50
                        });
                    }
                }

                return ServiceResult<bool>.Success(isAnomalous);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting anomalous pattern");
                return ServiceResult<bool>.Failure(
                    "Failed to detect anomalous pattern",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Detect geographical anomaly
        /// </summary>
        public async Task<ServiceResult<bool>> DetectGeographicalAnomalyAsync(
            Guid userId,
            string currentLocation)
        {
            try
            {
                // 1. 이 메서드는 'recentAttempts'를 기반으로 동작합니다. 'devices' 변수는 없습니다.
                var recentAttempts = await GetRecentAttemptsFromCacheAsync(userId);

                // Now you can use LINQ methods on recentAttempts
                var recentLocations = recentAttempts
                    .Where(a => !string.IsNullOrEmpty(a.Location))
                    .Select(a => a.Location)
                    .Distinct()
                    .ToList();

                var isNewLocation = !recentLocations.Contains(currentLocation);

                if (isNewLocation)
                {
                    _logger.LogWarning(
                        "Geographical anomaly detected for user {UserId}: New location {Location}",
                        userId, currentLocation);

                    var user = await _userRepository.GetByIdAsync(userId);
                    if (user != null)
                    {
                        // 3. 따라서 'if' 블록 안에서는 변수를 새로 만들 필요 없이,
                        //    위에서 만든 'recentLocations'를 그대로 사용하면 됩니다.
                        await _eventBus.PublishAsync(new GeographicalAnomalyDetectedEvent(userId)
                        {
                            OrganizationId = user.OrganizationId,
                            NewLocation = currentLocation,

                            // 이미 존재하는 'recentLocations'를 OfType<string>()으로 안전하게 변환
                            PreviousLocations = recentLocations.OfType<string>().ToList(),

                            RiskScore = 60
                        });
                    }
                }

                return ServiceResult<bool>.Success(isNewLocation);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting geographical anomaly");
                return ServiceResult<bool>.Failure(
                    "Failed to detect geographical anomaly",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region IP Management

        /// <summary>
        /// Block IP address with plan limit checking
        /// </summary>
        public async Task<ServiceResult> BlockIpAddressAsync(
            string ipAddress,
            TimeSpan duration,
            string reason,
            Guid? organizationId = null)
        {
            try
            {
                // Check organization's IP block limit
                if (organizationId.HasValue)
                {
                    var orgSettings = await GetOrganizationSecuritySettingsAsync(organizationId.Value);
                    var currentBlocks = GetOrganizationBlockedIpCount(organizationId.Value);

                    if (currentBlocks >= orgSettings.MaxIpBlocks)
                    {
                        // Publish event that limit is reached
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                            organizationId.Value,
                            orgSettings.PlanKey,
                            PlanLimitType.IpBlockLimit,
                            currentBlocks,
                            orgSettings.MaxIpBlocks,
                            Guid.Empty
                        ));

                        return ServiceResult.Failure(
                            $"IP block limit reached ({orgSettings.MaxIpBlocks}). Upgrade plan for more blocks.",
                            AuthConstants.ErrorCodes.RATE_LIMIT_EXCEEDED);
                    }
                }

                var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
                await _cacheService.SetAsync(cacheKey, new BlockedIpInfo
                {
                    IpAddress = ipAddress,
                    Reason = reason,
                    BlockedAt = _dateTimeProvider.UtcNow,
                    BlockedUntil = _dateTimeProvider.UtcNow.Add(duration),
                    OrganizationId = organizationId
                }, duration);

                _logger.LogWarning("IP {IpAddress} blocked: {Reason}", ipAddress, reason);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking IP {IpAddress}", ipAddress);
                return ServiceResult.Failure(
                    "Failed to block IP",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Unblock IP address
        /// </summary>
        public async Task<ServiceResult> UnblockIpAddressAsync(string ipAddress)
        {
            try
            {
                var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";
                await _cacheService.RemoveAsync(cacheKey);

                _logger.LogInformation("IP {IpAddress} unblocked", ipAddress);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking IP {IpAddress}", ipAddress);
                return ServiceResult.Failure(
                    "Failed to unblock IP",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Get blocked IP addresses
        /// </summary>
        public Task<ServiceResult<IEnumerable<string>>> GetBlockedIpAddressesAsync()
        {
            try
            {
                // In production, this should query from a persistent store
                var blockedIps = new List<string>();
                return Task.FromResult(ServiceResult<IEnumerable<string>>.Success(blockedIps));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting blocked IPs");
                return Task.FromResult(ServiceResult<IEnumerable<string>>.Failure(
                    "Failed to get blocked IPs",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR));
            }
        }

        /// <summary>
        /// Add trusted IP address
        /// </summary>
        public async Task<ServiceResult> AddTrustedIpAddressAsync(
            Guid organizationId,
            string ipAddress)
        {
            try
            {
                var cacheKey = $"{TRUSTED_IP_PREFIX}{organizationId}:{ipAddress}";
                await _cacheService.SetStringAsync(cacheKey, true.ToString(), TimeSpan.FromDays(365));

                _logger.LogInformation(
                    "Trusted IP {IpAddress} added for organization {OrganizationId}",
                    ipAddress, organizationId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding trusted IP");
                return ServiceResult.Failure(
                    "Failed to add trusted IP",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Authentication History Queries

        /// <summary>
        /// Get user authentication history
        /// </summary>
        public async Task<ServiceResult<AuthenticationHistory>> GetAuthenticationHistoryAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                // Set query period clearly
                var effectiveEndDate = endDate ?? _dateTimeProvider.UtcNow;
                var effectiveStartDate = startDate ?? effectiveEndDate.AddDays(-30);

                // Get all records for the user within the period
                var userHistory = await _attemptLogRepository.GetHistoryForUserAsync(
                    userId,
                    effectiveStartDate,
                    effectiveEndDate);

                // Find the most recent successful record
                var lastSuccessfulAttempt = userHistory.FirstOrDefault(log => log.IsSuccess);

                if (lastSuccessfulAttempt == null)
                {
                    _logger.LogWarning(
                        "No successful authentication history found for user {UserId} in the specified period",
                        userId);
                    return ServiceResult<AuthenticationHistory>.Failure(
                        "No successful authentication history found",
                        AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                // Map to DTO
                var historyDto = new AuthenticationHistory
                {
                    Id = lastSuccessfulAttempt.Id,
                    UserId = userId,
                    ConnectedId = lastSuccessfulAttempt.ConnectedId,
                    Method = lastSuccessfulAttempt.Method.ToString(),
                    Success = true,
                    AuthenticatedAt = lastSuccessfulAttempt.AttemptedAt,
                    IpAddress = lastSuccessfulAttempt.IpAddress,
                    Location = lastSuccessfulAttempt.Location,
                    DeviceName = lastSuccessfulAttempt.DeviceId ?? CommonDefaults.UnknownDevice,
                    DeviceType = lastSuccessfulAttempt.DeviceType ?? CommonDefaults.UnknownDeviceType,
                    SessionId = lastSuccessfulAttempt.SessionId
                };

                return ServiceResult<AuthenticationHistory>.Success(historyDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication history for user {UserId}", userId);
                return ServiceResult<AuthenticationHistory>.Failure(
                    "An error occurred while fetching authentication history",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Get recent authentication attempts
        /// </summary>
        public async Task<ServiceResult<IEnumerable<AuthenticationAttempts>>> GetRecentAttemptsAsync(
            Guid userId,
            int count = 10)
        {
            try
            {
                IEnumerable<AuthenticationAttemptLog> finalLogs;

                // Check cache first
                var cachedAttempts = await GetRecentAttemptsFromCacheAsync(userId);

                if (cachedAttempts != null && cachedAttempts.Count() >= count)
                {
                    finalLogs = cachedAttempts;
                }
                else
                {
                    // Get from database if cache is insufficient
                    var dbHistory = await _attemptLogRepository.GetHistoryForUserAsync(
                        userId,
                        _dateTimeProvider.UtcNow.AddDays(-30),
                        _dateTimeProvider.UtcNow);

                    finalLogs = dbHistory;
                }

                // Convert to DTO
                var resultDto = finalLogs
                    .Take(count)
                    .Select(x => new AuthenticationAttempts
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

                return ServiceResult<IEnumerable<AuthenticationAttempts>>.Success(resultDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting recent attempts for user {UserId}", userId);
                return ServiceResult<IEnumerable<AuthenticationAttempts>>.Failure(
                    "Failed to get recent attempts",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Get failed authentication attempts
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
                return ServiceResult<IEnumerable<AuthenticationFailure>>.Failure(
                    "Failed to get failed attempts",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Statistics and Analysis

        /// <summary>
        /// Calculate authentication success rate
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
                return ServiceResult<double>.Failure(
                    "Failed to calculate success rate",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Get authentication method statistics
        /// </summary>
        public async Task<ServiceResult<Dictionary<AuthenticationMethod, int>>> GetMethodStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null)
        {
            try
            {
                var from = startDate ?? _dateTimeProvider.UtcNow.AddMonths(-1);
                var to = _dateTimeProvider.UtcNow;

                var stats = await _attemptLogRepository.GetStatisticsAsync(from, to, organizationId);
                return ServiceResult<Dictionary<AuthenticationMethod, int>>.Success(stats.AttemptsByMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting method statistics");
                return ServiceResult<Dictionary<AuthenticationMethod, int>>.Failure(
                    "Failed to get method statistics",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Analyze failure reasons
        /// </summary>
        public async Task<ServiceResult<Dictionary<AuthenticationResult, int>>> AnalyzeFailureReasonsAsync(
            Guid organizationId,
            int periodDays = 30)
        {
            try
            {
                var from = _dateTimeProvider.UtcNow.AddDays(-periodDays);
                var to = _dateTimeProvider.UtcNow;

                var stats = await _attemptLogRepository.GetStatisticsAsync(from, to, organizationId);
                return ServiceResult<Dictionary<AuthenticationResult, int>>.Success(stats.FailureReasons);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing failure reasons");
                return ServiceResult<Dictionary<AuthenticationResult, int>>.Failure(
                    "Failed to analyze failure reasons",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Notifications

        /// <summary>
        /// Notify suspicious activity
        /// </summary>
        public async Task<ServiceResult> NotifySuspiciousActivityAsync(
            Guid userId,
            string activityDescription)
        {
            try
            {
                // Publish event for suspicious activity
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    await _eventBus.PublishAsync(new SuspiciousActivityNotificationEvent(
                        userId,
                        activityDescription)  // Pass as constructor parameter
                    {
                        OrganizationId = user.OrganizationId,
                        DetectedAt = _dateTimeProvider.UtcNow,
                        NotificationRequired = true
                    });
                }

                _logger.LogWarning(
                    "Suspicious activity for user {UserId}: {Description}",
                    userId, activityDescription);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying suspicious activity");
                return ServiceResult.Failure(
                    "Failed to notify suspicious activity",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Notify new device login
        /// </summary>
        public async Task<ServiceResult> NotifyNewDeviceLoginAsync(
            Guid userId,
            string deviceInfo,
            string location)
        {
            try
            {
                // Publish event for new device login
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    await _eventBus.PublishAsync(new NewDeviceLoginEvent(
                        // --- 생성자에 필수 값 전달 ---
                        userId: userId,
                        deviceInfo: deviceInfo,
                        location: location
                    )
                    {
                        // --- 나머지 선택적 속성들은 여기서 초기화 ---
                        OrganizationId = user.OrganizationId,
                        LoginTime = _dateTimeProvider.UtcNow,
                        RequiresVerification = true
                    });
                }

                _logger.LogInformation(
                    "New device login for user {UserId}: {Device} from {Location}",
                    userId, deviceInfo, location);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying new device login");
                return ServiceResult.Failure(
                    "Failed to notify new device login",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Notify account lock
        /// </summary>
        // async 키워드만 제거
        public Task<ServiceResult> NotifyAccountLockAsync(Guid userId, string reason)
        {
            try
            {
                _logger.LogWarning("Account locked notification for user {UserId}: {Reason}", userId, reason);
                // Task.FromResult를 사용하여 결과를 Task로 감싸서 반환
                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error notifying account lock");
                return Task.FromResult(ServiceResult.Failure(
                    "Failed to notify account lock",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR));
            }
        }

        #endregion

        #region Data Management

        /// <summary>
        /// Cleanup old logs
        /// </summary>
        public async Task<ServiceResult<int>> CleanupOldLogsAsync(
            int olderThanDays,
            bool keepFailedOnly = false)
        {
            try
            {
                var before = _dateTimeProvider.UtcNow.AddDays(-olderThanDays);
                var count = await _attemptLogRepository.CleanupOldLogsAsync(before);

                _logger.LogInformation("Cleaned up {Count} old authentication logs", count);
                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up old logs");
                return ServiceResult<int>.Failure(
                    "Failed to cleanup old logs",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// Archive authentication logs
        /// </summary>
        public async Task<ServiceResult<int>> ArchiveLogsAsync(
            Guid organizationId,
            DateTime beforeDate)
        {
            try
            {
                var archiveLocation = _configuration["Storage:ArchiveLocation"] ?? "archive";
                var count = await _attemptLogRepository.ArchiveSuccessfulLogsAsync(beforeDate, archiveLocation);

                _logger.LogInformation(
                    "Archived {Count} authentication logs for organization {OrganizationId}",
                    count, organizationId);

                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving logs");
                return ServiceResult<int>.Failure(
                    "Failed to archive logs",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Get organization security settings based on plan
        /// </summary>
        private async Task<OrganizationSecuritySettings> GetOrganizationSecuritySettingsAsync(Guid organizationId)
        {
            var cacheKey = $"{ORG_SETTINGS_PREFIX}{organizationId}";

            return await _cacheService.GetOrSetAsync(
                cacheKey,
                async () =>
                {
                    // Get organization's plan
                    var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(organizationId);
                    var planKey = subscription?.PlanKey ?? PricingConstants.DefaultPlanKey;

                    return new OrganizationSecuritySettings
                    {
                        OrganizationId = organizationId,
                        PlanKey = planKey,
                        MaxFailedAttempts = GetPlanBasedLimit(planKey, "MaxFailedAttempts", 5),
                        LockoutDurationMinutes = GetPlanBasedLimit(planKey, "LockoutDuration", 30),
                        BruteForceThreshold = GetPlanBasedLimit(planKey, "BruteForceThreshold", 10),
                        RiskScoreThreshold = GetPlanBasedLimit(planKey, "RiskScoreThreshold", 70),
                        MaxConcurrentSessions = GetMaxSessionsForPlan(planKey),
                        MaxIpBlocks = GetMaxIpBlocksForPlan(planKey)
                    };
                },
                TimeSpan.FromMinutes(5)
            );
        }

        /// <summary>
        /// Get plan-based limit value
        /// </summary>
        private int GetPlanBasedLimit(string planKey, string limitType, int defaultValue)
        {
            // Define limits based on plan
            return (planKey, limitType) switch
            {
                (PricingConstants.SubscriptionPlans.BASIC_KEY, "MaxFailedAttempts") => 3,
                (PricingConstants.SubscriptionPlans.PRO_KEY, "MaxFailedAttempts") => 5,
                (PricingConstants.SubscriptionPlans.BUSINESS_KEY, "MaxFailedAttempts") => 10,
                (PricingConstants.SubscriptionPlans.ENTERPRISE_KEY, "MaxFailedAttempts") => 20,

                (PricingConstants.SubscriptionPlans.BASIC_KEY, "LockoutDuration") => 60,  // 1 hour for basic
                (PricingConstants.SubscriptionPlans.PRO_KEY, "LockoutDuration") => 30,
                (PricingConstants.SubscriptionPlans.BUSINESS_KEY, "LockoutDuration") => 15,
                (PricingConstants.SubscriptionPlans.ENTERPRISE_KEY, "LockoutDuration") => 10,

                (PricingConstants.SubscriptionPlans.BASIC_KEY, "BruteForceThreshold") => 5,
                (PricingConstants.SubscriptionPlans.PRO_KEY, "BruteForceThreshold") => 10,
                (PricingConstants.SubscriptionPlans.BUSINESS_KEY, "BruteForceThreshold") => 20,
                (PricingConstants.SubscriptionPlans.ENTERPRISE_KEY, "BruteForceThreshold") => 50,

                _ => defaultValue
            };
        }

        /// <summary>
        /// Get maximum sessions allowed for plan
        /// </summary>
        private int GetMaxSessionsForPlan(string planKey)
        {
            return planKey switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => 1,
                PricingConstants.SubscriptionPlans.PRO_KEY => 3,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => 10,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => -1, // Unlimited
                _ => 3
            };
        }

        /// <summary>
        /// Get maximum IP blocks allowed for plan
        /// </summary>
        private int GetMaxIpBlocksForPlan(string planKey)
        {
            return planKey switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => 10,
                PricingConstants.SubscriptionPlans.PRO_KEY => 50,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => 200,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => -1, // Unlimited
                _ => 10
            };
        }

        /// <summary>
        /// Check IP blocking with plan limits
        /// </summary>
        private async Task<ServiceResult> CheckIpBlockingWithPlanLimitsAsync(
            string? ipAddress,
            Guid? organizationId,
            Guid? applicationId)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return ServiceResult.Success();

            if (await IsIpBlockedAsync(ipAddress))
            {
                // Publish event for blocked IP attempt
                await _eventBus.PublishAsync(new BlockedIpAccessAttemptEvent(
                    // --- 생성자에 필수 값 전달 ---
                    organizationId: organizationId ?? Guid.Empty,
                    ipAddress: ipAddress
                )
                {
                    // --- 나머지 선택적 속성들은 여기서 초기화 ---
                    ApplicationId = applicationId,
                    AttemptTime = _dateTimeProvider.UtcNow
                });

                return ServiceResult.Failure("IP address is blocked", AuthConstants.ErrorCodes.SuspiciousLogin);
            }

            return ServiceResult.Success();
        }
        /// <summary>
        /// Check session limits based on plan
        /// </summary>
        private async Task<ServiceResult> CheckSessionLimitsAsync(Guid userId, Guid? organizationId)
        {
            if (!organizationId.HasValue)
                return ServiceResult.Success();

            var orgSettings = await GetOrganizationSecuritySettingsAsync(organizationId.Value);

            if (orgSettings.MaxConcurrentSessions <= 0) // Unlimited
                return ServiceResult.Success();

            var activeSessions = await _sessionRepository.GetActiveSessionsByUserAsync(userId);
            var activeCount = activeSessions.Count();

            if (activeCount >= orgSettings.MaxConcurrentSessions)
            {
                // Publish plan limit reached event
                await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                    organizationId.Value,
                    orgSettings.PlanKey,
                    PlanLimitType.ConccurentSessions,
                    activeCount,
                    orgSettings.MaxConcurrentSessions,
                    userId
                ));

                return ServiceResult.Failure(
                    $"Maximum concurrent sessions limit ({orgSettings.MaxConcurrentSessions}) reached for {orgSettings.PlanKey} plan",
                    AuthConstants.ErrorCodes.RATE_LIMIT_EXCEEDED);
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// Detect suspicious activity based on patterns
        /// </summary>
        private async Task<bool> DetectSuspiciousActivityAsync(
            AuthenticationAttemptLog attemptLog,
            OrganizationSecuritySettings settings)
        {
            // Check various suspicious patterns
            var ipAttempts = await GetIpAttemptsAsync(attemptLog.IpAddress);
            var riskScore = await CalculateRiskScoreAsync(attemptLog.IpAddress, attemptLog.UserId);

            return ipAttempts > 5 || riskScore > settings.RiskScoreThreshold;
        }

        /// <summary>
        /// Check if IP is blocked
        /// </summary>
        private async Task<bool> IsIpBlockedAsync(string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;

            var cacheKey = $"{BLOCKED_IP_PREFIX}{ipAddress}";

            // Option 1: Use ExistsAsync if you just need to check existence
            return await _cacheService.ExistsAsync(cacheKey);
        }

        /// <summary>
        /// Check if IP is trusted
        /// </summary>
        private bool IsTrustedIp(string ipAddress)
        {
            // Check for local IPs
            if (ipAddress.StartsWith("192.168.") ||
                ipAddress == CommonDefaults.DefaultLocalIpV6 ||
                ipAddress == CommonDefaults.DefaultLocalIpV4)
                return true;

            // Check cache for trusted IPs
            // In production, implement more sophisticated logic
            return false;
        }

        /// <summary>
        /// Increment user failure count
        /// </summary>
        private async Task<int> IncrementFailureCountAsync(Guid userId)
        {
            var cacheKey = $"{FAILURE_COUNT_PREFIX}{userId}";

            // IncrementAsync is atomic and handles the increment operation
            var currentCount = await _cacheService.IncrementAsync(cacheKey, 1);

            // Note: IncrementAsync might not support expiration directly
            // You may need to set expiration separately if not already set
            // or handle it in your cache implementation

            return (int)currentCount;
        }

        /// <summary>
        /// Get user failure count
        /// </summary>
        private async Task<int> GetFailureCountAsync(Guid userId)
        {
            var cacheKey = $"{FAILURE_COUNT_PREFIX}{userId}";

            // Option 1: Using GetStringAsync (if storing as string)
            var countStr = await _cacheService.GetStringAsync(cacheKey);
            return string.IsNullOrEmpty(countStr) ? 0 : int.Parse(countStr);
        }
        /// <summary>
        /// Get IP attempt count
        /// </summary>
        private async Task<int> GetIpAttemptsAsync(string ipAddress)
        {
            var cacheKey = $"{IP_ATTEMPTS_PREFIX}{ipAddress}";

            // Option 1: Using GetStringAsync (if storing as string)
            var attemptsStr = await _cacheService.GetStringAsync(cacheKey);
            return string.IsNullOrEmpty(attemptsStr) ? 0 : int.Parse(attemptsStr);
        }

        /// <summary>
        /// Get organization blocked IP count
        /// </summary>
        private int GetOrganizationBlockedIpCount(Guid organizationId)
        {
            // In production, query from persistent store
            // For now, return estimated count
            return 0;
        }

        /// <summary>
        /// Clear user failure related caches
        /// </summary>
        private async void ClearUserFailureCaches(Guid userId)
        {
            await _cacheService.RemoveAsync($"{FAILURE_COUNT_PREFIX}{userId}");
            await _cacheService.RemoveAsync($"{MFA_ATTEMPTS_PREFIX}{userId}");
        }

        /// <summary>
        /// Update recent attempts cache
        /// </summary>
        private async Task UpdateRecentAttemptsCacheAsync(AuthenticationAttemptLog attemptLog)
        {
            if (attemptLog.UserId.HasValue)
            {
                var cacheKey = $"{RECENT_ATTEMPTS_PREFIX}{attemptLog.UserId}";
                var recentAttempts = await _cacheService.GetAsync<List<AuthenticationAttemptLog>>(cacheKey)
                                   ?? new List<AuthenticationAttemptLog>();

                recentAttempts.Insert(0, attemptLog);

                // Keep only last 100 attempts
                if (recentAttempts.Count > 100)
                {
                    recentAttempts = recentAttempts.Take(100).ToList();
                }

                // Cache for 1 hour
                await _cacheService.SetAsync(cacheKey, recentAttempts, TimeSpan.FromHours(1));
            }

            // Update IP attempt count - Option 1: Using IncrementAsync (preferred)
            var ipCacheKey = $"{IP_ATTEMPTS_PREFIX}{attemptLog.IpAddress}";
            await _cacheService.IncrementAsync(ipCacheKey, 1);

            // Option 2: If you need to set expiration and IncrementAsync doesn't support it
            // var ipAttemptsStr = await _cacheService.GetStringAsync(ipCacheKey);
            // var ipAttempts = string.IsNullOrEmpty(ipAttemptsStr) ? 0 : int.Parse(ipAttemptsStr);
            // await _cacheService.SetStringAsync(ipCacheKey, (ipAttempts + 1).ToString(), TimeSpan.FromMinutes(10));
        }

        /// <summary>
        /// Get recent attempts from cache
        /// </summary>
        private async Task<List<AuthenticationAttemptLog>> GetRecentAttemptsFromCacheAsync(Guid userId)
        {
            var cacheKey = $"{RECENT_ATTEMPTS_PREFIX}{userId}";
            return await _cacheService.GetAsync<List<AuthenticationAttemptLog>>(cacheKey)
                   ?? new List<AuthenticationAttemptLog>();
        }

        /// <summary>
        /// Check and block suspicious IP
        /// </summary>
        private async Task<bool> CheckAndBlockSuspiciousIpAsync(
            string ipAddress,
            Guid organizationId,
            OrganizationSecuritySettings settings)
        {
            var ipAttempts = await GetIpAttemptsAsync(ipAddress);

            if (ipAttempts >= settings.BruteForceThreshold)
            {
                await BlockIpAddressAsync(
                    ipAddress,
                    TimeSpan.FromHours(1),
                    $"Exceeded threshold with {ipAttempts} attempts",
                    organizationId);

                return true;
            }

            return false;
        }

        /// <summary>
        /// Calculate risk score for authentication attempt
        /// </summary>
        private async Task<int> CalculateRiskScoreAsync(string ipAddress, Guid? userId)
        {
            var score = 0;

            // IP-based risk
            var ipRisk = await AssessIpRiskAsync(ipAddress);
            if (ipRisk.IsSuccess && ipRisk.Data != null)
            {
                score += (int)(ipRisk.Data.RiskScore * 50);
            }

            // User-based risk
            if (userId.HasValue)
            {
                var failureCount = await GetFailureCountAsync(userId.Value);
                score += failureCount * 10;
            }

            return Math.Min(score, 100);
        }

        /// <summary>
        /// Get MFA response message
        /// </summary>
        private string GetMfaResponseMessage(
            bool isSuccess,
            int failedAttempts,
            int maxAttempts,
            string? failureReason)
        {
            if (isSuccess)
            {
                return "MFA authentication successful";
            }

            if (failedAttempts >= maxAttempts)
            {
                return $"Maximum attempts ({maxAttempts}) exceeded. Account temporarily locked.";
            }

            var attemptsRemaining = maxAttempts - failedAttempts;
            return $"{failureReason ?? "Authentication failed"}. {attemptsRemaining} attempt(s) remaining.";
        }

        #endregion

        #region Helper Classes

        /// <summary>
        /// Organization security settings
        /// </summary>
        private class OrganizationSecuritySettings
        {
            public Guid OrganizationId { get; set; }
            public string PlanKey { get; set; } = PricingConstants.DefaultPlanKey;
            public int MaxFailedAttempts { get; set; }
            public int LockoutDurationMinutes { get; set; }
            public int BruteForceThreshold { get; set; }
            public int RiskScoreThreshold { get; set; }
            public int MaxConcurrentSessions { get; set; }
            public int MaxIpBlocks { get; set; }
        }

        /// <summary>
        /// Account lock information
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
        /// Blocked IP information
        /// </summary>
        private class BlockedIpInfo
        {
            public string IpAddress { get; set; } = string.Empty;
            public string Reason { get; set; } = string.Empty;
            public DateTime BlockedAt { get; set; }
            public DateTime BlockedUntil { get; set; }
            public Guid? OrganizationId { get; set; }
        }

        /// <summary>
        /// MFA attempt information
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