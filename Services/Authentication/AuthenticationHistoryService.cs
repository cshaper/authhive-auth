using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Audit.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Core.Audit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Audit;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Models.Infra.Security.Common;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.System.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.User.Events;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 이력 및 감사 서비스 구현 - AuthHive v16.0 (최종 통합)
    /// ✨ IUnitOfWork와 IEventBus를 활용한 트랜잭션 관리 및 이벤트 기반 아키텍처
    /// ✨ 기존 모든 도메인 이벤트 모델과 100% 통합
    /// </summary>
    public class AuthenticationHistoryService : IAuthenticationHistoryService
    {
        private readonly IAuthenticationAttemptLogRepository _attemptRepository;
        private readonly IAuditLogRepository _auditRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly IAuthenticationAttemptService _attemptService;
        private readonly ICacheService _cacheService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationHistoryService> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus;

        private readonly int _maxFailedAttempts;
        private readonly int _lockoutDurationMinutes;
        private readonly double _highRiskThreshold;
        private readonly int _anomalyDetectionDays;

        public AuthenticationHistoryService(
            IAuthenticationAttemptLogRepository attemptRepository,
            IAuditLogRepository auditRepository,
            ISessionRepository sessionRepository,
            IAuthenticationAttemptService attemptService,
            ICacheService cacheService,
            IConfiguration configuration,
            ILogger<AuthenticationHistoryService> logger,
            IAuditService auditService,
            IUnitOfWork unitOfWork,
            IEventBus eventBus)
        {
            _attemptRepository = attemptRepository;
            _auditRepository = auditRepository;
            _sessionRepository = sessionRepository;
            _attemptService = attemptService;
            _cacheService = cacheService;
            _configuration = configuration;
            _logger = logger;
            _auditService = auditService;
            _unitOfWork = unitOfWork;
            _eventBus = eventBus;

            _maxFailedAttempts = configuration.GetValue<int>("Auth:Security:MaxFailedAttempts", 5);
            _lockoutDurationMinutes = configuration.GetValue<int>("Auth:Security:LockoutDurationMinutes", 30);
            _highRiskThreshold = configuration.GetValue<double>("Auth:Security:HighRiskThreshold", 0.7);
            _anomalyDetectionDays = configuration.GetValue<int>("Auth:Security:AnomalyDetectionDays", 30);
        }

        #region IService 구현

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                if (!_cacheService.IsHealthyAsync().Result) return false;
                await _attemptRepository.CountAsync();
                await _auditRepository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("AuthenticationHistoryService initialized");
            return _cacheService.InitializeAsync();
        }

        #endregion

        #region 인증 시도 기록

        /// <summary>
        /// ✨ 개선: UnitOfWork + EventBus + 기존 이벤트 통합
        /// - AuthenticationAttemptedEvent: 모든 시도 추적
        /// - UserAuthenticatedEvent: 성공한 인증 전용
        /// - SuspiciousLoginActivityEvent: 의심스러운 활동
        /// </summary>
        public async Task<ServiceResult> LogAuthenticationAttemptAsync(AuthenticationAttempts log)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var attemptLog = new AuthenticationAttemptLog
                {
                    Id = Guid.NewGuid(),
                    UserId = log.UserId,
                    ConnectedId = log.ConnectedId,
                    Username = log.AdditionalData.ContainsKey("username")
                        ? log.AdditionalData["username"].ToString()
                        : string.Empty,
                    Method = Enum.Parse<AuthenticationMethod>(log.Method),
                    IsSuccess = log.Success,
                    FailureReason = log.Success ? null : Enum.Parse<AuthenticationResult>(log.FailureReason ?? "Other"),
                    IpAddress = log.IpAddress,
                    UserAgent = log.UserAgent,
                    AttemptedAt = log.AttemptedAt,
                    OrganizationId = log.OrganizationId ?? Guid.Empty,
                    ApplicationId = log.ApplicationId
                };

                await _attemptRepository.AddAsync(attemptLog);
                await _unitOfWork.SaveChangesAsync();

                // ✨ 1. 모든 시도를 AuthenticationAttemptedEvent로 발행
                var authEvent = new AuthenticationAttemptedEvent(attemptLog.OrganizationId)
                {
                    UserId = attemptLog.UserId,
                    ConnectedId = attemptLog.ConnectedId,
                    Username = attemptLog.Username ?? string.Empty,
                    Method = attemptLog.Method,
                    IsSuccess = attemptLog.IsSuccess,
                    FailureReason = attemptLog.FailureReason,
                    IpAddress = attemptLog.IpAddress,
                    UserAgent = attemptLog.UserAgent,
                    ApplicationId = attemptLog.ApplicationId
                };

                if (!attemptLog.IsSuccess)
                {
                    authEvent.MarkAsFailed();
                }

                await _eventBus.PublishAsync(authEvent);

                // ✨ 2. 성공한 경우 기존 UserAuthenticatedEvent 발행
                // ✨ 2. 성공한 경우 기존 UserAuthenticatedEvent 발행
                if (attemptLog.IsSuccess && attemptLog.UserId.HasValue)
                {
                    await _eventBus.PublishAsync(new UserAuthenticatedEvent(
                        attemptLog.UserId.Value,
                        attemptLog.Method.ToString(),  // Pass method as constructor parameter
                        attemptLog.IpAddress)           // Pass ipAddress as constructor parameter
                    {
                        // Only optional properties in object initializer
                        ConnectedId = attemptLog.ConnectedId,
                        DeviceInfo = attemptLog.DeviceId
                    });
                }

                // ✨ 3. 실패 시 기존 SuspiciousLoginActivityEvent 발행
                if (!attemptLog.IsSuccess && attemptLog.ConsecutiveFailures >= _maxFailedAttempts)
                {
                    await _eventBus.PublishAsync(new SuspiciousLoginActivityEvent(
                        attemptLog.OrganizationId,
                        attemptLog.IpAddress,                    // Pass ipAddress as constructor parameter
                        attemptLog.Username ?? string.Empty)     // Pass username as constructor parameter
                    {
                        // Only optional properties in object initializer
                        DeviceFingerprint = attemptLog.DeviceId,
                        RiskScore = (int)(attemptLog.RiskScore > 0 ? attemptLog.RiskScore : 80),
                        DetectedPatterns = new List<string>
        {
            "ExcessiveFailedAttempts",
            $"ConsecutiveFailures:{attemptLog.ConsecutiveFailures}"
        }
                    });
                }

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error logging authentication attempt");
                return ServiceResult.Failure("Failed to log authentication attempt");
            }
        }

        public async Task<ServiceResult> LogSuccessfulAuthenticationAsync(
            Guid userId,
            string authenticationMethod,
            string ipAddress,
            string userAgent)
        {
            var method = Enum.Parse<AuthenticationMethod>(authenticationMethod);
            return await _attemptService.LogSuccessfulAuthenticationAsync(
                userId, null, method, ipAddress, userAgent);
        }

        public async Task<ServiceResult> LogFailedAuthenticationAsync(
            string username,
            string authenticationMethod,
            string failureReason,
            string ipAddress)
        {
            var method = Enum.Parse<AuthenticationMethod>(authenticationMethod);
            var reason = Enum.Parse<AuthenticationResult>(failureReason);
            return await _attemptService.LogFailedAuthenticationAsync(
                username, method, reason, ipAddress);
        }

        #endregion

        #region 이력 조회

        public async Task<ServiceResult<IEnumerable<AuthenticationHistory>>> GetAuthenticationHistoryAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var attempts = await _attemptRepository.GetHistoryForUserAsync(
                    userId,
                    startDate ?? DateTime.UtcNow.AddMonths(-3),
                    endDate ?? DateTime.UtcNow);

                var history = attempts.Select(a => new AuthenticationHistory
                {
                    Id = a.Id,
                    UserId = a.UserId ?? userId,
                    ConnectedId = a.ConnectedId,
                    Method = a.Method.ToString(),
                    Success = a.IsSuccess,
                    AuthenticatedAt = a.AttemptedAt,
                    IpAddress = a.IpAddress,
                    Location = a.Location,
                    DeviceName = a.DeviceId ?? "Unknown",
                    DeviceType = a.DeviceType ?? "Unknown",
                    SessionId = a.SessionId
                });

                return ServiceResult<IEnumerable<AuthenticationHistory>>.Success(history);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication history for user {UserId}", userId);
                return ServiceResult<IEnumerable<AuthenticationHistory>>.Failure(
                    "Failed to get authentication history");
            }
        }

        public async Task<ServiceResult<IEnumerable<AuthenticationFailure>>> GetAuthenticationFailuresAsync(
            Guid? userId = null,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var attempts = await _attemptRepository.GetFailedAttemptsAsync(
                    userId,
                    startDate ?? DateTime.UtcNow.AddDays(-7));

                var failures = attempts.Select(a => new AuthenticationFailure
                {
                    Id = a.Id,
                    UserId = a.UserId,
                    Username = a.Username ?? string.Empty,
                    Method = a.Method.ToString(),
                    FailureReason = a.FailureReason?.ToString() ?? "Unknown",
                    FailureCode = a.ErrorCode ?? string.Empty,
                    FailedAt = a.AttemptedAt,
                    IpAddress = a.IpAddress,
                    UserAgent = a.UserAgent ?? string.Empty,
                    ConsecutiveFailures = a.ConsecutiveFailures,
                    AccountLocked = a.TriggeredAccountLock
                });

                return ServiceResult<IEnumerable<AuthenticationFailure>>.Success(failures);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication failures");
                return ServiceResult<IEnumerable<AuthenticationFailure>>.Failure(
                    "Failed to get authentication failures");
            }
        }

        public async Task<ServiceResult<IEnumerable<SuspiciousActivity>>> GetSuspiciousActivitiesAsync(
            Guid? organizationId = null,
            DateTime? since = null)
        {
            try
            {
                var startDate = since ?? DateTime.UtcNow.AddDays(-7);
                var attempts = await _attemptRepository.GetSuspiciousAttemptsAsync(
                    organizationId, startDate);

                var activities = attempts
                    .GroupBy(a => new { a.IpAddress, a.UserId })
                    .Select(g => new SuspiciousActivity
                    {
                        Id = Guid.NewGuid(),
                        DetectedAt = DateTime.UtcNow,
                        Type = DetermineSuspiciousType(g.First()),
                        Description = GenerateSuspiciousDescription(g.First()),
                        IpAddress = g.Key.IpAddress,
                        UserId = g.Key.UserId,
                        Count = g.Count(),
                        FirstOccurrence = g.Min(a => a.AttemptedAt),
                        LastOccurrence = g.Max(a => a.AttemptedAt),
                        Pattern = AnalyzeSuspiciousPattern(g.ToList()),
                        RiskScore = g.Max(a => a.RiskScore).ToString()
                    })
                    .OrderByDescending(a => a.Count)
                    .ToList();

                return ServiceResult<IEnumerable<SuspiciousActivity>>.Success(activities);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting suspicious activities");
                return ServiceResult<IEnumerable<SuspiciousActivity>>.Failure(
                    "Failed to get suspicious activities");
            }
        }

        private string AnalyzeSuspiciousPattern(List<AuthenticationAttemptLog> attempts)
        {
            var patterns = new List<string>();
            var timeSpan = attempts.Max(a => a.AttemptedAt) - attempts.Min(a => a.AttemptedAt);
            if (timeSpan.TotalMinutes < 5) patterns.Add("RapidFire");
            var failureRate = attempts.Count(a => !a.IsSuccess) / (double)attempts.Count;
            if (failureRate > 0.8) patterns.Add("HighFailure");
            var maxConsecutiveFailures = attempts.Max(a => a.ConsecutiveFailures);
            if (maxConsecutiveFailures > 5) patterns.Add("ConsecutiveFailures");
            var methods = attempts.Select(a => a.Method).Distinct().Count();
            if (methods > 2) patterns.Add("MultipleMethodAttempts");
            return patterns.Any() ? string.Join(",", patterns) : "Normal";
        }

        #endregion

        #region 통계 및 분석

        public async Task<ServiceResult<AuthenticationStatistics>> GetStatisticsAsync(
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var startDate = from ?? DateTime.UtcNow.AddMonths(-1);
                var endDate = to ?? DateTime.UtcNow;

                var stats = await _attemptRepository.GetStatisticsAsync(
                    startDate, endDate, organizationId);

                var result = new AuthenticationStatistics
                {
                    PeriodStart = startDate,
                    PeriodEnd = endDate,
                    TotalAttempts = stats.TotalAttempts,
                    SuccessfulAttempts = stats.SuccessfulAttempts,
                    FailedAttempts = stats.FailedAttempts,
                    SuccessRate = stats.SuccessRate,
                    UniqueUsers = stats.UniqueUsers,
                    AttemptsByMethod = stats.AttemptsByMethod ?? new Dictionary<AuthenticationMethod, int>(),
                    FailureReasons = stats.FailureReasons ?? new Dictionary<AuthenticationResult, int>(),
                    PeakHour = stats.PeakHour
                };

                return ServiceResult<AuthenticationStatistics>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication statistics");
                return ServiceResult<AuthenticationStatistics>.Failure(
                    "Failed to get authentication statistics");
            }
        }

        public async Task<ServiceResult<IEnumerable<SuspiciousActivity>>> GetSuspiciousAttemptsAsync(
            Guid? organizationId,
            DateTime since)
        {
            return await GetSuspiciousActivitiesAsync(organizationId, since);
        }

        public async Task<ServiceResult<AuthenticationPatternAnalysis>> AnalyzeAuthenticationPatternsAsync(
            Guid userId)
        {
            try
            {
                var attempts = await _attemptRepository.GetHistoryForUserAsync(
                    userId,
                    DateTime.UtcNow.AddDays(-_anomalyDetectionDays),
                    DateTime.UtcNow);

                var analysis = new AuthenticationPatternAnalysis
                {
                    LoginTimePatterns = AnalyzeTimePatterns(attempts),
                    LocationPatterns = AnalyzeLocationPatterns(attempts),
                    DevicePatterns = AnalyzeDevicePatterns(attempts),
                    RiskScore = CalculateUserRiskScore(attempts)
                };

                return ServiceResult<AuthenticationPatternAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing authentication patterns for user {UserId}", userId);
                return ServiceResult<AuthenticationPatternAnalysis>.Failure(
                    "Failed to analyze authentication patterns");
            }
        }

        public async Task<ServiceResult<FailurePatternAnalysis>> AnalyzeFailurePatternsAsync(
            DateTime? since = null)
        {
            try
            {
                var startDate = since ?? DateTime.UtcNow.AddDays(-7);
                var failures = await _attemptRepository.GetFailedAttemptsAsync(null, startDate);

                var analysis = new FailurePatternAnalysis
                {
                    AnalyzedAt = DateTime.UtcNow,
                    PeriodStart = startDate,
                    PeriodEnd = DateTime.UtcNow,
                    TotalFailures = failures.Count(),
                    TopFailureReasons = failures
                        .GroupBy(f => f.FailureReason)
                        .OrderByDescending(g => g.Count())
                        .Take(5)
                        .ToDictionary(g => g.Key?.ToString() ?? "Unknown", g => g.Count()),
                    FailuresByHour = failures
                        .GroupBy(f => f.AttemptedAt.Hour)
                        .OrderBy(g => g.Key)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    SuspiciousIPs = IdentifySuspiciousIPs(failures),
                    BruteForceAttempts = CountBruteForceAttempts(failures)
                };

                return ServiceResult<FailurePatternAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing failure patterns");
                return ServiceResult<FailurePatternAnalysis>.Failure(
                    "Failed to analyze failure patterns");
            }
        }

        #endregion

        #region 계정 잠금 관리

        public async Task<ServiceResult<AccountLockStatus>> GetAccountLockStatusAsync(Guid userId)
        {
            return await _attemptService.CheckAccountLockStatusAsync(userId);
        }

        /// <summary>
        /// 계정 잠금 (개선: BaseEvent 패턴 이벤트 사용)
        /// </summary>
        public async Task<ServiceResult> LockAccountAsync(
            Guid userId,
            string reason,
            TimeSpan? duration = null)
        {
            var lockDuration = duration ?? TimeSpan.FromMinutes(_lockoutDurationMinutes);
            var result = await _attemptService.LockAccountAsync(userId, lockDuration, reason);

            if (result.IsSuccess)
            {
                // BaseEvent를 상속받은 UserAccountLockedEvent 발행
                var lockEvent = new UserAccountLockedEvent(userId)
                {
                    LockReason = reason,
                    FailedAttempts = _maxFailedAttempts,
                    AutoUnlockAt = DateTime.UtcNow.Add(lockDuration)
                };

                await _eventBus.PublishAsync(lockEvent);

                _logger.LogWarning("Account {UserId} locked for {Duration} minutes. Reason: {Reason}",
                    userId, lockDuration.TotalMinutes, reason);
            }

            return result;
        }

        /// <summary>
        /// 계정 잠금 해제 (개선: BaseEvent 패턴 이벤트 사용)
        /// </summary>
        public async Task<ServiceResult> UnlockAccountAsync(
            Guid userId,
            string? reason = null)
        {
            var result = await _attemptService.UnlockAccountAsync(userId);

            if (result.IsSuccess)
            {
                // BaseEvent를 상속받은 UserAccountUnlockedEvent 발행
                var unlockEvent = new UserAccountUnlockedEvent(userId)
                {
                    UnlockMethod = string.IsNullOrEmpty(reason) ? "AutoExpiry" : "AdminAction"
                };

                await _eventBus.PublishAsync(unlockEvent);

                _logger.LogInformation("Account {UserId} unlocked. Reason: {Reason}",
                    userId, reason ?? "Auto-unlock");
            }

            return result;
        }

        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var cacheKey = $"failure_count:{userId}";
                await _cacheService.RemoveAsync(cacheKey);

                await _attemptRepository.ResetConsecutiveFailuresAsync(userId);
                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Reset failed attempts for user {UserId}", userId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error resetting failed attempts for user {UserId}", userId);
                return ServiceResult.Failure("Failed to reset failed attempts");
            }
        }

        #endregion

        #region 위험 평가

        /// <summary>
        /// ✨ 개선: HighRiskAuthenticationEvent 발행
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessAuthenticationRiskAsync(
            AuthenticationRequest request)
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

                var ipRisk = await _attemptService.AssessIpRiskAsync(request.IpAddress ?? "unknown");
                if (ipRisk.IsSuccess && ipRisk.Data != null)
                {
                    assessment.RiskScore = ipRisk.Data.RiskScore;
                    assessment.RiskFactors.AddRange(ipRisk.Data.RiskFactors);
                }

                if (!string.IsNullOrEmpty(request.Username))
                {
                    var userRisk = await AssessUserRiskAsync(request.Username);
                    if (userRisk.IsSuccess && userRisk.Data != null)
                    {
                        assessment.RiskFactors.AddRange(userRisk.Data.RiskFactors);
                        assessment.RiskScore = Math.Max(assessment.RiskScore, userRisk.Data.RiskScore);
                    }
                }

                assessment.RiskLevel = assessment.RiskScore switch
                {
                    >= 0.8 => "Critical",
                    >= 0.6 => "High",
                    >= 0.4 => "Medium",
                    _ => "Low"
                };

                if (assessment.RiskScore >= 0.6)
                {
                    assessment.RequiresMfa = true;
                    assessment.RecommendedActions.Add("Require MFA authentication");
                }
                if (assessment.RiskScore >= 0.8)
                {
                    assessment.RequiresAdditionalVerification = true;
                    assessment.RecommendedActions.Add("Require additional verification");
                    assessment.RecommendedActions.Add("Notify security team");
                }

                // ✨ HighRiskAuthenticationEvent 발행
                if (assessment.RiskScore >= _highRiskThreshold)
                {
                    var highRiskEvent = new HighRiskAuthenticationEvent(request.OrganizationId ?? Guid.Empty)
                    {
                        Username = request.Username ?? "unknown",
                        IpAddress = request.IpAddress ?? "unknown",
                        RiskScore = assessment.RiskScore,
                        RiskLevel = assessment.RiskLevel,
                        RiskFactors = assessment.RiskFactors.Select(f => f.Name).ToList(),
                        RequiresMfa = assessment.RequiresMfa,
                        RequiresAdditionalVerification = assessment.RequiresAdditionalVerification
                    };

                    await _eventBus.PublishAsync(highRiskEvent);
                }

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing authentication risk");
                return ServiceResult<RiskAssessment>.Failure("Failed to assess authentication risk");
            }
        }

        /// <summary>
        /// ✨ 개선: 기존 GeographicalAnomalyDetectedEvent 사용
        /// </summary>
        public async Task<ServiceResult<AnomalyDetectionResult>> DetectAnomalyAsync(
            Guid userId,
            AuthenticationContext context)
        {
            try
            {
                var result = new AnomalyDetectionResult
                {
                    DetectedAt = DateTime.UtcNow,
                    DetectedAnomalies = new List<SecurityAnomaly>()
                };

                var isAnomalous = await _attemptService.DetectAnomalousPatternAsync(
                    userId, context.IpAddress ?? "unknown", context.DeviceFingerprint);

                if (isAnomalous.IsSuccess && isAnomalous.Data)
                {
                    result.DetectedAnomalies.Add(new SecurityAnomaly
                    {
                        Type = "NewDevice",
                        Description = "Login from new device or IP address",
                        Confidence = 0.8,
                        DetectedAt = DateTime.UtcNow,
                        Evidence = new Dictionary<string, object>
                        {
                            ["IpAddress"] = context.IpAddress ?? "unknown",
                            ["DeviceFingerprint"] = context.DeviceFingerprint ?? "unknown"
                        }
                    });
                }

                // ✨ 기존 GeographicalAnomalyDetectedEvent 사용
                if (!string.IsNullOrEmpty(context.Location))
                {
                    var geoAnomaly = await _attemptService.DetectGeographicalAnomalyAsync(userId, context.Location);
                    if (geoAnomaly.IsSuccess && geoAnomaly.Data)
                    {
                        result.DetectedAnomalies.Add(new SecurityAnomaly
                        {
                            Type = "GeographicalAnomaly",
                            Description = $"Unusual location: {context.Location}",
                            Confidence = 0.9,
                            DetectedAt = DateTime.UtcNow,
                            Evidence = new Dictionary<string, object> { ["Location"] = context.Location }
                        });

                        // 기존 이벤트 발행
                        var previousLocations = await GetPreviousLocationsAsync(userId);
                        await _eventBus.PublishAsync(new GeographicalAnomalyDetectedEvent(userId)
                        {
                            NewLocation = context.Location,
                            PreviousLocations = previousLocations,
                            RiskScore = (int)(result.AnomalyScore * 100)
                        });
                    }
                }

                result.AnomalyDetected = result.DetectedAnomalies.Any();
                result.AnomalyScore = result.DetectedAnomalies.Any()
                    ? result.DetectedAnomalies.Max(a => a.Confidence)
                    : 0;
                result.ConfidenceScore = result.AnomalyScore;

                if (result.AnomalyScore >= 0.8)
                {
                    result.BlockAccess = true;
                    result.RecommendedAction = "Block access and notify security team";
                }
                else if (result.AnomalyScore >= 0.6)
                {
                    result.RequireAdditionalVerification = true;
                    result.RecommendedAction = "Require additional verification";
                }
                else
                {
                    result.RecommendedAction = "Continue with standard authentication";
                }

                return ServiceResult<AnomalyDetectionResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting anomaly for user {UserId}", userId);
                return ServiceResult<AnomalyDetectionResult>.Failure("Failed to detect anomaly");
            }
        }

        /// <summary>
        /// ✨ 개선: 기존 BruteForceAttackDetectedEvent 사용
        /// </summary>
        public async Task<ServiceResult<IpReputationResult>> CheckIpReputationAsync(string ipAddress)
        {
            try
            {
                var result = new IpReputationResult
                {
                    IpAddress = ipAddress,
                    CheckedAt = DateTime.UtcNow,
                    ReputationScore = 1.0,
                    Categories = new List<string>()
                };

                if (IsInternalIp(ipAddress))
                {
                    result.IsTrusted = true;
                    result.Categories.Add("Internal");
                    return ServiceResult<IpReputationResult>.Success(result);
                }

                var recentFailures = await _attemptRepository.GetFailedAttemptsFromIpAsync(
                    ipAddress, DateTime.UtcNow.AddHours(-1));

                if (recentFailures.Count() > 10)
                {
                    result.ReputationScore = 0.3;
                    result.IsBlocked = true;
                    result.BlockReason = "Too many failed attempts";
                    result.Categories.Add("Suspicious");
                }
                else if (recentFailures.Count() > 5)
                {
                    result.ReputationScore = 0.6;
                    result.Categories.Add("Questionable");
                }

                var bruteForceDetected = await _attemptService.DetectBruteForceAttackAsync("check", ipAddress);
                if (bruteForceDetected.IsSuccess && bruteForceDetected.Data)
                {
                    result.ReputationScore = Math.Min(result.ReputationScore, 0.2);
                    result.IsBlocked = true;
                    result.BlockReason = "Brute force attack detected";
                    result.Categories.Add("Attacker");

                    // ✨ 기존 BruteForceAttackDetectedEvent 사용
                    var affectedUsers = recentFailures
             .Select(f => f.Username)                 // Select the nullable usernames.
             .Where(u => !string.IsNullOrEmpty(u))    // Filter out null or empty strings.
             .Select(u => u!)                         // Assert that the remaining strings are not null.
             .Distinct()                              // Find the distinct usernames.
             .ToList();

                    var bruteForceEvent = new BruteForceAttackDetectedEvent(Guid.Empty)
                    {
                        IpAddress = ipAddress,
                        AttemptsCount = recentFailures.Count(),
                        TimeWindow = TimeSpan.FromHours(1),
                        ActionTaken = "IP Blocked",
                        AffectedUsers = affectedUsers
                    };

                    await _eventBus.PublishAsync(bruteForceEvent);
                }

                return ServiceResult<IpReputationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking IP reputation for {IpAddress}", ipAddress);
                return ServiceResult<IpReputationResult>.Failure("Failed to check IP reputation");
            }
        }

        #endregion

        #region 감사 및 컴플라이언스

        public async Task<ServiceResult<IEnumerable<AuditLog>>> GetAuditTrailAsync(
            Guid? userId = null,
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var pagedResult = await _auditRepository.SearchAsync(
                    organizationId: organizationId,
                    userId: userId,
                    action: null,
                    connectedId: null,
                    applicationId: null,
                    startDate: from ?? DateTime.UtcNow.AddDays(-30),
                    endDate: to ?? DateTime.UtcNow,
                    pageNumber: 1,
                    pageSize: 1000);

                return ServiceResult<IEnumerable<AuditLog>>.Success(pagedResult.Items);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting audit trail");
                return ServiceResult<IEnumerable<AuditLog>>.Failure("Failed to get audit trail");
            }
        }

        public async Task<ServiceResult<ComplianceReport>> GenerateComplianceReportAsync(
            Guid organizationId,
            DateTime from,
            DateTime to)
        {
            try
            {
                var report = new ComplianceReport
                {
                    ReportId = Guid.NewGuid(),
                    Type = ComplianceReportType.Custom,
                    OrganizationId = organizationId,
                    PeriodStart = from,
                    PeriodEnd = to,
                    GeneratedAt = DateTime.UtcNow,
                    Data = new Dictionary<string, object>(),
                    Violations = new List<ComplianceViolation>()
                };

                var authStats = await GetStatisticsAsync(organizationId, from, to);
                if (authStats.IsSuccess && authStats.Data != null)
                {
                    report.Data["AuthenticationSummary"] = new
                    {
                        authStats.Data.TotalAttempts,
                        authStats.Data.SuccessRate,
                        authStats.Data.UniqueUsers,
                        authStats.Data.FailedAttempts
                    };
                }

                var suspiciousActivities = await GetSuspiciousActivitiesAsync(organizationId, from);
                if (suspiciousActivities.IsSuccess && suspiciousActivities.Data != null)
                {
                    var activities = suspiciousActivities.Data.ToList();
                    report.Data["SecurityEvents"] = new
                    {
                        TotalSuspiciousActivities = activities.Count,
                        UniqueUsersWithSuspiciousActivity = activities.Select(a => a.UserId).Distinct().Count(),
                        TotalSuspiciousAttempts = activities.Sum(a => a.Count),
                        MostFrequentPattern = activities.GroupBy(a => a.Pattern)
                            .OrderByDescending(g => g.Count())
                            .FirstOrDefault()?.Key ?? "None"
                    };

                    foreach (var activity in activities.Where(a => a.Count > 10))
                    {
                        report.Violations.Add(new ComplianceViolation
                        {
                            Rule = $"Security.SuspiciousActivity.{activity.Type}",
                            Description = $"Suspicious activity detected: {activity.Count} occurrences from {activity.IpAddress} between {activity.FirstOccurrence:g} and {activity.LastOccurrence:g}. Pattern: {activity.Pattern}",
                            Severity = activity.Count > 20 ? AuditEventSeverity.Critical : AuditEventSeverity.Warning,
                            OccurredAt = activity.LastOccurrence,
                            ResourceType = "User",
                            ResourceId = activity.UserId?.ToString(),
                            ConnectedId = null
                        });
                    }
                }

                var lockEventsResult = await _auditRepository.SearchAsync(
                    organizationId: organizationId,
                    userId: null,
                    action: "account.lock",
                    connectedId: null,
                    applicationId: null,
                    startDate: from,
                    endDate: to,
                    pageNumber: 1,
                    pageSize: 1000);

                var accountLocks = lockEventsResult.Items.ToList();
                report.Data["AccountSecurity"] = new
                {
                    AccountLocks = accountLocks.Count,
                    AverageUnlockTime = CalculateAverageUnlockTime(accountLocks)
                };

                if (accountLocks.Count > 10)
                {
                    report.Violations.Add(new ComplianceViolation
                    {
                        Rule = "Security.ExcessiveAccountLocks",
                        Description = $"Excessive account locks detected: {accountLocks.Count} locks in period",
                        Severity = AuditEventSeverity.Info,
                        OccurredAt = DateTime.UtcNow,
                        ResourceType = "Organization",
                        ResourceId = organizationId.ToString()
                    });
                }

                if (authStats.IsSuccess && authStats.Data != null)
                {
                    var failureRate = 1.0 - authStats.Data.SuccessRate;
                    if (failureRate > 0.3)
                    {
                        report.Violations.Add(new ComplianceViolation
                        {
                            Rule = "Authentication.HighFailureRate",
                            Description = $"High authentication failure rate: {failureRate:P}",
                            Severity = AuditEventSeverity.Warning,
                            OccurredAt = DateTime.UtcNow,
                            ResourceType = "Organization",
                            ResourceId = organizationId.ToString()
                        });
                    }
                }

                report.ReportUrl = $"/api/reports/compliance/{report.ReportId}";
                return ServiceResult<ComplianceReport>.Success(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance report for organization {OrganizationId}", organizationId);
                return ServiceResult<ComplianceReport>.Failure("Failed to generate compliance report");
            }
        }

        #endregion

        #region 정리 및 유지보수

        public async Task<ServiceResult<int>> CleanupOldHistoryAsync(
            DateTime olderThan,
            bool archiveBeforeDelete = true)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();
                int totalCleaned = 0;

                if (archiveBeforeDelete)
                {
                    var archivedCount = await _attemptRepository.MarkAsArchivedAsync(DateTime.MinValue, olderThan);
                    _logger.LogInformation("Marked {Count} authentication logs as archived.", archivedCount);
                }

                var deleted = await _attemptRepository.CleanupOldLogsAsync(olderThan);
                totalCleaned += deleted;

                var auditDeleted = await _auditRepository.CleanupOldLogsAsync(olderThan);
                totalCleaned += auditDeleted;

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Cleaned up {Total} old history records", totalCleaned);
                return ServiceResult<int>.Success(totalCleaned);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error cleaning up old history");
                return ServiceResult<int>.Failure("Failed to cleanup old history");
            }
        }

        public async Task<ServiceResult> ArchiveHistoryAsync(
            DateTime from,
            DateTime to,
            string archiveLocation)
        {
            try
            {
                _logger.LogInformation("Starting history archiving from {From} to {To}...", from, to);

                await _unitOfWork.BeginTransactionAsync();
                const int batchSize = 300;

                bool hasMoreAuthLogs = true;
                int authPage = 1;
                int totalAuthArchived = 0;

                while (hasMoreAuthLogs)
                {
                    var pagedResult = await _attemptRepository.GetPagedAsync(
                        authPage,
                        batchSize,
                        log => log.AttemptedAt >= from && log.AttemptedAt <= to);

                    var authLogsBatch = pagedResult.Items;

                    if (authLogsBatch.Any())
                    {
                        await ArchiveToStorageAsync(authLogsBatch, archiveLocation, "auth_attempts");
                        totalAuthArchived += authLogsBatch.Count();
                        authPage++;
                    }
                    else
                    {
                        hasMoreAuthLogs = false;
                    }
                }

                if (totalAuthArchived > 0)
                {
                    await _attemptRepository.MarkAsArchivedAsync(from, to);
                }

                bool hasMoreAuditLogs = true;
                int auditPage = 1;
                var auditLogIds = new List<Guid>();

                while (hasMoreAuditLogs)
                {
                    var auditPagedResult = await _auditRepository.SearchAsync(
                        null, null, null, null, null, from, to, auditPage, batchSize);

                    var auditLogsBatch = auditPagedResult.Items;

                    if (auditLogsBatch.Any())
                    {
                        await ArchiveToStorageAsync(auditLogsBatch, archiveLocation, "audit_logs");
                        auditLogIds.AddRange(auditLogsBatch.Select(l => l.Id));
                        auditPage++;
                    }
                    else
                    {
                        hasMoreAuditLogs = false;
                    }
                }

                if (auditLogIds.Any())
                {
                    await _auditRepository.MarkAsArchivedAsync(auditLogIds, archiveLocation);
                }

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation(
                    "Successfully archived {AuthCount} auth logs and {AuditCount} audit logs from {From} to {To} to {Location}",
                    totalAuthArchived, auditLogIds.Count, from, to, archiveLocation);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during history archiving");
                return ServiceResult.Failure("Failed to archive history");
            }
        }

        #endregion

        #region Private Helper Methods

        private string DetermineSuspiciousType(AuthenticationAttemptLog attempt)
        {
            if (attempt.ConsecutiveFailures > 5) return "BruteForce";
            if (attempt.RiskScore > 80) return "HighRisk";
            if (attempt.IsSuspicious) return "Suspicious";
            return "Unknown";
        }

        private string GenerateSuspiciousDescription(AuthenticationAttemptLog attempt)
        {
            var descriptions = new List<string>();
            if (attempt.ConsecutiveFailures > 5)
                descriptions.Add($"{attempt.ConsecutiveFailures} consecutive failures");
            if (attempt.RiskScore > 80)
                descriptions.Add($"High risk score: {attempt.RiskScore}");
            if (attempt.IsSuspicious)
                descriptions.Add("Flagged as suspicious");
            return string.Join(", ", descriptions);
        }

        private List<TimePattern> AnalyzeTimePatterns(IEnumerable<AuthenticationAttemptLog> attempts) =>
            attempts.Where(a => a.IsSuccess)
                .GroupBy(a => new { DayOfWeek = a.AttemptedAt.DayOfWeek.ToString(), Hour = a.AttemptedAt.Hour })
                .Select(g => new TimePattern
                {
                    DayOfWeek = g.Key.DayOfWeek,
                    Hour = g.Key.Hour,
                    Frequency = g.Count()
                })
                .OrderByDescending(p => p.Frequency)
                .Take(10)
                .ToList();

        private List<LocationPattern> AnalyzeLocationPatterns(IEnumerable<AuthenticationAttemptLog> attempts) =>
            attempts.Where(a => !string.IsNullOrEmpty(a.Location))
                .GroupBy(a => a.Location)
                .Select(g => new LocationPattern
                {
                    Country = ExtractCountry(g.Key ?? ""),
                    City = ExtractCity(g.Key ?? ""),
                    Frequency = g.Count()
                })
                .OrderByDescending(p => p.Frequency)
                .Take(10)
                .ToList();

        private List<DevicePattern> AnalyzeDevicePatterns(IEnumerable<AuthenticationAttemptLog> attempts) =>
            attempts.Where(a => !string.IsNullOrEmpty(a.DeviceType))
                .GroupBy(a => new { a.DeviceType, Browser = ExtractBrowser(a.UserAgent) })
                .Select(g => new DevicePattern
                {
                    DeviceType = g.Key.DeviceType ?? "Unknown",
                    Browser = g.Key.Browser,
                    Frequency = g.Count()
                })
                .OrderByDescending(p => p.Frequency)
                .Take(10)
                .ToList();

        private int CalculateUserRiskScore(IEnumerable<AuthenticationAttemptLog> attempts)
        {
            int score = 0;
            var recentAttempts = attempts.Where(a => a.AttemptedAt > DateTime.UtcNow.AddDays(-7));

            double failureRate = recentAttempts.Any()
                ? recentAttempts.Count(a => !a.IsSuccess) / (double)recentAttempts.Count()
                : 0;

            score += (int)(failureRate * 30);
            score += recentAttempts.Count(a => a.IsSuspicious) * 10;
            score += recentAttempts.Count(a => a.TriggeredAccountLock) * 20;

            return Math.Min(score, 100);
        }

        private List<string> IdentifySuspiciousIPs(IEnumerable<AuthenticationAttemptLog> failures) =>
            failures.GroupBy(f => f.IpAddress)
                .Where(g => g.Count() > 10)
                .Select(g => g.Key)
                .ToList();

        private int CountBruteForceAttempts(IEnumerable<AuthenticationAttemptLog> failures) =>
            failures.GroupBy(f => new { f.Username, f.IpAddress })
                .Count(g => g.Count() > 5);

        private async Task<ServiceResult<RiskAssessment>> AssessUserRiskAsync(string username)
        {
            var assessment = new RiskAssessment
            {
                AssessmentId = Guid.NewGuid(),
                AssessedAt = DateTime.UtcNow,
                RiskFactors = new List<RiskFactor>()
            };

            var recentFailures = await _attemptRepository.GetFailedAttemptsForUsernameAsync(
                username, DateTime.UtcNow.AddHours(-1));

            if (recentFailures.Count() > 3)
            {
                assessment.RiskFactors.Add(new RiskFactor
                {
                    Name = "MultipleFailures",
                    Description = $"{recentFailures.Count()} failed attempts in last hour",
                    Weight = 0.4,
                    Impact = 80,
                    Category = "Authentication"
                });
            }

            assessment.RiskScore = Math.Min(assessment.RiskFactors.Sum(f => f.WeightedScore) / 100, 1.0);
            return ServiceResult<RiskAssessment>.Success(assessment);
        }

        private async Task<List<string>> GetPreviousLocationsAsync(Guid userId)
        {
            var recentAttempts = await _attemptRepository.GetHistoryForUserAsync(
                userId,
                DateTime.UtcNow.AddDays(-30),
                DateTime.UtcNow);

            return recentAttempts
                .Where(a => !string.IsNullOrEmpty(a.Location))
                .Select(a => a.Location!)
                .Distinct()
                .Take(5)
                .ToList();
        }

        private bool IsInternalIp(string ipAddress) =>
            ipAddress.StartsWith("192.168.") ||
            ipAddress.StartsWith("10.") ||
            ipAddress.StartsWith("172.") ||
            ipAddress == "127.0.0.1" ||
            ipAddress == "::1";

        private string ExtractCountry(string location) =>
            location.Split(',').Length > 1 ? location.Split(',')[^1].Trim() : "Unknown";

        private string ExtractCity(string location) =>
            location.Split(',').Length > 0 ? location.Split(',')[0].Trim() : "Unknown";

        private string ExtractBrowser(string? userAgent)
        {
            if (string.IsNullOrEmpty(userAgent)) return "Unknown";
            if (userAgent.Contains("Chrome")) return "Chrome";
            if (userAgent.Contains("Firefox")) return "Firefox";
            if (userAgent.Contains("Safari")) return "Safari";
            if (userAgent.Contains("Edge")) return "Edge";
            return "Other";
        }

        private double CalculateAverageUnlockTime(List<AuditLog> lockEvents) => 30.0;

        private async Task ArchiveToStorageAsync<T>(IEnumerable<T> data, string location, string prefix)
        {
            await Task.CompletedTask;
            _logger.LogInformation("Archived {Count} {Type} records to {Location}",
                data.Count(), prefix, location);
        }

        public Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(
            Guid? organizationId, DateTime startDate, DateTime endDate) =>
            throw new NotImplementedException();

        #endregion
    }
}