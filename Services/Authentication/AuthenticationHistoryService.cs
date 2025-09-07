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
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Audit;
using Microsoft.EntityFrameworkCore;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 이력 및 감사 서비스 구현 - AuthHive v15.5
    /// 인증 시도, 성공/실패 추적, 패턴 분석, 위험 평가를 통합 관리
    /// </summary>
    public class AuthenticationHistoryService : IAuthenticationHistoryService
    {
        private readonly IAuthenticationAttemptLogRepository _attemptRepository;
        private readonly IAuditLogRepository _auditRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly IAuthenticationAttemptService _attemptService;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationHistoryService> _logger;

        // 설정값
        private readonly int _maxFailedAttempts;
        private readonly int _lockoutDurationMinutes;
        private readonly double _highRiskThreshold;
        private readonly int _anomalyDetectionDays;

        public AuthenticationHistoryService(
            IAuthenticationAttemptLogRepository attemptRepository,
            IAuditLogRepository auditRepository,
            ISessionRepository sessionRepository,
            IAuthenticationAttemptService attemptService,
            IMemoryCache cache,
            IConfiguration configuration,
            ILogger<AuthenticationHistoryService> logger)
        {
            _attemptRepository = attemptRepository;
            _auditRepository = auditRepository;
            _sessionRepository = sessionRepository;
            _attemptService = attemptService;
            _cache = cache;
            _configuration = configuration;
            _logger = logger;

            // 설정 로드
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
            return Task.CompletedTask;
        }

        #endregion

        #region 인증 시도 기록

        public async Task<ServiceResult> LogAuthenticationAttemptAsync(AuthenticationAttempts log)
        {
            try
            {
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

                // 감사 로그 생성
                await CreateAuditLogForAttemptAsync(attemptLog);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
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

            // 시간 패턴 분석
            var timeSpan = attempts.Max(a => a.AttemptedAt) - attempts.Min(a => a.AttemptedAt);
            if (timeSpan.TotalMinutes < 5)
            {
                patterns.Add("RapidFire");
            }

            // 실패 패턴 분석
            var failureRate = attempts.Count(a => !a.IsSuccess) / (double)attempts.Count;
            if (failureRate > 0.8)
            {
                patterns.Add("HighFailure");
            }

            // 연속 실패 패턴
            var maxConsecutiveFailures = attempts.Max(a => a.ConsecutiveFailures);
            if (maxConsecutiveFailures > 5)
            {
                patterns.Add("ConsecutiveFailures");
            }

            // 다양한 인증 방법 시도
            var methods = attempts.Select(a => a.Method).Distinct().Count();
            if (methods > 2)
            {
                patterns.Add("MultipleMethodAttempts");
            }

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
                    // AverageAttemptsPerUser는 계산된 속성이므로 설정 불필요
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

        // 메서드 추가
        public async Task<ServiceResult<IEnumerable<SuspiciousActivity>>> GetSuspiciousAttemptsAsync(
            Guid? organizationId,
            DateTime since)
        {
            // GetSuspiciousActivitiesAsync를 호출하거나 직접 구현
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

        public async Task<ServiceResult> LockAccountAsync(
            Guid userId,
            string reason,
            TimeSpan? duration = null)
        {
            var lockDuration = duration ?? TimeSpan.FromMinutes(_lockoutDurationMinutes);
            return await _attemptService.LockAccountAsync(userId, lockDuration, reason);
        }

        public async Task<ServiceResult> UnlockAccountAsync(
            Guid userId,
            string? reason = null)
        {
            var result = await _attemptService.UnlockAccountAsync(userId);

            if (result.IsSuccess && !string.IsNullOrEmpty(reason))
            {
                await CreateAuditLogAsync(new AuditLog
                {
                    Id = Guid.NewGuid(),
                    ActionType = AuditActionType.Update,
                    Action = "account.unlock",
                    ResourceType = "User",
                    ResourceId = userId.ToString(),
                    Success = true,
                    Metadata = $"{{\"reason\":\"{reason}\"}}",
                    Timestamp = DateTime.UtcNow,
                    Severity = AuditEventSeverity.Info
                });
            }

            return result;
        }

        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId)
        {
            try
            {
                // 캐시 초기화
                var cacheKey = $"failure_count:{userId}";
                _cache.Remove(cacheKey);

                // DB 업데이트
                await _attemptRepository.ResetConsecutiveFailuresAsync(userId);

                _logger.LogInformation("Reset failed attempts for user {UserId}", userId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting failed attempts for user {UserId}", userId);
                return ServiceResult.Failure("Failed to reset failed attempts");
            }
        }

        #endregion

        #region 위험 평가

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

                // IP 위험도 평가
                var ipRisk = await _attemptService.AssessIpRiskAsync(request.IpAddress ?? "unknown");
                if (ipRisk.IsSuccess && ipRisk.Data != null)
                {
                    assessment.RiskScore = ipRisk.Data.RiskScore;
                    assessment.RiskFactors.AddRange(ipRisk.Data.RiskFactors);
                }

                // 사용자 이력 기반 위험도
                if (!string.IsNullOrEmpty(request.Username))
                {
                    var userRisk = await AssessUserRiskAsync(request.Username);
                    if (userRisk.IsSuccess && userRisk.Data != null)
                    {
                        assessment.RiskFactors.AddRange(userRisk.Data.RiskFactors);
                        assessment.RiskScore = Math.Max(assessment.RiskScore, userRisk.Data.RiskScore);
                    }
                }

                // 위험 수준 결정
                assessment.RiskLevel = assessment.RiskScore switch
                {
                    >= 0.8 => "Critical",
                    >= 0.6 => "High",
                    >= 0.4 => "Medium",
                    _ => "Low"
                };

                // 권장 조치 결정
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

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing authentication risk");
                return ServiceResult<RiskAssessment>.Failure("Failed to assess authentication risk");
            }
        }

        public async Task<ServiceResult<AnomalyDetectionResult>> DetectAnomalyAsync(
            Guid userId,
            AuthenticationContext context)
        {
            try
            {
                var result = new AnomalyDetectionResult
                {
                    DetectedAt = DateTime.UtcNow,
                    DetectedAnomalies = new List<Anomaly>()
                };

                // 이상 패턴 감지
                var isAnomalous = await _attemptService.DetectAnomalousPatternAsync(
                    userId,
                    context.IpAddress ?? "unknown",
                    context.DeviceFingerprint);

                if (isAnomalous.IsSuccess && isAnomalous.Data)
                {
                    result.DetectedAnomalies.Add(new Anomaly
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

                // 지리적 이상 감지
                if (!string.IsNullOrEmpty(context.Location))
                {
                    var geoAnomaly = await _attemptService.DetectGeographicalAnomalyAsync(
                        userId, context.Location);

                    if (geoAnomaly.IsSuccess && geoAnomaly.Data)
                    {
                        result.DetectedAnomalies.Add(new Anomaly
                        {
                            Type = "GeographicalAnomaly",
                            Description = $"Unusual location: {context.Location}",
                            Confidence = 0.9,
                            DetectedAt = DateTime.UtcNow,
                            Evidence = new Dictionary<string, object>
                            {
                                ["Location"] = context.Location
                            }
                        });
                    }
                }

                result.AnomalyDetected = result.DetectedAnomalies.Any();
                result.AnomalyScore = result.DetectedAnomalies.Any()
                    ? result.DetectedAnomalies.Max(a => a.Confidence)
                    : 0;
                result.ConfidenceScore = result.AnomalyScore;

                // 액션 결정
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

        public async Task<ServiceResult<IpReputationResult>> CheckIpReputationAsync(string ipAddress)
        {
            try
            {
                var result = new IpReputationResult
                {
                    IpAddress = ipAddress,
                    CheckedAt = DateTime.UtcNow,
                    ReputationScore = 1.0, // 기본값: 신뢰
                    Categories = new List<string>()
                };

                // 내부 IP는 항상 신뢰
                if (IsInternalIp(ipAddress))
                {
                    result.IsTrusted = true;
                    result.Categories.Add("Internal");
                    return ServiceResult<IpReputationResult>.Success(result);
                }

                // 최근 실패 이력 확인
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

                // 무차별 대입 공격 감지
                var bruteForceDetected = await _attemptService.DetectBruteForceAttackAsync(
                    "check", ipAddress);

                if (bruteForceDetected.IsSuccess && bruteForceDetected.Data)
                {
                    result.ReputationScore = Math.Min(result.ReputationScore, 0.2);
                    result.IsBlocked = true;
                    result.BlockReason = "Brute force attack detected";
                    result.Categories.Add("Attacker");
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

        public async Task<ServiceResult> CreateAuditLogAsync(AuditLog log)
        {
            try
            {
                log.Id = Guid.NewGuid();
                log.CreatedAt = DateTime.UtcNow;

                await _auditRepository.AddAsync(log);

                _logger.LogInformation("Audit log created: {Action} for {ResourceType}:{ResourceId}",
                    log.Action, log.ResourceType, log.ResourceId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating audit log");
                return ServiceResult.Failure("Failed to create audit log");
            }
        }

        public async Task<ServiceResult<IEnumerable<AuditLog>>> GetAuditTrailAsync(
            Guid? userId = null,
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var startDate = from ?? DateTime.UtcNow.AddDays(-30);
                var endDate = to ?? DateTime.UtcNow;

                var logs = await _auditRepository.GetAuditLogsAsync(
                    userId, organizationId, startDate, endDate);

                return ServiceResult<IEnumerable<AuditLog>>.Success(logs);
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

                // 인증 통계 수집
                var authStats = await GetStatisticsAsync(organizationId, from, to);
                if (authStats.IsSuccess && authStats.Data != null)
                {
                    report.Data["AuthenticationSummary"] = new
                    {
                        TotalAttempts = authStats.Data.TotalAttempts,
                        SuccessRate = authStats.Data.SuccessRate,
                        UniqueUsers = authStats.Data.UniqueUsers,
                        FailedAttempts = authStats.Data.FailedAttempts
                    };
                }

                // 의심스러운 활동 확인
                var suspiciousActivities = await GetSuspiciousActivitiesAsync(organizationId, from);
                if (suspiciousActivities.IsSuccess && suspiciousActivities.Data != null)
                {
                    var activities = suspiciousActivities.Data.ToList();

                    // 통계 데이터 저장
                    report.Data["SecurityEvents"] = new
                    {
                        TotalSuspiciousActivities = activities.Count,
                        UniqueUsersWithSuspiciousActivity = activities.Select(a => a.UserId).Distinct().Count(),
                        TotalSuspiciousAttempts = activities.Sum(a => a.Count),
                        MostFrequentPattern = activities
                            .GroupBy(a => a.Pattern)
                            .OrderByDescending(g => g.Count())
                            .FirstOrDefault()?.Key ?? "None"
                    };

                    // 심각한 의심 활동을 위반으로 기록
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

                // 계정 잠금 이벤트 확인
                var lockEvents = await _auditRepository.GetAuditLogsAsync(
                    null, organizationId, from, to);
                var accountLocks = lockEvents.Where(l => l.Action == "account.lock").ToList();

                report.Data["AccountSecurity"] = new
                {
                    AccountLocks = accountLocks.Count,
                    AverageUnlockTime = CalculateAverageUnlockTime(accountLocks)
                };

                // 과도한 계정 잠금을 위반으로 기록
                if (accountLocks.Count > 10) // 임계값 설정
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

                // 실패율이 높은 경우 위반 추가
                if (authStats.IsSuccess && authStats.Data != null)
                {
                    var failureRate = 1.0 - authStats.Data.SuccessRate;
                    if (failureRate > 0.3) // 30% 이상 실패율
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

                // 보고서 URL 생성 (선택적)
                report.ReportUrl = $"/api/reports/compliance/{report.ReportId}";

                return ServiceResult<ComplianceReport>.Success(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance report for organization {OrganizationId}",
                    organizationId);
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
                int totalCleaned = 0;

                if (archiveBeforeDelete)
                {
                    // 아카이브
                    var archiveLocation = _configuration["Storage:ArchiveLocation"] ?? "archive";
                    var archived = await _attemptRepository.ArchiveSuccessfulLogsAsync(
                        olderThan, archiveLocation);

                    _logger.LogInformation("Archived {Count} authentication logs", archived);
                }

                // 오래된 로그 삭제
                var deleted = await _attemptRepository.CleanupOldLogsAsync(olderThan);
                totalCleaned += deleted;

                // 감사 로그도 정리
                var auditDeleted = await _auditRepository.CleanupOldLogsAsync(olderThan);
                totalCleaned += auditDeleted;

                _logger.LogInformation("Cleaned up {Total} old history records", totalCleaned);
                return ServiceResult<int>.Success(totalCleaned);
            }
            catch (Exception ex)
            {
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

                // --- 인증 로그 아카이브 (배치 처리) ---
                const int batchSize = 300; // 한 번에 처리할 로그 수
                bool hasMoreAuthLogs = true;
                // long lastId = 0; // 페이징 대신 ID 기반 커서 사용으로 성능 향상

                while (hasMoreAuthLogs)
                {
                    // ID 기반으로 다음 배치 조회
                    var authLogsBatch = await _attemptRepository.Query()
                        .Where(log => log.AttemptedAt >= from && log.AttemptedAt <= to)
                        .OrderBy(log => log.Id) // ID 순으로 정렬해야 함
                                                //.Where(log => log.Id > lastId) // DB가 GUID를 순차적으로 생성한다면 이 방법이 더 효율적
                        .Take(batchSize)
                        .ToListAsync();

                    if (authLogsBatch.Any())
                    {
                        await ArchiveToStorageAsync(authLogsBatch, archiveLocation, "auth_attempts");
                        // lastId = authLogsBatch.Last().Id; // ID 기반 커서 사용 시
                    }
                    else
                    {
                        hasMoreAuthLogs = false;
                    }

                    // 더 이상 처리할 로그가 없으면 루프 종료
                    if (authLogsBatch.Count < batchSize) hasMoreAuthLogs = false;
                }

                // --- 감사 로그 아카이브 (이것도 배치 처리하는 것이 좋음) ---
                var auditLogs = await _auditRepository.GetAuditLogsAsync(null, null, from, to);
                await ArchiveToStorageAsync(auditLogs, archiveLocation, "audit_logs");

                // 아카이브된 레코드에 '아카이브됨' 표시
                await _attemptRepository.MarkAsArchivedAsync(from, to);
                await _auditRepository.MarkAsArchivedAsync(from, to);

                _logger.LogInformation("Successfully archived history from {From} to {To} to {Location}",
                    from, to, archiveLocation);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during history archiving");
                return ServiceResult.Failure("Failed to archive history");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task CreateAuditLogForAttemptAsync(AuthenticationAttemptLog attempt)
        {
            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                PerformedByConnectedId = attempt.ConnectedId,
                ApplicationId = attempt.ApplicationId,
                ActionType = AuditActionType.Login,
                Action = attempt.IsSuccess ? "auth.success" : "auth.failure",
                ResourceType = "User",
                ResourceId = attempt.UserId?.ToString(),
                IPAddress = attempt.IpAddress,
                UserAgent = attempt.UserAgent,
                Success = attempt.IsSuccess,
                ErrorCode = attempt.ErrorCode,
                ErrorMessage = attempt.FailureMessage,
                Timestamp = attempt.AttemptedAt,
                Severity = attempt.IsSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                Metadata = $"{{\"method\":\"{attempt.Method}\"}}"
            };

            await _auditRepository.AddAsync(auditLog);
        }

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

        private List<TimePattern> AnalyzeTimePatterns(IEnumerable<AuthenticationAttemptLog> attempts)
        {
            return attempts
                .Where(a => a.IsSuccess)
                .GroupBy(a => new
                {
                    DayOfWeek = a.AttemptedAt.DayOfWeek.ToString(),
                    Hour = a.AttemptedAt.Hour
                })
                .Select(g => new TimePattern
                {
                    DayOfWeek = g.Key.DayOfWeek,
                    Hour = g.Key.Hour,
                    Frequency = g.Count()
                })
                .OrderByDescending(p => p.Frequency)
                .Take(10)
                .ToList();
        }

        private List<LocationPattern> AnalyzeLocationPatterns(IEnumerable<AuthenticationAttemptLog> attempts)
        {
            return attempts
                .Where(a => !string.IsNullOrEmpty(a.Location))
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
        }

        private List<DevicePattern> AnalyzeDevicePatterns(IEnumerable<AuthenticationAttemptLog> attempts)
        {
            return attempts
                .Where(a => !string.IsNullOrEmpty(a.DeviceType))
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
        }

        private int CalculateUserRiskScore(IEnumerable<AuthenticationAttemptLog> attempts)
        {
            var score = 0;
            var recentAttempts = attempts.Where(a => a.AttemptedAt > DateTime.UtcNow.AddDays(-7));

            // 실패율
            var failureRate = recentAttempts.Any()
                ? recentAttempts.Count(a => !a.IsSuccess) / (double)recentAttempts.Count()
                : 0;
            score += (int)(failureRate * 30);

            // 의심스러운 활동
            var suspiciousCount = recentAttempts.Count(a => a.IsSuspicious);
            score += suspiciousCount * 10;

            // 계정 잠금 트리거
            var lockTriggers = recentAttempts.Count(a => a.TriggeredAccountLock);
            score += lockTriggers * 20;

            return Math.Min(score, 100);
        }

        private List<string> IdentifySuspiciousIPs(IEnumerable<AuthenticationAttemptLog> failures)
        {
            return failures
                .GroupBy(f => f.IpAddress)
                .Where(g => g.Count() > 10)
                .Select(g => g.Key)
                .ToList();
        }

        private int CountBruteForceAttempts(IEnumerable<AuthenticationAttemptLog> failures)
        {
            return failures
                .GroupBy(f => new { f.Username, f.IpAddress })
                .Count(g => g.Count() > 5);
        }

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
                    FactorType = "MultipleFailures",
                    Description = $"{recentFailures.Count()} failed attempts in last hour",
                    Weight = 0.4,
                    Severity = "High"
                });
            }

            assessment.RiskScore = Math.Min(assessment.RiskFactors.Sum(f => f.Weight), 1.0);
            return ServiceResult<RiskAssessment>.Success(assessment);
        }

        private bool IsInternalIp(string ipAddress)
        {
            return ipAddress.StartsWith("192.168.") ||
                   ipAddress.StartsWith("10.") ||
                   ipAddress.StartsWith("172.") ||
                   ipAddress == "127.0.0.1" ||
                   ipAddress == "::1";
        }

        private string ExtractCountry(string location)
        {
            var parts = location.Split(',');
            return parts.Length > 1 ? parts[^1].Trim() : "Unknown";
        }

        private string ExtractCity(string location)
        {
            var parts = location.Split(',');
            return parts.Length > 0 ? parts[0].Trim() : "Unknown";
        }

        private string ExtractBrowser(string? userAgent)
        {
            if (string.IsNullOrEmpty(userAgent)) return "Unknown";

            if (userAgent.Contains("Chrome")) return "Chrome";
            if (userAgent.Contains("Firefox")) return "Firefox";
            if (userAgent.Contains("Safari")) return "Safari";
            if (userAgent.Contains("Edge")) return "Edge";

            return "Other";
        }

        private double CalculateAverageUnlockTime(List<AuditLog> lockEvents)
        {
            return 30.0; // 기본값: 30분
        }

        private async Task ArchiveToStorageAsync<T>(
            IEnumerable<T> data,
            string location,
            string prefix)
        {
            await Task.CompletedTask;
            _logger.LogInformation("Archived {Count} {Type} records to {Location}",
                data.Count(), prefix, location);
        }

        public Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(Guid? organizationId, DateTime startDate, DateTime endDate)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}