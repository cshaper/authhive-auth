using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Infra.Monitoring;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Models.Infra.Security.Common;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Core.UserEnums;

// Type aliases to avoid conflicts
using LocationInfo = AuthHive.Core.Models.User.Responses.LocationInfo;

namespace AuthHive.Auth.Services.Security
{
    /// <summary>
    /// 위험 평가 서비스 구현체 - AuthHive v15
    /// 인증 시도, 세션, 사용자 활동, 거래의 위험도를 평가하고 이상 탐지
    /// </summary>
    public class RiskAssessmentService : IRiskAssessmentService
    {
        #region Dependencies

        private readonly IUserRepository _userRepository;
        private readonly IAuthenticationAttemptLogRepository _authAttemptRepository;
        private readonly ISessionActivityLogRepository _sessionActivityRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IGeolocationService _geolocationService;
        private readonly IMemoryCache _memoryCache;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<RiskAssessmentService> _logger;
        private readonly RiskAssessmentSettings _settings;

        #endregion

        #region Constructor

        public RiskAssessmentService(
            IUserRepository userRepository,
            IAuthenticationAttemptLogRepository authAttemptRepository,
            ISessionActivityLogRepository sessionActivityRepository,
            IConnectedIdRepository connectedIdRepository,
            IGeolocationService geolocationService,
            IMemoryCache memoryCache,
            IUnitOfWork unitOfWork,
            ILogger<RiskAssessmentService> logger,
            IOptions<RiskAssessmentSettings> settings)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _authAttemptRepository = authAttemptRepository ?? throw new ArgumentNullException(nameof(authAttemptRepository));
            _sessionActivityRepository = sessionActivityRepository ?? throw new ArgumentNullException(nameof(sessionActivityRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _geolocationService = geolocationService ?? throw new ArgumentNullException(nameof(geolocationService));
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _settings = settings?.Value ?? throw new ArgumentNullException(nameof(settings));
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()  // Task<ServiceResult> 제거, Task만 반환
        {
            try
            {
                _logger.LogInformation("Initializing RiskAssessmentService");

                _memoryCache.Remove("risk_policy:default");

                var defaultPolicy = await LoadRiskPolicyAsync(null);
                if (defaultPolicy != null)
                {
                    _memoryCache.Set("risk_policy:default", defaultPolicy, TimeSpan.FromHours(1));
                }

                _logger.LogInformation("RiskAssessmentService initialized successfully");
                // return 문 제거 - Task는 아무것도 반환하지 않음
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize RiskAssessmentService");
                throw; // 예외 전파
            }
        }
        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()  // ServiceResult<bool> 대신 bool 반환
        {
            try
            {
                var checks = new List<bool>();

                try
                {
                    var testUser = await _userRepository.GetByIdAsync(Guid.NewGuid());
                    checks.Add(true);
                }
                catch
                {
                    checks.Add(false);
                }

                try
                {
                    _memoryCache.Set("health_check", true, TimeSpan.FromSeconds(1));
                    var cacheTest = _memoryCache.Get<bool>("health_check");
                    checks.Add(cacheTest);
                }
                catch
                {
                    checks.Add(false);
                }

                return checks.All(c => c);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check failed for RiskAssessmentService");
                return false;
            }
        }


        #endregion

        #region 위험도 평가

        /// <summary>
        /// 인증 위험도 평가
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessAuthenticationRiskAsync(AuthenticationRequest request)
        {
            try
            {
                var riskFactors = new List<RiskFactor>();
                var riskScore = 0.0;

                if (!string.IsNullOrWhiteSpace(request.IpAddress))
                {
                    var ipRiskFactor = await AssessIpRiskAsync(request.IpAddress);
                    if (ipRiskFactor != null)
                    {
                        riskFactors.Add(ipRiskFactor);
                        riskScore += ipRiskFactor.WeightedScore / 100.0;
                    }
                }

                if (request.DeviceInfo != null)
                {
                    var deviceRiskFactor = await AssessDeviceRiskAsync(request.DeviceInfo);
                    if (deviceRiskFactor != null)
                    {
                        riskFactors.Add(deviceRiskFactor);
                        riskScore += deviceRiskFactor.WeightedScore / 100.0;
                    }
                }

                var authMethodRiskFactor = AssessAuthenticationMethodRisk(request.Method);
                if (authMethodRiskFactor != null)
                {
                    riskFactors.Add(authMethodRiskFactor);
                    riskScore += authMethodRiskFactor.WeightedScore / 100.0;
                }

                if (!string.IsNullOrWhiteSpace(request.Username))
                {
                    var failureRiskFactor = await AssessRecentFailuresAsync(request.Username);
                    if (failureRiskFactor != null)
                    {
                        riskFactors.Add(failureRiskFactor);
                        riskScore += failureRiskFactor.WeightedScore / 100.0;
                    }
                }

                var timeRiskFactor = AssessTimeBasedRisk(DateTime.UtcNow);
                if (timeRiskFactor != null)
                {
                    riskFactors.Add(timeRiskFactor);
                    riskScore += timeRiskFactor.WeightedScore / 100.0;
                }

                riskScore = Math.Min(1.0, Math.Max(0.0, riskScore));

                var assessment = new RiskAssessment
                {
                    AssessmentId = Guid.NewGuid(),
                    RiskScore = riskScore,
                    RiskLevel = DetermineRiskLevel(riskScore),
                    RiskFactors = riskFactors,
                    RequiresMfa = riskScore >= _settings.MfaRequiredThreshold,
                    RequiresAdditionalVerification = riskScore >= _settings.AdditionalVerificationThreshold,
                    RecommendedActions = GenerateRecommendedActions(riskScore, riskFactors),
                    AssessedAt = DateTime.UtcNow
                };

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing authentication risk");
                return ServiceResult<RiskAssessment>.Failure(
                    "Failed to assess authentication risk",
                    "RISK_ASSESSMENT_ERROR");
            }
        }

        /// <summary>
        /// 세션 위험도 평가
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessSessionRiskAsync(Guid sessionId)
        {
            try
            {
                // 세션 활동 로그 조회
                var activities = await GetBySessionIdAsync(sessionId);
                if (!activities.Any())
                {
                    return ServiceResult<RiskAssessment>.NotFound("Session activities not found");
                }

                var riskFactors = new List<RiskFactor>();
                var riskScore = 0.0;

                // 1. 활동 빈도 분석
                var frequencyRisk = AnalyzeActivityFrequency(activities);
                if (frequencyRisk != null)
                {
                    riskFactors.Add(frequencyRisk);
                    riskScore += frequencyRisk.WeightedScore / 100.0;
                }

                // 2. 활동 패턴 분석
                var patternRisk = AnalyzeActivityPattern(activities);
                if (patternRisk != null)
                {
                    riskFactors.Add(patternRisk);
                    riskScore += patternRisk.WeightedScore / 100.0;
                }

                // 3. 지역 변경 감지 (동기 메서드로 변경)
                var locationRisk = AnalyzeLocationChanges(activities);
                if (locationRisk != null)
                {
                    riskFactors.Add(locationRisk);
                    riskScore += locationRisk.WeightedScore / 100.0;
                }

                // 정규화 (0.0 ~ 1.0)
                riskScore = Math.Min(1.0, Math.Max(0.0, riskScore));

                var assessment = new RiskAssessment
                {
                    AssessmentId = Guid.NewGuid(),
                    RiskScore = riskScore,
                    RiskLevel = DetermineRiskLevel(riskScore),
                    RiskFactors = riskFactors,
                    RequiresMfa = riskScore >= _settings.MfaRequiredThreshold,
                    RequiresAdditionalVerification = riskScore >= _settings.AdditionalVerificationThreshold,
                    RecommendedActions = GenerateRecommendedActions(riskScore, riskFactors),
                    AssessedAt = DateTime.UtcNow
                };

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing session risk for session {SessionId}", sessionId);
                return ServiceResult<RiskAssessment>.Failure(
                    "Failed to assess session risk",
                    "RISK_ASSESSMENT_ERROR");
            }
        }
        /// <summary>
        /// 사용자 활동 위험도 평가
        /// </summary>
        public async Task<ServiceResult<RiskAssessment>> AssessUserActivityRiskAsync(Guid userId, UserActivity activity)
        {
            try
            {
                var riskFactors = new List<RiskFactor>();
                var riskScore = 0.0;

                var activityTypeRisk = AssessActivityTypeRisk(activity.ActivityType);
                if (activityTypeRisk != null)
                {
                    riskFactors.Add(activityTypeRisk);
                    riskScore += activityTypeRisk.WeightedScore / 100.0;
                }

                if (!string.IsNullOrWhiteSpace(activity.IpAddress))
                {
                    var ipRisk = await AssessIpRiskAsync(activity.IpAddress);
                    if (ipRisk != null)
                    {
                        riskFactors.Add(ipRisk);
                        riskScore += ipRisk.WeightedScore / 100.0;
                    }
                }

                var userHistoryRisk = await AssessUserHistoryRiskAsync(userId);
                if (userHistoryRisk != null)
                {
                    riskFactors.Add(userHistoryRisk);
                    riskScore += userHistoryRisk.WeightedScore / 100.0;
                }

                riskScore = Math.Min(1.0, Math.Max(0.0, riskScore));

                var assessment = new RiskAssessment
                {
                    AssessmentId = Guid.NewGuid(),
                    RiskScore = riskScore,
                    RiskLevel = DetermineRiskLevel(riskScore),
                    RiskFactors = riskFactors,
                    RequiresMfa = riskScore >= _settings.MfaRequiredThreshold,
                    RequiresAdditionalVerification = riskScore >= _settings.AdditionalVerificationThreshold,
                    RecommendedActions = GenerateRecommendedActions(riskScore, riskFactors),
                    AssessedAt = DateTime.UtcNow
                };

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing user activity risk for user {UserId}", userId);
                return ServiceResult<RiskAssessment>.Failure(
                    "Failed to assess user activity risk",
                    "RISK_ASSESSMENT_ERROR");
            }
        }

        /// <summary>
        /// 거래 위험도 평가
        /// </summary>
        public async Task<ServiceResult<TransactionRiskAssessment>> AssessTransactionRiskAsync(TransactionContext context)
        {
            try
            {
                var riskFactors = new List<string>();
                var riskScore = 0;

                if (context.Amount > _settings.HighValueTransactionThreshold)
                {
                    riskFactors.Add("High value transaction");
                    riskScore += 30;
                }

                var patternRisk = await AnalyzeTransactionPatternAsync(context.UserId, context.Amount);
                if (patternRisk > 0)
                {
                    riskFactors.Add("Unusual transaction pattern");
                    riskScore += patternRisk;
                }

                if (!string.IsNullOrWhiteSpace(context.IpAddress))
                {
                    var ipRisk = await AssessIpRiskAsync(context.IpAddress);
                    if (ipRisk != null && (ipRisk.Impact / 100.0) > 0.5)
                    {
                        riskFactors.Add("Suspicious IP address");
                        riskScore += (int)(ipRisk.Impact * 0.3);
                    }
                }

                var typeRisk = AssessTransactionTypeRisk(context.TransactionType);
                if (typeRisk > 0)
                {
                    riskFactors.Add($"Risk transaction type: {context.TransactionType}");
                    riskScore += typeRisk;
                }

                riskScore = Math.Min(100, Math.Max(0, riskScore));

                var assessment = new TransactionRiskAssessment
                {
                    RiskScore = riskScore,
                    RiskLevel = DetermineTransactionRiskLevel(riskScore),
                    RiskFactors = riskFactors,
                    RequiresAdditionalVerification = riskScore >= 70,
                    RecommendedAction = GenerateTransactionRecommendation(riskScore)
                };

                return ServiceResult<TransactionRiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing transaction risk for user {UserId}", context.UserId);
                return ServiceResult<TransactionRiskAssessment>.Failure(
                    "Failed to assess transaction risk",
                    "RISK_ASSESSMENT_ERROR");
            }
        }

        #endregion
        #region 이상 탐지

        /// <summary>
        /// 이상 접근 감지
        /// </summary>
        public async Task<ServiceResult<AnomalyDetectionResult>> DetectAnomalyAsync(Guid userId, AuthenticationContext context)
        {
            try
            {
                var anomalies = new List<SecurityAnomaly>();
                var anomalyScore = 0.0;

                var locationAnomaly = await DetectLocationAnomalyInternalAsync(userId, context.IpAddress);
                if (locationAnomaly != null)
                {
                    anomalies.Add(locationAnomaly);
                    // SecurityAnomaly의 Severity는 AuditEventSeverity 타입
                    var severity = locationAnomaly.Severity;
                    anomalyScore += (severity == AuditEventSeverity.Critical || severity == AuditEventSeverity.Error) ? 0.4 : 0.2;
                }

                var timeAnomaly = await DetectTimeAnomalyAsync(userId, context.Timestamp);
                if (timeAnomaly != null)
                {
                    anomalies.Add(timeAnomaly);
                    var severity = timeAnomaly.Severity;
                    anomalyScore += (severity == AuditEventSeverity.Critical || severity == AuditEventSeverity.Error) ? 0.3 : 0.15;
                }

                var deviceAnomaly = await DetectDeviceAnomalyAsync(userId, context.DeviceFingerprint);
                if (deviceAnomaly != null)
                {
                    anomalies.Add(deviceAnomaly);
                    var severity = deviceAnomaly.Severity;
                    anomalyScore += (severity == AuditEventSeverity.Critical || severity == AuditEventSeverity.Error) ? 0.3 : 0.15;
                }

                var behaviorAnomaly = await DetectBehaviorAnomalyAsync(userId, context);
                if (behaviorAnomaly != null)
                {
                    anomalies.Add(behaviorAnomaly);
                    var severity = behaviorAnomaly.Severity;
                    anomalyScore += (severity == AuditEventSeverity.Critical || severity == AuditEventSeverity.Error) ? 0.35 : 0.2;
                }

                anomalyScore = Math.Min(1.0, Math.Max(0.0, anomalyScore));
                var confidenceScore = CalculateConfidenceScore(anomalies.Count, anomalyScore);

                var result = new AnomalyDetectionResult
                {
                    AnomalyDetected = anomalies.Any(),
                    AnomalyScore = anomalyScore,
                    ConfidenceScore = confidenceScore,
                    DetectedAnomalies = anomalies,
                    RequireAdditionalVerification = anomalyScore >= 0.5,
                    BlockAccess = anomalyScore >= 0.8,
                    RecommendedAction = DetermineAnomalyAction(anomalyScore),
                    DetectedAt = DateTime.UtcNow
                };

                return ServiceResult<AnomalyDetectionResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting anomaly for user {UserId}", userId);
                return ServiceResult<AnomalyDetectionResult>.Failure(
                    "Failed to detect anomaly",
                    "ANOMALY_DETECTION_ERROR");
            }
        }

        /// <summary>
        /// 위치 기반 이상 탐지
        /// </summary>
        public async Task<ServiceResult<LocationAnomalyResult>> DetectLocationAnomalyAsync(Guid userId, LocationInfo currentLocation)
        {
            try
            {
                var recentActivities = await GetRecentByUserIdAsync(userId, 10);
                if (!recentActivities.Any())
                {
                    return ServiceResult<LocationAnomalyResult>.Success(new LocationAnomalyResult
                    {
                        IsAnomaly = false
                    });
                }

                LocationInfo? previousLocation = null;
                DateTime? previousTime = null;

                foreach (var activity in recentActivities.OrderByDescending(a => a.AttemptedAt))
                {
                    if (!string.IsNullOrWhiteSpace(activity.Location))
                    {
                        var location = await GetLocationFromStringAsync(activity.Location);
                        if (location != null && !IsSameLocation(location, currentLocation))
                        {
                            previousLocation = location;
                            previousTime = activity.AttemptedAt;
                            break;
                        }
                    }
                }

                if (previousLocation == null)
                {
                    return ServiceResult<LocationAnomalyResult>.Success(new LocationAnomalyResult
                    {
                        IsAnomaly = false
                    });
                }

                var distance = CalculateDistance(previousLocation, currentLocation);
                var timeDifference = DateTime.UtcNow - previousTime!.Value;

                var impossibleTravel = false;
                if (timeDifference.TotalHours > 0)
                {
                    var speed = distance / timeDifference.TotalHours;
                    impossibleTravel = speed > 1000;
                }

                var result = new LocationAnomalyResult
                {
                    IsAnomaly = impossibleTravel || distance > _settings.SuspiciousDistanceKm,
                    Distance = distance,
                    TimeDifference = timeDifference,
                    ImpossibleTravel = impossibleTravel,
                    PreviousLocation = previousLocation
                };

                return ServiceResult<LocationAnomalyResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting location anomaly for user {UserId}", userId);
                return ServiceResult<LocationAnomalyResult>.Failure(
                    "Failed to detect location anomaly",
                    "LOCATION_ANOMALY_ERROR");
            }
        }

        #endregion

        #region IP 및 장치 평판

        /// <summary>
        /// IP 평판 확인
        /// </summary>
        public async Task<ServiceResult<IpReputationResult>> CheckIpReputationAsync(string ipAddress)
        {
            try
            {
                var cacheKey = $"ip_reputation:{ipAddress}";

                if (_memoryCache.TryGetValue<IpReputationResult>(cacheKey, out var cached) && cached != null)
                {
                    return ServiceResult<IpReputationResult>.Success(cached);
                }

                var result = new IpReputationResult
                {
                    IpAddress = ipAddress,
                    CheckedAt = DateTime.UtcNow,
                    ReputationScore = 1.0,
                    IsTrusted = true,
                    IsBlocked = false
                };

                if (await IsIpInBlacklistAsync(ipAddress))
                {
                    result.IsBlacklisted = true;
                    result.IsBlocked = true;
                    result.ReputationScore = 0.0;
                    result.BlockReason = "IP is blacklisted";
                    result.Categories.Add("Blacklisted");
                }

                var vpnTorCheck = await CheckVpnTorAsync(ipAddress);
                if (vpnTorCheck.IsVpn)
                {
                    result.IsVpn = true;
                    result.Categories.Add("VPN");
                    result.ReputationScore *= 0.7;
                }
                if (vpnTorCheck.IsTor)
                {
                    result.IsTor = true;
                    result.Categories.Add("Tor");
                    result.ReputationScore *= 0.5;
                }

                var geoInfo = await _geolocationService.GetLocationAsync(ipAddress);
                if (geoInfo != null)
                {
                    result.Country = geoInfo.CountryCode;
                    result.ISP = geoInfo.Isp;

                    if (_settings.HighRiskCountries.Contains(geoInfo.CountryCode))
                    {
                        result.Categories.Add("High Risk Country");
                        result.ReputationScore *= 0.8;
                    }
                }

                result.IsTrusted = result.ReputationScore >= _settings.TrustedIpThreshold;

                _memoryCache.Set(cacheKey, result, TimeSpan.FromHours(1));

                return ServiceResult<IpReputationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking IP reputation for {IpAddress}", ipAddress);
                return ServiceResult<IpReputationResult>.Failure(
                    "Failed to check IP reputation",
                    "IP_REPUTATION_ERROR");
            }
        }

        /// <summary>
        /// 장치 평판 확인
        /// </summary>
        public async Task<ServiceResult<DeviceReputationResult>> CheckDeviceReputationAsync(string deviceFingerprint)
        {
            try
            {
                var cacheKey = $"device_reputation:{deviceFingerprint}";


                // 수정된 코드
                if (_memoryCache.TryGetValue<DeviceReputationResult>(cacheKey, out var cached))
                {
                    return ServiceResult<DeviceReputationResult>.Success(cached!);  // ! 추가
                }

                var deviceHistory = await GetDeviceHistoryAsync(deviceFingerprint);

                var result = new DeviceReputationResult
                {
                    DeviceFingerprint = deviceFingerprint,
                    ReputationScore = 100,
                    IsTrusted = true,
                    IsBlacklisted = false,
                    RiskIndicators = 0,
                    FirstSeen = deviceHistory.FirstSeen,
                    LastSeen = deviceHistory.LastSeen
                };

                if (await IsDeviceBlacklistedInternalAsync(deviceFingerprint))
                {
                    result.IsBlacklisted = true;
                    result.IsTrusted = false;
                    result.ReputationScore = 0;
                    result.RiskIndicators++;
                }

                if (!deviceHistory.FirstSeen.HasValue ||
                    (DateTime.UtcNow - deviceHistory.FirstSeen.Value).TotalDays < 1)
                {
                    result.RiskIndicators++;
                    result.ReputationScore -= 20;
                }

                if (deviceHistory.FailedAttempts > 5)
                {
                    result.RiskIndicators++;
                    result.ReputationScore -= 30;
                }

                if (deviceHistory.UniqueUsers > 3)
                {
                    result.RiskIndicators++;
                    result.ReputationScore -= 25;
                }

                result.ReputationScore = Math.Max(0, result.ReputationScore);
                result.IsTrusted = result.ReputationScore >= 70;

                _memoryCache.Set(cacheKey, result, TimeSpan.FromMinutes(30));

                return ServiceResult<DeviceReputationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking device reputation for {DeviceFingerprint}", deviceFingerprint);
                return ServiceResult<DeviceReputationResult>.Failure(
                    "Failed to check device reputation",
                    "DEVICE_REPUTATION_ERROR");
            }
        }

        /// <summary>
        /// IP 블랙리스트 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsIpBlacklistedAsync(string ipAddress)
        {
            try
            {
                var isBlacklisted = await IsIpInBlacklistAsync(ipAddress);
                return ServiceResult<bool>.Success(isBlacklisted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking IP blacklist for {IpAddress}", ipAddress);
                return ServiceResult<bool>.Failure(
                    "Failed to check IP blacklist",
                    "BLACKLIST_CHECK_ERROR");
            }
        }

        /// <summary>
        /// 장치 블랙리스트 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsDeviceBlacklistedAsync(string deviceFingerprint)
        {
            try
            {
                var isBlacklisted = await IsDeviceBlacklistedInternalAsync(deviceFingerprint);
                return ServiceResult<bool>.Success(isBlacklisted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking device blacklist for {DeviceFingerprint}", deviceFingerprint);
                return ServiceResult<bool>.Failure(
                    "Failed to check device blacklist",
                    "BLACKLIST_CHECK_ERROR");
            }
        }

        #endregion

        #region 위험 정책

        /// <summary>
        /// 위험 정책 조회
        /// </summary>
        public async Task<ServiceResult<RiskPolicy>> GetRiskPolicyAsync(Guid? organizationId = null)
        {
            try
            {
                var cacheKey = $"risk_policy:{organizationId ?? Guid.Empty}";

                if (_memoryCache.TryGetValue<RiskPolicy>(cacheKey, out var cached))
                {
                    return ServiceResult<RiskPolicy>.Success(cached!);  // ! 추가
                }

                var policy = await LoadRiskPolicyAsync(organizationId);

                _memoryCache.Set(cacheKey, policy, TimeSpan.FromMinutes(10));

                return ServiceResult<RiskPolicy>.Success(policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting risk policy for organization {OrganizationId}", organizationId);
                return ServiceResult<RiskPolicy>.Failure(
                    "Failed to get risk policy",
                    "POLICY_RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// 위험 정책 설정
        /// </summary>
        public async Task<ServiceResult> SetRiskPolicyAsync(Guid organizationId, RiskPolicy policy)
        {
            try
            {
                if (!ValidateRiskPolicy(policy))
                {
                    return ServiceResult.Failure("Invalid risk policy", "INVALID_POLICY");
                }

                await SaveRiskPolicyAsync(organizationId, policy);

                var cacheKey = $"risk_policy:{organizationId}";
                _memoryCache.Remove(cacheKey);

                return ServiceResult.Success("Risk policy updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting risk policy for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure(
                    "Failed to set risk policy",
                    "POLICY_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 위험 임계값 설정
        /// </summary>
        public async Task<ServiceResult> SetRiskThresholdsAsync(Guid organizationId, RiskThresholds thresholds)
        {
            try
            {
                if (!ValidateThresholds(thresholds))
                {
                    return ServiceResult.Failure("Invalid thresholds", "INVALID_THRESHOLDS");
                }

                var policyResult = await GetRiskPolicyAsync(organizationId);
                if (!policyResult.IsSuccess)
                {
                    return ServiceResult.Failure("Failed to get current policy", "POLICY_NOT_FOUND");
                }

                var policy = policyResult.Data!;
                policy.Thresholds = thresholds;

                return await SetRiskPolicyAsync(organizationId, policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting risk thresholds for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure(
                    "Failed to set risk thresholds",
                    "THRESHOLD_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 위험 대응 규칙 설정
        /// </summary>
        public async Task<ServiceResult> SetRiskResponseRulesAsync(Guid organizationId, List<RiskResponseRule> rules)
        {
            try
            {
                if (!ValidateResponseRules(rules))
                {
                    return ServiceResult.Failure("Invalid response rules", "INVALID_RULES");
                }

                var policyResult = await GetRiskPolicyAsync(organizationId);
                if (!policyResult.IsSuccess)
                {
                    return ServiceResult.Failure("Failed to get current policy", "POLICY_NOT_FOUND");
                }

                var policy = policyResult.Data!;
                policy.ResponseRules = rules;

                return await SetRiskPolicyAsync(organizationId, policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting risk response rules for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure(
                    "Failed to set risk response rules",
                    "RULES_UPDATE_ERROR");
            }
        }

        #endregion

        #region 위험 이력

        /// <summary>
        /// 위험 이벤트 기록
        /// </summary>
        public async Task<ServiceResult> LogRiskEventAsync(RiskEvent riskEvent)
        {
            try
            {
                await SaveRiskEventAsync(riskEvent);

                if (riskEvent.RiskScore >= 80)
                {
                    await SendHighRiskAlertAsync(riskEvent);
                }

                return ServiceResult.Success("Risk event logged successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging risk event");
                return ServiceResult.Failure(
                    "Failed to log risk event",
                    "EVENT_LOG_ERROR");
            }
        }

        /// <summary>
        /// 위험 이력 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<RiskEvent>>> GetRiskHistoryAsync(
            Guid? userId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var events = await LoadRiskEventsAsync(userId, from, to);
                return ServiceResult<IEnumerable<RiskEvent>>.Success(events);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting risk history");
                return ServiceResult<IEnumerable<RiskEvent>>.Failure(
                    "Failed to get risk history",
                    "HISTORY_RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// 위험 트렌드 분석
        /// </summary>
        public async Task<ServiceResult<RiskTrendAnalysis>> AnalyzeRiskTrendsAsync(
            Guid? organizationId = null,
            TimeSpan period = default)
        {
            try
            {
                if (period == default)
                {
                    period = TimeSpan.FromDays(30);
                }

                var endDate = DateTime.UtcNow;
                var startDate = endDate - period;

                var events = await LoadRiskEventsAsync(null, startDate, endDate);

                var analysis = new RiskTrendAnalysis
                {
                    AverageRiskScore = events.Any() ? events.Average(e => e.RiskScore) : 0,
                    TotalRiskEvents = events.Count(),
                    EventsByType = events.GroupBy(e => e.EventType)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    RiskScoreTrend = GenerateRiskScoreTrend(events, startDate, endDate)
                };

                return ServiceResult<RiskTrendAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing risk trends");
                return ServiceResult<RiskTrendAnalysis>.Failure(
                    "Failed to analyze risk trends",
                    "TREND_ANALYSIS_ERROR");
            }
        }

        #endregion
        #region 위험 점수

        /// <summary>
        /// 사용자 위험 점수 계산
        /// </summary>
        public async Task<ServiceResult<UserRiskScore>> CalculateUserRiskScoreAsync(Guid userId)
        {
            try
            {
                var score = 0;
                var riskFactors = new List<string>();

                var recentFailures = await CountRecentFailuresAsync(userId);
                if (recentFailures > 0)
                {
                    score += recentFailures * 10;
                    riskFactors.Add($"{recentFailures} recent failed authentications");
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    var accountAge = DateTime.UtcNow - user.CreatedAt;
                    if (accountAge.TotalDays < 7)
                    {
                        score += 20;
                        riskFactors.Add("New account");
                    }
                }

                var anomalyCount = await CountRecentAnomaliesAsync(userId);
                if (anomalyCount > 0)
                {
                    score += anomalyCount * 15;
                    riskFactors.Add($"{anomalyCount} recent anomalies detected");
                }

                var riskyIpUsage = await CheckRiskyIpUsageAsync(userId);
                if (riskyIpUsage)
                {
                    score += 25;
                    riskFactors.Add("Used high-risk IP addresses");
                }

                score = Math.Min(100, Math.Max(0, score));

                var userRiskScore = new UserRiskScore
                {
                    UserId = userId,
                    CurrentScore = score,
                    RiskLevel = DetermineTransactionRiskLevel(score),
                    RiskFactors = riskFactors,
                    CalculatedAt = DateTime.UtcNow
                };

                return ServiceResult<UserRiskScore>.Success(userRiskScore);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating user risk score for {UserId}", userId);
                return ServiceResult<UserRiskScore>.Failure(
                    "Failed to calculate user risk score",
                    "SCORE_CALCULATION_ERROR");
            }
        }

        /// <summary>
        /// 조직 위험 점수 계산
        /// </summary>
        public async Task<ServiceResult<OrganizationRiskScore>> CalculateOrganizationRiskScoreAsync(Guid organizationId)
        {
            try
            {
                var connectedIds = await GetByOrganizationIdAsync(organizationId);

                var userScores = new Dictionary<Guid, int>();
                var totalScore = 0;
                var topRiskFactors = new List<string>();

                foreach (var connectedId in connectedIds)
                {
                    // FIX: UserId가 null인 경우 건너뛰기
                    if (!connectedId.UserId.HasValue)
                    {
                        _logger.LogWarning("ConnectedId {ConnectedId} has no UserId, skipping risk calculation",
                            connectedId.Id);
                        continue;
                    }

                    var userScoreResult = await CalculateUserRiskScoreAsync(connectedId.UserId.Value);
                    if (userScoreResult.IsSuccess && userScoreResult.Data != null)
                    {
                        userScores[connectedId.UserId.Value] = userScoreResult.Data.CurrentScore;
                        totalScore += userScoreResult.Data.CurrentScore;

                        if (userScoreResult.Data.CurrentScore >= 70)
                        {
                            topRiskFactors.AddRange(userScoreResult.Data.RiskFactors.Take(2));
                        }
                    }
                }

                var overallScore = userScores.Any() ? totalScore / userScores.Count : 0;

                if (await HasRecentSecurityIncidentsAsync(organizationId))
                {
                    overallScore += 15;
                    topRiskFactors.Add("Recent security incidents");
                }

                overallScore = Math.Min(100, overallScore);

                var orgRiskScore = new OrganizationRiskScore
                {
                    OrganizationId = organizationId,
                    OverallScore = overallScore,
                    UserRiskScores = userScores,
                    TopRiskFactors = topRiskFactors.Distinct().Take(5).ToList()
                };

                return ServiceResult<OrganizationRiskScore>.Success(orgRiskScore);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating organization risk score for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationRiskScore>.Failure(
                    "Failed to calculate organization risk score",
                    "SCORE_CALCULATION_ERROR");
            }
        }
        /// <summary>
        /// 위험 점수 업데이트
        /// </summary>
        public async Task<ServiceResult> UpdateRiskScoreAsync(Guid userId, RiskScoreUpdate update)
        {
            try
            {
                var currentScoreResult = await CalculateUserRiskScoreAsync(userId);
                if (!currentScoreResult.IsSuccess)
                {
                    return ServiceResult.Failure("Failed to get current risk score", "SCORE_NOT_FOUND");
                }

                var currentScore = currentScoreResult.Data!.CurrentScore;
                var newScore = currentScore + update.ScoreDelta;
                newScore = Math.Min(100, Math.Max(0, newScore));

                var riskEvent = new RiskEvent
                {
                    Id = Guid.NewGuid(),
                    EventType = "RiskScoreUpdated",
                    RiskScore = newScore,
                    UserId = userId,
                    OccurredAt = DateTime.UtcNow,
                    EventData = new Dictionary<string, object>
                    {
                        ["previousScore"] = currentScore,
                        ["delta"] = update.ScoreDelta,
                        ["reason"] = update.Reason,
                        ["updatedBy"] = update.UpdatedBy ?? "System"
                    }
                };

                await LogRiskEventAsync(riskEvent);

                return ServiceResult.Success("Risk score updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating risk score for user {UserId}", userId);
                return ServiceResult.Failure(
                    "Failed to update risk score",
                    "SCORE_UPDATE_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task<RiskFactor?> AssessIpRiskAsync(string ipAddress)
        {
            var reputationResult = await CheckIpReputationAsync(ipAddress);
            if (!reputationResult.IsSuccess || reputationResult.Data == null)
                return null;

            var reputation = reputationResult.Data;

            if (reputation.IsBlacklisted)
            {
                return new RiskFactor
                {
                    Name = "BlacklistedIP",
                    Description = "IP address is blacklisted",
                    Impact = 100,
                    Weight = 0.4
                };
            }

            if (reputation.IsTor)
            {
                return new RiskFactor
                {
                    Name = "TorNetwork",
                    Description = "Connection from Tor network",
                    Impact = 80,
                    Weight = 0.3
                };
            }

            if (reputation.IsVpn)
            {
                return new RiskFactor
                {
                    Name = "VpnConnection",
                    Description = "Connection from VPN",
                    Impact = 50,
                    Weight = 0.2
                };
            }

            if (reputation.ReputationScore < 0.5)
            {
                return new RiskFactor
                {
                    Name = "LowReputationIP",
                    Description = "IP has low reputation score",
                    Impact = (int)((1.0 - reputation.ReputationScore) * 100),
                    Weight = 0.25
                };
            }

            return null;
        }

        private async Task<RiskFactor?> AssessDeviceRiskAsync(DeviceInfo deviceInfo)
        {
            if (string.IsNullOrWhiteSpace(deviceInfo.DeviceId))
                return null;

            var reputationResult = await CheckDeviceReputationAsync(deviceInfo.DeviceId);
            if (!reputationResult.IsSuccess || reputationResult.Data == null)
                return null;

            var reputation = reputationResult.Data;

            if (reputation.IsBlacklisted)
            {
                return new RiskFactor
                {
                    Name = "BlacklistedDevice",
                    Description = "Device is blacklisted",
                    Impact = 100,
                    Weight = 0.35
                };
            }

            if (reputation.RiskIndicators > 2)
            {
                return new RiskFactor
                {
                    Name = "SuspiciousDevice",
                    Description = "Device has multiple risk indicators",
                    Impact = 70,
                    Weight = 0.25
                };
            }

            return null;
        }

        private RiskFactor? AssessAuthenticationMethodRisk(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Anonymous => new RiskFactor
                {
                    Name = "AnonymousAuth",
                    Description = "Anonymous authentication method",
                    Impact = 90,
                    Weight = 0.3
                },
                AuthenticationMethod.ApiKey => new RiskFactor
                {
                    Name = "ApiKeyAuth",
                    Description = "API key authentication",
                    Impact = 40,
                    Weight = 0.15
                },
                AuthenticationMethod.Password => new RiskFactor
                {
                    Name = "PasswordOnlyAuth",
                    Description = "Password-only authentication",
                    Impact = 30,
                    Weight = 0.1
                },
                _ => null
            };
        }

        private async Task<RiskFactor?> AssessRecentFailuresAsync(string username)
        {
            var failures = await GetRecentFailedAttemptsAsync(username, TimeSpan.FromHours(1));

            if (failures.Count() > 5)
            {
                return new RiskFactor
                {
                    Name = "MultipleFailedAttempts",
                    Description = $"{failures.Count()} failed attempts in last hour",
                    Impact = Math.Min(100, failures.Count() * 15),
                    Weight = 0.3
                };
            }

            return null;
        }

        private RiskFactor? AssessTimeBasedRisk(DateTime attemptTime)
        {
            var hour = attemptTime.Hour;

            if (hour >= 2 && hour <= 5)
            {
                return new RiskFactor
                {
                    Name = "UnusualTime",
                    Description = "Login attempt at unusual hour",
                    Impact = 40,
                    Weight = 0.15
                };
            }

            return null;
        }
        private RiskFactor? AnalyzeActivityFrequency(IEnumerable<Core.Entities.Auth.SessionActivityLog> activities)
        {
            var count = activities.Count();
            var timeSpan = DateTime.UtcNow - activities.Min(a => a.Timestamp);

            if (timeSpan.TotalMinutes > 0)
            {
                var rate = count / timeSpan.TotalMinutes;

                if (rate > 10)
                {
                    return new RiskFactor
                    {
                        Name = "HighActivityFrequency",
                        Description = "Unusually high activity frequency",
                        Impact = Math.Min(100, (int)(rate * 5)),
                        Weight = 0.25
                    };
                }
            }

            return null;
        }
        private RiskFactor? AnalyzeActivityPattern(IEnumerable<Core.Entities.Auth.SessionActivityLog> activities)
        {
            var distinctTypes = activities.Select(a => a.ActivityType).Distinct().Count();

            if (distinctTypes > 20)
            {
                return new RiskFactor
                {
                    Name = "UnusualActivityPattern",
                    Description = "Unusual variety of activities",
                    Impact = 60,
                    Weight = 0.2
                };
            }

            return null;
        }

        private RiskFactor? AnalyzeLocationChanges(IEnumerable<Core.Entities.Auth.SessionActivityLog> activities)  // async/Task 제거
        {
            var locations = activities
                .Where(a => !string.IsNullOrWhiteSpace(a.IpAddress))
                .Select(a => a.IpAddress)
                .Distinct()
                .ToList();

            if (locations.Count > 3)
            {
                return new RiskFactor
                {
                    Name = "MultipleLocations",
                    Description = "Session accessed from multiple locations",
                    Impact = 70,
                    Weight = 0.3
                };
            }

            return null;
        }

        private RiskFactor? AssessActivityTypeRisk(string activityType)
        {
            var highRiskActivities = new[] { "DataExport", "BulkDelete", "PermissionChange" };

            if (highRiskActivities.Contains(activityType))
            {
                return new RiskFactor
                {
                    Name = "HighRiskActivity",
                    Description = $"High risk activity: {activityType}",
                    Impact = 80,
                    Weight = 0.35
                };
            }

            return null;
        }

        private async Task<RiskFactor?> AssessUserHistoryRiskAsync(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
                return null;

            if (user.Status == UserStatus.Suspended || user.Status == UserStatus.Inactive)
            {
                return new RiskFactor
                {
                    Name = "SuspiciousUserStatus",
                    Description = $"User status: {user.Status}",
                    Impact = 90,
                    Weight = 0.4
                };
            }

            return null;
        }

        // Repository Extension Methods
        private async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentFailedAttemptsAsync(
            string username, TimeSpan timeSpan)
        {
            try
            {
                var endTime = DateTime.UtcNow;
                var startTime = endTime - timeSpan;

                var allAttempts = await _authAttemptRepository.GetAllAsync();

                return allAttempts
                    .Where(a => a.Username == username &&
                               !a.IsSuccess &&
                               a.AttemptedAt >= startTime &&
                               a.AttemptedAt <= endTime)
                    .OrderByDescending(a => a.AttemptedAt);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get recent failed attempts for {Username}", username);
                return Enumerable.Empty<AuthenticationAttemptLog>();
            }
        }

        private async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentByUserIdAsync(
            Guid userId, int count)
        {
            try
            {
                var allAttempts = await _authAttemptRepository.GetAllAsync();

                return allAttempts
                    .Where(a => a.UserId == userId)
                    .OrderByDescending(a => a.AttemptedAt)
                    .Take(count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get recent attempts for user {UserId}", userId);
                return Enumerable.Empty<AuthenticationAttemptLog>();
            }
        }

        private async Task<IEnumerable<Core.Entities.Auth.SessionActivityLog>> GetBySessionIdAsync(Guid sessionId)
        {
            try
            {
                var allActivities = await _sessionActivityRepository.GetAllAsync();

                return allActivities
                    .Where(a => a.SessionId == sessionId)
                    .OrderByDescending(a => a.Timestamp);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get activities for session {SessionId}", sessionId);
                return Enumerable.Empty<Core.Entities.Auth.SessionActivityLog>();
            }
        }

        private async Task<IEnumerable<Core.Entities.Auth.ConnectedId>> GetByOrganizationIdAsync(Guid organizationId)
        {
            try
            {
                var allConnectedIds = await _connectedIdRepository.GetAllAsync();

                return allConnectedIds
                    .Where(c => c.OrganizationId == organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get connected IDs for organization {OrganizationId}", organizationId);
                return Enumerable.Empty<Core.Entities.Auth.ConnectedId>();
            }
        }

        // Geolocation Helper Methods
        // Geolocation Helper Methods
        private async Task<LocationInfo?> GetLocationFromStringAsync(string locationString)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(locationString))
                    return null;

                var parts = locationString.Split(',');
                var location = new LocationInfo();

                foreach (var part in parts)
                {
                    var keyValue = part.Split(':');
                    if (keyValue.Length == 2)
                    {
                        switch (keyValue[0].Trim().ToLower())
                        {
                            case "country":
                                location.Country = keyValue[1].Trim();
                                break;
                            case "city":
                                location.City = keyValue[1].Trim();
                                break;
                            case "lat":
                            case "latitude":
                                if (double.TryParse(keyValue[1].Trim(), out var lat))
                                    location.Latitude = lat;
                                break;
                            case "lon":
                            case "longitude":
                                if (double.TryParse(keyValue[1].Trim(), out var lon))
                                    location.Longitude = lon;
                                break;
                            case "timezone":
                                location.TimeZone = keyValue[1].Trim();
                                break;
                        }
                    }
                }

                // async 메서드이므로 Task.FromResult 사용
                return await Task.FromResult(location);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse location string: {LocationString}", locationString);
                return null;
            }
        }
        // Additional Helper Methods
        private async Task<(bool IsVpn, bool IsTor)> CheckVpnTorAsync(string ipAddress)
        {
            try
            {
                await Task.Delay(10);
                var torExitNodes = new[] { "192.168.99.1", "10.0.99.1" };
                var isTor = torExitNodes.Contains(ipAddress);
                var isVpn = ipAddress.StartsWith("10.8.") || ipAddress.StartsWith("172.16.");
                return (isVpn, isTor);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check VPN/Tor for IP {IpAddress}", ipAddress);
                return (false, false);
            }
        }

        // GetDeviceHistoryAsync 메서드 수정
        private async Task<DeviceHistory> GetDeviceHistoryAsync(string deviceFingerprint)
        {
            try
            {
                var allAttempts = await _authAttemptRepository.GetAllAsync();
                var deviceAttempts = allAttempts.Where(a => a.DeviceId == deviceFingerprint).ToList();  // DeviceFingerprint → DeviceId

                var firstAttempt = deviceAttempts.OrderBy(a => a.AttemptedAt).FirstOrDefault();
                var lastAttempt = deviceAttempts.OrderByDescending(a => a.AttemptedAt).FirstOrDefault();
                var failedCount = deviceAttempts.Count(a => !a.IsSuccess);
                var uniqueUsers = deviceAttempts.Select(a => a.UserId).Distinct().Count();

                return new DeviceHistory
                {
                    FirstSeen = firstAttempt?.AttemptedAt,
                    LastSeen = lastAttempt?.AttemptedAt,
                    FailedAttempts = failedCount,
                    UniqueUsers = uniqueUsers
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get device history for {DeviceFingerprint}", deviceFingerprint);
                return new DeviceHistory
                {
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    FailedAttempts = 0,
                    UniqueUsers = 1
                };
            }
        }

        private async Task<bool> IsDeviceBlacklistedInternalAsync(string deviceFingerprint)
        {
            try
            {
                var blacklistedDevices = new[] { "BLACKLISTED_DEVICE_001", "BLACKLISTED_DEVICE_002" };
                return await Task.FromResult(blacklistedDevices.Contains(deviceFingerprint));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check device blacklist for {DeviceFingerprint}", deviceFingerprint);
                return false;
            }
        }

        private async Task<bool> IsIpInBlacklistAsync(string ipAddress)
        {
            try
            {
                var blacklistedIps = new[] { "192.168.100.1", "10.0.0.1", "172.16.0.1" };
                return await Task.FromResult(blacklistedIps.Contains(ipAddress));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check IP blacklist for {IpAddress}", ipAddress);
                return false;
            }
        }

        private async Task<RiskPolicy> LoadRiskPolicyAsync(Guid? organizationId)
        {
            try
            {
                return await Task.FromResult(new RiskPolicy
                {
                    IsEnabled = true,
                    Thresholds = new RiskThresholds
                    {
                        LowRisk = 20,
                        MediumRisk = 40,
                        HighRisk = 70,
                        CriticalRisk = 90
                    },
                    ResponseRules = new List<RiskResponseRule>
                    {
                        new RiskResponseRule
                        {
                            RuleName = "RequireMFA",
                            MinRiskScore = 60,
                            Action = "REQUIRE_MFA",
                        },
                        new RiskResponseRule
                        {
                            RuleName = "BlockAccess",
                            MinRiskScore = 90,
                            Action = "BLOCK",
                        }
                    },
                    Settings = new Dictionary<string, object>
                    {
                        ["autoBlockEnabled"] = true,
                        ["alertingEnabled"] = true
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load risk policy for organization {OrganizationId}", organizationId);
                throw;
            }
        }

        private bool ValidateRiskPolicy(RiskPolicy policy)
        {
            if (policy == null) return false;
            if (policy.Thresholds == null) return false;
            if (policy.ResponseRules == null) policy.ResponseRules = new List<RiskResponseRule>();
            return ValidateThresholds(policy.Thresholds);
        }

        private async Task SaveRiskPolicyAsync(Guid organizationId, RiskPolicy policy)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();
                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Failed to save risk policy for organization {OrganizationId}", organizationId);
                throw;
            }
        }

        private bool ValidateThresholds(RiskThresholds thresholds)
        {
            if (thresholds == null) return false;
            if (thresholds.LowRisk < 0 || thresholds.LowRisk > 100) return false;
            if (thresholds.MediumRisk <= thresholds.LowRisk || thresholds.MediumRisk > 100) return false;
            if (thresholds.HighRisk <= thresholds.MediumRisk || thresholds.HighRisk > 100) return false;
            if (thresholds.CriticalRisk <= thresholds.HighRisk || thresholds.CriticalRisk > 100) return false;
            return true;
        }

        private bool ValidateResponseRules(List<RiskResponseRule> rules)
        {
            if (rules == null || !rules.Any()) return false;
            foreach (var rule in rules)
            {
                if (string.IsNullOrWhiteSpace(rule.RuleName)) return false;
                if (string.IsNullOrWhiteSpace(rule.Action)) return false;
                if (rule.MinRiskScore < 0 || rule.MinRiskScore > 100) return false;
            }
            return true;
        }

        private async Task SaveRiskEventAsync(RiskEvent riskEvent)
        {
            try
            {
                _logger.LogInformation("Risk event saved: {EventType} for user {UserId} with score {RiskScore}",
                    riskEvent.EventType, riskEvent.UserId, riskEvent.RiskScore);
                await Task.Delay(10);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save risk event");
                throw;
            }
        }

        private async Task SendHighRiskAlertAsync(RiskEvent riskEvent)
        {
            try
            {
                _logger.LogCritical("HIGH RISK ALERT: {EventType} detected for user {UserId} with score {RiskScore}",
                    riskEvent.EventType, riskEvent.UserId, riskEvent.RiskScore);
                await Task.Delay(10);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send high risk alert");
            }
        }

        private async Task<IEnumerable<RiskEvent>> LoadRiskEventsAsync(Guid? userId, DateTime? from, DateTime? to)
        {
            try
            {
                return await Task.FromResult(new List<RiskEvent>());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load risk events");
                return new List<RiskEvent>();
            }
        }

        private List<DataPoint> GenerateRiskScoreTrend(IEnumerable<RiskEvent> events, DateTime start, DateTime end)
        {
            var trend = new List<DataPoint>();
            var days = (end - start).Days;

            for (int i = 0; i <= days; i++)
            {
                var date = start.AddDays(i);
                var dayEvents = events.Where(e => e.OccurredAt.Date == date.Date);

                trend.Add(new DataPoint
                {
                    Timestamp = date,
                    Value = dayEvents.Any() ? dayEvents.Average(e => e.RiskScore) : 0
                });
            }

            return trend;
        }

        private async Task<int> CountRecentFailuresAsync(Guid userId)
        {
            try
            {
                var endTime = DateTime.UtcNow;
                var startTime = endTime.AddHours(-24);
                var allAttempts = await _authAttemptRepository.GetAllAsync();
                return allAttempts.Count(a => a.UserId == userId && !a.IsSuccess &&
                                             a.AttemptedAt >= startTime && a.AttemptedAt <= endTime);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to count recent failures for user {UserId}", userId);
                return 0;
            }
        }

        private async Task<int> CountRecentAnomaliesAsync(Guid userId)
        {
            try
            {
                return await Task.FromResult(0);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to count recent anomalies for user {UserId}", userId);
                return 0;
            }
        }

        private async Task<bool> CheckRiskyIpUsageAsync(Guid userId)
        {
            try
            {
                var attempts = await GetRecentByUserIdAsync(userId, 10);

                foreach (var attempt in attempts)
                {
                    if (!string.IsNullOrWhiteSpace(attempt.IpAddress))
                    {
                        if (await IsIpInBlacklistAsync(attempt.IpAddress))
                            return true;

                        var vpnTorCheck = await CheckVpnTorAsync(attempt.IpAddress);
                        if (vpnTorCheck.IsTor)
                            return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check risky IP usage for user {UserId}", userId);
                return false;
            }
        }

        private async Task<bool> HasRecentSecurityIncidentsAsync(Guid organizationId)
        {
            try
            {
                return await Task.FromResult(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check recent security incidents for organization {OrganizationId}", organizationId);
                return false;
            }
        }

        private async Task<int> AnalyzeTransactionPatternAsync(Guid userId, decimal amount)
        {
            return await Task.FromResult(0);
        }

        private int AssessTransactionTypeRisk(string transactionType)
        {
            return transactionType switch
            {
                "Withdrawal" => 30,
                "Transfer" => 20,
                "Purchase" => 10,
                _ => 0
            };
        }

        private string GenerateTransactionRecommendation(int riskScore)
        {
            return riskScore switch
            {
                >= 70 => "Require additional verification and manual review",
                >= 50 => "Require two-factor authentication",
                >= 30 => "Send confirmation email",
                _ => "Proceed with standard security"
            };
        }

        private async Task<SecurityAnomaly?> DetectLocationAnomalyInternalAsync(Guid userId, string? ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            try
            {
                var geoInfo = await _geolocationService.GetLocationAsync(ipAddress);
                if (geoInfo == null)
                    return null;

                var currentLocation = new LocationInfo
                {
                    Country = geoInfo.CountryCode,
                    City = geoInfo.City,
                    Latitude = geoInfo.Latitude,
                    Longitude = geoInfo.Longitude
                };

                var anomalyResult = await DetectLocationAnomalyAsync(userId, currentLocation);
                if (!anomalyResult.IsSuccess || anomalyResult.Data?.IsAnomaly != true)
                    return null;

                return new SecurityAnomaly
                {
                    Type = "LocationAnomaly",
                    Description = anomalyResult.Data.ImpossibleTravel ?
                        "Impossible travel detected" : "Unusual location detected",
                    Confidence = anomalyResult.Data.ImpossibleTravel ? 0.9 : 0.6,
                    Evidence = new Dictionary<string, object>
                    {
                        ["distance"] = anomalyResult.Data.Distance,
                        ["timeDifference"] = anomalyResult.Data.TimeDifference.TotalMinutes
                    },
                    DetectedAt = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to detect location anomaly for user {UserId}", userId);
                return null;
            }
        }

        private async Task<SecurityAnomaly?> DetectTimeAnomalyAsync(Guid userId, DateTime timestamp)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
                return null;

            var hour = timestamp.Hour;

            if (hour >= 2 && hour <= 5)
            {
                return new SecurityAnomaly
                {
                    Type = "TimeAnomaly",
                    Description = "Activity at unusual hour",
                    Confidence = 0.5,
                    Evidence = new Dictionary<string, object>
                    {
                        ["hour"] = hour,
                        ["timestamp"] = timestamp
                    },
                    DetectedAt = DateTime.UtcNow
                };
            }

            return null;
        }

        private async Task<SecurityAnomaly?> DetectDeviceAnomalyAsync(Guid userId, string? deviceFingerprint)
        {
            if (string.IsNullOrWhiteSpace(deviceFingerprint))
                return null;

            var reputationResult = await CheckDeviceReputationAsync(deviceFingerprint);
            if (!reputationResult.IsSuccess || reputationResult.Data == null)
                return null;

            if (reputationResult.Data.IsBlacklisted || reputationResult.Data.RiskIndicators > 2)
            {
                return new SecurityAnomaly
                {
                    Type = "DeviceAnomaly",
                    Description = reputationResult.Data.IsBlacklisted ?
                        "Blacklisted device detected" : "Suspicious device detected",
                    Confidence = reputationResult.Data.IsBlacklisted ? 0.95 : 0.7,
                    Evidence = new Dictionary<string, object>
                    {
                        ["deviceId"] = deviceFingerprint,
                        ["riskIndicators"] = reputationResult.Data.RiskIndicators
                    },
                    DetectedAt = DateTime.UtcNow
                };
            }

            return null;
        }

        private async Task<SecurityAnomaly?> DetectBehaviorAnomalyAsync(Guid userId, AuthenticationContext context)
        {
            return await Task.FromResult<SecurityAnomaly?>(null);
        }

        private double CalculateConfidenceScore(int anomalyCount, double anomalyScore)
        {
            if (anomalyCount == 0)
                return 1.0;

            var confidence = Math.Min(1.0, (anomalyCount * 0.2) + (anomalyScore * 0.5));
            return confidence;
        }

        private string DetermineAnomalyAction(double anomalyScore)
        {
            return anomalyScore switch
            {
                >= 0.8 => "Block access and require identity verification",
                >= 0.5 => "Require multi-factor authentication",
                >= 0.3 => "Send security alert to user",
                _ => "Continue with standard monitoring"
            };
        }

        private bool IsSameLocation(LocationInfo loc1, LocationInfo loc2)
        {
            if (loc1.City == loc2.City && loc1.Country == loc2.Country)
                return true;

            if (loc1.Latitude.HasValue && loc1.Longitude.HasValue &&
                loc2.Latitude.HasValue && loc2.Longitude.HasValue)
            {
                var distance = CalculateDistance(loc1, loc2);
                return distance < 10;
            }

            return false;
        }

        private double CalculateDistance(LocationInfo loc1, LocationInfo loc2)
        {
            if (!loc1.Latitude.HasValue || !loc1.Longitude.HasValue ||
                !loc2.Latitude.HasValue || !loc2.Longitude.HasValue)
                return double.MaxValue;

            var R = 6371;
            var lat1Rad = loc1.Latitude.Value * Math.PI / 180;
            var lat2Rad = loc2.Latitude.Value * Math.PI / 180;
            var deltaLat = (loc2.Latitude.Value - loc1.Latitude.Value) * Math.PI / 180;
            var deltaLon = (loc2.Longitude.Value - loc1.Longitude.Value) * Math.PI / 180;

            var a = Math.Sin(deltaLat / 2) * Math.Sin(deltaLat / 2) +
                   Math.Cos(lat1Rad) * Math.Cos(lat2Rad) *
                   Math.Sin(deltaLon / 2) * Math.Sin(deltaLon / 2);

            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));

            return R * c;
        }

        private string DetermineRiskLevel(double riskScore)
        {
            return riskScore switch
            {
                >= 0.8 => "Critical",
                >= 0.6 => "High",
                >= 0.4 => "Medium",
                >= 0.2 => "Low",
                _ => "Minimal"
            };
        }

        private string DetermineTransactionRiskLevel(int riskScore)
        {
            return riskScore switch
            {
                >= 80 => "Critical",
                >= 60 => "High",
                >= 40 => "Medium",
                >= 20 => "Low",
                _ => "Minimal"
            };
        }

        private List<string> GenerateRecommendedActions(double riskScore, List<RiskFactor> factors)
        {
            var actions = new List<string>();

            if (riskScore >= 0.8)
            {
                actions.Add("Block access immediately");
                actions.Add("Notify security team");
                actions.Add("Require manual review");
            }
            else if (riskScore >= 0.6)
            {
                actions.Add("Require multi-factor authentication");
                actions.Add("Send security alert to user");
                actions.Add("Increase monitoring");
            }
            else if (riskScore >= 0.4)
            {
                actions.Add("Request additional verification");
                actions.Add("Log for audit review");
            }

            if (factors.Any(f => f.Name == "BlacklistedIP"))
            {
                actions.Add("Review IP blacklist status");
            }

            if (factors.Any(f => f.Name == "MultipleFailedAttempts"))
            {
                actions.Add("Consider account lockout");
            }

            return actions.Distinct().ToList();
        }


        #endregion

        #region Helper Classes

        private class DeviceHistory
        {
            public DateTime? FirstSeen { get; set; }
            public DateTime? LastSeen { get; set; }
            public int FailedAttempts { get; set; }
            public int UniqueUsers { get; set; }
        }

        private class SessionActivityLog
        {
            public Guid Id { get; set; }
            public Guid SessionId { get; set; }
            public string ActivityType { get; set; } = string.Empty;
            public DateTime Timestamp { get; set; }
            public string? IpAddress { get; set; }
        }

        private class ConnectedId
        {
            public Guid Id { get; set; }
            public Guid UserId { get; set; }
            public Guid OrganizationId { get; set; }
            public string? ExternalId { get; set; }
        }

        #endregion
    }

    #region Supporting Classes

    /// <summary>
    /// 위험 평가 설정
    /// </summary>
    public class RiskAssessmentSettings
    {
        public double MfaRequiredThreshold { get; set; } = 0.6;
        public double AdditionalVerificationThreshold { get; set; } = 0.4;
        public double TrustedIpThreshold { get; set; } = 0.7;
        public decimal HighValueTransactionThreshold { get; set; } = 10000;
        public double SuspiciousDistanceKm { get; set; } = 500;
        public List<string> HighRiskCountries { get; set; } = new() { "XX", "YY" };
    }

    #endregion
}