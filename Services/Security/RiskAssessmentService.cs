using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
// 제거: using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Infra.Monitoring;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider 추가
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
using AuthHive.Core.Models.User.Requests;

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
        private readonly ICacheService _cacheService; // 변경: IMemoryCache -> ICacheService
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus; // 추가: 이벤트 버스를 통한 느슨한 결합
        private readonly IDateTimeProvider _dateTimeProvider; // 추가: 테스트 용이성을 위한 시간 제공자
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
            ICacheService cacheService, // 변경: IMemoryCache 제거, ICacheService 추가
            IUnitOfWork unitOfWork,
            IEventBus eventBus, // 추가: 이벤트 버스 주입
            IDateTimeProvider dateTimeProvider, // 추가: 시간 제공자 주입
            ILogger<RiskAssessmentService> logger,
            IOptions<RiskAssessmentSettings> settings)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _authAttemptRepository = authAttemptRepository ?? throw new ArgumentNullException(nameof(authAttemptRepository));
            _sessionActivityRepository = sessionActivityRepository ?? throw new ArgumentNullException(nameof(sessionActivityRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _geolocationService = geolocationService ?? throw new ArgumentNullException(nameof(geolocationService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService)); // 할당
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus)); // 할당
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider)); // 할당
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _settings = settings?.Value ?? throw new ArgumentNullException(nameof(settings));
        }

        #endregion

        #region IService Implementation
        /// <summary>
        /// 서비스 초기화 - 캐시 정책 로드
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Initializing RiskAssessmentService");

                // MemoryCache 대신 ICacheService의 비동기 RemoveAsync 사용
                await _cacheService.RemoveAsync("risk_policy:default", cancellationToken);

                // CancellationToken을 LoadRiskPolicyAsync 호출에 전달
                var defaultPolicy = await LoadRiskPolicyAsync(null, cancellationToken);

                if (defaultPolicy != null)
                {
                    // MemoryCache 대신 ICacheService의 비동기 SetAsync 사용
                    await _cacheService.SetAsync("risk_policy:default", defaultPolicy, TimeSpan.FromHours(1), cancellationToken);
                }

                _logger.LogInformation("RiskAssessmentService initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize RiskAssessmentService");
                throw;
            }
        }

        /// <summary>
        /// 서비스 상태 확인 - DB 및 캐시 의존성 검사
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Repository Check (DB Dependency)
                // CancellationToken을 Repository 호출에 전달
                var repoCheckTask = _userRepository.GetByIdAsync(Guid.NewGuid(), cancellationToken)
                    .ContinueWith(t => !t.IsFaulted && !t.IsCanceled, cancellationToken);

                // 2. Cache Check (ICacheService Dependency)
                // ICacheService의 SetStringAsync를 사용하여 값 타입 제약 조건 회피
                var cacheCheckTask = Task.Run(async () =>
                {
                    try
                    {
                        var key = "health_check";
                        const string healthValue = "OK"; // 값 대신 참조 타입(string) 사용

                        // ICacheService.SetStringAsync를 사용하여 string 값 저장
                        await _cacheService.SetStringAsync(key, healthValue, TimeSpan.FromSeconds(1), cancellationToken);

                        // ICacheService.GetStringAsync를 사용하여 값 읽기 및 검증
                        var result = await _cacheService.GetStringAsync(key, cancellationToken);

                        // 읽어온 값이 "OK"인지 확인
                        return result == healthValue;
                    }
                    catch (OperationCanceledException)
                    {
                        // 취소 요청이 들어온 경우 작업 중단
                        throw;
                    }
                    catch
                    {
                        // 캐시 작업 실패 시 false 반환
                        return false;
                    }
                }, cancellationToken);


                // 모든 비동기 상태 확인 작업이 완료될 때까지 대기
                await Task.WhenAll(repoCheckTask, cacheCheckTask);

                var isRepoHealthy = repoCheckTask.Result;
                var isCacheHealthy = cacheCheckTask.Result;

                // 두 종속성 모두 정상인지 결합하여 반환
                return isRepoHealthy && isCacheHealthy;
            }
            catch (OperationCanceledException)
            {
                // 외부에서 취소 요청이 들어온 경우 예외 전파
                throw;
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
        public async Task<ServiceResult<RiskAssessment>> AssessAuthenticationRiskAsync(AuthenticationRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var riskFactors = new List<RiskFactor>();
                var riskScore = 0.0;

                if (!string.IsNullOrWhiteSpace(request.IpAddress))
                {
                    // CancellationToken 전달
                    var ipRiskFactor = await AssessIpRiskAsync(request.IpAddress, cancellationToken);
                    if (ipRiskFactor != null)
                    {
                        riskFactors.Add(ipRiskFactor);
                        riskScore += ipRiskFactor.WeightedScore / 100.0;
                    }
                }

                if (request.DeviceInfo != null)
                {
                    // CancellationToken 전달
                    var deviceRiskFactor = await AssessDeviceRiskAsync(request.DeviceInfo, cancellationToken);
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
                    // CancellationToken 전달
                    var failureRiskFactor = await AssessRecentFailuresAsync(request.Username, cancellationToken);
                    if (failureRiskFactor != null)
                    {
                        riskFactors.Add(failureRiskFactor);
                        riskScore += failureRiskFactor.WeightedScore / 100.0;
                    }
                }

                // IDateTimeProvider 사용
                var timeRiskFactor = AssessTimeBasedRisk(_dateTimeProvider.UtcNow);
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
                    AssessedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
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
        public async Task<ServiceResult<RiskAssessment>> AssessSessionRiskAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var activities = await GetBySessionIdAsync(sessionId, cancellationToken);
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

                // 3. 지역 변경 감지 (비동기 호출 포함하도록 수정)
                // CancellationToken 전달
                var locationRisk = await AnalyzeLocationChangesAsync(activities, cancellationToken);
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
                    AssessedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
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
        public async Task<ServiceResult<RiskAssessment>> AssessUserActivityRiskAsync(Guid userId, UserActivity activity, CancellationToken cancellationToken = default)
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
                    // CancellationToken 전달
                    var ipRisk = await AssessIpRiskAsync(activity.IpAddress, cancellationToken);
                    if (ipRisk != null)
                    {
                        riskFactors.Add(ipRisk);
                        riskScore += ipRisk.WeightedScore / 100.0;
                    }
                }

                // CancellationToken 전달
                var userHistoryRisk = await AssessUserHistoryRiskAsync(userId, cancellationToken);
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
                    AssessedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
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
        public async Task<ServiceResult<TransactionRiskAssessment>> AssessTransactionRiskAsync(TransactionContext context, CancellationToken cancellationToken = default)
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

                // CancellationToken 전달
                var patternRisk = await AnalyzeTransactionPatternAsync(context.UserId, context.Amount, cancellationToken);
                if (patternRisk > 0)
                {
                    riskFactors.Add("Unusual transaction pattern");
                    riskScore += patternRisk;
                }

                if (!string.IsNullOrWhiteSpace(context.IpAddress))
                {
                    // CancellationToken 전달
                    var ipRisk = await AssessIpRiskAsync(context.IpAddress, cancellationToken);
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

        /// <summary>
        /// UserActivityLogService 전용 위험도 평가 (LogUserActivityRequest DTO 기반)
        /// ConnectedId를 통해 UserId를 조회하여 해당 User의 위험 평가를 수행합니다.
        /// </summary>
        public async Task<int> AssessActivityRiskAsync(LogUserActivityRequest request, CancellationToken cancellationToken = default)
        {
            // 이 메서드는 사용자 활동 로깅 시점에 간소화된 위험 점수를 계산합니다.

            // 💡 ConnectedId를 사용하여 해당 ConnectedId 엔티티 조회
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(request.ConnectedId, cancellationToken);

            // 🚨 CS8602 해결: connectedIdEntity가 null이거나, UserId가 null인 경우를 명시적으로 처리
            if (connectedIdEntity == null || !connectedIdEntity.UserId.HasValue)
            {
                _logger.LogWarning("Cannot assess activity risk: ConnectedId {ConnectedId} not linked to a valid User or entity is null. Treating as minimal risk.", request.ConnectedId);
                return 0;
            }

            // 이제 connectedIdEntity는 null이 아님이 보장되고, UserId도 값을 가짐 (경고 해제)
            var userId = connectedIdEntity.UserId.Value;

            var activity = new UserActivity { ActivityType = request.ActivityType, IpAddress = request.IpAddress };

            // 조회된 UserId를 사용하여 위험 평가 수행. 
            // (이 로직은 ConnectedId 요청 컨텍스트를 User의 통합 위험 평가에 반영함.)
            var assessmentResult = await AssessUserActivityRiskAsync(userId, activity, cancellationToken);

            return assessmentResult.IsSuccess && assessmentResult.Data != null
                ? (int)(assessmentResult.Data.RiskScore * 100)
                : 0;
        }

        #endregion
        #region 이상 탐지

        /// <summary>
        /// 이상 접근 감지
        /// </summary>
        public async Task<ServiceResult<AnomalyDetectionResult>> DetectAnomalyAsync(Guid userId, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var anomalies = new List<SecurityAnomaly>();
                var anomalyScore = 0.0;

                // CancellationToken 전달
                var locationAnomaly = await DetectLocationAnomalyInternalAsync(userId, context.IpAddress, cancellationToken);
                if (locationAnomaly != null)
                {
                    anomalies.Add(locationAnomaly);
                    // SecurityAnomaly의 Severity는 AuditEventSeverity 타입 (간단화를 위해 Impact 사용)
                    var impact = locationAnomaly.Confidence;
                    anomalyScore += (impact >= 0.8) ? 0.4 : 0.2;
                }

                // CancellationToken 전달
                var timeAnomaly = await DetectTimeAnomalyAsync(userId, context.Timestamp, cancellationToken);
                if (timeAnomaly != null)
                {
                    anomalies.Add(timeAnomaly);
                    var impact = timeAnomaly.Confidence;
                    anomalyScore += (impact >= 0.8) ? 0.3 : 0.15;
                }

                // CancellationToken 전달
                var deviceAnomaly = await DetectDeviceAnomalyAsync(userId, context.DeviceFingerprint, cancellationToken);
                if (deviceAnomaly != null)
                {
                    anomalies.Add(deviceAnomaly);
                    var impact = deviceAnomaly.Confidence;
                    anomalyScore += (impact >= 0.8) ? 0.3 : 0.15;
                }

                // CancellationToken 전달
                var behaviorAnomaly = await DetectBehaviorAnomalyAsync(userId, context, cancellationToken);
                if (behaviorAnomaly != null)
                {
                    anomalies.Add(behaviorAnomaly);
                    var impact = behaviorAnomaly.Confidence;
                    anomalyScore += (impact >= 0.8) ? 0.35 : 0.2;
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
                    DetectedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
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
        public async Task<ServiceResult<LocationAnomalyResult>> DetectLocationAnomalyAsync(Guid userId, LocationInfo currentLocation, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var recentActivities = await GetRecentByUserIdAsync(userId, 10, cancellationToken);
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
                        // CancellationToken 전달
                        var location = await GetLocationFromStringAsync(activity.Location, cancellationToken);
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
                // IDateTimeProvider.UtcNow 사용
                var timeDifference = _dateTimeProvider.UtcNow - previousTime!.Value;

                var impossibleTravel = false;
                if (timeDifference.TotalHours > 0)
                {
                    var speed = distance / timeDifference.TotalHours;
                    // 시속 1000km 이상은 불가능한 이동으로 간주 (상용 항공기보다 빠름)
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
        public async Task<ServiceResult<IpReputationResult>> CheckIpReputationAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"ip_reputation:{ipAddress}";

                // ICacheService.GetAsync 사용
                var cached = await _cacheService.GetAsync<IpReputationResult>(cacheKey, cancellationToken);

                if (cached != null)
                {
                    return ServiceResult<IpReputationResult>.Success(cached);
                }

                var result = new IpReputationResult
                {
                    IpAddress = ipAddress,
                    CheckedAt = _dateTimeProvider.UtcNow, // IDateTimeProvider 사용
                    ReputationScore = 1.0,
                    IsTrusted = true,
                    IsBlocked = false
                };

                // CancellationToken 전달
                if (await IsIpInBlacklistAsync(ipAddress, cancellationToken))
                {
                    result.IsBlacklisted = true;
                    result.IsBlocked = true;
                    result.ReputationScore = 0.0;
                    result.BlockReason = "IP is blacklisted";
                    result.Categories.Add("Blacklisted");
                }

                // CancellationToken 전달
                var vpnTorCheck = await CheckVpnTorAsync(ipAddress, cancellationToken);
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

                // CancellationToken 전달
                var geoInfo = await _geolocationService.GetLocationAsync(ipAddress, cancellationToken);
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

                // ICacheService.SetAsync 사용
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromHours(1), cancellationToken);

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
        public async Task<ServiceResult<DeviceReputationResult>> CheckDeviceReputationAsync(string deviceFingerprint, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"device_reputation:{deviceFingerprint}";

                // ICacheService.GetAsync 사용
                var cached = await _cacheService.GetAsync<DeviceReputationResult>(cacheKey, cancellationToken);

                if (cached != null)
                {
                    // ! 연산자 대신 null 체크를 통해 안정성 확보
                    return ServiceResult<DeviceReputationResult>.Success(cached);
                }

                // CancellationToken 전달
                var deviceHistory = await GetDeviceHistoryAsync(deviceFingerprint, cancellationToken);

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

                // CancellationToken 전달
                if (await IsDeviceBlacklistedInternalAsync(deviceFingerprint, cancellationToken))
                {
                    result.IsBlacklisted = true;
                    result.IsTrusted = false;
                    result.ReputationScore = 0;
                    result.RiskIndicators++;
                }

                // IDateTimeProvider.UtcNow 사용
                if (!deviceHistory.FirstSeen.HasValue ||
                    (_dateTimeProvider.UtcNow - deviceHistory.FirstSeen.Value).TotalDays < 1)
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

                // ICacheService.SetAsync 사용
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(30), cancellationToken);

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
        public async Task<ServiceResult<bool>> IsIpBlacklistedAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var isBlacklisted = await IsIpInBlacklistAsync(ipAddress, cancellationToken);
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
        public async Task<ServiceResult<bool>> IsDeviceBlacklistedAsync(string deviceFingerprint, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var isBlacklisted = await IsDeviceBlacklistedInternalAsync(deviceFingerprint, cancellationToken);
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
        public async Task<ServiceResult<RiskPolicy>> GetRiskPolicyAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"risk_policy:{organizationId ?? Guid.Empty}";

                // ICacheService.GetAsync 사용
                var cached = await _cacheService.GetAsync<RiskPolicy>(cacheKey, cancellationToken);

                if (cached != null)
                {
                    return ServiceResult<RiskPolicy>.Success(cached);
                }

                // CancellationToken 전달
                var policy = await LoadRiskPolicyAsync(organizationId, cancellationToken);

                // ICacheService.SetAsync 사용
                await _cacheService.SetAsync(cacheKey, policy, TimeSpan.FromMinutes(10), cancellationToken);

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
        public async Task<ServiceResult> SetRiskPolicyAsync(Guid organizationId, RiskPolicy policy, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!ValidateRiskPolicy(policy))
                {
                    return ServiceResult.Failure("Invalid risk policy", "INVALID_POLICY");
                }

                // CancellationToken 전달
                await SaveRiskPolicyAsync(organizationId, policy, cancellationToken);

                var cacheKey = $"risk_policy:{organizationId}";
                // ICacheService.RemoveAsync 사용
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);

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
        public async Task<ServiceResult> SetRiskThresholdsAsync(Guid organizationId, RiskThresholds thresholds, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!ValidateThresholds(thresholds))
                {
                    return ServiceResult.Failure("Invalid thresholds", "INVALID_THRESHOLDS");
                }

                // CancellationToken 전달
                var policyResult = await GetRiskPolicyAsync(organizationId, cancellationToken);
                if (!policyResult.IsSuccess)
                {
                    return ServiceResult.Failure("Failed to get current policy", "POLICY_NOT_FOUND");
                }

                var policy = policyResult.Data!;
                policy.Thresholds = thresholds;

                // CancellationToken 전달
                return await SetRiskPolicyAsync(organizationId, policy, cancellationToken);
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
        public async Task<ServiceResult> SetRiskResponseRulesAsync(Guid organizationId, List<RiskResponseRule> rules, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!ValidateResponseRules(rules))
                {
                    return ServiceResult.Failure("Invalid response rules", "INVALID_RULES");
                }

                // CancellationToken 전달
                var policyResult = await GetRiskPolicyAsync(organizationId, cancellationToken);
                if (!policyResult.IsSuccess)
                {
                    return ServiceResult.Failure("Failed to get current policy", "POLICY_NOT_FOUND");
                }

                var policy = policyResult.Data!;
                policy.ResponseRules = rules;

                // CancellationToken 전달
                return await SetRiskPolicyAsync(organizationId, policy, cancellationToken);
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
        /// 위험 이벤트 기록 및 고위험 인증 이벤트 발행 (이벤트 버스 사용)
        /// </summary>
// Path: AuthHive.Auth.Services.Security.RiskAssessmentService.cs (994번째 줄 주변)

        /// <summary>
        /// 위험 이벤트 기록 및 고위험 인증 이벤트 발행 (이벤트 버스 사용)
        /// </summary>
        public async Task<ServiceResult> LogRiskEventAsync(RiskEvent riskEvent, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                await SaveRiskEventAsync(riskEvent, cancellationToken);

                // HighRiskSecurityEvent 대신 HighRiskAuthenticationEvent 사용
                if (riskEvent.RiskScore >= 80)
                {
                    // High Risk Alert 로그 및 이벤트 버스 발행
                    await SendHighRiskAlertAsync(riskEvent, cancellationToken);

                    // 💡 수정된 로직: OrganizationId 조회
                    Guid organizationId = Guid.Empty;
                    var eventData = riskEvent.EventData;

                    if (eventData != null) // Dictionary가 null이 아닌 경우에만 로직 실행
                    {
                        // ConnectedId를 통해 OrganizationId를 찾습니다.
                        if (eventData.TryGetValue("ConnectedId", out var connectedIdObj) && connectedIdObj is Guid connectedId)
                        {
                            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                            if (connectedIdEntity != null)
                            {
                                organizationId = connectedIdEntity.OrganizationId;
                            }
                        }

                        // HighRiskAuthenticationEvent 생성 및 발행
                        var highRiskEvent = new HighRiskAuthenticationEvent(organizationId)
                        {
                            UserId = riskEvent.UserId,
                            Username = eventData.GetValueOrDefault("Username") as string ?? "N/A",
                            IpAddress = eventData.GetValueOrDefault("IpAddress") as string ?? CommonDefaults.UnknownDevice,
                            RiskScore = riskEvent.RiskScore,
                            RiskLevel = DetermineRiskLevel(riskEvent.RiskScore / 100.0),
                            RiskFactors = (eventData.GetValueOrDefault("RiskFactors") as List<string>) ?? new List<string>(),
                            RequiresMfa = riskEvent.RiskScore >= _settings.MfaRequiredThreshold * 100,
                            RequiresAdditionalVerification = riskEvent.RiskScore >= _settings.AdditionalVerificationThreshold * 100
                        };

                        await _eventBus.PublishAsync(highRiskEvent, cancellationToken);
                    }
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
            DateTime? to = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var events = await LoadRiskEventsAsync(userId, from, to, cancellationToken);
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
            TimeSpan period = default,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (period == default)
                {
                    period = TimeSpan.FromDays(30);
                }

                var endDate = _dateTimeProvider.UtcNow; // IDateTimeProvider 사용
                var startDate = endDate - period;

                // CancellationToken 전달
                var events = await LoadRiskEventsAsync(null, startDate, endDate, cancellationToken);

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
        public async Task<ServiceResult<UserRiskScore>> CalculateUserRiskScoreAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var score = 0;
                var riskFactors = new List<string>();

                // CancellationToken 전달
                var recentFailures = await CountRecentFailuresAsync(userId, cancellationToken);
                if (recentFailures > 0)
                {
                    score += recentFailures * 10;
                    riskFactors.Add($"{recentFailures} recent failed authentications");
                }

                // CancellationToken 전달
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user != null)
                {
                    // IDateTimeProvider.UtcNow 사용
                    var accountAge = _dateTimeProvider.UtcNow - user.CreatedAt;
                    if (accountAge.TotalDays < 7)
                    {
                        score += 20;
                        riskFactors.Add("New account");
                    }
                }

                // CancellationToken 전달
                var anomalyCount = await CountRecentAnomaliesAsync(userId, cancellationToken);
                if (anomalyCount > 0)
                {
                    score += anomalyCount * 15;
                    riskFactors.Add($"{anomalyCount} recent anomalies detected");
                }

                // CancellationToken 전달
                var riskyIpUsage = await CheckRiskyIpUsageAsync(userId, cancellationToken);
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
                    CalculatedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
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
        public async Task<ServiceResult<OrganizationRiskScore>> CalculateOrganizationRiskScoreAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var connectedIds = await GetByOrganizationIdAsync(organizationId, cancellationToken);

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

                    // CancellationToken 전달
                    var userScoreResult = await CalculateUserRiskScoreAsync(connectedId.UserId.Value, cancellationToken);
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

                // CancellationToken 전달
                if (await HasRecentSecurityIncidentsAsync(organizationId, cancellationToken))
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
        public async Task<ServiceResult> UpdateRiskScoreAsync(Guid userId, RiskScoreUpdate update, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var currentScoreResult = await CalculateUserRiskScoreAsync(userId, cancellationToken);
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
                    OccurredAt = _dateTimeProvider.UtcNow, // IDateTimeProvider 사용
                    EventData = new Dictionary<string, object>
                    {
                        ["previousScore"] = currentScore,
                        ["delta"] = update.ScoreDelta,
                        ["reason"] = update.Reason,
                        ["updatedBy"] = update.UpdatedBy ?? "System"
                    }
                };

                // CancellationToken 전달
                await LogRiskEventAsync(riskEvent, cancellationToken);

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

        private async Task<RiskFactor?> AssessIpRiskAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
            var reputationResult = await CheckIpReputationAsync(ipAddress, cancellationToken);
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

        private async Task<RiskFactor?> AssessDeviceRiskAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(deviceInfo.DeviceId))
                return null;

            // CancellationToken 전달
            var reputationResult = await CheckDeviceReputationAsync(deviceInfo.DeviceId, cancellationToken);
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

        private async Task<RiskFactor?> AssessRecentFailuresAsync(string username, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
            var failures = await GetRecentFailedAttemptsAsync(username, TimeSpan.FromHours(1), cancellationToken);

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

            // UTC 기준 02:00 ~ 05:00 사이 활동은 비정상 시간으로 간주 (상황에 따라 현지 시간으로 변환 필요)
            if (hour >= 2 && hour <= 5)
            {
                return new RiskFactor
                {
                    Name = "UnusualTime",
                    Description = "Login attempt at unusual hour (UTC)",
                    Impact = 40,
                    Weight = 0.15
                };
            }

            return null;
        }

        private RiskFactor? AnalyzeActivityFrequency(IEnumerable<Core.Entities.Auth.SessionActivityLog> activities)
        {
            var count = activities.Count();
            var timeSpan = _dateTimeProvider.UtcNow - activities.Min(a => a.Timestamp); // IDateTimeProvider 사용

            if (timeSpan.TotalMinutes > 0)
            {
                var rate = count / timeSpan.TotalMinutes;

                if (rate > 10) // 분당 10회 이상의 활동은 비정상으로 간주
                {
                    return new RiskFactor
                    {
                        Name = "HighActivityFrequency",
                        Description = $"Unusually high activity frequency: {rate:F2} activities/min",
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
                    Description = $"Unusual variety of activities detected: {distinctTypes} types",
                    Impact = 60,
                    Weight = 0.2
                };
            }

            return null;
        }

        /// <summary>
        /// 세션 활동 로그의 위치 변화를 분석합니다.
        /// </summary>
        private async Task<RiskFactor?> AnalyzeLocationChangesAsync(IEnumerable<Core.Entities.Auth.SessionActivityLog> activities, CancellationToken cancellationToken = default)
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
                    Description = $"Session accessed from multiple locations: {locations.Count} IPs",
                    Impact = 70,
                    Weight = 0.3
                };
            }

            // 추가: 지리적 위치 변동성 검사 (첫 활동과 마지막 활동 IP의 지리적 위치가 다른 경우)
            if (activities.Count() >= 2)
            {
                var firstActivity = activities.OrderBy(a => a.Timestamp).First();
                var lastActivity = activities.OrderByDescending(a => a.Timestamp).First();

                if (!string.IsNullOrWhiteSpace(firstActivity.IpAddress) && !string.IsNullOrWhiteSpace(lastActivity.IpAddress) &&
                    firstActivity.IpAddress != lastActivity.IpAddress)
                {
                    // 위치 정보 조회 및 비교 (GeolocationService 사용)
                    var firstGeo = await _geolocationService.GetLocationAsync(firstActivity.IpAddress, cancellationToken);
                    var lastGeo = await _geolocationService.GetLocationAsync(lastActivity.IpAddress, cancellationToken);

                    if (firstGeo?.CountryCode != lastGeo?.CountryCode)
                    {
                        return new RiskFactor
                        {
                            Name = "CountryChange",
                            Description = $"Session country changed from {firstGeo?.CountryCode} to {lastGeo?.CountryCode}",
                            Impact = 80,
                            Weight = 0.4
                        };
                    }
                }
            }

            return null;
        }

        private RiskFactor? AssessActivityTypeRisk(string activityType)
        {
            var highRiskActivities = new[] { "DataExport", "BulkDelete", "PermissionChange", "PolicyModification" };

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

        private async Task<RiskFactor?> AssessUserHistoryRiskAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
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
            string username, TimeSpan timeSpan, CancellationToken cancellationToken = default)
        {
            try
            {
                var endTime = _dateTimeProvider.UtcNow; // IDateTimeProvider 사용
                var startTime = endTime - timeSpan;

                // CancellationToken 전달
                // ⚠️ 주의: _authAttemptRepository.GetAllAsync()가 User의 모든 ConnectedId 시도를 포함한다고 가정
                var allAttempts = await _authAttemptRepository.GetAllAsync(cancellationToken);

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
            Guid userId, int count, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                // ⚠️ 주의: _authAttemptRepository.GetAllAsync()가 User의 모든 ConnectedId 시도를 포함한다고 가정
                var allAttempts = await _authAttemptRepository.GetAllAsync(cancellationToken);

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

        private async Task<IEnumerable<Core.Entities.Auth.SessionActivityLog>> GetBySessionIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                // ⚠️ 주의: _sessionActivityRepository.GetAllAsync()가 ConnectedId/UserID 정보를 포함한다고 가정
                var allActivities = await _sessionActivityRepository.GetAllAsync(cancellationToken);

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

        private async Task<IEnumerable<Core.Entities.Auth.ConnectedId>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var allConnectedIds = await _connectedIdRepository.GetAllAsync(cancellationToken);

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
        /// <summary>
        /// 위치 문자열을 LocationInfo 객체로 파싱합니다. (비동기 처리)
        /// </summary>
        private async Task<LocationInfo?> GetLocationFromStringAsync(string locationString, CancellationToken cancellationToken = default)
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

                // CancellationToken을 존중하기 위해 Task.Yield 사용
                await Task.Yield();
                return location;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse location string: {LocationString}", locationString);
                return null;
            }
        }

        // Additional Helper Methods
        private async Task<(bool IsVpn, bool IsTor)> CheckVpnTorAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            try
            {
                // Task.Delay에도 CancellationToken 전달
                await Task.Delay(10, cancellationToken);
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

        /// <summary>
        /// 장치 지문 기록 조회
        /// </summary>
        private async Task<DeviceHistory> GetDeviceHistoryAsync(string deviceFingerprint, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var allAttempts = await _authAttemptRepository.GetAllAsync(cancellationToken);
                var deviceAttempts = allAttempts.Where(a => a.DeviceId == deviceFingerprint).ToList();

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
                    FirstSeen = _dateTimeProvider.UtcNow,
                    LastSeen = _dateTimeProvider.UtcNow,
                    FailedAttempts = 0,
                    UniqueUsers = 1
                };
            }
        }

        private async Task<bool> IsDeviceBlacklistedInternalAsync(string deviceFingerprint, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var blacklistedDevices = new[] { "BLACKLISTED_DEVICE_001", "BLACKLISTED_DEVICE_002" };
                return await Task.FromResult(blacklistedDevices.Contains(deviceFingerprint));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check device blacklist for {DeviceFingerprint}", deviceFingerprint);
                return false;
            }
        }

        private async Task<bool> IsIpInBlacklistAsync(string ipAddress, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var blacklistedIps = new[] { "192.168.100.1", "10.0.0.1", "172.16.0.1" };
                return await Task.FromResult(blacklistedIps.Contains(ipAddress));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check IP blacklist for {IpAddress}", ipAddress);
                return false;
            }
        }

        /// <summary>
        /// 위험 정책 로드 (Mock 구현)
        /// </summary>
        private async Task<RiskPolicy> LoadRiskPolicyAsync(Guid? organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                await Task.Delay(10, cancellationToken);
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

        /// <summary>
        /// 위험 정책 저장 (Mock 구현) - 트랜잭션 처리 포함
        /// </summary>
        private async Task SaveRiskPolicyAsync(Guid organizationId, RiskPolicy policy, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                await _unitOfWork.BeginTransactionAsync(cancellationToken);
                // 실제 DB 저장 로직 수행 (Mock)
                await Task.Delay(10, cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
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

        /// <summary>
        /// 위험 이벤트 저장 (Mock 구현)
        /// </summary>
        private async Task SaveRiskEventAsync(RiskEvent riskEvent, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Risk event saved: {EventType} for user {UserId} with score {RiskScore}",
                    riskEvent.EventType, riskEvent.UserId, riskEvent.RiskScore);
                // CancellationToken 전달
                await Task.Delay(10, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save risk event");
                throw;
            }
        }

        /// <summary>
        /// High Risk Alert 전송 (Mock 구현)
        /// </summary>
        private async Task SendHighRiskAlertAsync(RiskEvent riskEvent, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogCritical("HIGH RISK ALERT: {EventType} detected for user {UserId} with score {RiskScore}",
                    riskEvent.EventType, riskEvent.UserId, riskEvent.RiskScore);
                // CancellationToken 전달
                await Task.Delay(10, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send high risk alert");
            }
        }

        /// <summary>
        /// 위험 이벤트 로드 (Mock 구현)
        /// </summary>
        private async Task<IEnumerable<RiskEvent>> LoadRiskEventsAsync(Guid? userId, DateTime? from, DateTime? to, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
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

        private async Task<int> CountRecentFailuresAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var endTime = _dateTimeProvider.UtcNow; // IDateTimeProvider 사용
                var startTime = endTime.AddHours(-24);
                // CancellationToken 전달
                var allAttempts = await _authAttemptRepository.GetAllAsync(cancellationToken);
                return allAttempts.Count(a => a.UserId == userId && !a.IsSuccess &&
                                             a.AttemptedAt >= startTime && a.AttemptedAt <= endTime);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to count recent failures for user {UserId}", userId);
                return 0;
            }
        }

        private async Task<int> CountRecentAnomaliesAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                return await Task.FromResult(0);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to count recent anomalies for user {UserId}", userId);
                return 0;
            }
        }

        private async Task<bool> CheckRiskyIpUsageAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                var attempts = await GetRecentByUserIdAsync(userId, 10, cancellationToken);

                foreach (var attempt in attempts)
                {
                    if (!string.IsNullOrWhiteSpace(attempt.IpAddress))
                    {
                        // CancellationToken 전달
                        if (await IsIpInBlacklistAsync(attempt.IpAddress, cancellationToken))
                            return true;

                        // CancellationToken 전달
                        var vpnTorCheck = await CheckVpnTorAsync(attempt.IpAddress, cancellationToken);
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

        private async Task<bool> HasRecentSecurityIncidentsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken 전달
                return await Task.FromResult(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check recent security incidents for organization {OrganizationId}", organizationId);
                return false;
            }
        }

        private async Task<int> AnalyzeTransactionPatternAsync(Guid userId, decimal amount, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
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

        private async Task<SecurityAnomaly?> DetectLocationAnomalyInternalAsync(Guid userId, string? ipAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            try
            {
                // CancellationToken 전달
                var geoInfo = await _geolocationService.GetLocationAsync(ipAddress, cancellationToken);
                if (geoInfo == null)
                    return null;

                var currentLocation = new LocationInfo
                {
                    Country = geoInfo.CountryCode,
                    City = geoInfo.City,
                    Latitude = geoInfo.Latitude,
                    Longitude = geoInfo.Longitude
                };

                // CancellationToken 전달
                var anomalyResult = await DetectLocationAnomalyAsync(userId, currentLocation, cancellationToken);
                if (!anomalyResult.IsSuccess || anomalyResult.Data?.IsAnomaly != true)
                    return null;

                // 최근 활동 로그를 다시 가져와서 lastActivity.AttemptedAt을 정확히 참조해야 합니다.
                var recentActivities = await GetRecentByUserIdAsync(userId, 1, cancellationToken);
                var lastAttemptTime = recentActivities.FirstOrDefault()?.AttemptedAt ?? _dateTimeProvider.UtcNow;
                var timeDifferenceMinutes = (_dateTimeProvider.UtcNow - lastAttemptTime).TotalMinutes;


                return new SecurityAnomaly
                {
                    Type = "LocationAnomaly",
                    Description = anomalyResult.Data.ImpossibleTravel ?
                        "Impossible travel detected" : "Unusual location detected",
                    Confidence = anomalyResult.Data.ImpossibleTravel ? 0.9 : 0.6,
                    Evidence = new Dictionary<string, object>
                    {
                        ["distance"] = anomalyResult.Data.Distance,
                        // IDateTimeProvider.UtcNow 사용
                        ["timeDifference"] = timeDifferenceMinutes
                    },
                    DetectedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to detect location anomaly for user {UserId}", userId);
                return null;
            }
        }

        private async Task<SecurityAnomaly?> DetectTimeAnomalyAsync(Guid userId, DateTime timestamp, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
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
                    DetectedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
                };
            }

            return null;
        }

        private async Task<SecurityAnomaly?> DetectDeviceAnomalyAsync(Guid userId, string? deviceFingerprint, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(deviceFingerprint))
                return null;

            // CancellationToken 전달
            var reputationResult = await CheckDeviceReputationAsync(deviceFingerprint, cancellationToken);
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
                    DetectedAt = _dateTimeProvider.UtcNow // IDateTimeProvider 사용
                };
            }

            return null;
        }

        private async Task<SecurityAnomaly?> DetectBehaviorAnomalyAsync(Guid userId, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            // CancellationToken 전달
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

    }
    public class RiskAssessmentSettings
    {
        public double MfaRequiredThreshold { get; set; } = 0.6;
        public double AdditionalVerificationThreshold { get; set; } = 0.4;
        public double TrustedIpThreshold { get; set; } = 0.7;
        public decimal HighValueTransactionThreshold { get; set; } = 10000;
        public double SuspiciousDistanceKm { get; set; } = 500;
        public List<string> HighRiskCountries { get; set; } = new() { "XX", "YY" };
    }
}