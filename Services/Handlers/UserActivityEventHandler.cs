
using System;
using System.Collections.Generic;
using System.IO; // 👈 [FIX CS1503] Stream 사용을 위해 필요
using System.Linq; // 👈 [FIX CS1061] ValidationErrors 처리를 위해 필요
using System.Text.Json; // 👈 [FIX CS1503] JSON 직렬화를 위해 필요
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler;
// 👇 이벤트 모델 네임스페이스 확인 및 조정 필요 (리팩토링된 네임스페이스 사용)
using AuthHive.Core.Models.User.Events.Activity;
using AuthHive.Core.Models.User.Events.System; // HighRiskActivityDetectedEvent (가정)
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Service; // IPlanRestrictionService, IConnectedIdService
using AuthHive.Core.Models.Common; // ServiceResult<T>
using AuthHive.Core.Models.Auth.ConnectedId.Responses; // ConnectedIdDetailResponse

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// SaaS 최적화 사용자 활동 이벤트 핸들러
    /// </summary>
    public class UserActivityEventHandler : IUserActivityEventHandler, IService
    {
        private readonly ILogger<UserActivityEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IEventBus _eventBus;
        private readonly IConnectedIdService _connectedIdService;

        private const string CACHE_KEY_PREFIX = "activity";

        public int Priority => 2;
        public bool IsEnabled { get; private set; } = true;

        public UserActivityEventHandler(
            ILogger<UserActivityEventHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IPlanRestrictionService planRestrictionService,
            IEventBus eventBus,
            IConnectedIdService connectedIdService)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _planRestrictionService = planRestrictionService;
            _eventBus = eventBus;
            _connectedIdService = connectedIdService;
        }

        #region IService Implementation
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await WarmUpActivityRulesAsync(cancellationToken);
            _logger.LogInformation("UserActivityEventHandler initialized");
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // [INFO] 필요 시 IPlanRestrictionService, IConnectedIdService 등 다른 의존성의 상태 확인 추가
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }

        private async Task WarmUpActivityRulesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("UserActivityEventHandler warmup: Rules loaded on demand via IPlanRestrictionService.");
                await Task.CompletedTask; // 별도 워밍업 불필요
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Activity rules cache warmup failed (this may be informational)");
            }
        }
        #endregion

        public async Task OnActivityLoggedAsync(ActivityLoggedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var activityData = new Dictionary<string, object>
                {
                    ["type"] = @event.ActivityType.ToString(),
                    ["timestamp"] = @event.OccurredAt, // BaseEvent에서 상속
                    ["successful"] = @event.IsSuccessful,
                    ["risk_score"] = @event.RiskScore
                };

                if (!string.IsNullOrEmpty(@event.ResourceId))
                    activityData["resource_id"] = @event.ResourceId;
                if (!string.IsNullOrEmpty(@event.ResourceType))
                    activityData["resource_type"] = @event.ResourceType;
                if (!string.IsNullOrEmpty(@event.ActivityDescription))
                    activityData["description"] = @event.ActivityDescription;

                // 동적 메타데이터 병합 (BaseEvent에 Metadata 속성이 있다고 가정)
                if (@event.Metadata != null && @event.Metadata.Count > 0) // Check dictionary directly
                {
                    try
                    {
                        // [FIX] Loop through the existing dictionary directly
                        foreach (var kvp in @event.Metadata)
                        {
                            // Add with "custom_" prefix
                            activityData[$"custom_{kvp.Key}"] = kvp.Value;
                        }
                    }
                    catch (Exception ex) // Catch potential errors during the loop/assignment
                    {
                        _logger.LogError(ex, "An unexpected error occurred while merging metadata dictionary. EventId={EventId}", @event.EventId);
                        // Optionally, add raw metadata info if possible, though it's already a dictionary
                        // activityData["metadata_merge_error"] = ex.Message;
                    }
                }


                var dateKey = _dateTimeProvider.UtcNow.ToString("yyyy-MM-dd");
                var countKey = $"{CACHE_KEY_PREFIX}:count:{@event.UserId:N}:{dateKey}";

                var count = await _cacheService.IncrementAsync(countKey, 1);

                if (count == 1) // 해당 날짜의 첫 활동이면 캐시 만료 시간 설정
                {
                    var countData = new Dictionary<string, object>
                    {
                        ["count"] = count,
                        ["started_at"] = _dateTimeProvider.UtcNow
                    };

                    // [FIX CS1503 - Stream for Cache]
                    await using var countStream = new MemoryStream();
                    await JsonSerializer.SerializeAsync(countStream, countData, cancellationToken: cancellationToken);
                    countStream.Position = 0;
                    await _cacheService.SetAsync(countKey, countStream, TimeSpan.FromHours(25), cancellationToken); // 다음 날 자정 이후까지 유지
                }

                // 활동량 임계값 확인
                var threshold = await GetTenantThresholdAsync(@event, "daily_activity_limit", cancellationToken);

                if (count > threshold)
                {
                    _logger.LogWarning("Daily activity threshold exceeded for user {UserId}: {Count}/{Threshold}",
                        @event.UserId, count, threshold);
                    // [INFO] 임계값 초과 시 별도 이벤트 발행 고려
                    // await _eventBus.PublishAsync(new DailyActivityThresholdExceededEvent(...), cancellationToken);
                }

                // 중요 활동 또는 고위험 활동만 감사 로그 기록
                if (@event.RiskScore > 50 || IsImportantActivity(@event.ActivityType))
                {
                    // [FIX CS1503 - string for Audit]
                    var metadataJson = JsonSerializer.Serialize(activityData);

                    await _auditService.LogActionAsync(
                           DetermineAuditActionType(@event.ActivityType),
                           @event.ActivityType.ToString(),
                           @event.ConnectedId,
                           resourceId: @event.ResourceId,
                           metadata: activityData);
                }
            }
            catch (Exception ex)
            {
                // 로깅 실패는 다른 로직을 중단시키지 않도록 Debug 레벨로 처리
                _logger.LogDebug(ex, "Activity logging processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
            }
        }

        public async Task OnHighRiskActivityDetectedAsync(HighRiskActivityDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var threatLevel = ParseThreatLevel(@event.ThreatLevel);

                var riskData = new Dictionary<string, object>
                {
                    ["activity_log_id"] = @event.ActivityLogId,
                    ["risk_score"] = @event.RiskScore,
                    ["threat_type"] = @event.ThreatType,
                    ["threat_level"] = threatLevel.ToString(),
                    ["description"] = @event.Description,
                    ["timestamp"] = @event.OccurredAt // BaseEvent에서 상속
                };

                if (@event.RecommendedActions?.Length > 0)
                {
                    riskData["recommended_actions"] = @event.RecommendedActions;
                }

                // 동적 메타데이터 병합 (BaseEvent에 Metadata 속성이 있다고 가정)
                // 동적 메타데이터 병합
                // [FIX] @event.Metadata는 이미 Dictionary이므로 역직렬화 제거
                if (@event.Metadata != null && @event.Metadata.Count > 0) // Check dictionary directly
                {
                    try
                    {
                        // [FIX] Loop through the existing dictionary directly
                        foreach (var kvp in @event.Metadata)
                        {
                            // Add with "custom_" prefix
                            riskData[$"custom_{kvp.Key}"] = kvp.Value;
                        }
                    }
                    catch (Exception ex) // Catch potential errors during the loop/assignment
                    {
                        _logger.LogError(ex, "An unexpected error occurred while merging high-risk metadata dictionary. EventId={EventId}", @event.EventId);
                        // Optionally, add raw metadata info if possible, though it's already a dictionary
                        // riskData["metadata_merge_error"] = ex.Message;
                    }
                }

                // 위험 수준별 대응 실행 (예: 이벤트 발행)
                await ExecuteRiskResponseAsync(threatLevel, @event, cancellationToken);

                // 감사 로그 기록
                // [FIX CS1503 - string for Audit]
                var riskDataJson = JsonSerializer.Serialize(riskData);

                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 또는 threatLevel에 따른 동적 타입
                    $"HIGH_RISK_{@event.ThreatType.ToUpperInvariant()}",
                    @event.ConnectedId,
                    resourceId: @event.ActivityLogId.ToString(),
                    metadata: riskData); // JSON 문자열 전달

                // 위험 정보 캐싱 (예: 최근 위험 활동 표시용)
                var riskKey = $"{CACHE_KEY_PREFIX}:risk:{@event.UserId:N}";

                // [FIX CS1503 - Stream for Cache]
                await using var riskStream = new MemoryStream();
                await JsonSerializer.SerializeAsync(riskStream, riskData, cancellationToken: cancellationToken);
                riskStream.Position = 0;
                await _cacheService.SetAsync(riskKey, riskStream, TimeSpan.FromHours(24), cancellationToken);
            }
            catch (Exception ex)
            {
                // 고위험 활동 처리 실패는 심각할 수 있으므로 Error 레벨로 로깅
                _logger.LogError(ex, "High risk activity processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
                // 필요 시 예외를 다시 던져서 상위 핸들러에게 알림
                // throw;
            }
        }

        public async Task OnAnomalousActivityDetectedAsync(AnomalousActivityDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var anomalyData = new Dictionary<string, object>
                {
                    ["type"] = @event.AnomalyType,
                    ["description"] = @event.Description,
                    ["confidence_score"] = @event.ConfidenceScore,
                    ["timestamp"] = @event.OccurredAt // BaseEvent에서 상속
                };

                if (@event.AnomalyIndicators?.Length > 0)
                {
                    anomalyData["indicators"] = @event.AnomalyIndicators;
                }

                // [FIX CS1061] BaseEvent의 ClientIpAddress 사용
                if (!string.IsNullOrEmpty(@event.ClientIpAddress))
                    anomalyData["ip_address"] = @event.ClientIpAddress;

                // [INFO] Location은 AnomalousActivityDetectedEvent의 고유 속성
                if (!string.IsNullOrEmpty(@event.Location))
                    anomalyData["location"] = @event.Location;

                // [INFO] DeviceFingerprint는 AnomalousActivityDetectedEvent의 고유 속성
                if (!string.IsNullOrEmpty(@event.DeviceFingerprint))
                    anomalyData["device"] = @event.DeviceFingerprint;

                // 신뢰도가 특정 수준 이상인 경우만 추가 처리 (예: 감사 로그, ML 데이터 저장)
                if (@event.ConfidenceScore > 0.75) // 임계값은 설정 파일 등에서 관리하는 것이 좋음
                {
                    // ML 학습용 데이터 캐시 저장 (예시)
                    var mlKey = $"{CACHE_KEY_PREFIX}:anomaly:ml:{@event.UserId:N}:{Guid.NewGuid():N}";

                    // [FIX CS1503 - Stream for Cache]
                    await using var mlStream = new MemoryStream();
                    await JsonSerializer.SerializeAsync(mlStream, anomalyData, cancellationToken: cancellationToken);
                    mlStream.Position = 0;
                    // TTL을 적절히 설정하여 데이터가 너무 오래 쌓이지 않도록 관리
                    await _cacheService.SetAsync(mlKey, mlStream, TimeSpan.FromDays(7), cancellationToken);

                    // 감사 로그 기록
                    // [FIX CS1503 - string for Audit]
                    var anomalyDataJson = JsonSerializer.Serialize(anomalyData);

                    await _auditService.LogActionAsync(
                        AuditActionType.System, // 시스템 감지 이벤트
                        "ANOMALY_DETECTED",
                        @event.ConnectedId,
                        resourceId: @event.UserId.ToString(), // 대상 사용자 ID
                        metadata: anomalyData); // JSON 문자열 전달

                    _logger.LogWarning("High confidence anomaly detected for User {UserId}: Type={AnomalyType}, Score={ConfidenceScore}, EventId={EventId}",
                        @event.UserId, @event.AnomalyType, @event.ConfidenceScore, @event.EventId);
                }
                else
                {
                    // 낮은 신뢰도의 이상 활동은 Debug 레벨로만 로깅하거나 무시할 수 있음
                    _logger.LogDebug("Low confidence anomaly detected for User {UserId}: Type={AnomalyType}, Score={ConfidenceScore}, EventId={EventId}",
                       @event.UserId, @event.AnomalyType, @event.ConfidenceScore, @event.EventId);
                }
            }
            catch (Exception ex)
            {
                // 이상 활동 처리 실패는 Error 레벨로 로깅
                _logger.LogError(ex, "Anomaly detection processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
            }
        }

        #region Helper Methods

        private bool IsImportantActivity(UserActivityType activityType)
        {
            // 중요 활동 타입 정의 (변경 없음)
            var importantTypes = new HashSet<UserActivityType> { /* ... */ };
            return importantTypes.Contains(activityType);
        }

        private AuditActionType DetermineAuditActionType(UserActivityType activityType)
        {
            return activityType switch
            {
                UserActivityType.Login => AuditActionType.Login,
                UserActivityType.Logout => AuditActionType.Logout,
                UserActivityType.LoginFailed => AuditActionType.FailedLogin,
                UserActivityType.PasswordChanged => AuditActionType.PasswordChange,
                UserActivityType.SettingsChange => AuditActionType.Update,
                UserActivityType.FileUpload => AuditActionType.Create, // Upload는 Create로 간주
                UserActivityType.FileDownload => AuditActionType.Read,   // Download는 Read로 간주
                UserActivityType.RoleAssigned => AuditActionType.Grant,
                UserActivityType.PermissionGranted => AuditActionType.Grant,
                UserActivityType.RoleRemoved => AuditActionType.Revoke,
                UserActivityType.PermissionRevoked => AuditActionType.Revoke,
                UserActivityType.AccountLocked => AuditActionType.Blocked,
                UserActivityType.AccountUnlocked => AuditActionType.System, // 잠금 해제는 시스템 동작으로 간주
                // 👇 [FIX CS8509] 모든 나머지 경우를 처리하는 discard 패턴 추가
                _ => AuditActionType.Read // 명시되지 않은 다른 모든 활동은 기본적으로 '읽기'로 간주 (또는 AuditActionType.System)
            };
        }

private SecurityThreatLevel ParseThreatLevel(string threatLevel)
        {
            // Input string (e.g., from an event) is converted to uppercase
            // and matched against the SecurityThreatLevel enum members.
            return threatLevel?.ToUpperInvariant() switch
            {
                "CRITICAL" => SecurityThreatLevel.Critical, // Matches Critical = 4
                "HIGH"     => SecurityThreatLevel.High,     // Matches High = 3
                "MEDIUM"   => SecurityThreatLevel.Medium,   // Matches Medium = 2
                "LOW"      => SecurityThreatLevel.Low,      // Matches Low = 1
                _          => SecurityThreatLevel.Low       // Default to Low for null or unrecognized strings
            };
        }

private async Task ExecuteRiskResponseAsync(SecurityThreatLevel threatLevel, HighRiskActivityDetectedEvent @event, CancellationToken cancellationToken)
        {
            // [REQ-7] IEventBus를 사용하여 실제 조치(계정 잠금, 세션 종료 등)를 위한
            // 별도의 이벤트를 발행(publish)합니다.

            switch (threatLevel)
            {
                case SecurityThreatLevel.Critical:
                    // Log the critical event
                    _logger.LogCritical(
                        "Critical threat detected: {ThreatType} for User {UserId} (ConnectedId: {ConnectedId}). Risk Score: {RiskScore}. Description: {Description}. EventId={EventId}",
                        @event.ThreatType, @event.UserId, @event.ConnectedId, @event.RiskScore, @event.Description, @event.EventId);

                    // [ACTION EXAMPLE] Publish events for immediate response
                    // await _eventBus.PublishAsync(new TriggerAccountLockoutEvent(@event.UserId, @event.ConnectedId, "CriticalThreatDetected"), cancellationToken);
                    // await _eventBus.PublishAsync(new RevokeAllUserSessionsEvent(@event.UserId, "CriticalThreatDetected"), cancellationToken);
                    // await _eventBus.PublishAsync(new NotifySecurityTeamEvent("Critical", @event), cancellationToken);
                    break;

                case SecurityThreatLevel.High:
                    // Log the high-level threat
                    _logger.LogError(
                        "High threat detected: {ThreatType} for User {UserId} (ConnectedId: {ConnectedId}). Risk Score: {RiskScore}. Description: {Description}. EventId={EventId}",
                        @event.ThreatType, @event.UserId, @event.ConnectedId, @event.RiskScore, @event.Description, @event.EventId);

                    // [ACTION EXAMPLE] Publish events for strong security measures
                    // await _eventBus.PublishAsync(new ForceMfaReauthenticationEvent(@event.UserId, @event.ConnectedId, "HighThreatDetected"), cancellationToken);
                    // await _eventBus.PublishAsync(new RevokeSpecificSessionEvent(@event.SessionId ?? Guid.Empty, "HighThreatDetected"), cancellationToken); // Assuming SessionId is available
                    // await _eventBus.PublishAsync(new FlagUserForReviewEvent(@event.UserId, "HighThreatDetected"), cancellationToken);
                    break;

                case SecurityThreatLevel.Medium:
                    // Log the medium-level threat
                    _logger.LogWarning(
                        "Medium threat detected: {ThreatType} for User {UserId} (ConnectedId: {ConnectedId}). Risk Score: {RiskScore}. Description: {Description}. EventId={EventId}",
                        @event.ThreatType, @event.UserId, @event.ConnectedId, @event.RiskScore, @event.Description, @event.EventId);

                    // [ACTION EXAMPLE] Publish events for increased monitoring or user notification
                    // await _eventBus.PublishAsync(new IncreaseMonitoringLevelEvent(@event.UserId, "Medium"), cancellationToken);
                    // await _eventBus.PublishAsync(new NotifyUserOfSuspiciousActivityEvent(@event.UserId, @event.Description), cancellationToken);
                    break;

                case SecurityThreatLevel.Low:
                    // Log the low-level threat for informational purposes
                    _logger.LogInformation(
                        "Low threat detected: {ThreatType} for User {UserId} (ConnectedId: {ConnectedId}). Risk Score: {RiskScore}. Description: {Description}. EventId={EventId}",
                        @event.ThreatType, @event.UserId, @event.ConnectedId, @event.RiskScore, @event.Description, @event.EventId);

                    // [ACTION EXAMPLE] Typically, only logging is needed for Low threats.
                    // No event publishing might be necessary unless specific tracking is required.
                    break;

                default:
                    // Handle unexpected enum values (defensive coding)
                    _logger.LogWarning("Unknown SecurityThreatLevel '{ThreatLevel}' encountered for event {EventId}", threatLevel, @event.EventId);
                    break;
            }

            // No need for 'await Task.CompletedTask;' if using await inside the switch.
            // If publishing events, ensure they are awaited properly.
            // If just logging synchronously, 'await Task.CompletedTask;' could be added back,
            // but making the method fully async allows for future await calls without signature changes.
            await Task.CompletedTask; // Keep if no async operations are performed inside the switch currently. Remove if awaiting event publishing.
        }

        /// <summary>
        /// 사용자의 플랜에 따른 숫자 임계값을 가져옵니다.
        /// (IConnectedIdService -> IPlanRestrictionService 연계)
        /// </summary>
        private async Task<int> GetTenantThresholdAsync(ActivityLoggedEvent @event, string thresholdKey, CancellationToken cancellationToken)
        {
            // 캐시 키 생성 (UserId 기반)
            var cacheKey = $"{CACHE_KEY_PREFIX}:threshold:{@event.UserId:N}:{thresholdKey}";
            const int defaultLimit = 10000; // 조회 실패 또는 플랜 미설정 시 기본값

            // 1. 캐시에서 먼저 조회 시도
            try
            {
                var cached = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);
                if (cached != null && cached.TryGetValue("value", out var value))
                {
                    if (int.TryParse(value?.ToString(), out var parsedValue))
                    {
                        _logger.LogDebug("Threshold '{ThresholdKey}' for User {UserId} found in cache: {Value}", thresholdKey, @event.UserId, parsedValue);
                        return parsedValue;
                    }
                }
            }
            catch (Exception cacheEx)
            {
                _logger.LogWarning(cacheEx, "Failed to get threshold from cache for key {CacheKey}. Will fetch from source.", cacheKey);
            }

            _logger.LogDebug("Threshold '{ThresholdKey}' for User {UserId} not found in cache or cache failed. Fetching from source.", thresholdKey, @event.UserId);

            // 2. 캐시에 없으면 OrganizationId 조회
            Guid organizationId;
            try
            {
                // [FIX CS1061] GetByIdAsync 사용
                var result = await _connectedIdService.GetByIdAsync(@event.ConnectedId, cancellationToken);

                // [FIX CS1061] ServiceResult<T> 속성 사용
                if (!result.IsSuccess || result.Data == null)
                {
                    string errorDetail = result.ErrorMessage ?? "Unknown error";
                    if (result.ValidationErrors != null && result.ValidationErrors.Any())
                    {
                        errorDetail += " Validation Errors: " + string.Join("; ", result.ValidationErrors.Select(kvp => $"{kvp.Key}: {string.Join(", ", kvp.Value)}"));
                    }
                    throw new InvalidOperationException($"OrganizationId lookup failed for ConnectedId {@event.ConnectedId}. Errors: {errorDetail}");
                }

                organizationId = result.Data.OrganizationId;

                if (organizationId == Guid.Empty)
                {
                    throw new InvalidOperationException($"ConnectedId {@event.ConnectedId} returned an empty OrganizationId.");
                }
                _logger.LogDebug("Resolved OrganizationId {OrganizationId} for ConnectedId {ConnectedId}", organizationId, @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to resolve OrganizationId from ConnectedId {ConnectedId}. Using default threshold ({DefaultLimit}). EventId={EventId}", @event.ConnectedId, defaultLimit, @event.EventId);
                return defaultLimit; // 조직 조회 실패 시 기본값 반환
            }

            // 3. IPlanRestrictionService 호출하여 임계값 조회
            int limitValue;
            try
            {
                // [INFO] IPlanRestrictionService 인터페이스에 GetNumericLimitAsync가 정의되어 있어야 함
                limitValue = await _planRestrictionService.GetNumericLimitAsync(
                    organizationId,
                    thresholdKey,
                    defaultLimit, // 플랜에 값이 없을 경우 사용할 기본값 전달
                    cancellationToken);
                _logger.LogDebug("Fetched threshold '{ThresholdKey}' for Org {OrganizationId} from IPlanRestrictionService: {Value}", thresholdKey, organizationId, limitValue);
            }
            catch (Exception planEx)
            {
                _logger.LogError(planEx, "Failed to get threshold '{ThresholdKey}' from IPlanRestrictionService for Org {OrganizationId}. Using default threshold ({DefaultLimit}). EventId={EventId}", thresholdKey, organizationId, defaultLimit, @event.EventId);
                limitValue = defaultLimit; // 플랜 서비스 조회 실패 시 기본값 사용
            }


            // 4. 조회된 결과를 캐시에 저장 (다음 조회를 위해)
            try
            {
                var thresholdData = new Dictionary<string, object>
                {
                    ["value"] = limitValue,
                    ["cached_at"] = _dateTimeProvider.UtcNow
                };

                // [FIX CS1503 - Stream for Cache]
                await using var thresholdStream = new MemoryStream();
                await JsonSerializer.SerializeAsync(thresholdStream, thresholdData, cancellationToken: cancellationToken);
                thresholdStream.Position = 0;
                await _cacheService.SetAsync(cacheKey, thresholdStream, TimeSpan.FromHours(1), cancellationToken); // 1시간 캐시
                _logger.LogDebug("Stored fetched threshold '{ThresholdKey}' for User {UserId} in cache.", thresholdKey, @event.UserId);
            }
            catch (Exception cacheSetEx)
            {
                _logger.LogWarning(cacheSetEx, "Failed to set threshold in cache for key {CacheKey}. Subsequent requests might refetch.", cacheKey);
            }


            return limitValue;
        }

        #endregion
    }
}