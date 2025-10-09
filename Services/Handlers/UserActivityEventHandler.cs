using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler;
using AuthHive.Core.Models.User.Events;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Enums.Core;

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

        private const string CACHE_KEY_PREFIX = "activity";
        private const int DEFAULT_CACHE_MINUTES = 15;

        private readonly Dictionary<string, int> _defaultThresholds = new()
        {
            { "daily_activity_limit", 10000 },
            { "anomaly_score_threshold", 75 },
            { "concurrent_session_limit", 5 }
        };

        public int Priority => 2;
        public bool IsEnabled { get; private set; } = true;

        public UserActivityEventHandler(
            ILogger<UserActivityEventHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation
        // UserActivityEventHandler.cs

        public async Task InitializeAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            // Pass the token to the long-running async operation
            await WarmUpActivityRulesAsync(cancellationToken);

            _logger.LogInformation("UserActivityEventHandler initialized");
            // No need to return Task.CompletedTask here, as the method is already async due to the await above.
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            // Pass the token to the dependency's health check
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        private async Task WarmUpActivityRulesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}:rules:default";
                await _cacheService.SetAsync(cacheKey, _defaultThresholds, TimeSpan.FromHours(24));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Activity rules cache warmup failed");
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
                    ["timestamp"] = @event.OccurredAt,
                    ["successful"] = @event.IsSuccessful,
                    ["risk_score"] = @event.RiskScore
                };

                if (!string.IsNullOrEmpty(@event.ResourceId))
                    activityData["resource_id"] = @event.ResourceId;
                if (!string.IsNullOrEmpty(@event.ResourceType))
                    activityData["resource_type"] = @event.ResourceType;
                if (!string.IsNullOrEmpty(@event.ActivityDescription))
                    activityData["description"] = @event.ActivityDescription;

                // 동적 메타데이터 병합
                if (!string.IsNullOrEmpty(@event.Metadata))
                {
                    try
                    {
                        var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(@event.Metadata);
                        if (metadata != null)
                        {
                            foreach (var kvp in metadata)
                            {
                                activityData[$"custom_{kvp.Key}"] = kvp.Value;
                            }
                        }
                    }
                    catch
                    {
                        activityData["raw_metadata"] = @event.Metadata;
                    }
                }

                var dateKey = _dateTimeProvider.UtcNow.ToString("yyyy-MM-dd");
                var countKey = $"{CACHE_KEY_PREFIX}:count:{@event.UserId:N}:{dateKey}";

                var count = await _cacheService.IncrementAsync(countKey, 1);

                if (count == 1)
                {
                    // CS0452 수정: long을 Dictionary로 감싸서 참조 타입으로 만듦
                    var countData = new Dictionary<string, object>
                    {
                        ["count"] = count,
                        ["started_at"] = _dateTimeProvider.UtcNow
                    };
                    await _cacheService.SetAsync(countKey, countData, TimeSpan.FromHours(25));
                }

                var threshold = await GetTenantThresholdAsync(@event.UserId, "daily_activity_limit");

                if (count > threshold)
                {
                    _logger.LogWarning("Daily activity threshold exceeded for user {UserId}: {Count}/{Threshold}",
                        @event.UserId, count, threshold);
                }

                // 중요 활동이거나 위험 점수가 높은 경우만 감사
                if (@event.RiskScore > 50 || IsImportantActivity(@event.ActivityType))
                {
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
                _logger.LogDebug(ex, "Activity logging failed for user {UserId}", @event.UserId);
            }
        }

        public async Task OnHighRiskActivityDetectedAsync(HighRiskActivityDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // SecurityThreatLevel enum 활용
                var threatLevel = ParseThreatLevel(@event.ThreatLevel);

                var riskData = new Dictionary<string, object>
                {
                    ["activity_log_id"] = @event.ActivityLogId,
                    ["risk_score"] = @event.RiskScore,
                    ["threat_type"] = @event.ThreatType,
                    ["threat_level"] = threatLevel.ToString(),
                    ["description"] = @event.Description,
                    ["timestamp"] = _dateTimeProvider.UtcNow
                };

                if (@event.RecommendedActions?.Length > 0)
                {
                    riskData["recommended_actions"] = @event.RecommendedActions;
                }

                // 동적 메타데이터 병합
                if (!string.IsNullOrEmpty(@event.Metadata))
                {
                    try
                    {
                        var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(@event.Metadata);
                        if (metadata != null)
                        {
                            foreach (var kvp in metadata)
                            {
                                riskData[$"custom_{kvp.Key}"] = kvp.Value;
                            }
                        }
                    }
                    catch
                    {
                        riskData["raw_metadata"] = @event.Metadata;
                    }
                }

                // 위험 수준별 처리
                await ExecuteRiskResponseAsync(threatLevel, @event);

                // 감사 로그
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked,
                    $"HIGH_RISK_{@event.ThreatType.ToUpperInvariant()}",
                    @event.ConnectedId,
                    resourceId: @event.ActivityLogId.ToString(),
                    metadata: riskData);

                // 위험 정보 캐싱
                var riskKey = $"{CACHE_KEY_PREFIX}:risk:{@event.UserId:N}";
                await _cacheService.SetAsync(riskKey, riskData, TimeSpan.FromHours(24));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "High risk activity processing failed for user {UserId}", @event.UserId);
                throw;
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
                    ["timestamp"] = _dateTimeProvider.UtcNow
                };

                if (@event.AnomalyIndicators?.Length > 0)
                {
                    anomalyData["indicators"] = @event.AnomalyIndicators;
                }

                if (!string.IsNullOrEmpty(@event.IpAddress))
                    anomalyData["ip_address"] = @event.IpAddress;
                if (!string.IsNullOrEmpty(@event.Location))
                    anomalyData["location"] = @event.Location;
                if (!string.IsNullOrEmpty(@event.DeviceFingerprint))
                    anomalyData["device"] = @event.DeviceFingerprint;

                // 신뢰도가 높은 이상 활동만 처리
                if (@event.ConfidenceScore > 0.75)
                {
                    // ML 학습용 데이터 저장
                    var mlKey = $"{CACHE_KEY_PREFIX}:anomaly:ml:{@event.UserId:N}:{Guid.NewGuid():N}";
                    await _cacheService.SetAsync(mlKey, anomalyData, TimeSpan.FromDays(7));

                    // 감사 로그
                    await _auditService.LogActionAsync(
                        AuditActionType.System,
                        "ANOMALY_DETECTED",
                        @event.ConnectedId,
                        resourceId: @event.UserId.ToString(),
                        metadata: anomalyData);

                    _logger.LogWarning("High confidence anomaly detected for user {UserId}: {Type} (score: {Score})",
                        @event.UserId, @event.AnomalyType, @event.ConfidenceScore);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Anomaly detection processing failed for user {UserId}", @event.UserId);
            }
        }

        #region Helper Methods

        private bool IsImportantActivity(UserActivityType activityType)
        {
            // 중요 활동 타입 정의
            var importantTypes = new HashSet<UserActivityType>
            {
                UserActivityType.Login,
                UserActivityType.Logout,
                UserActivityType.PasswordChanged,
                UserActivityType.TwoFactorEnabled,
                UserActivityType.TwoFactorDisabled,
                UserActivityType.RoleAssigned,
                UserActivityType.RoleRemoved,
                UserActivityType.PermissionGranted,
                UserActivityType.PermissionRevoked,
                UserActivityType.AccountLocked,
                UserActivityType.AccountUnlocked,
                UserActivityType.LoginFailed
            };

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
                UserActivityType.FileUpload or UserActivityType.FileDownload => AuditActionType.Read,
                UserActivityType.RoleAssigned or UserActivityType.PermissionGranted => AuditActionType.Grant,
                UserActivityType.RoleRemoved or UserActivityType.PermissionRevoked => AuditActionType.Revoke,
                UserActivityType.AccountLocked => AuditActionType.Blocked,
                _ => AuditActionType.Read
            };
        }

        private SecurityThreatLevel ParseThreatLevel(string threatLevel)
        {
            return threatLevel?.ToUpperInvariant() switch
            {
                "CRITICAL" => SecurityThreatLevel.Critical,
                "HIGH" => SecurityThreatLevel.High,
                "MEDIUM" => SecurityThreatLevel.Medium,
                "LOW" => SecurityThreatLevel.Low,
                _ => SecurityThreatLevel.Low
            };
        }

        private async Task ExecuteRiskResponseAsync(SecurityThreatLevel threatLevel, HighRiskActivityDetectedEvent @event)
        {
            switch (threatLevel)
            {
                case SecurityThreatLevel.Critical:
                    _logger.LogCritical("Critical threat detected - immediate action required for user {UserId}", @event.UserId);
                    // 즉시 계정 차단
                    break;

                case SecurityThreatLevel.High:
                    _logger.LogError("High threat detected - security measures activated for user {UserId}", @event.UserId);
                    // 2FA 강제, 세션 종료
                    break;

                case SecurityThreatLevel.Medium:
                    _logger.LogWarning("Medium threat detected - monitoring increased for user {UserId}", @event.UserId);
                    // 모니터링 강화
                    break;

                case SecurityThreatLevel.Low:
                    _logger.LogInformation("Low threat detected for user {UserId}", @event.UserId);
                    // 로그만 기록
                    break;
            }

            await Task.CompletedTask;
        }

        private async Task<int> GetTenantThresholdAsync(Guid userId, string thresholdKey)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:threshold:{userId:N}:{thresholdKey}";

            // CS0452 수정: int? 대신 Dictionary<string, object> 사용
            var cached = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);

            if (cached != null && cached.TryGetValue("value", out var value))
            {
                if (value is int intValue)
                    return intValue;
                if (int.TryParse(value?.ToString(), out var parsedValue))
                    return parsedValue;
            }

            // 기본값 사용하고 캐시에 저장
            var defaultValue = _defaultThresholds.GetValueOrDefault(thresholdKey, 1000);

            // 캐시에 저장 (선택사항)
            var thresholdData = new Dictionary<string, object>
            {
                ["value"] = defaultValue,
                ["cached_at"] = _dateTimeProvider.UtcNow
            };
            await _cacheService.SetAsync(cacheKey, thresholdData, TimeSpan.FromHours(1));

            return defaultValue;
        }

        #endregion
    }
}