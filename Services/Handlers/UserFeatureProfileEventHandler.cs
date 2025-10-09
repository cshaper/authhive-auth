using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler;
using AuthHive.Core.Models.User.Events;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// SaaS 최적화 사용자 기능 프로필 이벤트 핸들러
    /// 동적 애드온 및 기능 관리, 멀티테넌트 사용량 추적
    /// </summary>
    public class UserFeatureProfileEventHandler : IUserFeatureProfileEventHandler, IService
    {
        private readonly ILogger<UserFeatureProfileEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;

        private const string CACHE_KEY_PREFIX = "feature";
        private const int FEATURE_CACHE_MINUTES = 60;

        public int Priority => 4;
        public bool IsEnabled { get; private set; } = true;

        public UserFeatureProfileEventHandler(
            ILogger<UserFeatureProfileEventHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("UserFeatureProfileEventHandler initialized");
            return Task.CompletedTask;
        }

        // 1. CancellationToken added to the signature.
        // 2. CancellationToken passed to the dependency's health check.
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Pass the token to the underlying service call.
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion

        public async Task OnAddonActivatedAsync(AddonActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 동적 애드온 데이터 처리
                var addonData = new Dictionary<string, object>
                {
                    ["addon_key"] = @event.AddonKey,
                    ["addon_name"] = @event.AddonName,
                    ["activated_at"] = @event.ActivatedAt,
                    ["activated_by"] = @event.ActivatedByConnectedId ?? @event.UserId
                };

                // 동적 메타데이터 병합 (SaaS 고객의 커스텀 데이터)
                if (!string.IsNullOrEmpty(@event.Metadata))
                {
                    MergeDynamicMetadata(addonData, @event.Metadata);
                }

                // 사용자 기능 캐시 업데이트
                var userFeaturesKey = $"{CACHE_KEY_PREFIX}:user:{@event.UserId:N}";
                var features = await _cacheService.GetAsync<HashSet<string>>(userFeaturesKey) ?? new HashSet<string>();
                features.Add(@event.AddonKey);
                await _cacheService.SetAsync(userFeaturesKey, features, TimeSpan.FromMinutes(FEATURE_CACHE_MINUTES));

                // 사용량 추적 시작 (테넌트별)
                await InitializeUsageTrackingAsync(@event.UserId, @event.AddonKey, @event.OrganizationId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Create,
                    $"ADDON_ACTIVATED",
                    @event.ActivatedByConnectedId ?? @event.UserId,
                    resourceId: @event.AddonKey,
                    metadata: addonData);

                _logger.LogInformation("Addon {AddonKey} activated for user {UserId}", @event.AddonKey, @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Addon activation failed for {AddonKey}, user {UserId}",
                    @event.AddonKey, @event.UserId);
                // 애드온 활성화 실패는 치명적이지 않음
            }
        }

        public async Task OnAddonDeactivatedAsync(AddonDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 사용자 기능 캐시에서 제거
                var userFeaturesKey = $"{CACHE_KEY_PREFIX}:user:{@event.UserId:N}";
                var features = await _cacheService.GetAsync<HashSet<string>>(userFeaturesKey) ?? new HashSet<string>();
                features.Remove(@event.AddonKey);
                await _cacheService.SetAsync(userFeaturesKey, features, TimeSpan.FromMinutes(FEATURE_CACHE_MINUTES));

                // 사용량 추적 중지
                await StopUsageTrackingAsync(@event.UserId, @event.AddonKey);

                // 감사 로그 (이유 포함)
                var metadata = new Dictionary<string, object>
                {
                    ["addon_key"] = @event.AddonKey,
                    ["reason"] = @event.DeactivationReason ?? "not_specified"
                };

                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Delete,
                    "ADDON_DEACTIVATED",
                    @event.DeactivatedByConnectedId ?? @event.UserId,
                    resourceId: @event.AddonKey,
                    metadata: metadata);

                _logger.LogInformation("Addon {AddonKey} deactivated for user {UserId}", @event.AddonKey, @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Addon deactivation failed for {AddonKey}, user {UserId}",
                    @event.AddonKey, @event.UserId);
            }
        }

        public async Task OnApiAccessChangedAsync(ApiAccessChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 동적 권한 처리 - SaaS 고객이 정의한 권한도 수용
                var permissionData = new Dictionary<string, object>();

                // 권한 변경 캐시 업데이트
                var permKey = $"{CACHE_KEY_PREFIX}:permissions:{@event.UserId:N}";
                await _cacheService.SetAsync(permKey, @event.CurrentPermissions, TimeSpan.FromMinutes(30));

                // 동적 Rate Limiting 규칙 계산
                var rateLimits = CalculateDynamicRateLimits(@event.CurrentPermissions);
                var rateLimitKey = $"{CACHE_KEY_PREFIX}:ratelimit:{@event.UserId:N}";
                await _cacheService.SetAsync(rateLimitKey, rateLimits, TimeSpan.FromHours(1));

                // 중요 권한 변경만 감사
                if (@event.AddedPermissions.Any(p => IsHighValuePermission(p)) ||
                    @event.RemovedPermissions.Any(p => IsHighValuePermission(p)))
                {
                    var metadata = new Dictionary<string, object>
                    {
                        ["added"] = @event.AddedPermissions,
                        ["removed"] = @event.RemovedPermissions,
                        ["current_count"] = @event.CurrentPermissions.Length
                    };

                    await _auditService.LogActionAsync(
                        Core.Enums.Core.AuditActionType.Update,
                        "API_ACCESS_CHANGED",
                        @event.ChangedByConnectedId ?? @event.UserId,
                        resourceId: @event.UserId.ToString(),
                        metadata: metadata);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "API access change processing failed for user {UserId}", @event.UserId);
            }
        }

        public async Task OnFeatureUsageThresholdReachedAsync(FeatureUsageThresholdReachedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var usageData = new Dictionary<string, object>
                {
                    ["feature"] = @event.FeatureKey,
                    ["type"] = @event.ThresholdType,
                    ["current"] = @event.CurrentValue,
                    ["threshold"] = @event.ThresholdValue,
                    ["percentage"] = (@event.CurrentValue * 100.0) / @event.ThresholdValue,
                    // severity를 metadata에 포함
                    ["severity"] = @event.CurrentValue >= @event.ThresholdValue
                        ? AuditEventSeverity.Warning.ToString()
                        : AuditEventSeverity.Info.ToString()
                };

                var exceedPercentage = ((@event.CurrentValue - @event.ThresholdValue) * 100.0) / @event.ThresholdValue;

                if (exceedPercentage > 0)
                {
                    await HandleThresholdExceededAsync(@event, exceedPercentage);
                }
                else if (exceedPercentage > -10)
                {
                    _logger.LogWarning("Usage approaching limit for {Feature}: {Current}/{Threshold}",
                        @event.FeatureName, @event.CurrentValue, @event.ThresholdValue);
                }

                var usageKey = $"{CACHE_KEY_PREFIX}:usage:{@event.UserId:N}:{@event.FeatureKey}:{@event.ThresholdType}";
                await _cacheService.SetAsync(usageKey, usageData, TimeSpan.FromHours(1));

                if (@event.CurrentValue >= @event.ThresholdValue)
                {
                    // CS1739 수정: severity 매개변수 제거, metadata에 포함
                    await _auditService.LogActionAsync(
                        AuditActionType.Execute,  // 또는 Blocked
                        "USAGE_THRESHOLD_EXCEEDED",
                        @event.UserId,
                        resourceId: @event.FeatureKey,
                        metadata: usageData); // severity는 metadata에 포함됨
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Usage threshold processing failed for feature {Feature}, user {UserId}",
                    @event.FeatureName, @event.UserId);
            }
        }
        #region Helper Methods

        private void MergeDynamicMetadata(Dictionary<string, object> target, string? metadata)
        {
            if (string.IsNullOrEmpty(metadata)) return;

            try
            {
                var dynamicData = JsonSerializer.Deserialize<Dictionary<string, object>>(metadata);
                if (dynamicData != null)
                {
                    foreach (var kvp in dynamicData)
                    {
                        target[$"custom_{kvp.Key}"] = kvp.Value;
                    }
                }
            }
            catch
            {
                target["raw_metadata"] = metadata;
            }
        }

        private async Task InitializeUsageTrackingAsync(Guid userId, string addonKey, Guid? organizationId)
        {
            // 사용량 추적 초기화
            var trackingKey = $"{CACHE_KEY_PREFIX}:tracking:{organizationId:N}:{userId:N}:{addonKey}";
            var trackingData = new Dictionary<string, object>
            {
                ["started_at"] = _dateTimeProvider.UtcNow,
                ["usage_count"] = 0,
                ["last_used"] = _dateTimeProvider.UtcNow
            };

            await _cacheService.SetAsync(trackingKey, trackingData, TimeSpan.FromDays(30));
        }

        private async Task StopUsageTrackingAsync(Guid userId, string addonKey)
        {
            // 사용량 추적 데이터 보관 (분석용)
            var trackingPattern = $"{CACHE_KEY_PREFIX}:tracking:*:{userId:N}:{addonKey}";
            await _cacheService.RemoveByPatternAsync(trackingPattern);
        }

        private Dictionary<string, int> CalculateDynamicRateLimits(string[] permissions)
        {
            // 동적 Rate Limit 계산
            var baseLimits = new Dictionary<string, int>
            {
                ["requests_per_minute"] = 60,
                ["requests_per_hour"] = 1000,
                ["concurrent_requests"] = 10
            };

            // 권한 수준에 따라 동적 조정
            foreach (var permission in permissions)
            {
                if (permission.Contains("premium", StringComparison.OrdinalIgnoreCase))
                {
                    baseLimits["requests_per_minute"] *= 2;
                    baseLimits["requests_per_hour"] *= 2;
                }
                else if (permission.Contains("enterprise", StringComparison.OrdinalIgnoreCase))
                {
                    baseLimits["requests_per_minute"] *= 5;
                    baseLimits["requests_per_hour"] *= 5;
                    baseLimits["concurrent_requests"] *= 2;
                }
            }

            return baseLimits;
        }

        private bool IsHighValuePermission(string permission)
        {
            // 동적으로 중요 권한 판단
            var highValuePatterns = new[]
            {
                "admin", "delete", "export", "billing", "security", "audit"
            };

            var permLower = permission.ToLowerInvariant();
            return highValuePatterns.Any(pattern => permLower.Contains(pattern));
        }

        private async Task HandleThresholdExceededAsync(FeatureUsageThresholdReachedEvent @event, double exceedPercentage)
        {
            if (exceedPercentage > 50)
            {
                // CS0452 수정: bool을 Dictionary로 감싸서 참조 타입으로 만듦
                var blockKey = $"{CACHE_KEY_PREFIX}:blocked:{@event.UserId:N}:{@event.FeatureKey}";
                var blockData = new Dictionary<string, object>
                {
                    ["blocked"] = true,
                    ["blocked_at"] = _dateTimeProvider.UtcNow,
                    ["reason"] = $"Exceeded by {exceedPercentage:F1}%"
                };
                await _cacheService.SetAsync(blockKey, blockData, TimeSpan.FromHours(1));

                _logger.LogError("Feature {Feature} blocked for user {UserId} - exceeded by {Percentage}%",
                    @event.FeatureName, @event.UserId, exceedPercentage);
            }
            else if (exceedPercentage > 20)
            {
                // CS0452 수정: double을 Dictionary로 감싸서 참조 타입으로 만듦
                var throttleKey = $"{CACHE_KEY_PREFIX}:throttle:{@event.UserId:N}:{@event.FeatureKey}";
                var throttleData = new Dictionary<string, object>
                {
                    ["exceed_percentage"] = exceedPercentage,
                    ["throttled_at"] = _dateTimeProvider.UtcNow,
                    ["throttle_level"] = "medium"
                };
                await _cacheService.SetAsync(throttleKey, throttleData, TimeSpan.FromMinutes(30));

                _logger.LogWarning("Feature {Feature} throttled for user {UserId} - exceeded by {Percentage}%",
                    @event.FeatureName, @event.UserId, exceedPercentage);
            }
            else
            {
                _logger.LogWarning("Feature {Feature} exceeded for user {UserId} by {Percentage}%",
                    @event.FeatureName, @event.UserId, exceedPercentage);
            }
        }
        #endregion
    }
}