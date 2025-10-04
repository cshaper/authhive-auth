using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Core.Handlers;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.PlatformApplication.Events;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Handlers
{
    /// <summary>
    /// 애플리케이션 이벤트 핸들러 - SaaS 최적화 버전
    /// 핵심: 동적 데이터 처리, 테넌트 격리, 캐싱, 비용 최적화
    /// </summary>
    public class ApplicationEventHandler : IApplicationEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IApplicationService _applicationService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<ApplicationEventHandler> _logger;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;

        // 캐시 TTL 설정 (비용 최적화)
        private static readonly TimeSpan ApplicationCacheTTL = TimeSpan.FromHours(6);
        private static readonly TimeSpan SettingsCacheTTL = TimeSpan.FromHours(1);
        private static readonly TimeSpan UsageStatsCacheTTL = TimeSpan.FromMinutes(5);

        // 사용량 임계값 상수 (나중에 동적으로 변경 가능)
        private const decimal DefaultApiUsageThreshold = 0.80m; // 80%
        private const decimal DefaultStorageThreshold = 0.90m; // 90%

        public ApplicationEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IPlatformApplicationRepository applicationRepository,
            IApplicationService applicationService,
            IDateTimeProvider dateTimeProvider,
            ILogger<ApplicationEventHandler> logger,
            IEventBus eventBus,
            IUnitOfWork unitOfWork)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _applicationRepository = applicationRepository;
            _applicationService = applicationService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation

        public async Task InitializeAsync()
        {
            _logger.LogInformation("ApplicationEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);

            // 자주 사용되는 애플리케이션 설정 미리 캐싱
            await WarmUpCacheAsync();
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync() &&
                   await _auditService.IsHealthyAsync();
        }

        private async Task WarmUpCacheAsync()
        {
            try
            {
                _logger.LogDebug("Warming up application cache...");

                // 활성 애플리케이션 목록 캐싱 - GetQueryable 사용
                var activeApps = await _applicationRepository
                    .GetQueryable()
                    .Where(a => a.Status == ApplicationStatus.Active)
                    .Take(100)
                    .ToListAsync();

                foreach (var app in activeApps)
                {
                    var cacheKey = GetApplicationCacheKey(app.OrganizationId, app.Id);
                    await _cacheService.SetAsync(cacheKey, app, ApplicationCacheTTL);
                }

                _logger.LogInformation("Application cache warmed up for {Count} applications", activeApps.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to warm up application cache");
            }
        }

        #endregion

        #region Core Application Events (필수 기능만 구현)

        public async Task HandleApplicationCreatedAsync(ApplicationCreatedEvent eventData)
        {
            try
            {
                _logger.LogInformation("Application created: AppId={ApplicationId}, OrgId={OrganizationId}, Type={Type}",
                    eventData.ApplicationId, eventData.OrganizationId, eventData.ApplicationType);

                // 1. 감사 로그 - 동적 데이터 처리
                var auditData = BuildDynamicAuditData(eventData, new Dictionary<string, object>
                {
                    ["ApplicationKey"] = eventData.ApplicationKey,
                    ["ApplicationType"] = eventData.ApplicationType.ToString(),
                    ["OrganizationId"] = eventData.OrganizationId
                });

                await _auditService.LogActionAsync(
                    eventData.CreatedByConnectedId,
                    "APPLICATION_CREATED",
                    AuditActionType.Create,
                    "Application",
                    eventData.ApplicationId.ToString(),
                    true,
                    JsonSerializer.Serialize(auditData));

                // 2. 캐시 설정 - 테넌트별 격리
                await CacheApplicationWithTenantIsolationAsync(eventData);

                // 3. 기본 설정 초기화 (플랜별 기본값 적용)
                await InitializeApplicationDefaultsAsync(eventData);

                // 4. 조직의 애플리케이션 목록 캐시 무효화
                await InvalidateOrganizationApplicationListCacheAsync(eventData.OrganizationId);

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogDebug("Application created successfully for organization {OrgId}", eventData.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling application created event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleApplicationUpdatedAsync(ApplicationUpdatedEvent eventData)
        {
            try
            {
                // 변경된 속성만 로깅 (효율성)
                if (eventData.ChangedProperties.Any())
                {
                    _logger.LogInformation("Application updated: AppId={ApplicationId}, ChangedFields={Fields}",
                        eventData.ApplicationId, string.Join(",", eventData.ChangedProperties.Keys));

                    // 중요한 변경사항만 감사 로그
                    if (ShouldAuditUpdate(eventData.ChangedProperties))
                    {
                        await _auditService.LogActionAsync(
                            eventData.UpdatedByConnectedId,
                            "APPLICATION_UPDATED",
                            AuditActionType.Update,
                            "Application",
                            eventData.ApplicationId.ToString(),
                            true,
                            JsonSerializer.Serialize(eventData.ChangedProperties));
                    }

                    // 캐시 업데이트 (전체 무효화 대신 부분 업데이트)
                    await UpdateApplicationCacheAsync(eventData);
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling application updated event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleApplicationDeletedAsync(ApplicationDeletedEvent eventData)
        {
            try
            {
                _logger.LogInformation("Application deleted: AppId={ApplicationId}, IsSoftDelete={IsSoftDelete}",
                    eventData.ApplicationId, eventData.IsSoftDelete);

                // 감사 로그
                await _auditService.LogActionAsync(
                    eventData.DeletedByConnectedId,
                    eventData.IsSoftDelete ? "APPLICATION_SOFT_DELETED" : "APPLICATION_DELETED",
                    AuditActionType.Delete,
                    "Application",
                    eventData.ApplicationId.ToString(),
                    true,
                    JsonSerializer.Serialize(new { IsSoftDelete = eventData.IsSoftDelete }));

                // 캐시 정리
                await CleanupApplicationCacheAsync(eventData.ApplicationId);

                // Soft delete의 경우 상태만 변경
                if (eventData.IsSoftDelete)
                {
                    // 관련 서비스들에 애플리케이션 비활성화 알림
                    await _eventBus.PublishAsync(new ApplicationDeactivatedNotification
                    {
                        ApplicationId = eventData.ApplicationId,
                        DeactivatedAt = eventData.DeletedAt
                    });
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling application deleted event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleApplicationStatusChangedAsync(ApplicationStatusChangedEvent eventData)
        {
            try
            {
                _logger.LogInformation("Application status changed: AppId={ApplicationId}, {OldStatus} -> {NewStatus}",
                    eventData.ApplicationId, eventData.OldStatus, eventData.NewStatus);

                // 중요한 상태 변경만 감사
                if (IsImportantStatusChange(eventData.OldStatus, eventData.NewStatus))
                {
                    await _auditService.LogActionAsync(
                        eventData.ChangedByConnectedId,
                        "APPLICATION_STATUS_CHANGED",
                        AuditActionType.StatusChange,
                        "Application",
                        eventData.ApplicationId.ToString(),
                        true,
                        JsonSerializer.Serialize(new
                        {
                            OldStatus = eventData.OldStatus.ToString(),
                            NewStatus = eventData.NewStatus.ToString(),
                            Reason = eventData.Reason
                        }));
                }

                // 상태별 처리
                await ProcessStatusChangeAsync(eventData);

                // 캐시 업데이트
                await UpdateApplicationStatusInCacheAsync(eventData);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling application status changed event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        #endregion

        #region Settings Events (간소화된 구현)

        public async Task HandleApplicationSettingsChangedAsync(ApplicationSettingsChangedEvent eventData)
        {
            try
            {
                // 설정 변경은 자주 발생하므로 배치로 처리
                var cacheKey = GetApplicationSettingsCacheKey(eventData.ApplicationId);

                // 기존 설정 가져오기
                var settings = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey)
                    ?? new Dictionary<string, object>();

                // 동적 설정 업데이트
                // After (Corrected)
                if (eventData.NewValue != null)
                {
                    settings[eventData.SettingKey] = eventData.NewValue;
                }
                else
                {
                    // If the new value is null, remove the key from the settings.
                    settings.Remove(eventData.SettingKey);
                }
                // 캐시 업데이트
                await _cacheService.SetAsync(cacheKey, settings, SettingsCacheTTL);

                // 중요한 설정 변경만 로깅
                if (IsImportantSetting(eventData.SettingKey))
                {
                    _logger.LogInformation("Important setting changed: App={AppId}, Key={Key}",
                        eventData.ApplicationId, eventData.SettingKey);
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling settings changed event");
                await _unitOfWork.RollbackTransactionAsync();
                // 설정 변경 실패는 크리티컬하지 않으므로 예외 전파하지 않음
            }
        }

        public async Task HandleOAuthSettingsChangedAsync(OAuthSettingsChangedEvent eventData)
        {
            try
            {
                // OAuth 설정은 보안상 중요하므로 항상 감사
                await _auditService.LogActionAsync(
                    eventData.ChangedByConnectedId,
                    "OAUTH_SETTINGS_CHANGED",
                    AuditActionType.Configuration,
                    "Application",
                    eventData.ApplicationId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        CallbackUrlsChanged = !AreListsEqual(eventData.OldCallbackUrls, eventData.NewCallbackUrls),
                        AllowedOriginsChanged = !AreListsEqual(eventData.OldAllowedOrigins, eventData.NewAllowedOrigins)
                    }));

                // OAuth 캐시 무효화 (보안상 즉시 적용)
                await InvalidateOAuthCacheAsync(eventData.ApplicationId);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling OAuth settings changed event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        public async Task HandleResourceQuotaChangedAsync(ResourceQuotaChangedEvent eventData)
        {
            try
            {
                _logger.LogInformation("Resource quota changed: App={AppId}, Type={Type}, {Old} -> {New}",
                    eventData.ApplicationId, eventData.ResourceType, eventData.OldQuota, eventData.NewQuota);

                // 할당량 캐시 업데이트
                var quotaKey = GetResourceQuotaCacheKey(eventData.ApplicationId, eventData.ResourceType);
                await _cacheService.SetAsync<object>(quotaKey, eventData.NewQuota, TimeSpan.FromHours(24));

                // 할당량 감소 시 경고
                if (eventData.NewQuota < eventData.OldQuota)
                {
                    await _eventBus.PublishAsync(new ResourceQuotaReducedWarning
                    {
                        ApplicationId = eventData.ApplicationId,
                        ResourceType = eventData.ResourceType,
                        NewQuota = eventData.NewQuota
                    });
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling resource quota changed event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        #endregion

        #region Usage Events (핵심 비즈니스 로직)

        public async Task HandleApiUsageThresholdReachedAsync(ApiUsageThresholdEvent eventData)
        {
            try
            {
                var usagePercentage = (decimal)eventData.CurrentUsage / eventData.Quota;

                _logger.LogWarning("API usage threshold reached: App={AppId}, Usage={Percentage:P}, Type={Type}",
                    eventData.ApplicationId, usagePercentage, eventData.ThresholdType);

                // 임계값별 처리
                if (usagePercentage >= 1.0m) // 100% 도달
                {
                    // API 차단 이벤트 발행
                    await _eventBus.PublishAsync(new ApiQuotaExceededEvent
                    {
                        ApplicationId = eventData.ApplicationId,
                        QuotaType = eventData.ThresholdType,
                        BlockedAt = _dateTimeProvider.UtcNow
                    });
                }
                else if (usagePercentage >= DefaultApiUsageThreshold) // 80% 이상
                {
                    // 경고 알림 발송
                    await SendUsageWarningNotificationAsync(eventData);
                }

                // 사용량 통계 캐싱 (대시보드용)
                await UpdateUsageStatsCacheAsync(eventData);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling API usage threshold event");
                // 사용량 추적 실패는 서비스를 중단시키지 않음
            }
        }

        public async Task HandleStorageUsageThresholdReachedAsync(StorageUsageThresholdEvent eventData)
        {
            try
            {
                var usagePercentage = eventData.CurrentUsageGB / eventData.QuotaGB;

                _logger.LogWarning("Storage threshold reached: App={AppId}, Usage={Current:F2}GB/{Quota:F2}GB ({Percentage:P})",
                    eventData.ApplicationId, eventData.CurrentUsageGB, eventData.QuotaGB, usagePercentage);

                // 90% 이상 시 자동 정리 제안
                if (usagePercentage >= DefaultStorageThreshold)
                {
                    await _eventBus.PublishAsync(new StorageCleanupSuggestionEvent
                    {
                        ApplicationId = eventData.ApplicationId,
                        CurrentUsageGB = eventData.CurrentUsageGB,
                        SuggestedActions = new[] { "Archive old data", "Delete temporary files", "Compress large files" }
                    });
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling storage usage threshold event");
            }
        }

        public async Task HandleUsageResetAsync(UsageResetEvent eventData)
        {
            try
            {
                _logger.LogInformation("Usage reset: App={AppId}, Type={Type}, PreviousUsage={Usage}",
                    eventData.ApplicationId, eventData.ResetType, eventData.PreviousUsage);

                // 사용량 리셋 전 통계 저장
                await StoreUsageHistoryAsync(eventData);

                // 캐시 초기화
                var usageKey = GetUsageCacheKey(eventData.ApplicationId, eventData.ResetType);
                await _cacheService.RemoveAsync(usageKey);

                // 리셋 알림
                await _eventBus.PublishAsync(new UsageResetNotification
                {
                    ApplicationId = eventData.ApplicationId,
                    ResetType = eventData.ResetType,
                    NextResetDate = CalculateNextResetDate(eventData.ResetType)
                });

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling usage reset event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        #endregion

        #region Point Events (SaaS 핵심 - 과금 관련)

        public async Task HandleApiBlockedDueToInsufficientPointsAsync(InsufficientPointsEvent eventData)
        {
            try
            {
                _logger.LogWarning("API blocked due to insufficient points: App={AppId}, Required={Required}, Available={Available}",
                    eventData.ApplicationId, eventData.RequiredPoints, eventData.AvailablePoints);

                // 즉시 API 차단 설정
                var blockKey = GetApiBlockCacheKey(eventData.ApplicationId);
                await _cacheService.SetAsync(blockKey, new ApiBlockInfo
                {
                    IsBlocked = true,
                    BlockedAt = _dateTimeProvider.UtcNow,
                    Reason = "InsufficientPoints",
                    RequiredPoints = eventData.RequiredPoints,
                    AvailablePoints = eventData.AvailablePoints
                }, TimeSpan.FromMinutes(5)); // 5분 후 재시도 허용

                // 긴급 알림 발송
                await SendInsufficientPointsAlertAsync(eventData);

                // 감사 로그
                await _auditService.LogActionAsync(
                    eventData.ConnectedId,
                    "API_BLOCKED_INSUFFICIENT_POINTS",
                    AuditActionType.Blocked,
                    "Application",
                    eventData.ApplicationId.ToString(),
                    false,
                    JsonSerializer.Serialize(new
                    {
                        ApiEndpoint = eventData.ApiEndpoint,
                        RequiredPoints = eventData.RequiredPoints,
                        AvailablePoints = eventData.AvailablePoints
                    }));

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling insufficient points event");
                // API 차단은 중요하므로 예외 전파
                throw;
            }
        }

        public async Task HandlePointSettingsChangedAsync(PointSettingsChangedEvent eventData)
        {
            try
            {
                // 포인트 설정 변경은 과금에 직접적 영향
                _logger.LogInformation("Point settings changed: App={AppId}, UsePoints={Old}->{New}, Rate={OldRate}->{NewRate}",
                    eventData.ApplicationId,
                    eventData.OldUsePointsForApiCalls, eventData.NewUsePointsForApiCalls,
                    eventData.OldPointsPerApiCall, eventData.NewPointsPerApiCall);

                // 중요 변경사항 감사
                await _auditService.LogActionAsync(
                    eventData.ChangedByConnectedId,
                    "POINT_SETTINGS_CHANGED",
                    AuditActionType.Configuration,
                    "Application",
                    eventData.ApplicationId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        UsePointsChanged = eventData.OldUsePointsForApiCalls != eventData.NewUsePointsForApiCalls,
                        RateChanged = eventData.OldPointsPerApiCall != eventData.NewPointsPerApiCall,
                        OldRate = eventData.OldPointsPerApiCall,
                        NewRate = eventData.NewPointsPerApiCall
                    }));

                // 포인트 설정 캐시 업데이트
                await UpdatePointSettingsCacheAsync(eventData);

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling point settings changed event");
                await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }

        #endregion

        #region Private Helper Methods - SaaS Optimized

        private string GetApplicationCacheKey(Guid organizationId, Guid applicationId)
        {
            return $"tenant:{organizationId}:app:{applicationId}";
        }

        private string GetApplicationSettingsCacheKey(Guid applicationId)
        {
            return $"app:{applicationId}:settings";
        }

        private string GetResourceQuotaCacheKey(Guid applicationId, string resourceType)
        {
            return $"app:{applicationId}:quota:{resourceType}";
        }

        private string GetUsageCacheKey(Guid applicationId, string usageType)
        {
            return $"app:{applicationId}:usage:{usageType}";
        }

        private string GetApiBlockCacheKey(Guid applicationId)
        {
            return $"app:{applicationId}:api:blocked";
        }

        private Dictionary<string, object> BuildDynamicAuditData(object eventData, Dictionary<string, object> baseData)
        {
            // 동적 데이터 처리 - SaaS 특성상 어떤 데이터가 올지 모름
            var properties = eventData.GetType().GetProperties();
            foreach (var prop in properties)
            {
                var key = prop.Name;
                if (!baseData.ContainsKey(key))
                {
                    var value = prop.GetValue(eventData);
                    if (value != null && IsJsonSerializable(value))
                    {
                        baseData[key] = value;
                    }
                }
            }
            return baseData;
        }

        private bool IsJsonSerializable(object value)
        {
            // 기본 타입과 컬렉션만 허용
            return value is string || value is bool || value is DateTime ||
                   value is Guid || value.GetType().IsPrimitive ||
                   value is IEnumerable<object>;
        }

        private async Task CacheApplicationWithTenantIsolationAsync(ApplicationCreatedEvent eventData)
        {
            var cacheKey = GetApplicationCacheKey(eventData.OrganizationId, eventData.ApplicationId);

            // 최소한의 필수 정보만 캐싱 (메모리 효율)
            var appData = new Dictionary<string, object>
            {
                ["Id"] = eventData.ApplicationId,
                ["OrganizationId"] = eventData.OrganizationId,
                ["ApplicationKey"] = eventData.ApplicationKey,
                ["ApplicationType"] = eventData.ApplicationType.ToString(),
                ["CreatedAt"] = eventData.CreatedAt,
                ["Status"] = ApplicationStatus.Active.ToString()
            };

            await _cacheService.SetAsync(cacheKey, appData, ApplicationCacheTTL);

            // 조직별 애플리케이션 목록 업데이트
            var orgAppsKey = $"tenant:{eventData.OrganizationId}:apps";
            var appList = await _cacheService.GetAsync<List<Guid>>(orgAppsKey) ?? new List<Guid>();
            appList.Add(eventData.ApplicationId);
            await _cacheService.SetAsync(orgAppsKey, appList, TimeSpan.FromDays(1));
        }

        private async Task UpdateApplicationCacheAsync(ApplicationUpdatedEvent eventData)
        {
            // 부분 캐시 업데이트 (전체 무효화 대신)
            var app = await _applicationRepository.GetByIdAsync(eventData.ApplicationId);
            if (app != null)
            {
                var cacheKey = GetApplicationCacheKey(app.OrganizationId, app.Id);
                var cachedData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);

                if (cachedData != null)
                {
                    // 변경된 속성만 업데이트
                    foreach (var change in eventData.ChangedProperties)
                    {
                        // After (Corrected)
                        if (change.Value != null && IsJsonSerializable(change.Value))
                        {
                            cachedData[change.Key] = change.Value;
                        }
                    }

                    await _cacheService.SetAsync(cacheKey, cachedData, ApplicationCacheTTL);
                }
            }
        }

        private async Task UpdateApplicationStatusInCacheAsync(ApplicationStatusChangedEvent eventData)
        {
            var app = await _applicationRepository.GetByIdAsync(eventData.ApplicationId);
            if (app != null)
            {
                var cacheKey = GetApplicationCacheKey(app.OrganizationId, app.Id);
                var cachedData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);

                if (cachedData != null)
                {
                    cachedData["Status"] = eventData.NewStatus.ToString();
                    cachedData["StatusChangedAt"] = eventData.ChangedAt;

                    await _cacheService.SetAsync(cacheKey, cachedData, ApplicationCacheTTL);
                }
            }
        }

        private async Task CleanupApplicationCacheAsync(Guid applicationId)
        {
            var app = await _applicationRepository.GetByIdAsync(applicationId);
            if (app != null)
            {
                // 애플리케이션 캐시 제거
                var appKey = GetApplicationCacheKey(app.OrganizationId, app.Id);
                await _cacheService.RemoveAsync(appKey);

                // 설정 캐시 제거
                var settingsKey = GetApplicationSettingsCacheKey(app.Id);
                await _cacheService.RemoveAsync(settingsKey);

                // 사용량 캐시 패턴 제거
                var usagePattern = $"app:{app.Id}:*";
                await _cacheService.RemoveByPatternAsync(usagePattern);
            }
        }

        private async Task InvalidateOrganizationApplicationListCacheAsync(Guid organizationId)
        {
            var orgAppsKey = $"tenant:{organizationId}:apps";
            await _cacheService.RemoveAsync(orgAppsKey);
        }

        private async Task InvalidateOAuthCacheAsync(Guid applicationId)
        {
            var oauthKey = $"app:{applicationId}:oauth:*";
            await _cacheService.RemoveByPatternAsync(oauthKey);
        }

        private async Task InitializeApplicationDefaultsAsync(ApplicationCreatedEvent eventData)
        {
            // 조직의 플랜에 따른 기본 설정 적용
            var defaultSettings = await GetDefaultSettingsForApplicationTypeAsync(eventData.ApplicationType);

            var settingsKey = GetApplicationSettingsCacheKey(eventData.ApplicationId);
            await _cacheService.SetAsync(settingsKey, defaultSettings, SettingsCacheTTL);
        }

        private Task<Dictionary<string, object>> GetDefaultSettingsForApplicationTypeAsync(ApplicationType type)
        {
            // 애플리케이션 타입별 기본 설정
            var settings = type switch
            {
                ApplicationType.Web => new Dictionary<string, object>
                {
                    ["MaxSessionDuration"] = 3600,
                    ["EnableCors"] = true,
                    ["DefaultApiRateLimit"] = 1000
                },
                ApplicationType.Mobile => new Dictionary<string, object>
                {
                    ["MaxSessionDuration"] = 86400,
                    ["EnablePushNotifications"] = true,
                    ["DefaultApiRateLimit"] = 500
                },
                ApplicationType.Api => new Dictionary<string, object>
                {
                    ["MaxSessionDuration"] = 7200,
                    ["RequireApiKey"] = true,
                    ["DefaultApiRateLimit"] = 10000
                },
                _ => new Dictionary<string, object>()
            };

            return Task.FromResult(settings);
        }

        private async Task ProcessStatusChangeAsync(ApplicationStatusChangedEvent eventData)
        {
            switch (eventData.NewStatus)
            {
                case ApplicationStatus.Suspended:
                    // 애플리케이션 비활성화 알림
                    await _eventBus.PublishAsync(new ApplicationSuspendedNotification
                    {
                        ApplicationId = eventData.ApplicationId,
                        SuspendedAt = eventData.ChangedAt,
                        Reason = eventData.Reason
                    });

                    // API 키 관련 캐시 무효화
                    var apiKeyCachePattern = $"app:{eventData.ApplicationId}:apikeys:*";
                    await _cacheService.RemoveByPatternAsync(apiKeyCachePattern);
                    break;

                case ApplicationStatus.Active:
                    // 애플리케이션 활성화 알림
                    await _eventBus.PublishAsync(new ApplicationActivatedNotification
                    {
                        ApplicationId = eventData.ApplicationId,
                        ActivatedAt = eventData.ChangedAt
                    });

                    // API 키 캐시 재구성 필요 플래그 설정
                    var reactivateKey = $"app:{eventData.ApplicationId}:needs-reactivation";
                    await _cacheService.SetAsync(reactivateKey, new { NeedsReactivation = true }, TimeSpan.FromMinutes(5));
                    break;

                case ApplicationStatus.Deleted:
                    // 완전 삭제 처리
                    await CleanupApplicationCacheAsync(eventData.ApplicationId);
                    break;
            }
        }

        private async Task UpdateUsageStatsCacheAsync(ApiUsageThresholdEvent eventData)
        {
            var statsKey = $"app:{eventData.ApplicationId}:stats:usage";
            var stats = new Dictionary<string, object>
            {
                ["CurrentUsage"] = eventData.CurrentUsage,
                ["Quota"] = eventData.Quota,
                ["Percentage"] = (decimal)eventData.CurrentUsage / eventData.Quota,
                ["UpdatedAt"] = eventData.OccurredAt,
                ["ThresholdType"] = eventData.ThresholdType
            };

            await _cacheService.SetAsync(statsKey, stats, UsageStatsCacheTTL);
        }

        private async Task UpdatePointSettingsCacheAsync(PointSettingsChangedEvent eventData)
        {
            var pointKey = $"app:{eventData.ApplicationId}:points:settings";
            var settings = new Dictionary<string, object>
            {
                ["UsePointsForApiCalls"] = eventData.NewUsePointsForApiCalls,
                ["PointsPerApiCall"] = eventData.NewPointsPerApiCall,
                ["UpdatedAt"] = eventData.ChangedAt
            };

            await _cacheService.SetAsync(pointKey, settings, TimeSpan.FromHours(12));
        }

        private async Task StoreUsageHistoryAsync(UsageResetEvent eventData)
        {
            // 히스토리는 영구 저장이 필요하므로 DB에 직접 저장
            var historyKey = $"app:{eventData.ApplicationId}:history:{eventData.ResetType}:{eventData.ResetAt:yyyyMMdd}";
            await _cacheService.SetAsync(historyKey, new
            {
                PreviousUsage = eventData.PreviousUsage,
                ResetAt = eventData.ResetAt,
                ResetType = eventData.ResetType
            }, TimeSpan.FromDays(90)); // 90일 보관
        }

        private async Task SendUsageWarningNotificationAsync(ApiUsageThresholdEvent eventData)
        {
            await _eventBus.PublishAsync(new UsageWarningNotification
            {
                ApplicationId = eventData.ApplicationId,
                CurrentUsage = eventData.CurrentUsage,
                Quota = eventData.Quota,
                ThresholdPercentage = eventData.ThresholdPercentage,
                NotificationType = "API_USAGE_WARNING"
            });
        }

        private async Task SendInsufficientPointsAlertAsync(InsufficientPointsEvent eventData)
        {
            await _eventBus.PublishAsync(new InsufficientPointsAlert
            {
                ApplicationId = eventData.ApplicationId,
                ConnectedId = eventData.ConnectedId,
                RequiredPoints = eventData.RequiredPoints,
                AvailablePoints = eventData.AvailablePoints,
                ApiEndpoint = eventData.ApiEndpoint,
                AlertLevel = "CRITICAL"
            });
        }

        private bool AreListsEqual(List<string>? list1, List<string>? list2)
        {
            if (list1 == null && list2 == null) return true;
            if (list1 == null || list2 == null) return false;
            return list1.SequenceEqual(list2);
        }

        private bool ShouldAuditUpdate(Dictionary<string, object?> changes)
        {
            // 중요한 필드 변경만 감사
            var importantFields = new[] { "ApplicationKey", "ApplicationType", "OrganizationId", "Status" };
            return changes.Keys.Any(k => importantFields.Contains(k, StringComparer.OrdinalIgnoreCase));
        }

        private bool IsImportantStatusChange(ApplicationStatus oldStatus, ApplicationStatus newStatus)
        {
            // Active <-> Suspended/Deleted 변경은 중요
            return (oldStatus == ApplicationStatus.Active && newStatus != ApplicationStatus.Active) ||
                   (oldStatus != ApplicationStatus.Active && newStatus == ApplicationStatus.Active);
        }

        private bool IsImportantSetting(string settingKey)
        {
            var importantSettings = new[] { "ApiRateLimit", "MaxSessionDuration", "RequireApiKey", "SecurityLevel" };
            return importantSettings.Contains(settingKey, StringComparer.OrdinalIgnoreCase);
        }

        private DateTime CalculateNextResetDate(string resetType)
        {
            var now = _dateTimeProvider.UtcNow;
            return resetType.ToLower() switch
            {
                "daily" => now.AddDays(1).Date,
                "weekly" => now.AddDays(7 - (int)now.DayOfWeek).Date,
                "monthly" => new DateTime(now.Year, now.Month, 1).AddMonths(1),
                _ => now.AddDays(1)
            };
        }

        #endregion
    }

    #region Internal Event Classes (최소한만 유지)

    internal class ApplicationDeactivatedNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public DateTime DeactivatedAt { get; set; }
    }

    internal class ApiQuotaExceededEvent : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public string QuotaType { get; set; } = string.Empty;
        public DateTime BlockedAt { get; set; }
    }

    internal class StorageCleanupSuggestionEvent : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public decimal CurrentUsageGB { get; set; }
        public string[] SuggestedActions { get; set; } = Array.Empty<string>();
    }

    internal class UsageResetNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; } 
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public string ResetType { get; set; } = string.Empty;
        public DateTime NextResetDate { get; set; }
    }

    internal class ResourceQuotaReducedWarning : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public string ResourceType { get; set; } = string.Empty;
        public decimal NewQuota { get; set; }
    }

    internal class UsageWarningNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public long CurrentUsage { get; set; }
        public long Quota { get; set; }
        public decimal ThresholdPercentage { get; set; }
        public string NotificationType { get; set; } = string.Empty;
    }

    internal class InsufficientPointsAlert : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public Guid ConnectedId { get; set; }
        public decimal RequiredPoints { get; set; }
        public decimal AvailablePoints { get; set; }
        public string ApiEndpoint { get; set; } = string.Empty;
        public string AlertLevel { get; set; } = string.Empty;
    }

    internal class ApiBlockInfo
    {
        public bool IsBlocked { get; set; }
        public DateTime BlockedAt { get; set; }
        public string Reason { get; set; } = string.Empty;
        public decimal RequiredPoints { get; set; }
        public decimal AvailablePoints { get; set; }
    }

    internal class ApplicationSuspendedNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public DateTime SuspendedAt { get; set; }
        public string? Reason { get; set; }
    }

    internal class ApplicationActivatedNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public Guid AggregateId { get; private set; }
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid ApplicationId { get; set; }
        public DateTime ActivatedAt { get; set; }
    }

    #endregion
}