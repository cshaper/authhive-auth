// File: AuthHive.Auth/Services/Handlers/Application/ManageApplicationCacheOnCreateHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationCreatedEvent
using AuthHive.Core.Enums.Core; // ApplicationType
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore
{
    /// <summary>
    /// 애플리케이션 생성 시, 기본 정보 및 기본 설정을 캐시에 저장합니다.
    /// (ApplicationEventHandler의 CacheApplication... + InitializeApplicationDefaults... 로직 결합)
    /// </summary>
    public class ManageApplicationCacheOnCreateHandler :
        IDomainEventHandler<ApplicationCreatedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider; // (GetDefaultSettingsForApplicationTypeAsync가 IDateTimeProvider를 사용할 경우 필요)
        private readonly ILogger<ManageApplicationCacheOnCreateHandler> _logger;

        // 캐시 키 (기존 핸들러 참조)
        private const string APP_CACHE_KEY_FORMAT = "tenant:{0}:app:{1}";
        private const string SETTINGS_CACHE_KEY_FORMAT = "app:{0}:settings";
        private static readonly TimeSpan ApplicationCacheTTL = TimeSpan.FromHours(6);
        private static readonly TimeSpan SettingsCacheTTL = TimeSpan.FromHours(1);

        public int Priority => 20; // 감사 로그(10) 이후 수행
        public bool IsEnabled => true;

        public ManageApplicationCacheOnCreateHandler(
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<ManageApplicationCacheOnCreateHandler> logger)
        {
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;

            if (organizationId == Guid.Empty)
            {
                _logger.LogError("Cannot cache application: OrganizationId is missing for AppId {AppId}", applicationId);
                return;
            }

            try
            {
                // 1. 애플리케이션 기본 정보 캐시
                var appCacheKey = string.Format(APP_CACHE_KEY_FORMAT, organizationId, applicationId);
                var appData = new Dictionary<string, object>
                {
                    ["Id"] = applicationId,
                    ["OrganizationId"] = organizationId,
                    ["ApplicationKey"] = @event.ApplicationKey,
                    ["ApplicationType"] = @event.ApplicationType.ToString(),
                    ["CreatedAt"] = @event.CreatedAt,
                    ["Status"] = "Active" // ❗️ 생성 시 기본 상태 'Active' 가정
                };
                await _cacheService.SetAsync(appCacheKey, appData, ApplicationCacheTTL, cancellationToken);

                // 2. 애플리케이션 기본 설정 캐시
                var settingsKey = string.Format(SETTINGS_CACHE_KEY_FORMAT, applicationId);
                var defaultSettings = GetDefaultSettingsForApplicationType(@event.ApplicationType);
                if (defaultSettings.Count > 0)
                {
                    await _cacheService.SetAsync(settingsKey, defaultSettings, SettingsCacheTTL, cancellationToken);
                }
                
                _logger.LogInformation("Application details and default settings cached for AppId: {AppId}, OrgId: {OrgId}", applicationId, organizationId);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Caching application data for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache application data for AppId: {AppId}", applicationId);
                // 캐시 실패는 로깅만 하고 넘어가되, 트랜잭션을 중단시킬 필요는 없음
            }
        }
        
        // 헬퍼 메서드 (기존 ApplicationEventHandler 로직)
        private Dictionary<string, object> GetDefaultSettingsForApplicationType(ApplicationType type)
        {
            return type switch
            {
                ApplicationType.Web => new Dictionary<string, object> { ["MaxSessionDuration"] = 3600, ["EnableCors"] = true, ["DefaultApiRateLimit"] = 1000 },
                ApplicationType.Mobile => new Dictionary<string, object> { ["MaxSessionDuration"] = 86400, ["EnablePushNotifications"] = true, ["DefaultApiRateLimit"] = 500 },
                ApplicationType.Api => new Dictionary<string, object> { ["MaxSessionDuration"] = 7200, ["RequireApiKey"] = true, ["DefaultApiRateLimit"] = 10000 },
                _ => new Dictionary<string, object>()
            };
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}