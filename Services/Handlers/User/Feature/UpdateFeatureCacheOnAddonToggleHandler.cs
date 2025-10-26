// File: authhive.auth/services/handlers/User/Features/UpdateFeatureCacheOnAddonToggleHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IDomainEventHandler와 IService를 구현합니다.
// 목적: 애드온 활성화/비활성화 시 사용자 기능 캐시(HashSet<string>)를 업데이트합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; 
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Features;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// 애드온 상태 변경 시 사용자 기능 캐시를 업데이트합니다. (제약 조건 4: ICacheService 사용)
    /// </summary>
    public class UpdateFeatureCacheOnAddonToggleHandler :
        IDomainEventHandler<AddonActivatedEvent>,     // ❗️ 수정됨
        IDomainEventHandler<AddonDeactivatedEvent>,   // ❗️ 수정됨
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<UpdateFeatureCacheOnAddonToggleHandler> _logger;
        private const string CACHE_KEY_PREFIX = "feature";
        private const int FEATURE_CACHE_MINUTES = 60;

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;

        public UpdateFeatureCacheOnAddonToggleHandler(
            ICacheService cacheService,
            ILogger<UpdateFeatureCacheOnAddonToggleHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 애드온 활성화 시 캐시에 기능을 추가합니다.
        /// </summary>
        public async Task HandleAsync(AddonActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var userFeaturesKey = $"{CACHE_KEY_PREFIX}:user:{@event.UserId:N}";
                var features = await _cacheService.GetAsync<HashSet<string>>(userFeaturesKey, cancellationToken) ?? new HashSet<string>();
                
                if (features.Add(@event.AddonKey))
                {
                    await _cacheService.SetAsync(userFeaturesKey, features, TimeSpan.FromMinutes(FEATURE_CACHE_MINUTES), cancellationToken);
                    _logger.LogDebug("Addon {AddonKey} added to cache for user {UserId}.", @event.AddonKey, @event.UserId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update feature cache (activation) for user {UserId}, Addon {AddonKey}.", @event.UserId, @event.AddonKey);
            }
        }

        /// <summary>
        /// (한글 주석) 애드온 비활성화 시 캐시에서 기능을 제거합니다.
        /// </summary>
        public async Task HandleAsync(AddonDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var userFeaturesKey = $"{CACHE_KEY_PREFIX}:user:{@event.UserId:N}";
                var features = await _cacheService.GetAsync<HashSet<string>>(userFeaturesKey, cancellationToken);

                if (features != null && features.Remove(@event.AddonKey))
                {
                    await _cacheService.SetAsync(userFeaturesKey, features, TimeSpan.FromMinutes(FEATURE_CACHE_MINUTES), cancellationToken);
                    _logger.LogDebug("Addon {AddonKey} removed from cache for user {UserId}.", @event.AddonKey, @event.UserId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update feature cache (deactivation) for user {UserId}, Addon {AddonKey}.", @event.UserId, @event.AddonKey);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        #endregion
    }
}