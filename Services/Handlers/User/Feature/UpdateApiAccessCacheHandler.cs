// File: authhive.auth/services/handlers/User/Features/UpdateApiAccessCacheHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IDomainEventHandler와 IService를 구현합니다.
// 목적: API 접근 권한 변경 시, 관련 캐시(권한 목록)를 업데이트합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Features;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// API 접근 권한 변경 시 권한 목록 캐시를 업데이트합니다. (제약 조건 4: ICacheService 사용)
    /// </summary>
    public class UpdateApiAccessCacheHandler : 
        IDomainEventHandler<ApiAccessChangedEvent>, // ❗️ 수정됨
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<UpdateApiAccessCacheHandler> _logger;
        private const string CACHE_KEY_PREFIX = "feature";

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;

        public UpdateApiAccessCacheHandler(
            ICacheService cacheService,
            ILogger<UpdateApiAccessCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) API 접근 권한 변경 이벤트를 처리하여, 사용자의 현재 권한 목록을 캐시에 저장합니다.
        /// </summary>
        public async Task HandleAsync(ApiAccessChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 사용자의 권한 목록을 캐시에 저장합니다.
                var permKey = $"{CACHE_KEY_PREFIX}:permissions:{@event.UserId:N}";
                await _cacheService.SetAsync(permKey, @event.CurrentPermissions, TimeSpan.FromMinutes(30), cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update API access cache for user {UserId}.", @event.UserId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        #endregion
    }
}