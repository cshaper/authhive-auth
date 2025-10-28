// File: AuthHive.Auth/Services/Handlers/Application/InvalidateOrganizationAppListCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationCreatedEvent, ApplicationDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore
{
    /// <summary>
    /// 애플리케이션 생성 또는 삭제 시, 조직의 애플리케이션 '목록' 캐시를 무효화합니다.
    /// (ApplicationEventHandler의 InvalidateOrganizationApplicationListCacheAsync 로직 분리)
    /// </summary>
    public class InvalidateOrganizationAppListCacheHandler :
        IDomainEventHandler<ApplicationCreatedEvent>,
        IDomainEventHandler<ApplicationDeletedEvent>, // (추후 처리)
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateOrganizationAppListCacheHandler> _logger;
        // 캐시 키 (기존 핸들러 참조)
        private const string ORG_APPS_LIST_KEY_FORMAT = "tenant:{0}:apps"; 

        public int Priority => 30; // 다른 캐시 작업(20) 이후 수행
        public bool IsEnabled => true;

        public InvalidateOrganizationAppListCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateOrganizationAppListCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public Task HandleAsync(ApplicationCreatedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.OrganizationId, "ApplicationCreated", c);

        public Task HandleAsync(ApplicationDeletedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.OrganizationId, "ApplicationDeleted", c);
        
        private async Task InvalidateCacheInternalAsync(Guid? organizationId, string reason, CancellationToken cancellationToken)
        {
            if (organizationId == null || organizationId == Guid.Empty)
            {
                 _logger.LogWarning("Cannot invalidate organization app list cache: OrganizationId is missing. Reason: {Reason}", reason);
                return;
            }

            try
            {
                var orgAppsKey = string.Format(ORG_APPS_LIST_KEY_FORMAT, organizationId);
                await _cacheService.RemoveAsync(orgAppsKey, cancellationToken);
                _logger.LogInformation("Invalidated organization application list cache for OrgId {OrgId} due to {Reason}", organizationId, reason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate organization app list cache for OrgId: {OrgId}", organizationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}