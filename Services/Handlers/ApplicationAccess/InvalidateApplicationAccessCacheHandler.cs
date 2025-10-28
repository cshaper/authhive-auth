// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/InvalidateApplicationAccessCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; 
using AuthHive.Core.Models.PlatformApplication.Events; // 모든 관련 이벤트
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // List<string>
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 애플리케이션 접근 권한 변경 시 관련 사용자 캐시를 무효화합니다.
    /// (AccessGranted, Revoked, Modified, Expired, RoleChanged, PermissionsAdded/Removed, TemplateApplied/Removed 이벤트 구독)
    /// </summary>
    public class InvalidateApplicationAccessCacheHandler :
        IDomainEventHandler<AccessGrantedEvent>,
        IDomainEventHandler<AccessRevokedEvent>,
        IDomainEventHandler<AccessModifiedEvent>,
        IDomainEventHandler<AccessExpiredEvent>,
        IDomainEventHandler<ApplicationRoleChangedEvent>, // ❗️ 이름 변경된 이벤트
        IDomainEventHandler<ApplicationPermissionsAddedEvent>, // ❗️ 이름 변경된 이벤트
        IDomainEventHandler<ApplicationPermissionsRemovedEvent>, // ❗️ 이름 변경된 이벤트
        IDomainEventHandler<ApplicationTemplateAppliedEvent>, // ❗️ 이름 변경된 이벤트
        IDomainEventHandler<ApplicationTemplateRemovedEvent>, // ❗️ 이름 변경된 이벤트
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateApplicationAccessCacheHandler> _logger;
        // 캐시 키 포맷 (예: "permissions:appId:connId")
        private const string PERMISSION_CACHE_KEY_FORMAT = "permissions:{0}:{1}";
        // 사용자별 앱 목록 캐시 키 (예: "userapps:connId")
        private const string USER_APPS_CACHE_KEY_FORMAT = "userapps:{0}";

        public int Priority => 5; // 캐시 무효화는 우선순위 높음
        public bool IsEnabled => true;

        public InvalidateApplicationAccessCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateApplicationAccessCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // --- Event Handlers ---
        public Task HandleAsync(AccessGrantedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "AccessGranted", c);
        
        public Task HandleAsync(AccessRevokedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "AccessRevoked", c);

        public Task HandleAsync(AccessModifiedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "AccessModified", c);

        public Task HandleAsync(AccessExpiredEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "AccessExpired", c);

        // PlatformApplication 네임스페이스의 RoleChangedEvent
        public Task HandleAsync(ApplicationRoleChangedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "ApplicationRoleChanged", c);

        public Task HandleAsync(ApplicationPermissionsAddedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "ApplicationPermissionsAdded", c);
        
        public Task HandleAsync(ApplicationPermissionsRemovedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "ApplicationPermissionsRemoved", c);

        public Task HandleAsync(ApplicationTemplateAppliedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "ApplicationTemplateApplied", c);

        // ApplicationTemplateRemovedEvent (CS1061 오류 수정됨)
        public Task HandleAsync(ApplicationTemplateRemovedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.ConnectedId, "ApplicationTemplateRemoved", c);
        
        /// <summary>
        /// 특정 사용자의 애플리케이션 권한 캐시를 무효화하는 내부 로직
        /// </summary>
        private async Task InvalidateCacheInternalAsync(Guid? applicationId, Guid connectedId, string reason, CancellationToken cancellationToken)
        {
            if (applicationId == null || applicationId == Guid.Empty || connectedId == Guid.Empty)
            {
                _logger.LogWarning("Skipping permission cache invalidation due to missing AppId or ConnectedId. Reason: {Reason}", reason);
                return;
            }

            try
            {
                // 1. 특정 앱/사용자 권한 캐시 키
                var cacheKey = string.Format(PERMISSION_CACHE_KEY_FORMAT, applicationId, connectedId);
                // 2. 사용자가 접근 가능한 앱 목록 캐시 키
                var userAppsKey = string.Format(USER_APPS_CACHE_KEY_FORMAT, connectedId);

                _logger.LogInformation(
                    "Invalidating application permission cache due to {Reason}. AppId: {AppId}, ConnectedId: {ConnectedId}, Keys: [{CacheKey}, {UserAppsKey}]",
                    reason, applicationId, connectedId, cacheKey, userAppsKey);

                // ❗️ 지침 4 (ICacheService) 및 7 (IUnitOfWork) 준수:
                // 캐시 무효화는 즉시 수행되어야 하므로 UnitOfWork 트랜잭션에는 포함하지 않습니다.
                await _cacheService.RemoveMultipleAsync(new List<string> { cacheKey, userAppsKey }, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating permission cache for App {AppId}, ConnId {ConnectedId} was canceled.", applicationId, connectedId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate permission cache for App: {AppId}, ConnId: {ConnectedId}", applicationId, connectedId);
                // 캐시 무효화 실패가 핵심 비즈니스 로직을 중단시켜서는 안 됨
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled); // CacheService의 Health Check를 위임받을 수 있음
        #endregion
    }
}