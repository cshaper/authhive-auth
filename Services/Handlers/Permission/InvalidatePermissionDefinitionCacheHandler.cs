// File: AuthHive.Auth/Services/Handlers/Permission/InvalidatePermissionDefinitionCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.Auth.Permissions.Events; // 관련 이벤트들 (Created, Modified, Deleted)
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 정의(Permission Definition) 변경 시 관련 캐시를 무효화합니다.
    /// (Created, Modified, Deleted 이벤트 구독)
    /// </summary>
    public class InvalidatePermissionDefinitionCacheHandler :
        IDomainEventHandler<PermissionCreatedEvent>,
        IDomainEventHandler<PermissionModifiedEvent>,
        IDomainEventHandler<PermissionDeletedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidatePermissionDefinitionCacheHandler> _logger;

        // 캐시 무효화는 로깅(10) 이후, 다른 작업 전에 수행 (5)
        public int Priority => 5;
        public bool IsEnabled => true;

        public InvalidatePermissionDefinitionCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidatePermissionDefinitionCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // --- PermissionCreatedEvent 처리 ---
        public async Task HandleAsync(PermissionCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            // 이벤트에서 Scope 속성 사용
            await InvalidateCacheInternalAsync(@event.Scope, "created", cancellationToken);
        }

        // --- PermissionModifiedEvent 처리 ---
        public async Task HandleAsync(PermissionModifiedEvent @event, CancellationToken cancellationToken = default)
        {
             // 이벤트에서 PermissionScope 속성 사용
            await InvalidateCacheInternalAsync(@event.PermissionScope, "modified", cancellationToken);
        }

        // --- PermissionDeletedEvent 처리 ---
        public async Task HandleAsync(PermissionDeletedEvent @event, CancellationToken cancellationToken = default)
        {
             // 이벤트에서 Scope 속성 사용
            await InvalidateCacheInternalAsync(@event.Scope, "deleted", cancellationToken);
        }

        /// <summary>
        /// 권한 정의 관련 캐시를 무효화하는 내부 로직
        /// </summary>
        private async Task InvalidateCacheInternalAsync(string permissionScope, string changeType, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(permissionScope))
            {
                _logger.LogWarning("Cannot invalidate permission definition cache: Permission scope is empty for change type {ChangeType}.", changeType);
                return;
            }

            try
            {
                // 권한 정의 자체에 대한 캐시 키 (Scope 기반)
                var definitionCacheKey = $"{AuthConstants.CacheKeys.PermissionPrefix}definition:{permissionScope}";
                // 모든 권한 목록 캐시 키 (변경 시 목록 캐시도 무효화 필요)
                var allDefinitionsCacheKey = $"{AuthConstants.CacheKeys.PermissionPrefix}definitions:all";

                _logger.LogInformation(
                    "Invalidating permission definition caches due to '{ChangeType}' event for scope: {Scope}",
                    changeType, permissionScope);

                // 여러 키 동시 제거
                await _cacheService.RemoveMultipleAsync(new[] { definitionCacheKey, allDefinitionsCacheKey }, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating permission definition cache for scope {Scope} was canceled.", permissionScope);
                 throw; // 취소는 다시 던짐
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate permission definition cache for scope: {Scope}", permissionScope);
                // 캐시 제거 실패는 로깅만 하고 계속 진행
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled); // CacheService 의존성 확인 가능
        #endregion
    }
}