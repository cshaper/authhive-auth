// File: AuthHive.Auth/Services/Handlers/Role/InvalidateRoleDefinitionCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.Auth.Role.Events; // RoleCreatedEvent, RoleChangedEvent, RoleDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 역할 정의(Role Definition) 변경 시 관련 캐시를 무효화합니다.
    /// (Created, Changed, Deleted 이벤트 구독)
    /// </summary>
    public class InvalidateRoleDefinitionCacheHandler :
        IDomainEventHandler<RoleCreatedEvent>,
        IDomainEventHandler<RoleChangedEvent>, // 추후 처리
        IDomainEventHandler<RoleDeletedEvent>, // 추후 처리
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateRoleDefinitionCacheHandler> _logger;

        public int Priority => 5;
        public bool IsEnabled => true;

        public InvalidateRoleDefinitionCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateRoleDefinitionCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // --- RoleCreatedEvent 처리 ---
        public async Task HandleAsync(RoleCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheInternalAsync(@event.AggregateId, "created", cancellationToken);
        }

        // --- RoleChangedEvent 처리 (추후 구현) ---
        public async Task HandleAsync(RoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheInternalAsync(@event.AggregateId, "modified", cancellationToken);
        }

        // --- RoleDeletedEvent 처리 (추후 구현) ---
        public async Task HandleAsync(RoleDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheInternalAsync(@event.AggregateId, "deleted", cancellationToken);
        }

        /// <summary>
        /// 역할 정의 관련 캐시를 무효화하는 내부 로직
        /// </summary>
        private async Task InvalidateCacheInternalAsync(Guid roleId, string changeType, CancellationToken cancellationToken)
        {
            if (roleId == Guid.Empty) return;

            try
            {
                // 역할 정의 자체에 대한 캐시 키 (RoleId 기반)
                var definitionCacheKey = $"{AuthConstants.CacheKeys.RolePrefix}definition:{roleId}";
                // 모든 역할 목록 캐시 키 (변경 시 목록 캐시도 무효화 필요)
                var allDefinitionsCacheKey = $"{AuthConstants.CacheKeys.RolePrefix}definitions:all";

                _logger.LogInformation(
                    "Invalidating role definition caches due to '{ChangeType}' event for RoleId: {RoleId}",
                    changeType, roleId);

                // 여러 키 동시 제거
                await _cacheService.RemoveMultipleAsync(new[] { definitionCacheKey, allDefinitionsCacheKey }, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating role definition cache for RoleId {RoleId} was canceled.", roleId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate role definition cache for RoleId: {RoleId}", roleId);
                // 캐시 제거 실패는 로깅만 하고 계속 진행
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}