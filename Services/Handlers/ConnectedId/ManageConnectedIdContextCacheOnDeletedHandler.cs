// File: AuthHive.Auth/Services/Handlers/ConnectedId/ManageConnectedIdContextCacheOnDeletedHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
// ❗️ 수정: 이벤트 이름 변경
using AuthHive.Core.Models.Auth.ConnectedId.Events; // ConnectedIdContextDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ConnectedId
{
    /// <summary>
    /// ConnectedId 컨텍스트 삭제 시 캐시에서 해당 컨텍스트를 제거합니다.
    /// </summary>
    // ❗️ 수정: 이벤트 이름 변경
    public class ManageConnectedIdContextCacheOnDeletedHandler :
        IDomainEventHandler<ConnectedIdContextDeletedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageConnectedIdContextCacheOnDeletedHandler> _logger;
        private const string CACHE_KEY_PREFIX = "context"; // 캐시 키 접두사

        public int Priority => 20; // 캐시 작업
        public bool IsEnabled => true;

        public ManageConnectedIdContextCacheOnDeletedHandler(
            ICacheService cacheService,
            ILogger<ManageConnectedIdContextCacheOnDeletedHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // ❗️ 수정: 이벤트 이름 변경
        public async Task HandleAsync(ConnectedIdContextDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            // 캐시 키 생성 (ContextCreated 핸들러와 동일한 로직 사용 필요)
            // 컨텍스트 엔티티 ID가 있다면 그것을 키로 사용하는 것이 더 정확할 수 있음
            var cacheKey = $"{CACHE_KEY_PREFIX}:{organizationId}:{connectedId}"; // 또는 ContextEntityId 사용

            try
            {
                _logger.LogInformation(
                    "Removing context from cache due to deletion event. ConnectedId: {ConnectedId}, Key: {CacheKey}",
                    connectedId, cacheKey);

                // 캐시에서 제거
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Removing context cache for ConnectedId={ConnectedId} was canceled.", connectedId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove context cache for ConnectedId: {ConnectedId}", connectedId);
                // 캐시 제거 실패는 재시도 필요 없을 수 있음
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}