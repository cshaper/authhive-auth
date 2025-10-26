// File: AuthHive.Auth/Services/Handlers/ConnectedId/ManageConnectedIdContextCacheOnCreatedHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.Auth.ConnectedId.Events; // ConnectedIdContextCreatedEvent
using AuthHive.Core.Entities.Auth; // ConnectedIdContext 엔티티
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ConnectedId
{
    /// <summary>
    /// ConnectedId 컨텍스트 생성 시 캐시에 해당 컨텍스트를 추가합니다.
    /// </summary>
    public class ManageConnectedIdContextCacheOnCreatedHandler :
        IDomainEventHandler<ConnectedIdContextCreatedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<ManageConnectedIdContextCacheOnCreatedHandler> _logger;
        private const string CACHE_KEY_PREFIX = "context";

        public int Priority => 20;
        public bool IsEnabled => true;

        public ManageConnectedIdContextCacheOnCreatedHandler(
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<ManageConnectedIdContextCacheOnCreatedHandler> logger)
        {
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task HandleAsync(ConnectedIdContextCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            // ❗️ 수정: 캐시 키는 컨텍스트 엔티티 ID를 사용하는 것이 더 정확할 수 있음
            // var cacheKey = $"{CACHE_KEY_PREFIX}:{organizationId}:{@event.ContextEntityId}";
            var cacheKey = $"{CACHE_KEY_PREFIX}:{organizationId}:{connectedId}"; // 이전 방식 유지 가정

            try
            {
                // 이벤트 메타데이터에서 캐시에 저장할 실제 컨텍스트 엔티티 추출 (가정)
                // ❗️ 수정: 타입 이름 변경 ConnectedIdContext (엔티티)
                if (@event.Metadata == null || !@event.Metadata.TryGetValue("ContextObject", out var contextObj) || !(contextObj is ConnectedIdContext contextToCache))
                {
                    _logger.LogWarning("Cannot cache context for {ConnectedId}: Context data not found in event metadata.", connectedId);
                    return;
                }

                var now = _dateTimeProvider.UtcNow;
                // ❗️ 수정: 엔티티 속성 접근 (가정)
                var expiresAt = contextToCache.ExpiresAt; 
                var expiration = expiresAt > now ? expiresAt - now : TimeSpan.FromMinutes(1);

                _logger.LogInformation(
                    "Caching created context for ConnectedId: {ConnectedId}, Key: {CacheKey}, Expires in: {Expiration}",
                    connectedId, cacheKey, expiration);

                await _cacheService.SetAsync(cacheKey, contextToCache, expiration, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Caching context for ConnectedId={ConnectedId} was canceled.", connectedId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache created context for ConnectedId: {ConnectedId}", connectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}