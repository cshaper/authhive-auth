// File: AuthHive.Auth/Services/Handlers/ApplicationCore/CacheApiBlockOnInsufficientPointsHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // InsufficientPointsEvent
using AuthHive.Core.Models.PlatformApplication.Common; // ApiBlockInfo
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 포인트 부족 시, API 호출을 일시적으로 차단하는 캐시 플래그를 설정합니다.
    /// (ApplicationEventHandler 로직 분리)
    /// </summary>
    public class CacheApiBlockOnInsufficientPointsHandler :
        IDomainEventHandler<InsufficientPointsEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<CacheApiBlockOnInsufficientPointsHandler> _logger;

        // 캐시 키 (기존 핸들러 참조)
        private const string API_BLOCK_CACHE_KEY_FORMAT = "app:{0}:api:blocked";
        private static readonly TimeSpan BlockTTL = TimeSpan.FromMinutes(5); // 5분 후 재시도 허용

        public int Priority => 20; // 감사 로그(10) 이후 수행
        public bool IsEnabled => true;

        public CacheApiBlockOnInsufficientPointsHandler(
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<CacheApiBlockOnInsufficientPointsHandler> logger)
        {
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task HandleAsync(InsufficientPointsEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var cacheKey = string.Format(API_BLOCK_CACHE_KEY_FORMAT, applicationId);

            try
            {
                _logger.LogWarning("Caching API block flag for AppId: {AppId} due to insufficient points.", applicationId);
                
                var blockInfo = new ApiBlockInfo
                {
                    IsBlocked = true,
                    BlockedAt = _dateTimeProvider.UtcNow,
                    Reason = "InsufficientPoints",
                    RequiredPoints = @event.RequiredPoints,
                    AvailablePoints = @event.AvailablePoints
                };
                
                // ❗️ 5분간 차단 캐시 설정
                await _cacheService.SetAsync(cacheKey, blockInfo, BlockTTL, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Caching API block for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache API block for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}