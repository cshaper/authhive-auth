// File: AuthHive.Auth/Services/Handlers/ApplicationCore/ManageApplicationUsageCacheOnResetHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // UsageResetEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 사용량 초기화 시, 기존 사용량 캐시를 삭제하고 히스토리 캐시를 저장합니다.
    /// (이전 이름: ManageUsageCacheOnResetHandler)
    /// </summary>
    public class ManageApplicationUsageCacheOnResetHandler : // ❗️ 이름 수정
        IDomainEventHandler<UsageResetEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageApplicationUsageCacheOnResetHandler> _logger; // ❗️ 이름 수정

        // 캐시 키 (기존 핸들러 참조)
        private const string USAGE_CACHE_KEY_FORMAT = "app:{0}:usage:{1}"; 
        private const string STATS_CACHE_KEY_FORMAT = "app:{0}:stats:usage:{1}";
        private const string HISTORY_CACHE_KEY_FORMAT = "app:{0}:history:{1}:{2:yyyyMMdd}";
        private static readonly TimeSpan HistoryCacheTTL = TimeSpan.FromDays(90);

        public int Priority => 20; 
        public bool IsEnabled => true;

        public ManageApplicationUsageCacheOnResetHandler( // ❗️ 이름 수정
            ICacheService cacheService,
            ILogger<ManageApplicationUsageCacheOnResetHandler> logger) // ❗️ 이름 수정
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(UsageResetEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var resetType = @event.ResetType;

            try
            {
                // 1. 이전 사용량 히스토리 캐시에 저장
                var historyKey = string.Format(HISTORY_CACHE_KEY_FORMAT, applicationId, resetType, @event.OccurredAt);
                var historyData = new
                {
                    PreviousUsage = @event.PreviousUsage,
                    ResetAt = @event.OccurredAt,
                    ResetType = resetType
                };
                await _cacheService.SetAsync(historyKey, historyData, HistoryCacheTTL, cancellationToken);

                // 2. 현재 사용량 캐시 및 통계 캐시 삭제
                var usageKey = string.Format(USAGE_CACHE_KEY_FORMAT, applicationId, resetType);
                var statsKey = string.Format(STATS_CACHE_KEY_FORMAT, applicationId, resetType);

                await _cacheService.RemoveMultipleAsync(new[] { usageKey, statsKey }, cancellationToken);
                
                _logger.LogInformation("Usage cache reset and history stored for AppId: {AppId}, Type: {ResetType}", applicationId, resetType);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Managing usage cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to manage usage cache on reset for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}