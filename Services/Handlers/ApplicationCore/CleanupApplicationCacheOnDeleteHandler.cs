// File: AuthHive.Auth/Services/Handlers/ApplicationCore/CleanupApplicationCacheOnDeleteHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // List<string>
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 삭제 시, 관련된 모든 캐시(기본 정보, 설정, API 키, 할당량 등)를 정리합니다.
    /// (ApplicationEventHandler의 CleanupApplicationCacheAsync 로직 분리)
    /// </summary>
    public class CleanupApplicationCacheOnDeleteHandler :
        IDomainEventHandler<ApplicationDeletedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<CleanupApplicationCacheOnDeleteHandler> _logger;

        // 캐시 키 (기존 핸들러 참조)
        private const string APP_CACHE_KEY_FORMAT = "tenant:{0}:app:{1}";
        private const string SETTINGS_CACHE_KEY_FORMAT = "app:{0}:settings";
        private const string API_BLOCK_CACHE_KEY_FORMAT = "app:{0}:api:blocked";
        private const string POINT_SETTINGS_CACHE_KEY_FORMAT = "app:{0}:points:settings";
        private const string OAUTH_CACHE_PATTERN_FORMAT = "app:{0}:oauth:*";
        private const string APIKEY_CACHE_PATTERN_FORMAT = "app:{0}:apikeys:*";
        private const string QUOTA_CACHE_PATTERN_FORMAT = "app:{0}:quota:*";
        private const string USAGE_CACHE_PATTERN_FORMAT = "app:{0}:usage:*";
        private const string STATS_CACHE_PATTERN_FORMAT = "app:{0}:stats:*";
        private const string HISTORY_CACHE_PATTERN_FORMAT = "app:{0}:history:*";

        public int Priority => 20; // 감사 로그(10) 이후 수행
        public bool IsEnabled => true;

        public CleanupApplicationCacheOnDeleteHandler(
            ICacheService cacheService,
            ILogger<CleanupApplicationCacheOnDeleteHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;

            if (organizationId == Guid.Empty)
            {
                _logger.LogError("Cannot cleanup application cache: OrganizationId is missing for AppId {AppId}", applicationId);
                return;
            }

            try
            {
                _logger.LogWarning("Cleaning up all caches related to deleted AppId: {AppId}", applicationId);

                // 1. 개별 키 제거
                var keysToRemove = new List<string>
                {
                    string.Format(APP_CACHE_KEY_FORMAT, organizationId, applicationId),
                    string.Format(SETTINGS_CACHE_KEY_FORMAT, applicationId),
                    string.Format(API_BLOCK_CACHE_KEY_FORMAT, applicationId),
                    string.Format(POINT_SETTINGS_CACHE_KEY_FORMAT, applicationId)
                };
                await _cacheService.RemoveMultipleAsync(keysToRemove, cancellationToken);

                // 2. 패턴 기반 제거 (ICacheService가 지원한다고 가정)
                var patternsToRemove = new List<string>
                {
                    string.Format(OAUTH_CACHE_PATTERN_FORMAT, applicationId),
                    string.Format(APIKEY_CACHE_PATTERN_FORMAT, applicationId),
                    string.Format(QUOTA_CACHE_PATTERN_FORMAT, applicationId),
                    string.Format(USAGE_CACHE_PATTERN_FORMAT, applicationId),
                    string.Format(STATS_CACHE_PATTERN_FORMAT, applicationId),
                    string.Format(HISTORY_CACHE_PATTERN_FORMAT, applicationId)
                };

                foreach (var pattern in patternsToRemove)
                {
                    await _cacheService.RemoveByPatternAsync(pattern, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Cleaning up application cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup application cache for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}