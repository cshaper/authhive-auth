using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.ConnectedId.Cache;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// ConnectedId 관련 캐시 관리 로직을 구현합니다.
    /// </summary>
    public class ConnectedIdCacheService : IConnectedIdCacheService
    {
        private readonly IMemoryCache _cache;
        private readonly ILogger<ConnectedIdCacheService> _logger;

        // 캐시 키를 관리하기 위한 내부 상수
        private const string CACHE_PREFIX = "connected_id:";
        private const string ORG_CACHE_TOKEN_PREFIX = "org_cache_token:";

        public ConnectedIdCacheService(
            IMemoryCache cache,
            ILogger<ConnectedIdCacheService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation

        public Task<bool> IsHealthyAsync()
        {
            // IMemoryCache는 일반적으로 실패하지 않으므로, 의존성이 주입되었는지 여부만 확인
            return Task.FromResult(_cache != null);
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdCacheService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Cache Management

        public Task<ServiceResult> ClearConnectedIdCacheAsync(Guid connectedId)
        {
            try
            {
                var cacheKey = $"{CACHE_PREFIX}{connectedId}";
                _cache.Remove(cacheKey);
                _logger.LogDebug("Cache cleared for ConnectedId {ConnectedId}", connectedId);
                return Task.FromResult(ServiceResult.Success("Cache cleared successfully."));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear cache for ConnectedId {ConnectedId}", connectedId);
                return Task.FromResult(ServiceResult.Failure("Failed to clear cache."));
            }
        }

        public Task<ServiceResult<int>> ClearOrganizationConnectedIdCacheAsync(Guid organizationId)
        {
            try
            {
                // CancellationTokenSource를 사용하여 조직에 속한 모든 캐시를 한 번에 무효화합니다.
                var tokenKey = $"{ORG_CACHE_TOKEN_PREFIX}{organizationId}";
                if (_cache.TryGetValue(tokenKey, out CancellationTokenSource? cts) && cts != null)
                {
                    cts.Cancel(); // 이 토큰과 연결된 모든 캐시 항목이 만료됩니다.
                    cts.Dispose();
                    _cache.Remove(tokenKey); // 토큰 자체도 제거
                    _logger.LogInformation("Cache invalidated for organization {OrganizationId}", organizationId);
                }
                
                // 정확한 카운트는 어려우므로 성공 여부만 반환
                return Task.FromResult(ServiceResult<int>.Success(1)); 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for organization {OrganizationId}", organizationId);
                return Task.FromResult(ServiceResult<int>.Failure("Failed to invalidate organization cache."));
            }
        }

        public Task<ServiceResult<ConnectedIdCacheStatistics>> GetCacheStatisticsAsync()
        {
            var stats = _cache.GetCurrentStatistics();
            if (stats == null)
            {
                return Task.FromResult(ServiceResult<ConnectedIdCacheStatistics>.Failure("Cache statistics are not available."));
            }

            var totalRequests = stats.TotalHits + stats.TotalMisses;

            var response = new ConnectedIdCacheStatistics
            {
                TotalCachedItems = stats.CurrentEntryCount,
                HitRate = totalRequests > 0 ? (double)stats.TotalHits / totalRequests : 0.0,
                MissRate = totalRequests > 0 ? (double)stats.TotalMisses / totalRequests : 0.0,
                GeneratedAt = DateTime.UtcNow,
                EntriesByOrganization = new Dictionary<Guid, long>(),
                EntriesByMembershipType = new Dictionary<MembershipType, long>(),
                EntriesByStatus = new Dictionary<ConnectedIdStatus, long>(),
                MostAccessed = new List<FrequentlyAccessedConnectedId>(),
                AverageConnectedIdCacheTtl = 0
            };
            
            return Task.FromResult(ServiceResult<ConnectedIdCacheStatistics>.Success(response));
        }

        #endregion
    }
}