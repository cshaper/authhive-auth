using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.ConnectedId.Cache;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// ConnectedId 관련 캐시 관리 로직을 구현합니다.
    /// HybridCacheService를 통해 IMemoryCache + IDistributedCache 전략을 캡슐화합니다.
    /// </summary>
    public class ConnectedIdCacheService : IConnectedIdCacheService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ConnectedIdCacheService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        private const string CACHE_PREFIX = "connected_id:";
        private const string ORG_CACHE_TOKEN_PREFIX = "org_cache_token:";

        public ConnectedIdCacheService(
            ICacheService cacheService,
            ILogger<ConnectedIdCacheService> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _cacheService = cacheService;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return _cacheService.IsHealthyAsync(cancellationToken);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdCacheService initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        #endregion

        #region Cache Management

        public async Task<ServiceResult> ClearConnectedIdCacheAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CACHE_PREFIX}{connectedId}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogDebug("Cache cleared for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult.Success("Cache cleared successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear cache for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult.Failure("Failed to clear cache.");
            }
        }

        public async Task<ServiceResult<int>> ClearOrganizationConnectedIdCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var tokenKey = $"{ORG_CACHE_TOKEN_PREFIX}{organizationId}";
                await _cacheService.RemoveAsync(tokenKey, cancellationToken);
                _logger.LogInformation("Cache invalidated for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Success(1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure("Failed to invalidate organization cache.");
            }
        }

        public async Task<ServiceResult<ConnectedIdCacheStatistics>> GetCacheStatisticsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var stats = await _cacheService.GetStatisticsAsync(cancellationToken);
                var totalRequests = stats.TotalHits + stats.TotalMisses;

                var response = new ConnectedIdCacheStatistics
                {
                    TotalCachedItems = stats.CurrentEntryCount,
                    HitRate = totalRequests > 0 ? (double)stats.TotalHits / totalRequests : 0.0,
                    MissRate = totalRequests > 0 ? (double)stats.TotalMisses / totalRequests : 0.0,
                    GeneratedAt = _dateTimeProvider.UtcNow,
                    EntriesByOrganization = new Dictionary<Guid, long>(),
                    EntriesByMembershipType = new Dictionary<MembershipType, long>(),
                    EntriesByStatus = new Dictionary<ConnectedIdStatus, long>(),
                    MostAccessed = new List<FrequentlyAccessedConnectedId>(),
                    AverageConnectedIdCacheTtl = 0
                };

                return ServiceResult<ConnectedIdCacheStatistics>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve cache statistics.");
                return ServiceResult<ConnectedIdCacheStatistics>.Failure("Cache statistics are not available.");
            }
        }

        #endregion
    }
}
