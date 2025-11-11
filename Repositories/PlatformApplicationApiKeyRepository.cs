// Path: AuthHive.Auth/Repositories/PlatformApplicationApiKeyRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.PlatformApplication.Responses; 
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 API 키 저장소 구현 - v17 (Refactored)
    /// </summary>
    public class PlatformApplicationApiKeyRepository :
        BaseRepository<PlatformApplicationApiKey>,
        IPlatformApplicationApiKeyRepository
    {
        private readonly ILogger<PlatformApplicationApiKeyRepository> _logger;

        public PlatformApplicationApiKeyRepository(
            AuthDbContext context,
            ILogger<PlatformApplicationApiKeyRepository> logger,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }
        
        protected override bool IsOrganizationScopedEntity() => true;

        #region API Key 전용 조회 Operations (CancellationToken 추가)

        public async Task<PlatformApplicationApiKey?> GetByIdNoTrackingAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .AsNoTracking()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.Id == id, cancellationToken);
        }

        public async Task<PlatformApplicationApiKey?> GetByKeyValueAsync(
            string keyValue,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(keyValue))
                throw new ArgumentException("Key value cannot be empty", nameof(keyValue));

            return await Query()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.ApiKey == keyValue && k.IsActive, cancellationToken);
        }

        public async Task<PlatformApplicationApiKey?> GetByHashedKeyAsync(
            string hashedKey,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = GetCacheKey($"HashedKey:{hashedKey}");
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<PlatformApplicationApiKey>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            if (string.IsNullOrWhiteSpace(hashedKey))
                throw new ArgumentException("Hashed key cannot be empty", nameof(hashedKey));

            var apiKey = await Query()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.KeyHash == hashedKey && k.IsActive, cancellationToken);

            if (apiKey != null && _cacheService != null)
            {
                 var ttl = apiKey.ExpiresAt.HasValue ? apiKey.ExpiresAt.Value - DateTime.UtcNow : TimeSpan.FromHours(1);
                 if (ttl > TimeSpan.Zero)
                 {
                     await _cacheService.SetAsync(cacheKey, apiKey, ttl, cancellationToken);
                 }
            }
            return apiKey;
        }

        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByApplicationIdAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(k => k.ApplicationId == applicationId)
                .OrderByDescending(k => k.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByOrganizationIdAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(k => k.PlatformApplication)
                .OrderBy(k => k.ApplicationId).ThenByDescending(k => k.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Override BaseRepository Methods with Logging and Cancellation (CancellationToken 추가)

        public override async Task<PlatformApplicationApiKey> AddAsync(
            PlatformApplicationApiKey apiKey,
            CancellationToken cancellationToken = default)
        {
            if (apiKey.OrganizationId == Guid.Empty && apiKey.ApplicationId != Guid.Empty)
            {
                apiKey.OrganizationId = await GetOrganizationIdForApplicationAsync(apiKey.ApplicationId, cancellationToken);
            }

            var result = await base.AddAsync(apiKey, cancellationToken);
            _logger.LogInformation("Created API key {KeyId} for application {ApplicationId}",
                result.Id, result.ApplicationId);
            await InvalidateApiKeyCachesAsync(result, cancellationToken);
            return result;
        }

        public override async Task UpdateAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            await base.UpdateAsync(entity, cancellationToken);
            await InvalidateApiKeyCachesAsync(entity, cancellationToken);
            _logger.LogInformation("Updated API key {KeyId}", entity.Id);
        }

        public override async Task DeleteAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(entity, cancellationToken);
            await InvalidateApiKeyCachesAsync(entity, cancellationToken);
            _logger.LogWarning("Soft Deleted API key {KeyId}", entity.Id);
        }

        #endregion

        #region Validation Operations (CancellationToken 추가)

        public async Task<bool> ExistsByKeyValueAsync(
            string keyValue,
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("Checking existence by raw API key value. Consider using hashed key check instead.");
            return !string.IsNullOrWhiteSpace(keyValue) &&
                   await Query().AnyAsync(k => k.ApiKey == keyValue, cancellationToken);
        }

        public async Task<bool> IsDuplicateNameAsync(
            Guid applicationId,
            string name,
            Guid? excludeId = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            var query = Query().Where(k => k.ApplicationId == applicationId && k.KeyName == name);

            if (excludeId.HasValue)
                query = query.Where(k => k.Id != excludeId.Value);

            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region Usage & Statistics Operations (CancellationToken 추가)

        public async Task<bool> RecordUsageAsync(
            Guid id,
            DateTime usedAt,
            CancellationToken cancellationToken = default)
        {
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null || !apiKey.IsActive) return false;

            int affected = await Query()
                .Where(k => k.Id == id)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.LastUsedAt, usedAt)
                    .SetProperty(k => k.UseCount, k => k.UseCount + 1),
                    cancellationToken);

            if(affected > 0)
            {
                 await InvalidateApiKeyCachesAsync(id, cancellationToken);
                 return true;
            }
            return false;
        }

        public async Task<bool> IncrementDailyUsageAsync(
            Guid id,
            int count = 1,
            CancellationToken cancellationToken = default)
        {
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null || !apiKey.IsActive) return false;

             int affected = await Query()
                 .Where(k => k.Id == id)
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(k => k.DailyUseCount, k => k.DailyUseCount + count)
                     .SetProperty(k => k.LastUsedAt, DateTime.UtcNow),
                     cancellationToken);

            if(affected > 0)
            {
                await InvalidateApiKeyCachesAsync(id, cancellationToken);
                return true;
            }
            return false;
        }

        public async Task<bool> ResetDailyUsageAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
             int affected = await Query()
                 .Where(k => k.Id == id && k.DailyUseCount > 0)
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(k => k.DailyUseCount, 0)
                     .SetProperty(k => k.LastDailyResetAt, DateTime.UtcNow),
                     cancellationToken);

            if(affected > 0)
            {
                await InvalidateApiKeyCachesAsync(id, cancellationToken);
                _logger.LogInformation("Reset daily usage for API key {KeyId}", id);
                return true;
            }
            return false;
        }

        public async Task<IEnumerable<PlatformApplicationApiKey>> GetExpiredKeysAsync(
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Where(k => k.ExpiresAt.HasValue && k.ExpiresAt < now && k.IsActive)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<int> GetActiveCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await CountAsync(k => k.ApplicationId == applicationId && k.IsActive, cancellationToken);
        }

        #endregion

        #region Bulk Operations (CancellationToken 추가)

        public async Task<bool> DeleteRangeByIdsAsync(
            IEnumerable<Guid> ids,
            CancellationToken cancellationToken = default)
        {
            var idList = ids?.ToList();
            if (idList == null || !idList.Any()) return false;

            int deletedCount = await Query()
                .Where(k => idList.Contains(k.Id) && !k.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.IsDeleted, true)
                    .SetProperty(k => k.DeletedAt, DateTime.UtcNow)
                    , cancellationToken);

            if (deletedCount > 0)
            {
                 foreach(var id in idList) await InvalidateApiKeyCachesAsync(id, cancellationToken);
                _logger.LogWarning("Bulk soft deleted {Count} API keys by IDs", deletedCount);
                return true;
            }
            return false;
        }

        public async Task<bool> DeleteByApplicationIdAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
             int deletedCount = await Query()
                .Where(k => k.ApplicationId == applicationId && !k.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.IsDeleted, true)
                    .SetProperty(k => k.DeletedAt, DateTime.UtcNow)
                    , cancellationToken);

            if (deletedCount > 0)
            {
                 await InvalidateApiKeysForApplicationCacheAsync(applicationId, cancellationToken);
                 _logger.LogWarning("Soft deleted {Count} API keys for application {ApplicationId}", deletedCount, applicationId);
                 return true;
            }
            return false;
        }

        public async Task<bool> SoftDeleteAsync(
            Guid id,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
             int affected = await Query()
                .Where(k => k.Id == id && !k.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.IsDeleted, true)
                    .SetProperty(k => k.DeletedAt, DateTime.UtcNow)
                    .SetProperty(k => k.DeletedByConnectedId, deletedByConnectedId)
                    , cancellationToken);

            if (affected > 0)
            {
                await InvalidateApiKeyCachesAsync(id, cancellationToken);
                _logger.LogInformation("Soft deleted API key {KeyId} by connected ID {ConnectedId}", id, deletedByConnectedId);
                return true;
            }
            return false;
        }

        #endregion

        #region Advanced Query Operations (CancellationToken 추가)

        public async Task<ApplicationApiKeyListResponse> GetPagedAsync(
            Expression<Func<PlatformApplicationApiKey, bool>>? predicate,
            int pageNumber,
            int pageSize,
            string? sortBy = null,
            bool sortDescending = true,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationApiKey, object>>[] includes)
        {
             IQueryable<PlatformApplicationApiKey> query = Query();

             if (predicate != null) query = query.Where(predicate);

             if (includes != null)
             {
                 query = includes.Aggregate(query, (current, include) => current.Include(include));
             }

             var totalCount = await query.CountAsync(cancellationToken);

             if (string.IsNullOrEmpty(sortBy))
             {
                 query = sortDescending ?
                         query.OrderByDescending(k => k.CreatedAt) :
                         query.OrderBy(k => k.CreatedAt);
             }
             // TODO: sortBy 문자열을 기반으로 동적 정렬(Dynamic Linq) 구현 필요

             // ✅ CS1061 오류 최종 수정:
             // 엔티티(k)에 'Status'와 'Environment'가 추가되었으므로 매핑에 포함합니다.
             var items = await query
                 .Skip((pageNumber - 1) * pageSize)
                 .Take(pageSize)
                 .AsNoTracking()
                 .Select(k => new ApplicationApiKeyResponse
                 {
                    Id = k.Id,
                    ApplicationId = k.ApplicationId,
                    KeyName = k.KeyName,
                    KeyHash = k.KeyHash,
                    KeyPrefix = k.KeyPrefix,
                    IsActive = k.IsActive,
                    ExpiresAt = k.ExpiresAt,
                    LastUsedAt = k.LastUsedAt,
                    UseCount = k.UseCount,
                    CreatedAt = k.CreatedAt,
                    KeySource = k.KeySource,
                    PermissionLevel = k.PermissionLevel,
                    Status = k.Status,
                    Environment = k.Environment 
                 })
                 .ToListAsync(cancellationToken);

             return new ApplicationApiKeyListResponse
             {
                 Items = items,
                 TotalCount = totalCount
             };
        }

        #endregion

        #region Helper Methods (CancellationToken 추가)
        
        private async Task<Guid> GetOrganizationIdForApplicationAsync(Guid applicationId, CancellationToken cancellationToken)
        {
             var orgId = await _context.Set<PlatformApplicationEntity>()
                 .Where(a => a.Id == applicationId)
                 .Select(a => a.OrganizationId)
                 .FirstOrDefaultAsync(cancellationToken);

             if(orgId == Guid.Empty)
                 throw new InvalidOperationException($"Organization not found for Application {applicationId}");

             return orgId;
        }

        private async Task InvalidateApiKeyCachesAsync(Guid apiKeyId, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;
            await InvalidateCacheAsync(apiKeyId, cancellationToken);
            _logger.LogDebug("Invalidated caches related to API key {ApiKeyId}", apiKeyId);
        }

        private async Task InvalidateApiKeyCachesAsync(PlatformApplicationApiKey apiKey, CancellationToken cancellationToken)
        {
            if (_cacheService == null || apiKey == null) return;

            var tasks = new List<Task>
            {
                InvalidateCacheAsync(apiKey.Id, cancellationToken)
            };

            if (!string.IsNullOrEmpty(apiKey.KeyHash))
            {
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey($"HashedKey:{apiKey.KeyHash}"), cancellationToken));
            }
            
            tasks.Add(InvalidateApiKeysForApplicationCacheAsync(apiKey.ApplicationId, cancellationToken));

            await Task.WhenAll(tasks);
            _logger.LogDebug("Invalidated caches related to API key {ApiKeyId}", apiKey.Id);
        }

        private async Task InvalidateApiKeysForApplicationCacheAsync(Guid applicationId, CancellationToken cancellationToken)
        {
             if (_cacheService == null) return;
             await _cacheService.RemoveAsync($"ApiKeys:App:{applicationId}", cancellationToken);
             _logger.LogDebug("Invalidated API key list cache for Application {ApplicationId}", applicationId);
        }

        #endregion
    }
}