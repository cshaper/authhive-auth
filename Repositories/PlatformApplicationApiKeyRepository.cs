using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Caching.Memory; // IMemoryCache 제거
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; 
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 API 키 저장소 구현 - AuthHive v16 (최종)
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class PlatformApplicationApiKeyRepository :
        BaseRepository<PlatformApplicationApiKey>,
        IPlatformApplicationApiKeyRepository
    {
        private readonly ILogger<PlatformApplicationApiKeyRepository> _logger;

        public PlatformApplicationApiKeyRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ILogger<PlatformApplicationApiKeyRepository> logger,
            ICacheService? cacheService = null) // IMemoryCache -> ICacheService?, 생성자 매개변수 순서 변경
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. API 키는 조직 범위에 속함 (true).
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region API Key 전용 조회 Operations (CancellationToken 추가)

        public async Task<PlatformApplicationApiKey?> GetByIdNoTrackingAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            // TODO: 캐싱 추가 고려 (ID 기반 조회)
            return await Query()
                .AsNoTracking()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.Id == id, cancellationToken); // CT 추가
        }

        public async Task<PlatformApplicationApiKey?> GetByKeyValueAsync(
            string keyValue,
            CancellationToken cancellationToken = default)
        {
            // API Key 값 자체는 민감 정보일 수 있으므로 직접 캐싱하지 않는 것이 좋음
            if (string.IsNullOrWhiteSpace(keyValue))
                throw new ArgumentException("Key value cannot be empty", nameof(keyValue));

            // Query() 사용 (IsDeleted=false 포함)
            return await Query()
                .Include(k => k.PlatformApplication)
                 // IsActive 조건 추가 (활성 키만 유효)
                .FirstOrDefaultAsync(k => k.ApiKey == keyValue && k.IsActive, cancellationToken); // CT 추가
        }

        public async Task<PlatformApplicationApiKey?> GetByHashedKeyAsync(
            string hashedKey,
            CancellationToken cancellationToken = default)
        {
            // 해시값 기반 캐싱은 가능
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
                 // IsActive 조건 추가
                .FirstOrDefaultAsync(k => k.KeyHash == hashedKey && k.IsActive, cancellationToken); // CT 추가

            if (apiKey != null && _cacheService != null)
            {
                 // 키 만료 시간 고려하여 TTL 설정
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
            // TODO: 캐싱 추가 고려 (애플리케이션별 키 목록)
            return await Query()
                .Where(k => k.ApplicationId == applicationId)
                .OrderByDescending(k => k.CreatedAt)
                .AsNoTracking() // 읽기 전용 목록 조회
                .ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByOrganizationIdAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 캐싱 추가 고려 (조직별 키 목록)
            return await QueryForOrganization(organizationId)
                .Include(k => k.PlatformApplication) // 앱 정보 포함
                .OrderBy(k => k.ApplicationId).ThenByDescending(k => k.CreatedAt) // 정렬 추가
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region Override BaseRepository Methods with Logging and Cancellation (CancellationToken 추가)

        public override async Task<PlatformApplicationApiKey> AddAsync(
            PlatformApplicationApiKey apiKey,
            CancellationToken cancellationToken = default)
        {
            // apiKey.Id = apiKey.Id == Guid.Empty ? Guid.NewGuid() : apiKey.Id; // BaseEntity 처리
            // apiKey.CreatedAt = DateTime.UtcNow; // Interceptor 처리
            // OrganizationId 설정 (BaseRepository AddAsync는 처리 안 함)
            if (apiKey.OrganizationId == Guid.Empty && apiKey.ApplicationId != Guid.Empty)
            {
                 apiKey.OrganizationId = await GetOrganizationIdForApplicationAsync(apiKey.ApplicationId, cancellationToken);
            }

            var result = await base.AddAsync(apiKey, cancellationToken);
            _logger.LogInformation("Created API key {KeyId} for application {ApplicationId}",
                result.Id, result.ApplicationId);
            // 캐시 무효화 (BaseRepository.AddAsync는 캐시 무효화 안 함)
            await InvalidateApiKeyCachesAsync(result, cancellationToken);
            return result;
        }

        public override async Task UpdateAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            // entity.UpdatedAt = DateTime.UtcNow; // Interceptor 처리
            await base.UpdateAsync(entity, cancellationToken); // BaseRepository.UpdateAsync 호출 (ID 기반 캐시 무효화 포함)
             // 추가 캐시 무효화
            await InvalidateApiKeyCachesAsync(entity, cancellationToken);
            _logger.LogInformation("Updated API key {KeyId}", entity.Id);
        }

        public override async Task DeleteAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            // entity.IsDeleted = true; // BaseRepository.DeleteAsync 처리
            // entity.DeletedAt = DateTime.UtcNow; // BaseRepository.DeleteAsync 처리
            await base.DeleteAsync(entity, cancellationToken); // BaseRepository.DeleteAsync 호출 (ID 기반 캐시 무효화 포함)
            // 추가 캐시 무효화
            await InvalidateApiKeyCachesAsync(entity, cancellationToken);
            _logger.LogWarning("Soft Deleted API key {KeyId}", entity.Id);
        }

        #endregion

        #region Validation Operations (CancellationToken 추가)

        public async Task<bool> ExistsByKeyValueAsync(
            string keyValue,
            CancellationToken cancellationToken = default)
        {
            // 키 값 자체로 직접 쿼리하는 것은 보안상 좋지 않을 수 있음 (해시값 비교 권장)
            _logger.LogWarning("Checking existence by raw API key value. Consider using hashed key check instead.");
            return !string.IsNullOrWhiteSpace(keyValue) &&
                   await Query().AnyAsync(k => k.ApiKey == keyValue, cancellationToken); // CT 추가
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

            return await query.AnyAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region Usage & Statistics Operations (CancellationToken 추가)

        // TODO:[성능] RecordUsageAsync/IncrementDailyUsageAsync는 ICacheService 원자적 연산 또는 DB 배치 업데이트로 변경 필요

        public async Task<bool> RecordUsageAsync(
            Guid id,
            DateTime usedAt,
            CancellationToken cancellationToken = default)
        {
             // GetByIdAsync는 캐시를 먼저 확인
            var apiKey = await GetByIdAsync(id, cancellationToken); // CT 추가
            if (apiKey == null || !apiKey.IsActive) return false; // 비활성 키 사용 기록 안 함

            // ExecuteUpdateAsync (EF Core 7+) 사용 고려
            int affected = await Query()
                .Where(k => k.Id == id)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.LastUsedAt, usedAt)
                    .SetProperty(k => k.UseCount, k => k.UseCount + 1), // UseCount 증가
                    cancellationToken); // CT 추가

            if(affected > 0)
            {
                 // 캐시 업데이트 또는 무효화
                 await InvalidateApiKeyCachesAsync(id, cancellationToken); // CT 추가
                 return true;
            }
            return false;
        }

        public async Task<bool> IncrementDailyUsageAsync(
            Guid id,
            int count = 1,
            CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 캐시를 먼저 확인
            var apiKey = await GetByIdAsync(id, cancellationToken); // CT 추가
            if (apiKey == null || !apiKey.IsActive) return false;

            // ExecuteUpdateAsync 사용 고려
             int affected = await Query()
                 .Where(k => k.Id == id)
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(k => k.DailyUseCount, k => k.DailyUseCount + count) // DailyUseCount 증가
                     .SetProperty(k => k.LastUsedAt, DateTime.UtcNow),
                     cancellationToken); // CT 추가

            if(affected > 0)
            {
                await InvalidateApiKeyCachesAsync(id, cancellationToken); // CT 추가
                return true;
            }
            return false;
        }

        public async Task<bool> ResetDailyUsageAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
             int affected = await Query()
                 .Where(k => k.Id == id && k.DailyUseCount > 0) // 리셋할 필요가 있는 키만 대상
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(k => k.DailyUseCount, 0)
                     .SetProperty(k => k.LastDailyResetAt, DateTime.UtcNow),
                     cancellationToken); // CT 추가

            if(affected > 0)
            {
                await InvalidateApiKeyCachesAsync(id, cancellationToken); // CT 추가
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
                .Where(k => k.ExpiresAt.HasValue && k.ExpiresAt < now && k.IsActive) // 활성 키 중에서 만료된 것
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<int> GetActiveCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository.CountAsync 사용
            return await CountAsync(k => k.ApplicationId == applicationId && k.IsActive, cancellationToken); // CT 추가
        }

        #endregion

        #region Bulk Operations (CancellationToken 추가)

        // TODO:[성능] Bulk 삭제는 ExecuteDeleteAsync 사용 권장

        public async Task<bool> DeleteRangeByIdsAsync(
            IEnumerable<Guid> ids,
            CancellationToken cancellationToken = default)
        {
            var idList = ids?.ToList();
            if (idList == null || !idList.Any()) return false;

            // Soft Delete를 위해 엔티티 로드 (비효율적)
            // var apiKeys = await Query().Where(k => idList.Contains(k.Id)).ToListAsync(cancellationToken);
            // if (!apiKeys.Any()) return false;
            // await base.DeleteRangeAsync(apiKeys, cancellationToken);

            // ExecuteUpdateAsync를 이용한 Soft Delete (더 효율적)
            int deletedCount = await Query()
                .Where(k => idList.Contains(k.Id) && !k.IsDeleted) // 아직 삭제되지 않은 키만 대상
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.IsDeleted, true)
                    .SetProperty(k => k.DeletedAt, DateTime.UtcNow)
                    // .SetProperty(k => k.DeletedByConnectedId, ...) // 삭제 주체 필요 시
                    , cancellationToken);

            if (deletedCount > 0)
            {
                 // 관련 캐시 무효화 (개별 ID 또는 조직/앱 단위)
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
             // ExecuteUpdateAsync를 이용한 Soft Delete
            int deletedCount = await Query()
                .Where(k => k.ApplicationId == applicationId && !k.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(k => k.IsDeleted, true)
                    .SetProperty(k => k.DeletedAt, DateTime.UtcNow)
                    // .SetProperty(k => k.DeletedByConnectedId, ...)
                    , cancellationToken);

            if (deletedCount > 0)
            {
                // 관련 캐시 무효화 (애플리케이션 ID 기반 등)
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
             // ExecuteUpdateAsync 사용
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

        public async Task<PaginationResponse<PlatformApplicationApiKey>> GetPagedAsync(
            Expression<Func<PlatformApplicationApiKey, bool>>? predicate,
            PaginationRequest pagination,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationApiKey, object>>[] includes) // includes 매개변수 추가
        {
             // BaseRepository의 GetPagedAsync 활용 + Include 적용
             IQueryable<PlatformApplicationApiKey> query = Query();

             if (predicate != null) query = query.Where(predicate);

             // Include 적용
             if (includes != null)
             {
                 query = includes.Aggregate(query, (current, include) => current.Include(include));
             }

             var totalCount = await query.CountAsync(cancellationToken);

             var items = await query
                 .OrderByDescending(k => k.CreatedAt) // 정렬 조건 명시
                 .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                 .Take(pagination.PageSize)
                 .AsNoTracking()
                 .ToListAsync(cancellationToken);

            return PaginationResponse<PlatformApplicationApiKey>.Create(
                items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        #endregion

        #region Helper Methods (CancellationToken 추가)

        // 애플리케이션 ID로부터 조직 ID를 조회하는 헬퍼
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

        // API 키 관련 캐시 무효화 (ID 기반)
        private async Task InvalidateApiKeyCachesAsync(Guid apiKeyId, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;
            // ID 기반 캐시 (BaseRepository Update/Delete에서 처리될 수 있음)
            await InvalidateCacheAsync(apiKeyId, cancellationToken);

            // 해시값 기반 캐시 등 추가 캐시 키 무효화 (해시값을 알아야 함 - GetById 필요)
            // var apiKey = await GetByIdAsync(apiKeyId, cancellationToken); // 캐시 무효화를 위해 DB 조회 발생 가능성
            // if(apiKey != null && !string.IsNullOrEmpty(apiKey.KeyHash)) {
            //     await _cacheService.RemoveAsync(GetCacheKey($"HashedKey:{apiKey.KeyHash}"), cancellationToken);
            // }
            _logger.LogDebug("Invalidated caches related to API key {ApiKeyId}", apiKeyId);

        }
         // API 키 관련 캐시 무효화 (엔티티 기반)
        private async Task InvalidateApiKeyCachesAsync(PlatformApplicationApiKey apiKey, CancellationToken cancellationToken)
        {
            if (_cacheService == null || apiKey == null) return;

            var tasks = new List<Task>
            {
                // ID 기반 캐시
                InvalidateCacheAsync(apiKey.Id, cancellationToken)
            };

            // 해시값 기반 캐시
            if (!string.IsNullOrEmpty(apiKey.KeyHash))
            {
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey($"HashedKey:{apiKey.KeyHash}"), cancellationToken));
            }

            // 애플리케이션별 목록 캐시
            tasks.Add(InvalidateApiKeysForApplicationCacheAsync(apiKey.ApplicationId, cancellationToken));

            await Task.WhenAll(tasks);
            _logger.LogDebug("Invalidated caches related to API key {ApiKeyId}", apiKey.Id);
        }

        // 애플리케이션별 API 키 목록 캐시 무효화
        private async Task InvalidateApiKeysForApplicationCacheAsync(Guid applicationId, CancellationToken cancellationToken)
        {
             if (_cacheService == null) return;
             // 애플리케이션별 키 목록 캐시 키 정의 필요 (예: "ApiKeys:App:{appId}")
             await _cacheService.RemoveAsync($"ApiKeys:App:{applicationId}", cancellationToken);
             _logger.LogDebug("Invalidated API key list cache for Application {ApplicationId}", applicationId);
        }

        #endregion
    }
}