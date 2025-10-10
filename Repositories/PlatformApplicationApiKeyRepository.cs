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
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 사용

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 API 키 저장소 구현 - AuthHive v16 (최종)
    /// </summary>
    public class PlatformApplicationApiKeyRepository :
        BaseRepository<PlatformApplicationApiKey>,
        IPlatformApplicationApiKeyRepository
    {
        private readonly ILogger<PlatformApplicationApiKeyRepository> _logger;
        // IMemoryCache는 BaseRepository가 ICacheService를 사용하므로 제거되었습니다.

        public PlatformApplicationApiKeyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<PlatformApplicationApiKeyRepository> logger,
            ICacheService cacheService) // ICacheService를 받도록 수정
            : base(context, organizationContext, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region API Key 전용 조회 Operations

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
            if (string.IsNullOrWhiteSpace(hashedKey))
                throw new ArgumentException("Hashed key cannot be empty", nameof(hashedKey));

            return await Query()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.KeyHash == hashedKey && k.IsActive, cancellationToken);
        }

        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByApplicationIdAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(k => k.ApplicationId == applicationId)
                .OrderByDescending(k => k.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        // IPlatformApplicationApiKeyRepository에 추가된 멤버 구현
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByOrganizationIdAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 QueryForOrganization protected 메서드를 사용하여 구현
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Override BaseRepository Methods with Logging and Cancellation

        public override async Task<PlatformApplicationApiKey> AddAsync(
            PlatformApplicationApiKey apiKey,
            CancellationToken cancellationToken = default)
        {
            var result = await base.AddAsync(apiKey, cancellationToken); // CancellationToken 전달
            _logger.LogInformation("Created API key {KeyId} for application {ApplicationId}",
                apiKey.Id, apiKey.ApplicationId);
            return result;
        }

        public override async Task UpdateAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            await base.UpdateAsync(entity, cancellationToken); // CancellationToken 전달
            _logger.LogInformation("Updated API key {KeyId}", entity.Id);
        }

        public override async Task DeleteAsync(
            PlatformApplicationApiKey entity,
            CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(entity, cancellationToken); // CancellationToken 전달
            _logger.LogWarning("Deleted API key {KeyId}", entity.Id);
        }

        #endregion

        #region Validation Operations

        public async Task<bool> ExistsByKeyValueAsync(
            string keyValue,
            CancellationToken cancellationToken = default)
        {
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

        #region Usage & Statistics Operations

        // TODO: [비용 최적화 필요 - 성능 크리티컬] RecordUsageAsync와 IncrementDailyUsageAsync는 
        // 매 요청마다 DB I/O를 발생시키므로, ICacheService의 원자적 Increment/DecrementAsync를 활용하거나, 
        // EF Core/Raw SQL의 배치 업데이트를 통해 DB 부하와 비용을 최적화해야 합니다.
        // 현재는 기존 로직에 CancellationToken만 전달합니다.

        public async Task<bool> RecordUsageAsync(
            Guid id,
            DateTime usedAt,
            CancellationToken cancellationToken = default)
        {
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null) return false;

            apiKey.LastUsedAt = usedAt;
            apiKey.UseCount++; // TotalRequestCount 대신 UseCount를 직접 사용 (엔티티 필드 기반)

            await UpdateAsync(apiKey, cancellationToken);
            return true;
        }

        public async Task<bool> IncrementDailyUsageAsync(
            Guid id,
            int count = 1,
            CancellationToken cancellationToken = default)
        {
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null) return false;

            apiKey.UseCount += count;
            apiKey.LastUsedAt = DateTime.UtcNow;

            await UpdateAsync(apiKey, cancellationToken);
            return true;
        }

        /// <summary>
        /// API 키의 일일 사용량을 리셋합니다 (자정 배치용)
        /// </summary>
        public async Task<bool> ResetDailyUsageAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            // CancellationToken은 BaseRepository의 GetByIdAsync에 전달됩니다.
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null) return false;
            if (apiKey.DailyUseCount > 0)
            {
                // 1. 일일 카운트를 0으로 초기화
                apiKey.DailyUseCount = 0;

                // 2. 리셋 일시 기록
                apiKey.LastDailyResetAt = DateTime.UtcNow;

                // 3. 변경 사항을 DB에 반영하도록 추적 상태 변경 (UpdateAsync 호출)
                await UpdateAsync(apiKey, cancellationToken);
            }

            return true;
        }
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetExpiredKeysAsync(
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Where(k => k.ExpiresAt.HasValue && k.ExpiresAt < now && k.IsActive)
                .ToListAsync(cancellationToken);
        }

        public async Task<int> GetActiveCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(k => k.ApplicationId == applicationId && k.IsActive)
                .CountAsync(cancellationToken);
        }

        #endregion

        #region Bulk Operations

        // TODO: [비용 최적화 필요 - Bulk 삭제] 조회 후 삭제하는 방식은 비효율적입니다. 
        // EF Core의 ExecuteDeleteAsync (Batch Delete)를 사용하도록 리팩토링하여 DB에서 한 번에 처리해야 합니다.

        public async Task<bool> DeleteRangeByIdsAsync(
            IEnumerable<Guid> ids,
            CancellationToken cancellationToken = default)
        {
            var idList = ids.ToList();
            if (!idList.Any()) return false;

            var apiKeys = await Query()
                .Where(k => idList.Contains(k.Id))
                .ToListAsync(cancellationToken);

            if (!apiKeys.Any()) return false;

            // BaseRepository의 DeleteRangeAsync는 Soft Delete 로직을 포함합니다.
            await base.DeleteRangeAsync(apiKeys, cancellationToken);
            _logger.LogWarning("Bulk deleted {Count} API keys by IDs", apiKeys.Count);
            return true;
        }

        public async Task<bool> DeleteByApplicationIdAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var apiKeys = await Query()
                .Where(k => k.ApplicationId == applicationId)
                .ToListAsync(cancellationToken);

            if (!apiKeys.Any()) return false;

            await base.DeleteRangeAsync(apiKeys, cancellationToken);
            _logger.LogWarning("Deleted all API keys for application {ApplicationId}", applicationId);
            return true;
        }

        public async Task<bool> SoftDeleteAsync(
            Guid id,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var apiKey = await GetByIdAsync(id, cancellationToken);
            if (apiKey == null) return false;

            apiKey.DeletedByConnectedId = deletedByConnectedId;

            // BaseRepository의 SoftDeleteAsync를 호출합니다.
            await base.SoftDeleteAsync(id, cancellationToken);
            _logger.LogInformation("Soft deleted API key {KeyId} by connected ID {ConnectedId}",
                id, deletedByConnectedId);
            return true;
        }

        #endregion

        #region Advanced Query Operations

        public async Task<PaginationResponse<PlatformApplicationApiKey>> GetPagedAsync(
            Expression<Func<PlatformApplicationApiKey, bool>>? predicate,
            PaginationRequest pagination,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationApiKey, object>>[] includes)
        {
            // BaseRepository의 GetPagedAsync를 호출하여 로직 재활용
            var (items, totalCount) = await base.GetPagedAsync(
                pagination.PageNumber,
                pagination.PageSize,
                predicate,
                orderBy: null, // BaseRepository에서 Id로 기본 정렬
                isDescending: true,
                cancellationToken: cancellationToken);

            return PaginationResponse<PlatformApplicationApiKey>.Create(
                items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        #endregion

        // SaveChangesAsync는 BaseRepository에 있으므로 여기서는 구현하지 않습니다.
    }
}