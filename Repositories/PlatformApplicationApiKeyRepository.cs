using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 API 키 저장소 구현 - AuthHive v15
    /// BaseRepository를 상속받아 API 키 전용 기능만 구현
    /// </summary>
    public class PlatformApplicationApiKeyRepository : 
        BaseRepository<PlatformApplicationApiKey>, 
        IPlatformApplicationApiKeyRepository
    {
        private readonly ILogger<PlatformApplicationApiKeyRepository> _logger;

        public PlatformApplicationApiKeyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<PlatformApplicationApiKeyRepository> logger,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region API Key 전용 조회 Operations

        /// <summary>
        /// ID로 API 키를 조회 (추적 없음, 대량 데이터 조회 시 성능 최적화용)
        /// </summary>
        public async Task<PlatformApplicationApiKey?> GetByIdNoTrackingAsync(Guid id)
        {
            return await Query()
                .AsNoTracking()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.Id == id);
        }

        /// <summary>
        /// 키 값으로 API 키 조회 (클라이언트 인증 시 사용)
        /// </summary>
        public async Task<PlatformApplicationApiKey?> GetByKeyValueAsync(string keyValue)
        {
            if (string.IsNullOrWhiteSpace(keyValue))
                throw new ArgumentException("Key value cannot be empty", nameof(keyValue));

            return await Query()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.ApiKey == keyValue && k.IsActive);
        }

        /// <summary>
        /// 해시값으로 API 키 조회 (보안 강화된 인증 시 사용)
        /// </summary>
        public async Task<PlatformApplicationApiKey?> GetByHashedKeyAsync(string hashedKey)
        {
            if (string.IsNullOrWhiteSpace(hashedKey))
                throw new ArgumentException("Hashed key cannot be empty", nameof(hashedKey));

            return await Query()
                .Include(k => k.PlatformApplication)
                .FirstOrDefaultAsync(k => k.KeyHash == hashedKey && k.IsActive);
        }

        /// <summary>
        /// 애플리케이션별 모든 API 키 조회 (관리 대시보드용)
        /// </summary>
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByApplicationIdAsync(Guid applicationId)
        {
            return await Query()
                .Where(k => k.ApplicationId == applicationId)
                .OrderByDescending(k => k.CreatedAt)
                .ToListAsync();
        }

        #endregion

        #region Override BaseRepository Methods with Logging

        /// <summary>
        /// API 키 생성 - 로깅 추가
        /// </summary>
        public override async Task<PlatformApplicationApiKey> AddAsync(PlatformApplicationApiKey apiKey)
        {
            var result = await base.AddAsync(apiKey);
            _logger.LogInformation("Created API key {KeyId} for application {ApplicationId}", 
                apiKey.Id, apiKey.ApplicationId);
            return result;
        }

        /// <summary>
        /// API 키 수정 - 로깅 추가
        /// </summary>
        public override async Task UpdateAsync(PlatformApplicationApiKey entity)
        {
            await base.UpdateAsync(entity);
            _logger.LogInformation("Updated API key {KeyId}", entity.Id);
        }

        /// <summary>
        /// API 키 삭제 - 로깅 추가
        /// </summary>
        public override async Task DeleteAsync(PlatformApplicationApiKey entity)
        {
            await base.DeleteAsync(entity);
            _logger.LogWarning("Deleted API key {KeyId}", entity.Id);
        }

        #endregion

        #region Validation Operations

        /// <summary>
        /// 키 값 중복 확인
        /// </summary>
        public async Task<bool> ExistsByKeyValueAsync(string keyValue)
        {
            return !string.IsNullOrWhiteSpace(keyValue) && 
                   await Query().AnyAsync(k => k.ApiKey == keyValue);
        }

        /// <summary>
        /// 키 이름 중복 확인 (같은 애플리케이션 내에서)
        /// </summary>
        public async Task<bool> IsDuplicateNameAsync(Guid applicationId, string name, Guid? excludeId = null)
        {
            if (string.IsNullOrWhiteSpace(name)) 
                return false;

            var query = Query().Where(k => k.ApplicationId == applicationId && k.KeyName == name);
            
            if (excludeId.HasValue) 
                query = query.Where(k => k.Id != excludeId.Value);
            
            return await query.AnyAsync();
        }

        #endregion

        #region Usage & Statistics Operations

        /// <summary>
        /// API 키 사용량 기록 (매 요청마다 호출)
        /// </summary>
        public async Task<bool> RecordUsageAsync(Guid id, DateTime usedAt)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            apiKey.LastUsedAt = usedAt;
            apiKey.TotalRequestCount++;
            
            await UpdateAsync(apiKey);
            return true;
        }

        /// <summary>
        /// 일일 사용량 증가 (배치 처리용)
        /// </summary>
        public async Task<bool> IncrementDailyUsageAsync(Guid id, int count = 1)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            apiKey.TotalRequestCount += count;
            apiKey.LastUsedAt = DateTime.UtcNow;
            
            await UpdateAsync(apiKey);
            return true;
        }

        /// <summary>
        /// 일일 사용량 리셋 (자정 배치용)
        /// </summary>
        public async Task<bool> ResetDailyUsageAsync(Guid id)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;
            
            // 필요한 리셋 로직 추가
            await UpdateAsync(apiKey);
            return true;
        }

        /// <summary>
        /// 만료된 API 키 조회 (정리 작업용)
        /// </summary>
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetExpiredKeysAsync()
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Where(k => k.ExpiresAt.HasValue && k.ExpiresAt < now && k.IsActive)
                .ToListAsync();
        }

        /// <summary>
        /// 애플리케이션의 활성 키 개수 조회
        /// </summary>
        public async Task<int> GetActiveCountByApplicationAsync(Guid applicationId)
        {
            return await Query()
                .Where(k => k.ApplicationId == applicationId && k.IsActive)
                .CountAsync();
        }

        #endregion

        #region Bulk Operations

        /// <summary>
        /// 여러 API 키 일괄 삭제
        /// </summary>
        public async Task<bool> DeleteRangeAsync(IEnumerable<Guid> ids)
        {
            var idList = ids.ToList();
            if (!idList.Any()) return false;

            var apiKeys = await Query()
                .Where(k => idList.Contains(k.Id))
                .ToListAsync();
            
            if (!apiKeys.Any()) return false;

            // BaseRepository의 DeleteRangeAsync 사용
            await base.DeleteRangeAsync(apiKeys);
            _logger.LogWarning("Bulk deleted {Count} API keys", apiKeys.Count);
            return true;
        }

        /// <summary>
        /// 애플리케이션의 모든 API 키 삭제
        /// </summary>
        public async Task<bool> DeleteByApplicationIdAsync(Guid applicationId)
        {
            var apiKeys = await Query()
                .Where(k => k.ApplicationId == applicationId)
                .ToListAsync();
            
            if (!apiKeys.Any()) return false;

            await base.DeleteRangeAsync(apiKeys);
            _logger.LogWarning("Deleted all API keys for application {ApplicationId}", applicationId);
            return true;
        }

        /// <summary>
        /// API 키 소프트 삭제 (감사 정보 포함)
        /// </summary>
        public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            // 감사 정보 추가
            apiKey.DeletedByConnectedId = deletedByConnectedId;
            
            await base.SoftDeleteAsync(id);
            _logger.LogInformation("Soft deleted API key {KeyId} by connected ID {ConnectedId}", 
                id, deletedByConnectedId);
            return true;
        }

        #endregion

        #region Advanced Query Operations

        /// <summary>
        /// 페이징된 API 키 목록 조회 (관리자 페이지용)
        /// </summary>
        public async Task<PaginationResponse<PlatformApplicationApiKey>> GetPagedAsync(
            Expression<Func<PlatformApplicationApiKey, bool>>? predicate,
            PaginationRequest pagination,
            params Expression<Func<PlatformApplicationApiKey, object>>[] includes)
        {
            var query = Query();
            
            if (predicate != null) 
                query = query.Where(predicate);
            
            foreach (var include in includes) 
                query = query.Include(include);

            var totalCount = await query.CountAsync();
            
            var items = await query
                .OrderByDescending(k => k.CreatedAt)
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize)
                .ToListAsync();

            return PaginationResponse<PlatformApplicationApiKey>.Create(
                items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        #endregion

        #region Unit of Work

        /// <summary>
        /// 변경사항 저장
        /// </summary>
        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }

        #endregion
    }
}