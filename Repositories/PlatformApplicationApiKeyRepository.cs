using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 API 키 저장소 구현 - AuthHive v15
    /// </summary>
    public class PlatformApplicationApiKeyRepository : OrganizationScopedRepository<PlatformApplicationApiKey>, IPlatformApplicationApiKeyRepository
    {
        private readonly ILogger<PlatformApplicationApiKeyRepository> _logger;

        public PlatformApplicationApiKeyRepository(
            AuthDbContext context,
            ILogger<PlatformApplicationApiKeyRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region Basic CRUD Operations

        /// <summary>ID로 API 키를 조회 (관련 애플리케이션 정보 포함)</summary>
        public new async Task<PlatformApplicationApiKey?> GetByIdAsync(Guid id)
        {
            return await Query().Include(k => k.PlatformApplication).FirstOrDefaultAsync(k => k.Id == id);
        }

        /// <summary>ID로 API 키를 조회 (추적 없음, 대량 데이터 조회 시 성능 최적화용)</summary>
        public async Task<PlatformApplicationApiKey?> GetByIdNoTrackingAsync(Guid id)
        {
            return await Query().AsNoTracking().Include(k => k.PlatformApplication).FirstOrDefaultAsync(k => k.Id == id);
        }

        /// <summary>키 값으로 API 키 조회 (클라이언트 인증 시 사용)</summary>
        public async Task<PlatformApplicationApiKey?> GetByKeyValueAsync(string keyValue)
        {
            if (string.IsNullOrWhiteSpace(keyValue))
                throw new ArgumentException("Key value cannot be empty", nameof(keyValue));

            return await Query().Include(k => k.PlatformApplication).FirstOrDefaultAsync(k => k.ApiKey == keyValue && k.IsActive);
        }

        /// <summary>해시값으로 API 키 조회 (보안 강화된 인증 시 사용)</summary>
        public async Task<PlatformApplicationApiKey?> GetByHashedKeyAsync(string hashedKey)
        {
            if (string.IsNullOrWhiteSpace(hashedKey))
                throw new ArgumentException("Hashed key cannot be empty", nameof(hashedKey));

            return await Query().Include(k => k.PlatformApplication).FirstOrDefaultAsync(k => k.KeyHash == hashedKey && k.IsActive);
        }

        /// <summary>애플리케이션별 모든 API 키 조회 (관리 대시보드용)</summary>
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetByApplicationIdAsync(Guid applicationId)
        {
            return await Query().Where(k => k.ApplicationId == applicationId).OrderByDescending(k => k.CreatedAt).ToListAsync();
        }

        /// <summary>API 키 생성 (관리자가 새로운 API 키 발급 시 사용)</summary>
        public new async Task<PlatformApplicationApiKey> AddAsync(PlatformApplicationApiKey apiKey)
        {
            var entry = await _context.PlatformApplicationApiKeys.AddAsync(apiKey);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created API key {KeyId} for application {ApplicationId}", apiKey.Id, apiKey.ApplicationId);
            return entry.Entity;
        }

        /// <summary>API 키 수정 (키 이름, 권한, 설정 변경 시 사용)</summary>
        public new async Task<PlatformApplicationApiKey> UpdateAsync(PlatformApplicationApiKey apiKey)
        {
            apiKey.UpdatedAt = DateTime.UtcNow;
            var entry = _context.PlatformApplicationApiKeys.Update(apiKey);
            await _context.SaveChangesAsync();
            return entry.Entity;
        }

        /// <summary>API 키 완전 삭제 (데이터베이스에서 물리적 삭제)</summary>
        public new async Task<bool> DeleteAsync(Guid id)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            _context.PlatformApplicationApiKeys.Remove(apiKey);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>API 키 소프트 삭제 (감사 로그 유지하면서 비활성화)</summary>
        public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            apiKey.IsDeleted = true;
            apiKey.DeletedAt = DateTime.UtcNow;
            apiKey.DeletedByConnectedId = deletedByConnectedId;
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion

        #region Advanced Query Operations

        /// <summary>조건에 따른 API 키 검색</summary>
        public new async Task<IEnumerable<PlatformApplicationApiKey>> FindAsync(Expression<Func<PlatformApplicationApiKey, bool>> predicate)
        {
            return await Query().Where(predicate).Include(k => k.PlatformApplication).ToListAsync();
        }

        /// <summary>페이징된 API 키 목록 조회 (관리자 페이지용)</summary>
        public async Task<PaginationResponse<PlatformApplicationApiKey>> GetPagedAsync(
            Expression<Func<PlatformApplicationApiKey, bool>>? predicate,
            PaginationRequest pagination,
            params Expression<Func<PlatformApplicationApiKey, object>>[] includes)
        {
            var query = Query();
            if (predicate != null) query = query.Where(predicate);
            foreach (var include in includes) query = query.Include(include);

            var totalCount = await query.CountAsync();
            var items = await query.OrderByDescending(k => k.CreatedAt)
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize).ToListAsync();

            return PaginationResponse<PlatformApplicationApiKey>.Create(items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        /// <summary>조직별 모든 API 키 조회</summary>
        public new async Task<IEnumerable<PlatformApplicationApiKey>> GetByOrganizationIdAsync(Guid organizationId)
        {
            return await Query().Where(k => k.OrganizationId == organizationId).Include(k => k.PlatformApplication).ToListAsync();
        }

        /// <summary>쿼리 가능한 컬렉션 반환</summary>
        public new IQueryable<PlatformApplicationApiKey> GetQueryable() => Query();

        #endregion

        #region Existence & Validation Operations

        /// <summary>API 키 존재 여부 확인</summary>
        public new async Task<bool> ExistsAsync(Guid id) => await Query().AnyAsync(k => k.Id == id);

        /// <summary>키 값 중복 확인</summary>
        public async Task<bool> ExistsByKeyValueAsync(string keyValue) => 
            !string.IsNullOrWhiteSpace(keyValue) && await Query().AnyAsync(k => k.ApiKey == keyValue);

        /// <summary>키 이름 중복 확인 (같은 애플리케이션 내에서)</summary>
        public async Task<bool> IsDuplicateNameAsync(Guid applicationId, string name, Guid? excludeId = null)
        {
            if (string.IsNullOrWhiteSpace(name)) return false;
            var query = Query().Where(k => k.ApplicationId == applicationId && k.KeyName == name);
            if (excludeId.HasValue) query = query.Where(k => k.Id != excludeId.Value);
            return await query.AnyAsync();
        }

        #endregion

        #region Usage & Statistics Operations

        /// <summary>API 키 사용량 기록 (매 요청마다 호출)</summary>
        public async Task<bool> RecordUsageAsync(Guid id, DateTime usedAt)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            apiKey.LastUsedAt = usedAt;
            apiKey.TotalRequestCount++;
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>일일 사용량 증가 (배치 처리용)</summary>
        public async Task<bool> IncrementDailyUsageAsync(Guid id, int count = 1)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;

            apiKey.TotalRequestCount += count;
            apiKey.LastUsedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>일일 사용량 리셋 (자정 배치용)</summary>
        public async Task<bool> ResetDailyUsageAsync(Guid id)
        {
            var apiKey = await GetByIdAsync(id);
            if (apiKey == null) return false;
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>만료된 API 키 조회 (정리 작업용)</summary>
        public async Task<IEnumerable<PlatformApplicationApiKey>> GetExpiredKeysAsync()
        {
            var now = DateTime.UtcNow;
            return await Query().Where(k => k.ExpiresAt.HasValue && k.ExpiresAt < now && k.IsActive).ToListAsync();
        }

        /// <summary>애플리케이션의 활성 키 개수 조회</summary>
        public async Task<int> GetActiveCountByApplicationAsync(Guid applicationId)
        {
            return await Query().Where(k => k.ApplicationId == applicationId && k.IsActive).CountAsync();
        }

        #endregion

        #region Bulk Operations

        /// <summary>여러 API 키 일괄 생성</summary>
        public new async Task<IEnumerable<PlatformApplicationApiKey>> AddRangeAsync(IEnumerable<PlatformApplicationApiKey> apiKeys)
        {
            var keyList = apiKeys.ToList();
            if (!keyList.Any()) return keyList;

            await _context.PlatformApplicationApiKeys.AddRangeAsync(keyList);
            await _context.SaveChangesAsync();
            return keyList;
        }

        /// <summary>여러 API 키 일괄 수정</summary>
        public new async Task<IEnumerable<PlatformApplicationApiKey>> UpdateRangeAsync(IEnumerable<PlatformApplicationApiKey> apiKeys)
        {
            var keyList = apiKeys.ToList();
            if (!keyList.Any()) return keyList;

            var now = DateTime.UtcNow;
            keyList.ForEach(k => k.UpdatedAt = now);
            _context.PlatformApplicationApiKeys.UpdateRange(keyList);
            await _context.SaveChangesAsync();
            return keyList;
        }

        /// <summary>여러 API 키 일괄 삭제</summary>
        public async Task<bool> DeleteRangeAsync(IEnumerable<Guid> ids)
        {
            var apiKeys = await Query().Where(k => ids.Contains(k.Id)).ToListAsync();
            if (!apiKeys.Any()) return false;

            _context.PlatformApplicationApiKeys.RemoveRange(apiKeys);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>애플리케이션의 모든 API 키 삭제</summary>
        public async Task<bool> DeleteByApplicationIdAsync(Guid applicationId)
        {
            var apiKeys = await Query().Where(k => k.ApplicationId == applicationId).ToListAsync();
            if (!apiKeys.Any()) return false;

            _context.PlatformApplicationApiKeys.RemoveRange(apiKeys);
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion

        #region Unit of Work

        /// <summary>변경사항 저장</summary>
        public new async Task<int> SaveChangesAsync() => await _context.SaveChangesAsync();

        #endregion

        #region Helper Methods

        /// <summary>기본 쿼리 (소프트 삭제된 항목 제외)</summary>
        private new IQueryable<PlatformApplicationApiKey> Query() => _context.PlatformApplicationApiKeys.Where(k => !k.IsDeleted);

        #endregion
    }
}