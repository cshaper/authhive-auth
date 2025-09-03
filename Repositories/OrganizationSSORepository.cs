using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 SSO 설정 Repository 구현체 - AuthHive v15
    /// SSO 설정 관리, 검증, 우선순위 처리 등 SSO 관련 모든 데이터 접근을 담당합니다.
    /// </summary>
    public class OrganizationSSORepository : BaseRepository<OrganizationSSO>, IOrganizationSSORepository
    {
        public OrganizationSSORepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        #region SSO 고유 조회

        /// <summary>
        /// 조직의 기본 SSO 설정 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <returns>기본 SSO 설정</returns>
        public async Task<OrganizationSSO?> GetDefaultByOrganizationAsync(Guid organizationId)
        {
            // 캐시 확인
            var cacheKey = $"OrgSSO:Default:{organizationId}";
            if (_cache?.TryGetValue(cacheKey, out OrganizationSSO? cached) == true)
            {
                return cached;
            }

            var result = await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .FirstOrDefaultAsync(s => s.IsDefault && s.IsActive);

            // 캐시 저장
            if (result != null && _cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        /// <summary>
        /// SSO 타입별 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="ssoType">SSO 타입</param>
        /// <param name="includeInactive">비활성 포함 여부</param>
        /// <returns>SSO 설정 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetByTypeAsync(
            Guid organizationId,
            OSType ssoType,
            bool includeInactive = false)
        {
            var query = QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.SSOType == ssoType);

            if (!includeInactive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 제공자별 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="provider">SSO 제공자</param>
        /// <returns>SSO 설정 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetByProviderAsync(
            Guid organizationId,
            SSOProvider provider)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.ProviderName == provider && s.IsActive)
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 활성 상태 관리

        /// <summary>
        /// 활성 SSO 설정 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <returns>활성 SSO 설정 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetActiveByOrganizationAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.IsActive)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.CreatedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 우선순위 순으로 정렬된 SSO 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="onlyActive">활성만 조회</param>
        /// <returns>우선순위 정렬된 SSO 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetByPriorityAsync(
            Guid organizationId,
            bool onlyActive = true)
        {
            var query = QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .AsQueryable();  // 명시적 변환

            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .ThenByDescending(s => s.IsDefault)
                .ThenBy(s => s.CreatedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 검증 및 테스트

        /// <summary>
        /// 테스트가 필요한 SSO 설정 조회
        /// </summary>
        /// <param name="daysSinceLastTest">마지막 테스트 이후 일수</param>
        /// <returns>테스트 필요 SSO 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetRequiringTestAsync(int daysSinceLastTest = 30)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysSinceLastTest);

            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive && 
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || s.LastTestedAt < cutoffDate))
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
                .ThenBy(s => s.OrganizationId)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 테스트 실패한 SSO 설정 조회
        /// </summary>
        /// <param name="organizationId">조직 ID (null이면 전체)</param>
        /// <returns>테스트 실패 SSO 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetFailedTestsAsync(Guid? organizationId = null)
        {
            // Note: 실제 구현에서는 테스트 결과를 별도 테이블에 저장하고 조인해야 합니다.
            // 현재는 60일 이상 테스트되지 않은 항목을 반환하는 임시 로직입니다.
            var cutoffDate = DateTime.UtcNow.AddDays(-60);
            
            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive && 
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || s.LastTestedAt < cutoffDate));

            if (organizationId.HasValue)
            {
                query = query.Where(s => s.OrganizationId == organizationId.Value);
            }

            return await query
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 기본 설정 관리

        /// <summary>
        /// 조직의 다른 SSO를 기본이 아닌 것으로 설정
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="excludeSsoId">제외할 SSO ID</param>
        /// <returns>업데이트된 개수</returns>
        public async Task<int> UnsetDefaultExceptAsync(Guid organizationId, Guid excludeSsoId)
        {
            // 캐시 무효화
            if (_cache != null)
            {
                _cache.Remove($"OrgSSO:Default:{organizationId}");
            }

            var ssoToUpdate = await _dbSet
                .Where(s => s.OrganizationId == organizationId && 
                           s.Id != excludeSsoId && 
                           s.IsDefault && 
                           !s.IsDeleted)
                .ToListAsync();

            if (ssoToUpdate.Count == 0)
            {
                return 0;
            }

            foreach (var sso in ssoToUpdate)
            {
                sso.IsDefault = false;
                sso.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            return ssoToUpdate.Count;
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// SSO 타입별 사용 통계
        /// </summary>
        /// <returns>타입별 카운트</returns>
        public async Task<Dictionary<OSType, int>> GetTypeStatisticsAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.SSOType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Type, s => s.Count);
        }

        /// <summary>
        /// 조직별 SSO 타입별 사용 통계
        /// </summary>
        /// <param name="organizationId">특정 조직 ID</param>
        /// <returns>타입별 카운트</returns>
        public async Task<Dictionary<OSType, int>> GetTypeStatisticsByOrganizationAsync(Guid organizationId)
        {
            var statistics = await _dbSet
                .Where(s => s.OrganizationId == organizationId && s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.SSOType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Type, s => s.Count);
        }

        /// <summary>
        /// 제공자별 사용 통계
        /// </summary>
        /// <returns>제공자별 카운트</returns>
        public async Task<Dictionary<SSOProvider, int>> GetProviderStatisticsAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.ProviderName)
                .Select(g => new { Provider = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Provider, s => s.Count);
        }

        /// <summary>
        /// 조직별 제공자별 사용 통계
        /// </summary>
        /// <param name="organizationId">특정 조직 ID</param>
        /// <returns>제공자별 카운트</returns>
        public async Task<Dictionary<SSOProvider, int>> GetProviderStatisticsByOrganizationAsync(Guid organizationId)
        {
            var statistics = await _dbSet
                .Where(s => s.OrganizationId == organizationId && s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.ProviderName)
                .Select(g => new { Provider = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Provider, s => s.Count);
        }

        #endregion

        #region 추가 유틸리티 메서드

        /// <summary>
        /// SSO 테스트 상태 업데이트
        /// </summary>
        /// <param name="ssoId">SSO ID</param>
        /// <param name="testedByConnectedId">테스트 실행자 ConnectedId</param>
        /// <param name="testedAt">테스트 시간 (null이면 현재 시간)</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> UpdateTestStatusAsync(
            Guid ssoId, 
            Guid testedByConnectedId, 
            DateTime? testedAt = null)
        {
            var sso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted);
            if (sso == null)
                return false;

            sso.LastTestedAt = testedAt ?? DateTime.UtcNow;
            sso.LastTestedByConnectedId = testedByConnectedId;
            sso.UpdatedAt = DateTime.UtcNow;
            sso.UpdatedByConnectedId = testedByConnectedId;

            try
            {
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 기본 SSO 설정 변경
        /// </summary>
        /// <param name="ssoId">새로운 기본 SSO ID</param>
        /// <param name="updatedByConnectedId">업데이트 실행자 ConnectedId</param>
        /// <returns>변경 성공 여부</returns>
        public async Task<bool> SetAsDefaultAsync(Guid ssoId, Guid updatedByConnectedId)
        {
            var newDefaultSso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted);
            if (newDefaultSso == null)
                return false;

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // 기존 기본 설정들을 해제
                await UnsetDefaultExceptAsync(newDefaultSso.OrganizationId, ssoId);

                // 새 기본 설정 지정
                newDefaultSso.IsDefault = true;
                newDefaultSso.UpdatedAt = DateTime.UtcNow;
                newDefaultSso.UpdatedByConnectedId = updatedByConnectedId;

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
                
                // 캐시 업데이트
                if (_cache != null)
                {
                    var cacheKey = $"OrgSSO:Default:{newDefaultSso.OrganizationId}";
                    _cache.Set(cacheKey, newDefaultSso, TimeSpan.FromMinutes(10));
                }
                
                return true;
            }
            catch
            {
                await transaction.RollbackAsync();
                return false;
            }
        }

        /// <summary>
        /// 조직의 SSO 설정 개수 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="onlyActive">활성만 카운트</param>
        /// <returns>SSO 설정 개수</returns>
        public async Task<int> GetCountByOrganizationAsync(Guid organizationId, bool onlyActive = true)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId && !s.IsDeleted);
            
            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 표시 이름으로 SSO 검색
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="displayName">표시 이름</param>
        /// <returns>검색된 SSO 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> SearchByDisplayNameAsync(
            Guid organizationId, 
            string displayName)
        {
            if (string.IsNullOrWhiteSpace(displayName))
            {
                return await GetActiveByOrganizationAsync(organizationId);
            }

            var searchTerm = displayName.Trim().ToLower();

            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.IsActive && 
                           s.DisplayName != null && 
                           s.DisplayName.ToLower().Contains(searchTerm))
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion
    }
}