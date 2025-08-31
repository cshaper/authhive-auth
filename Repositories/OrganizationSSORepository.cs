using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 SSO 설정 Repository 구현체 - AuthHive v15
    /// SSO 설정 관리, 검증, 우선순위 처리 등 SSO 관련 모든 데이터 접근을 담당합니다.
    /// </summary>
    public class OrganizationSSORepository : OrganizationScopedRepository<OrganizationSSO>, IOrganizationSSORepository
    {
        public OrganizationSSORepository(AuthDbContext context) : base(context)
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
            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .FirstOrDefaultAsync(s => s.OrganizationId == organizationId && 
                                         s.IsDefault && 
                                         s.IsActive && 
                                         !s.IsDeleted);
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
            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.OrganizationId == organizationId && 
                           s.SSOType == ssoType && 
                           !s.IsDeleted);

            if (!includeInactive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
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
            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.OrganizationId == organizationId && 
                           s.ProviderName == provider && 
                           s.IsActive && 
                           !s.IsDeleted)
                .OrderBy(s => s.Priority)
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
            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.OrganizationId == organizationId && 
                           s.IsActive && 
                           !s.IsDeleted)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.CreatedAt)
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
            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.OrganizationId == organizationId && !s.IsDeleted);

            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .ThenByDescending(s => s.IsDefault)
                .ThenBy(s => s.CreatedAt)
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
                .ToListAsync();
        }

        /// <summary>
        /// 테스트 실패한 SSO 설정 조회 (구현 예시 - 실제로는 테스트 결과를 별도 저장해야 함)
        /// </summary>
        /// <param name="organizationId">조직 ID (null이면 전체)</param>
        /// <returns>테스트 실패 SSO 목록</returns>
        public async Task<IEnumerable<OrganizationSSO>> GetFailedTestsAsync(Guid? organizationId = null)
        {
            // 실제 구현에서는 테스트 결과를 별도 테이블에 저장하고 조인해야 합니다.
            // 여기서는 예시로 오래된 테스트나 한 번도 테스트되지 않은 것을 반환합니다.
            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive && 
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || 
                            s.LastTestedAt < DateTime.UtcNow.AddDays(-60))); // 60일 이상 테스트되지 않은 것

            if (organizationId.HasValue)
            {
                query = query.Where(s => s.OrganizationId == organizationId.Value);
            }

            return await query
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
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
            var ssoToUpdate = await _dbSet
                .Where(s => s.OrganizationId == organizationId && 
                           s.Id != excludeSsoId && 
                           s.IsDefault && 
                           !s.IsDeleted)
                .ToListAsync();

            var updateCount = ssoToUpdate.Count;
            
            foreach (var sso in ssoToUpdate)
            {
                sso.IsDefault = false;
                sso.UpdatedAt = DateTime.UtcNow;
            }

            if (updateCount > 0)
            {
                await _context.SaveChangesAsync();
            }

            return updateCount;
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
        /// 기본 SSO 설정 변경 (기존 기본 설정 해제 + 새 기본 설정)
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
                // 1. 기존 기본 설정들을 해제
                await UnsetDefaultExceptAsync(newDefaultSso.OrganizationId, ssoId);

                // 2. 새 기본 설정 설정
                newDefaultSso.IsDefault = true;
                newDefaultSso.UpdatedAt = DateTime.UtcNow;
                newDefaultSso.UpdatedByConnectedId = updatedByConnectedId;

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
                
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
                return await GetActiveByOrganizationAsync(organizationId);

            var searchTerm = displayName.Trim().ToLower();

            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.OrganizationId == organizationId && 
                           s.IsActive && 
                           !s.IsDeleted &&
                           (s.DisplayName != null && s.DisplayName.ToLower().Contains(searchTerm)))
                .OrderBy(s => s.Priority)
                .ToListAsync();
        }

        #endregion
    }
}