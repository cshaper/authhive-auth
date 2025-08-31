// Path: AuthHive.Auth/Repositories/OrganizationRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Organization Repository 구현체 - AuthHive v15
    /// 조직의 CRUD와 계층 구조 관리를 담당합니다.
    /// </summary>
    public class OrganizationRepository : BaseRepository<Organization>, IOrganizationRepository
    {
        public OrganizationRepository(AuthDbContext context) : base(context)
        {
        }

        #region IOrganizationRepository 구현

        /// <summary>
        /// 조직 키로 조직 조회
        /// </summary>
        public async Task<Organization?> GetByOrganizationKeyAsync(string organizationKey)
        {
            return await _dbSet
                .FirstOrDefaultAsync(o => o.OrganizationKey == organizationKey && !o.IsDeleted);
        }

        /// <summary>
        /// 특정 상태의 조직들 조회
        /// </summary>
        public async Task<IEnumerable<Organization>> GetByStatusAsync(OrganizationStatus status)
        {
            return await _dbSet
                .Where(o => o.Status == status && !o.IsDeleted)
                .OrderBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 자식 조직들 조회 (재귀 옵션 포함)
        /// </summary>
        public async Task<IEnumerable<Organization>> GetChildOrganizationsAsync(Guid parentId, bool recursive = false)
        {
            if (recursive)
            {
                // 재귀적으로 모든 하위 조직 조회 (Path 활용)
                var parentOrg = await GetByIdAsync(parentId);
                if (parentOrg == null) return Enumerable.Empty<Organization>();

                return await _dbSet
                    .Where(o => o.Path.StartsWith(parentOrg.Path + parentId.ToString() + "/") && !o.IsDeleted)
                    .OrderBy(o => o.Level)
                    .ThenBy(o => o.SortOrder)
                    .ThenBy(o => o.Name)
                    .ToListAsync();
            }
            else
            {
                // 직접 자식만 조회
                return await _dbSet
                    .Where(o => o.ParentId == parentId && !o.IsDeleted)
                    .OrderBy(o => o.SortOrder)
                    .ThenBy(o => o.Name)
                    .ToListAsync();
            }
        }

        /// <summary>
        /// 조직 키 중복 확인
        /// </summary>
        public async Task<bool> IsOrganizationKeyExistsAsync(string organizationKey, Guid? excludeId = null)
        {
            var query = _dbSet.Where(o => o.OrganizationKey == organizationKey && !o.IsDeleted);

            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            return await query.AnyAsync();
        }

        /// <summary>
        /// 조직명 중복 확인
        /// </summary>
        public async Task<bool> IsNameExistsAsync(string name, Guid? excludeId = null)
        {
            var query = _dbSet.Where(o => o.Name == name && !o.IsDeleted);

            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            return await query.AnyAsync();
        }

        #endregion

        #region 계층 구조 관련 추가 메서드

        /// <summary>
        /// 루트 조직들 조회
        /// </summary>
        public async Task<IEnumerable<Organization>> GetRootOrganizationsAsync()
        {
            return await _dbSet
                .Where(o => o.ParentId == null && !o.IsDeleted)
                .OrderBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 상위 조직들 조회 (부모부터 루트까지)
        /// </summary>
        public async Task<IEnumerable<Organization>> GetAncestorsAsync(Guid organizationId, bool includeSelf = false)
        {
            var organization = await GetByIdAsync(organizationId);
            if (organization == null) return Enumerable.Empty<Organization>();

            var ancestorIds = organization.Path
                .Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Where(id => Guid.TryParse(id, out _))
                .Select(Guid.Parse)
                .ToList();

            var query = _dbSet.Where(o => ancestorIds.Contains(o.Id) && !o.IsDeleted);

            if (!includeSelf)
            {
                query = query.Where(o => o.Id != organizationId);
            }

            return await query
                .OrderBy(o => o.Level)
                .ToListAsync();
        }

        /// <summary>
        /// 하위 조직 개수 조회
        /// </summary>
        public async Task<int> GetChildCountAsync(Guid parentId)
        {
            return await _dbSet
                .CountAsync(o => o.ParentId == parentId && !o.IsDeleted);
        }

        /// <summary>
        /// 조직의 전체 하위 조직 개수 조회 (재귀)
        /// </summary>
        public async Task<int> GetDescendantCountAsync(Guid parentId)
        {
            var parentOrg = await GetByIdAsync(parentId);
            if (parentOrg == null) return 0;

            return await _dbSet
                .CountAsync(o => o.Path.StartsWith(parentOrg.Path + parentId.ToString() + "/") && !o.IsDeleted);
        }

        /// <summary>
        /// 조직 계층 트리 조회 (특정 조직 하위)
        /// </summary>
        public async Task<IEnumerable<Organization>> GetOrganizationTreeAsync(Guid? rootId = null)
        {
            IQueryable<Organization> query;

            if (rootId.HasValue)
            {
                var rootOrg = await GetByIdAsync(rootId.Value);
                if (rootOrg == null) return Enumerable.Empty<Organization>();

                query = _dbSet.Where(o => 
                    (o.Id == rootId.Value || o.Path.StartsWith(rootOrg.Path + rootId.ToString() + "/")) 
                    && !o.IsDeleted);
            }
            else
            {
                query = _dbSet.Where(o => !o.IsDeleted);
            }

            return await query
                .OrderBy(o => o.Level)
                .ThenBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 순환 참조 확인 (조직이 자신의 하위 조직을 부모로 설정하려고 하는지)
        /// </summary>
        public async Task<bool> WouldCreateCircularReferenceAsync(Guid organizationId, Guid newParentId)
        {
            var organization = await GetByIdAsync(organizationId);
            if (organization == null) return false;

            // 새 부모가 현재 조직의 하위 조직인지 확인
            return await _dbSet.AnyAsync(o => 
                o.Id == newParentId && 
                o.Path.StartsWith(organization.Path + organizationId.ToString() + "/") && 
                !o.IsDeleted);
        }

        /// <summary>
        /// 조직과 모든 하위 조직 일괄 삭제
        /// </summary>
        public async Task<int> DeleteWithDescendantsAsync(Guid organizationId, Guid? deletedByConnectedId = null)
        {
            var organization = await GetByIdAsync(organizationId);
            if (organization == null) return 0;

            var descendants = await _dbSet
                .Where(o => 
                    (o.Id == organizationId || o.Path.StartsWith(organization.Path + organizationId.ToString() + "/")) 
                    && !o.IsDeleted)
                .ToListAsync();

            var timestamp = DateTime.UtcNow;
            foreach (var org in descendants)
            {
                org.IsDeleted = true;
                org.DeletedAt = timestamp;
                org.DeletedByConnectedId = deletedByConnectedId;
            }

            _dbSet.UpdateRange(descendants);
            await _context.SaveChangesAsync();

            return descendants.Count;
        }

        /// <summary>
        /// 조직 이동 (부모 변경)
        /// </summary>
        public async Task<bool> MoveOrganizationAsync(Guid organizationId, Guid? newParentId, Guid? updatedByConnectedId = null)
        {
            // 순환 참조 확인
            if (newParentId.HasValue && await WouldCreateCircularReferenceAsync(organizationId, newParentId.Value))
            {
                return false;
            }

            var organization = await GetByIdAsync(organizationId);
            if (organization == null) return false;

            var oldPath = organization.Path;
            var oldLevel = organization.Level;

            // 새 부모 정보 설정
            if (newParentId.HasValue)
            {
                var newParent = await GetByIdAsync(newParentId.Value);
                if (newParent == null) return false;

                organization.ParentId = newParentId;
                organization.Path = newParent.Path + newParentId.ToString() + "/";
                organization.Level = newParent.Level + 1;
            }
            else
            {
                // 루트로 이동
                organization.ParentId = null;
                organization.Path = "/";
                organization.Level = 0;
            }

            organization.UpdatedByConnectedId = updatedByConnectedId;
            organization.UpdatedAt = DateTime.UtcNow;

            // 모든 하위 조직의 Path와 Level 업데이트
            var descendants = await _dbSet
                .Where(o => o.Path.StartsWith(oldPath + organizationId.ToString() + "/") && !o.IsDeleted)
                .ToListAsync();

            var levelDifference = organization.Level - oldLevel;
            var newBasePath = organization.Path + organizationId.ToString() + "/";

            foreach (var descendant in descendants)
            {
                descendant.Path = descendant.Path.Replace(oldPath + organizationId.ToString() + "/", newBasePath);
                descendant.Level += levelDifference;
                descendant.UpdatedByConnectedId = updatedByConnectedId;
                descendant.UpdatedAt = DateTime.UtcNow;
            }

            _dbSet.Update(organization);
            _dbSet.UpdateRange(descendants);
            await _context.SaveChangesAsync();

            return true;
        }

        #endregion

        #region 추가 유틸리티 메서드

        /// <summary>
        /// 활성 조직 개수 조회
        /// </summary>
        public async Task<int> GetActiveOrganizationCountAsync()
        {
            return await _dbSet.CountAsync(o => o.Status == OrganizationStatus.Active && !o.IsDeleted);
        }

        /// <summary>
        /// 지역별 조직 조회
        /// </summary>
        public async Task<IEnumerable<Organization>> GetByRegionAsync(string region)
        {
            return await _dbSet
                .Where(o => o.Region == region && !o.IsDeleted)
                .OrderBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 조직 유형별 조회
        /// </summary>
        public async Task<IEnumerable<Organization>> GetByTypeAsync(OrganizationType type)
        {
            return await _dbSet
                .Where(o => o.Type == type && !o.IsDeleted)
                .OrderBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 최근 생성된 조직들 조회
        /// </summary>
        public async Task<IEnumerable<Organization>> GetRecentOrganizationsAsync(int count = 10)
        {
            return await _dbSet
                .Where(o => !o.IsDeleted)
                .OrderByDescending(o => o.CreatedAt)
                .Take(count)
                .ToListAsync();
        }

        /// <summary>
        /// 조직 검색
        /// </summary>
        public async Task<IEnumerable<Organization>> SearchAsync(string keyword)
        {
            return await _dbSet
                .Where(o => !o.IsDeleted && 
                           (o.Name.Contains(keyword) || 
                            o.OrganizationKey.Contains(keyword) || 
                            (o.Description != null && o.Description.Contains(keyword))))
                .OrderBy(o => o.Name)
                .ToListAsync();
        }

        #endregion
    }
}