using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using System.Linq.Expressions;
using AuthHive.Core.Models.Common;
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using System.Linq;
using AuthHive.Core.Models.Auth.Permissions.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Permission 저장소 구현체 - AuthHive v15
    /// 시스템 전역 권한 정의를 관리하는 Repository
    /// </summary>
    public class PermissionRepository : BaseRepository<Permission>, IPermissionRepository
    {
        public PermissionRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        #region 고유 조회 메서드

        public async Task<Permission?> GetByScopeAsync(string scope)
        {
            return await _dbSet
                .Include(p => p.ParentPermission)
                .Include(p => p.ChildPermissions)
                .FirstOrDefaultAsync(p => p.Scope == scope && p.IsActive && !p.IsDeleted);
        }

        /// <summary>
        /// 특정 ConnectedId가 가진 모든 활성 역할을 통해 최종적으로 부여받는 모든 권한을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Permission>> GetPermissionsForConnectedIdAsync(
            Guid connectedId,
            bool includeInactive = false)
        {
            // 1. ConnectedId를 기준으로 활성 상태인 모든 역할들의 ID를 조회합니다.
            var activeRoleIds = await _context.Set<ConnectedIdRole>()
                .Where(cr =>
                    cr.ConnectedId == connectedId &&
                    cr.IsActive &&
                    (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
                .Select(cr => cr.RoleId)
                .Distinct()
                .ToListAsync();

            if (!activeRoleIds.Any())
            {
                return Enumerable.Empty<Permission>();
            }

            // 2. 해당 역할 ID들에 연결된 모든 권한들을 조회합니다.
            // Role -> RolePermission -> Permission 엔티티를 거쳐 조회합니다.
            var query = _context.Set<RolePermission>()
                .Where(rp => activeRoleIds.Contains(rp.RoleId))
                .Select(rp => rp.Permission);

            if (!includeInactive)
            {
                // Permission 테이블 자체에도 IsActive 플래그가 있다고 가정
                query = query.Where(p => p.IsActive);
            }
            
            // 3. 중복을 제거하고 최종 권한 목록을 반환합니다.
            return await query.Distinct().ToListAsync();
        }

        public async Task<IEnumerable<Permission>> GetByScopesAsync(IEnumerable<string> scopes)
        {
            return await _dbSet
                .Where(p => scopes.Contains(p.Scope) && p.IsActive && !p.IsDeleted)
                .Include(p => p.ParentPermission)
                .ToListAsync();
        }

        #endregion

        #region 추가 조회 메서드

        /// <summary>
        /// 모든 활성 권한 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetActivePermissionsAsync()
        {
            return await _dbSet
                .Where(p => p.IsActive && !p.IsDeleted)
                .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 스코프 패턴으로 권한 조회 (와일드카드 지원)
        /// SQL LIKE 패턴을 사용하여 권한을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByScopePatternAsync(string pattern)
        {
            // SQL LIKE 패턴을 EF Core에서 사용
            // 예: "organization:%" -> organization으로 시작하는 모든 스코프
            return await _dbSet
                .Where(p => EF.Functions.Like(p.Scope, pattern) && p.IsActive && !p.IsDeleted)
                .OrderBy(p => p.Scope)
                .ToListAsync();
        }

        /// <summary>
        /// 애플리케이션에서 사용 가능한 권한 조회
        /// 애플리케이션에 할당된 역할들이 가진 권한을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByApplicationAsync(Guid applicationId)
        {
            // Application -> Role -> RolePermission -> Permission 관계를 통해 조회
            var query = from p in _dbSet
                        join rp in _context.Set<RolePermission>() on p.Id equals rp.PermissionId
                        join r in _context.Set<Role>() on rp.RoleId equals r.Id
                        where r.ApplicationId == applicationId && 
                              p.IsActive && 
                              !p.IsDeleted && 
                              rp.IsActive && 
                              r.IsActive
                        select p;

            return await query.Distinct().ToListAsync();
        }

        /// <summary>
        /// 여러 ID로 권한 일괄 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<Guid> ids)
        {
            return await _dbSet
                .Where(p => ids.Contains(p.Id) && !p.IsDeleted)
                .OrderBy(p => p.Name)
                .ToListAsync();
        }

        #endregion

        #region 카테고리별 조회 메서드
        
        public async Task<IEnumerable<Permission>> GetByCategoryAsync(
            PermissionCategory category,
            bool includeInactive = false)
        {
            var query = _dbSet.AsQueryable();

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .Where(p => p.Category == category && !p.IsDeleted)
                .OrderBy(p => p.Name)
                .ToListAsync();
        }

        #endregion

        #region 계층 구조 조회 메서드
        
        public async Task<IEnumerable<Permission>> GetChildPermissionsAsync(
            Guid parentPermissionId,
            bool includeInactive = false)
        {
            var query = _dbSet.AsQueryable();

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .Where(p => p.ParentPermissionId == parentPermissionId && !p.IsDeleted)
                .OrderBy(p => p.Name)
                .ToListAsync();
        }

        public async Task<IEnumerable<Permission>> GetPermissionTreeAsync(
            Guid? rootPermissionId = null,
            int? maxDepth = null)
        {
            var allPermissions = await _dbSet
                .Where(p => p.IsActive && !p.IsDeleted)
                .Include(p => p.ParentPermission)
                .Include(p => p.ChildPermissions)
                .ToListAsync();

            var rootPermissions = rootPermissionId.HasValue
                ? allPermissions.Where(p => p.Id == rootPermissionId.Value)
                : allPermissions.Where(p => p.ParentPermissionId == null);

            var result = new List<Permission>();

            foreach (var root in rootPermissions)
            {
                BuildPermissionTree(root, allPermissions, result, 0, maxDepth ?? int.MaxValue);
            }

            return result;
        }

        private void BuildPermissionTree(Permission current, IEnumerable<Permission> allPermissions,
            List<Permission> result, int currentDepth, int maxDepth)
        {
            if (currentDepth > maxDepth) return;

            result.Add(current);

            var children = allPermissions.Where(p => p.ParentPermissionId == current.Id);
            foreach (var child in children)
            {
                BuildPermissionTree(child, allPermissions, result, currentDepth + 1, maxDepth);
            }
        }

        #endregion

        #region 시스템 권한 메서드
        
        public async Task<IEnumerable<Permission>> GetSystemPermissionsAsync(bool includeInactive = false)
        {
            var query = _dbSet.Where(p => p.IsSystemPermission && !p.IsDeleted);

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
                .ToListAsync();
        }

        #endregion

        #region 리소스/액션 기반 조회 메서드
        
        public async Task<Permission?> GetByResourceAndActionAsync(
            string resourceType,
            string actionType)
        {
            return await _dbSet
                .FirstOrDefaultAsync(p =>
                    p.ResourceType == resourceType &&
                    p.ActionType == actionType &&
                    p.IsActive &&
                    !p.IsDeleted);
        }

        #endregion

        #region 역할 관련 메서드

        public async Task<IEnumerable<Permission>> GetByRoleIdAsync(
            Guid roleId,
            bool includeInactive = false)
        {
            var query = from p in _dbSet
                        join rp in _context.Set<RolePermission>() on p.Id equals rp.PermissionId
                        where rp.RoleId == roleId && !p.IsDeleted && rp.IsActive
                        select p;

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query.Distinct().ToListAsync();
        }

        public async Task<IEnumerable<Permission>> GetByRoleIdsAsync(
            IEnumerable<Guid> roleIds,
            bool includeInactive = false)
        {
            var query = from p in _dbSet
                        join rp in _context.Set<RolePermission>() on p.Id equals rp.PermissionId
                        where roleIds.Contains(rp.RoleId) && !p.IsDeleted && rp.IsActive
                        select p;

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query.Distinct().ToListAsync();
        }

        #endregion

        #region 통계 메서드
        
        public async Task<PermissionStatistics> GetStatisticsAsync()
        {
            var totalCount = await _dbSet.CountAsync(p => !p.IsDeleted);
            var activeCount = await _dbSet.CountAsync(p => p.IsActive && !p.IsDeleted);
            var systemPermissionCount = await _dbSet.CountAsync(p => p.IsSystemPermission && !p.IsDeleted);

            var categoryStats = await _dbSet
                .Where(p => p.IsActive && !p.IsDeleted)
                .GroupBy(p => p.Category)
                .Select(g => new { Category = g.Key, Count = g.Count() })
                .ToListAsync();

            var levelStats = await _dbSet
                .Where(p => p.IsActive && !p.IsDeleted)
                .GroupBy(p => p.Level)
                .Select(g => new { Level = g.Key, Count = g.Count() })
                .ToListAsync();

            var lastCreated = await _dbSet
                .Where(p => !p.IsDeleted)
                .OrderByDescending(p => p.CreatedAt)
                .Select(p => p.CreatedAt)
                .FirstOrDefaultAsync();

            var lastModified = await _dbSet
                .Where(p => !p.IsDeleted && p.UpdatedAt.HasValue)
                .OrderByDescending(p => p.UpdatedAt)
                .Select(p => p.UpdatedAt)
                .FirstOrDefaultAsync();

            return new PermissionStatistics
            {
                TotalCount = totalCount,
                ActiveCount = activeCount,
                InactiveCount = totalCount - activeCount,
                SystemPermissionCount = systemPermissionCount,
                CustomPermissionCount = totalCount - systemPermissionCount,
                CountByCategory = categoryStats.ToDictionary(x => x.Category, x => x.Count),
                CountByLevel = levelStats.ToDictionary(x => x.Level, x => x.Count),
                LastCreatedAt = lastCreated,
                LastModifiedAt = lastModified
            };
        }

        #endregion

        #region 관계 로딩 메서드
        
        public async Task<Permission?> GetWithRelatedDataAsync(
            Guid id,
            bool includeParent = false,
            bool includeChildren = false,
            bool includeRoles = false,
            bool includeValidationLogs = false)
        {
            var query = _dbSet.Where(p => p.Id == id && !p.IsDeleted);

            if (includeParent)
                query = query.Include(p => p.ParentPermission);

            if (includeChildren)
                query = query.Include(p => p.ChildPermissions);

            if (includeRoles)
                query = query.Include(p => p.RolePermissions).ThenInclude(rp => rp.Role);

            if (includeValidationLogs)
                query = query.Include(p => p.ValidationLogs.Take(100)); // 최근 100개만

            return await query.FirstOrDefaultAsync();
        }

        #endregion
    }
}