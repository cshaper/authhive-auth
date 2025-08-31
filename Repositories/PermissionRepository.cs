// Path: AuthHive.Auth/Repositories/PermissionRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using System.Linq.Expressions;
using AuthHive.Core.Models.Common;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Permission 저장소 구현체 - AuthHive v15
    /// 시스템 전역 권한 정의를 관리하는 Repository
    /// </summary>
    public class PermissionRepository : BaseRepository<Permission>, IPermissionRepository
    {
        public PermissionRepository(AuthDbContext context) : base(context)
        {
        }

        #region 고유 조회 메서드

        /// <summary>
        /// Scope로 권한 조회
        /// </summary>
        public async Task<Permission?> GetByScopeAsync(string scope)
        {
            return await _dbSet
                .Include(p => p.ParentPermission)
                .Include(p => p.ChildPermissions)
                .FirstOrDefaultAsync(p => p.Scope == scope && p.IsActive && !p.IsDeleted);
        }

        /// <summary>
        /// 여러 Scope로 권한 일괄 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByScopesAsync(IEnumerable<string> scopes)
        {
            return await _dbSet
                .Where(p => scopes.Contains(p.Scope) && p.IsActive && !p.IsDeleted)
                .Include(p => p.ParentPermission)
                .ToListAsync();
        }

        #endregion

        #region 카테고리별 조회 메서드

        /// <summary>
        /// 카테고리별 권한 조회
        /// </summary>
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

        /// <summary>
        /// 자식 권한 조회
        /// </summary>
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

        /// <summary>
        /// 권한 트리 조회 (재귀적)
        /// </summary>
        public async Task<IEnumerable<Permission>> GetPermissionTreeAsync(
            Guid? rootPermissionId = null,
            int? maxDepth = null)
        {
            var allPermissions = await _dbSet
                .Where(p => p.IsActive && !p.IsDeleted)
                .Include(p => p.ParentPermission)
                .Include(p => p.ChildPermissions)
                .ToListAsync();

            // 루트 권한들부터 시작
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

        /// <summary>
        /// 시스템 권한만 조회
        /// </summary>
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

        /// <summary>
        /// 리소스와 액션으로 권한 조회
        /// </summary>
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

        /// <summary>
        /// 특정 역할에 할당된 권한 조회
        /// </summary>
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

        /// <summary>
        /// 여러 역할에 할당된 권한 조회 (중복 제거)
        /// </summary>
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

        /// <summary>
        /// 권한 통계 조회
        /// </summary>
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

        /// <summary>
        /// 관련 엔티티를 포함하여 조회
        /// </summary>
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