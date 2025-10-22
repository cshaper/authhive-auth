using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
// using Microsoft.Extensions.Caching.Memory; // IMemoryCache 제거
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using System.Linq.Expressions;
using AuthHive.Core.Models.Common;
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using System.Linq;
using AuthHive.Core.Models.Auth.Permissions.Common;
// using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationContext 제거
using System.Threading; // CancellationToken 추가

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Permission 저장소 구현체 - AuthHive v16
    /// 시스템 전역 권한 정의를 관리하는 Repository
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class PermissionRepository : BaseRepository<Permission>, IPermissionRepository
    {
        public PermissionRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ICacheService? cacheService = null) // IMemoryCache -> ICacheService?
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. Permission은 전역적이므로 조직 범위 아님 (false).
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;


        #region 고유 조회 메서드 (CancellationToken 추가)

        public async Task<Permission?> GetByScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            // TODO: 캐싱 추가 고려 (Scope는 고유 식별자이므로 캐싱 가능)
            string cacheKey = GetCacheKey($"Scope:{scope.ToLowerInvariant()}");
            if(_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<Permission>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var permission = await Query() // Query() 사용 (IsDeleted=false 필터 포함)
                .Include(p => p.ParentPermission)
                .Include(p => p.ChildPermissions)
                .FirstOrDefaultAsync(p => p.Scope == scope && p.IsActive, cancellationToken); // IsDeleted 조건은 Query()에 포함됨

            if (permission != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, permission, TimeSpan.FromHours(1), cancellationToken); // 권한 정의는 자주 안 바뀌므로 TTL 길게
            }
            return permission;
        }

        /// <summary>
        /// 특정 ConnectedId가 가진 모든 활성 역할을 통해 최종적으로 부여받는 모든 권한을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Permission>> GetPermissionsForConnectedIdAsync(
            Guid connectedId,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var activeRoleIds = await _context.Set<ConnectedIdRole>()
                .Where(cr =>
                    cr.ConnectedId == connectedId &&
                    cr.IsActive &&
                    (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
                .Select(cr => cr.RoleId)
                .Distinct()
                .ToListAsync(cancellationToken); // CT 추가

            if (!activeRoleIds.Any())
            {
                return Enumerable.Empty<Permission>();
            }

            // [FIXED] RolePermission에 IsActive 필터 추가 (RolePermission 관계 자체가 비활성화될 수 있음)
            var query = _context.Set<RolePermission>()
                .Where(rp => activeRoleIds.Contains(rp.RoleId) && rp.IsActive) // rp.IsActive 추가
                .Select(rp => rp.Permission)
                .Where(p => p != null && !p.IsDeleted); // Permission이 null이 아니고 삭제되지 않았는지 확인

            if (!includeInactive)
            {
                query = query.Where(p => p.IsActive);
            }

            // TODO: 캐싱 추가 고려 (ConnectedId별 권한 목록은 자주 조회될 수 있음)
            return await query.Distinct().ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<Permission>> GetByScopesAsync(
            IEnumerable<string> scopes,
            CancellationToken cancellationToken = default)
        {
             if (scopes == null || !scopes.Any()) return Enumerable.Empty<Permission>();

            // TODO: 캐싱 추가 고려 (여러 Scope 조회 결과 캐싱)
            return await Query() // Query() 사용
                .Where(p => scopes.Contains(p.Scope) && p.IsActive) // IsDeleted 조건 제거
                .Include(p => p.ParentPermission) // 필요 시 AsNoTracking() 추가
                .ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region 추가 조회 메서드 (CancellationToken 추가)

        /// <summary>
        /// 모든 활성 권한 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetActivePermissionsAsync(CancellationToken cancellationToken = default)
        {
             // TODO: 캐싱 추가 고려 (전체 활성 권한 목록은 캐싱 효율 높음)
            return await Query() // Query() 사용
                .Where(p => p.IsActive) // IsDeleted 조건 제거
                .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
                .AsNoTracking() // 읽기 전용이므로 추적 불필요
                .ToListAsync(cancellationToken); // CT 추가
        }

        /// <summary>
        /// 스코프 패턴으로 권한 조회 (와일드카드 지원)
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByScopePatternAsync(string pattern, CancellationToken cancellationToken = default)
        {
            return await Query() // Query() 사용
                .Where(p => EF.Functions.Like(p.Scope, pattern) && p.IsActive) // IsDeleted 조건 제거
                .OrderBy(p => p.Scope)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        /// <summary>
        /// 애플리케이션에서 사용 가능한 권한 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByApplicationAsync(Guid applicationId, CancellationToken cancellationToken = default)
        {
            // Join 조건에서 IsDeleted 필터 추가
            var query = from p in _dbSet
                        join rp in _context.Set<RolePermission>().Where(x => x.IsActive) on p.Id equals rp.PermissionId
                        join r in _context.Set<Role>().Where(x => x.IsActive && !x.IsDeleted) on rp.RoleId equals r.Id
                        where r.ApplicationId == applicationId &&
                              p.IsActive &&
                              !p.IsDeleted // p에 대한 IsDeleted 조건 명시 (Query() 자동 적용 안됨)
                        select p;

            // TODO: 캐싱 추가 고려 (애플리케이션별 권한 목록)
            return await query.Distinct().AsNoTracking().ToListAsync(cancellationToken); // CT 추가
        }

        /// <summary>
        /// 여러 ID로 권한 일괄 조회
        /// </summary>
        public async Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
        {
            if (ids == null || !ids.Any()) return Enumerable.Empty<Permission>();

            return await Query() // Query() 사용 (IsDeleted=false 필터 포함)
                .Where(p => ids.Contains(p.Id))
                .OrderBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region 카테고리별 조회 메서드 (CancellationToken 추가)

        public async Task<IEnumerable<Permission>> GetByCategoryAsync(
            PermissionCategory category,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = Query(); // Query() 사용

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .Where(p => p.Category == category) // IsDeleted 조건 제거
                .OrderBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region 계층 구조 조회 메서드 (CancellationToken 추가)

        public async Task<IEnumerable<Permission>> GetChildPermissionsAsync(
            Guid parentPermissionId,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = Query(); // Query() 사용

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .Where(p => p.ParentPermissionId == parentPermissionId) // IsDeleted 조건 제거
                .OrderBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<Permission>> GetPermissionTreeAsync(
            Guid? rootPermissionId = null,
            int? maxDepth = null,
            CancellationToken cancellationToken = default)
        {
            // DB에서 모든 활성 권한 로드 (계층 구조 포함)
             var allPermissions = await Query() // Query() 사용
                 .Where(p => p.IsActive) // IsDeleted 조건 제거
                 .Include(p => p.ParentPermission)
                 // .Include(p => p.ChildPermissions) // 순환 참조 및 성능 문제로 제거 고려. 필요 시 재귀 로딩.
                 .AsNoTracking()
                 .ToListAsync(cancellationToken); // CT 추가

             // 메모리에서 트리 재구성
            var lookup = allPermissions.ToDictionary(p => p.Id);
            var tree = new List<Permission>();

             // 루트 노드 찾기
             var roots = rootPermissionId.HasValue
                 ? allPermissions.Where(p => p.Id == rootPermissionId.Value)
                 : allPermissions.Where(p => p.ParentPermissionId == null);

             foreach (var root in roots)
             {
                 // 재귀적으로 자식 추가 (메모리 내에서)
                 root.ChildPermissions = GetChildrenRecursive(root, allPermissions, 0, maxDepth ?? int.MaxValue);
                 tree.Add(root);
             }

             // 필요 시 트리 구조를 평탄화(Flatten)하여 반환할 수 있음
             // return FlattenTree(tree);
             return tree; // 트리 구조 그대로 반환
        }

        // 메모리 내에서 자식 노드를 재귀적으로 찾는 헬퍼 함수
        private List<Permission> GetChildrenRecursive(Permission parent, List<Permission> allPermissions, int currentDepth, int maxDepth)
        {
             if (currentDepth >= maxDepth) return new List<Permission>();

             var children = allPermissions
                 .Where(p => p.ParentPermissionId == parent.Id)
                 .OrderBy(p=> p.Name) // 필요 시 정렬
                 .ToList();

             foreach (var child in children)
             {
                 child.ChildPermissions = GetChildrenRecursive(child, allPermissions, currentDepth + 1, maxDepth);
             }
             return children;
        }

        /*
        // 트리 구조를 평탄화하는 헬퍼 함수 (필요 시 사용)
        private IEnumerable<Permission> FlattenTree(IEnumerable<Permission> nodes)
        {
            var list = new List<Permission>();
            foreach (var node in nodes)
            {
                list.Add(node);
                if (node.ChildPermissions != null && node.ChildPermissions.Any())
                {
                    list.AddRange(FlattenTree(node.ChildPermissions));
                }
            }
            return list;
        }
        */

        // BuildPermissionTree 메서드 제거 (메모리 재구성 방식으로 대체)

        #endregion

        #region 시스템 권한 메서드 (CancellationToken 추가)

        public async Task<IEnumerable<Permission>> GetSystemPermissionsAsync(
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(p => p.IsSystemPermission); // Query() 사용, IsDeleted 조건 제거

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            return await query
                .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region 리소스/액션 기반 조회 메서드 (CancellationToken 추가)

        public async Task<Permission?> GetByResourceAndActionAsync(
            string resourceType,
            string actionType,
            CancellationToken cancellationToken = default)
        {
             // TODO: 캐싱 추가 고려 (리소스+액션 조합은 자주 사용될 수 있음)
            return await Query() // Query() 사용
                .FirstOrDefaultAsync(p =>
                    p.ResourceType == resourceType &&
                    p.ActionType == actionType &&
                    p.IsActive, // IsDeleted 조건 제거
                    cancellationToken); // CT 추가
        }

        #endregion

        #region 역할 관련 메서드 (CancellationToken 추가)

        public async Task<IEnumerable<Permission>> GetByRoleIdAsync(
            Guid roleId,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = from p in _dbSet.Where(x => !x.IsDeleted) // p에 IsDeleted 필터 추가
                        join rp in _context.Set<RolePermission>().Where(x => x.IsActive) on p.Id equals rp.PermissionId
                        where rp.RoleId == roleId
                        select p;

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            // TODO: 캐싱 추가 고려 (역할별 권한 목록)
            return await query.Distinct().AsNoTracking().ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<Permission>> GetByRoleIdsAsync(
            IEnumerable<Guid> roleIds,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
             if (roleIds == null || !roleIds.Any()) return Enumerable.Empty<Permission>();

            var query = from p in _dbSet.Where(x => !x.IsDeleted) // p에 IsDeleted 필터 추가
                        join rp in _context.Set<RolePermission>().Where(x => x.IsActive) on p.Id equals rp.PermissionId
                        where roleIds.Contains(rp.RoleId)
                        select p;

            if (!includeInactive)
                query = query.Where(p => p.IsActive);

            // TODO: 캐싱 추가 고려 (여러 역할 권한 목록)
            return await query.Distinct().AsNoTracking().ToListAsync(cancellationToken); // CT 추가
        }

        #endregion

        #region 통계 메서드 (CancellationToken 추가)

        public async Task<PermissionStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
        {
            // BaseRepository의 CountAsync 사용
            var totalCount = await CountAsync(null, cancellationToken); // IsDeleted=false 조건 자동 포함
            var activeCount = await CountAsync(p => p.IsActive, cancellationToken); // IsDeleted=false 조건 자동 포함
            var systemPermissionCount = await CountAsync(p => p.IsSystemPermission, cancellationToken); // IsDeleted=false 조건 자동 포함

            // BaseRepository의 GetGroupCountAsync 사용
            var categoryStats = await GetGroupCountAsync(p => p.Category, p => p.IsActive, cancellationToken); // IsDeleted=false 조건 자동 포함
            var levelStats = await GetGroupCountAsync(p => p.Level, p => p.IsActive, cancellationToken); // IsDeleted=false 조건 자동 포함

            // 마지막 생성/수정일 조회 (Query() 사용)
            var lastCreated = await Query()
                .OrderByDescending(p => p.CreatedAt)
                .Select(p => p.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken);

            var lastModified = await Query()
                .Where(p => p.UpdatedAt.HasValue)
                .OrderByDescending(p => p.UpdatedAt)
                .Select(p => p.UpdatedAt)
                .FirstOrDefaultAsync(cancellationToken);

            return new PermissionStatistics
            {
                TotalCount = totalCount,
                ActiveCount = activeCount,
                InactiveCount = totalCount - activeCount,
                SystemPermissionCount = systemPermissionCount,
                CustomPermissionCount = totalCount - systemPermissionCount,
                CountByCategory = categoryStats, // 이미 Dictionary 형태
                CountByLevel = levelStats,       // 이미 Dictionary 형태
                LastCreatedAt = lastCreated,
                LastModifiedAt = lastModified
            };
        }

        #endregion

        #region 관계 로딩 메서드 (CancellationToken 추가)

        public async Task<Permission?> GetWithRelatedDataAsync(
            Guid id,
            bool includeParent = false,
            bool includeChildren = false,
            bool includeRoles = false,
            bool includeValidationLogs = false,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(p => p.Id == id); // Query() 사용

            if (includeParent)
                query = query.Include(p => p.ParentPermission);

            if (includeChildren)
                query = query.Include(p => p.ChildPermissions.Where(c => !c.IsDeleted && c.IsActive)); // 활성 자식만 로드

            if (includeRoles)
                query = query.Include(p => p.RolePermissions.Where(rp => rp.IsActive)) // 활성 관계만
                           .ThenInclude(rp => rp.Role)
                           .Where(p => p.RolePermissions.Any(rp => rp.Role != null && !rp.Role.IsDeleted && rp.Role.IsActive)); // 활성 역할만

            // ValidationLogs는 Permission 엔티티에 없으므로 주석 처리 또는 제거
            // if (includeValidationLogs)
            //     query = query.Include(p => p.ValidationLogs.Take(100));

            return await query.AsNoTracking().FirstOrDefaultAsync(cancellationToken); // CT 추가
        }

        #endregion
    }
}