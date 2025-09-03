using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using System.Linq.Expressions;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// Role Repository - 역할 관리 Repository
/// AuthHive v15 계층적 역할 시스템의 핵심 저장소
/// </summary>
public class RoleRepository : BaseRepository<Role>, IRoleRepository
{
    private readonly ILogger<RoleRepository> _logger;
    public RoleRepository(
               AuthDbContext context,
               IOrganizationContext organizationContext,
               ILogger<RoleRepository> logger,
               IMemoryCache? cache = null)
               : base(context, organizationContext, cache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }


    // Override Query to add Organization filtering for Role
    public override IQueryable<Role> Query()
    {
        // Role은 OrganizationScopedEntity이므로 기본 쿼리 사용
        // 조직 필터링은 메서드 파라미터로 명시적으로 처리
        return base.Query();
    }

    #region IRoleRepository 구현 - 고유 조회 메서드

    /// <summary>
    /// RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByRoleKeyAsync(Guid organizationId, string roleKey)
    {
        return await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r => r.RoleKey == roleKey);
    }

    /// <summary>
    /// Application별 RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByApplicationAndRoleKeyAsync(
        Guid organizationId,
        Guid applicationId,
        string roleKey)
    {
        return await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r =>
                r.ApplicationId == applicationId &&
                r.RoleKey == roleKey);
    }

    #endregion

    #region IRoleRepository 구현 - 범위별 조회

    /// <summary>
    /// 조직의 모든 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByOrganizationAsync(
        Guid organizationId,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// Application별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationAsync(
        Guid applicationId,
        bool includeInactive = false)
    {
        var query = Query().Where(r => r.ApplicationId == applicationId);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// Scope별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByScopeAsync(
        Guid organizationId,
        RoleScope scope,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.Scope == scope);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 카테고리별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByCategoryAsync(
        Guid organizationId,
        RoleCategory category,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.Category == category);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    #endregion

    #region IRoleRepository 구현 - 계층 구조 조회

    /// <summary>
    /// 자식 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetChildRolesAsync(
        Guid parentRoleId,
        bool includeInactive = false)
    {
        var query = Query().Where(r => r.ParentRoleId == parentRoleId);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 루트 역할 조회 (ParentRoleId가 null)
    /// </summary>
    public async Task<IEnumerable<Role>> GetRootRolesAsync(
        Guid organizationId,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.ParentRoleId == null);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 역할 트리 조회 (재귀적)
    /// </summary>
    public async Task<IEnumerable<Role>> GetRoleTreeAsync(
        Guid organizationId,
        Guid? rootRoleId = null,
        int? maxDepth = null)
    {
        var allRoles = await QueryForOrganization(organizationId)
            .Where(r => r.IsActive)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();

        if (rootRoleId.HasValue)
        {
            var root = allRoles.FirstOrDefault(r => r.Id == rootRoleId.Value);
            if (root == null) return Enumerable.Empty<Role>();

            return BuildTreeFromRoot(allRoles, root, maxDepth ?? int.MaxValue);
        }

        return BuildHierarchy(allRoles);
    }

    #endregion

    #region IRoleRepository 구현 - 레벨별 조회

    /// <summary>
    /// 특정 레벨의 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByLevelAsync(
        Guid organizationId,
        int level,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => (int)r.Level == level);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 레벨 이상의 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByMinimumLevelAsync(
        Guid organizationId,
        int minimumLevel,
        bool includeInactive = false)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => (int)r.Level >= minimumLevel);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderByDescending(r => r.Level)
            .ThenBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    #endregion

    #region IRoleRepository 구현 - ConnectedId 관련

    /// <summary>
    /// ConnectedId에 할당된 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByConnectedIdAsync(
        Guid connectedId,
        bool includeInactive = false)
    {
        var query = from r in Query()
                    join cr in _context.Set<ConnectedIdRole>()
                        on r.Id equals cr.RoleId
                    where cr.ConnectedId == connectedId && !cr.IsDeleted
                    select r;

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 역할을 가진 ConnectedId 수 조회
    /// </summary>
    public async Task<int> GetAssignedUserCountAsync(Guid roleId)
    {
        return await _context.Set<ConnectedIdRole>()
            .Where(cr => cr.RoleId == roleId && !cr.IsDeleted)
            .CountAsync();
    }

    #endregion

    #region IRoleRepository 구현 - 권한 관련

    /// <summary>
    /// 특정 권한을 가진 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesWithPermissionAsync(
        Guid organizationId,
        Guid permissionId)
    {
        var query = from r in QueryForOrganization(organizationId)
                    join rp in _context.Set<RolePermission>()
                        on r.Id equals rp.RoleId
                    where rp.PermissionId == permissionId && !rp.IsDeleted
                    select r;

        return await query
            .Distinct()
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 역할의 권한 수 조회
    /// </summary>
    public async Task<int> GetPermissionCountAsync(Guid roleId)
    {
        return await _context.Set<RolePermission>()
            .Where(rp => rp.RoleId == roleId && !rp.IsDeleted)
            .CountAsync();
    }

    #endregion

    #region IRoleRepository 구현 - 만료 관련

    /// <summary>
    /// 만료된 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiredRolesAsync(
        Guid organizationId,
        DateTime asOfDate)
    {
        return await QueryForOrganization(organizationId)
            .Where(r => r.ExpiresAt.HasValue && r.ExpiresAt <= asOfDate)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 곧 만료될 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiringRolesAsync(
        Guid organizationId,
        TimeSpan withinTimeSpan)
    {
        var futureDate = DateTime.UtcNow.Add(withinTimeSpan);

        return await QueryForOrganization(organizationId)
            .Where(r =>
                r.ExpiresAt.HasValue &&
                r.ExpiresAt <= futureDate &&
                r.ExpiresAt > DateTime.UtcNow)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    #endregion

    #region IRoleRepository 구현 - 중복 확인

    /// <summary>
    /// RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsAsync(
        Guid organizationId,
        string roleKey,
        Guid? excludeRoleId = null)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync();
    }

    /// <summary>
    /// Application별 RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsInApplicationAsync(
        Guid organizationId,
        Guid applicationId,
        string roleKey,
        Guid? excludeRoleId = null)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r =>
                r.ApplicationId == applicationId &&
                r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync();
    }

    #endregion

    #region IRoleRepository 구현 - 통계

    /// <summary>
    /// 조직의 역할 통계 조회
    /// </summary>
    public async Task<RoleStatistics> GetStatisticsAsync(Guid organizationId)
    {
        var roles = await QueryForOrganization(organizationId).ToListAsync();

        var now = DateTime.UtcNow;
        var stats = new RoleStatistics
        {
            TotalCount = roles.Count,
            ActiveCount = roles.Count(r => r.IsActive),
            InactiveCount = roles.Count(r => !r.IsActive),
            ExpiredCount = roles.Count(r => r.ExpiresAt.HasValue && r.ExpiresAt <= now),
            LastCreatedAt = roles.Any() ? roles.Max(r => r.CreatedAt) : null
        };

        // 카테고리별 분포
        stats.CountByCategory = roles
            .Where(r => r.Category.HasValue)
            .GroupBy(r => r.Category!.Value)
            .ToDictionary(g => g.Key, g => g.Count());

        // 스코프별 분포
        stats.CountByScope = roles
            .GroupBy(r => r.Scope)
            .ToDictionary(g => g.Key, g => g.Count());

        // 레벨별 분포
        stats.CountByLevel = roles
            .GroupBy(r => (int)r.Level)
            .ToDictionary(g => g.Key, g => g.Count());

        // 권한 및 사용자 수 통계는 별도 쿼리로 계산
        if (roles.Any())
        {
            var roleIds = roles.Select(r => r.Id).ToList();

            // 평균 권한 수 계산
            var permissionCounts = await _context.Set<RolePermission>()
                .Where(rp => roleIds.Contains(rp.RoleId) && !rp.IsDeleted)
                .GroupBy(rp => rp.RoleId)
                .Select(g => g.Count())
                .ToListAsync();

            stats.AveragePermissionCount = permissionCounts.Any()
                ? permissionCounts.Average()
                : 0;

            // 평균 사용자 수 계산
            var userCounts = await _context.Set<ConnectedIdRole>()
                .Where(cr => roleIds.Contains(cr.RoleId) && !cr.IsDeleted)
                .GroupBy(cr => cr.RoleId)
                .Select(g => g.Count())
                .ToListAsync();

            stats.AverageUserCount = userCounts.Any()
                ? userCounts.Average()
                : 0;
        }

        return stats;
    }

    #endregion

    #region IRoleRepository 구현 - 관계 로딩

    /// <summary>
    /// 관련 엔티티를 포함하여 조회
    /// </summary>
    public async Task<Role?> GetWithRelatedDataAsync(
        Guid id,
        bool includePermissions = false,
        bool includeUsers = false,
        bool includeParent = false,
        bool includeChildren = false,
        bool includeApplication = false)
    {
        var query = Query().Where(r => r.Id == id);

        if (includePermissions)
        {
            query = query
                .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission);
        }

        if (includeUsers)
        {
            query = query
                .Include(r => r.ConnectedIdRoles)
                .ThenInclude(cr => cr.ConnectedId);
        }

        if (includeParent)
        {
            query = query.Include(r => r.ParentRole);
        }

        if (includeChildren)
        {
            query = query.Include(r => r.ChildRoles);
        }

        if (includeApplication)
        {
            query = query.Include(r => r.PlatformApplication);
        }

        return await query.FirstOrDefaultAsync();
    }

    #endregion

    #region 기존 메서드 정리 (중복 제거)

    /// <summary>
    /// 이름으로 역할 조회 - 기존 메서드 유지
    /// </summary>
    public async Task<Role?> GetByNameAsync(
        string name,
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        return await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r => r.Name == name, cancellationToken);
    }

    /// <summary>
    /// 조직별 모든 역할 조회 - override 키워드로 부모 메서드 재정의
    /// </summary>
    public override async Task<IEnumerable<Role>> GetByOrganizationIdAsync(Guid organizationId)
    {
        return await GetByOrganizationAsync(organizationId, includeInactive: true);
    }

    /// <summary>
    /// 애플리케이션별 역할 조회 - GetByApplicationAsync로 통합
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationIdAsync(
        Guid applicationId,
        CancellationToken cancellationToken = default)
    {
        return await GetByApplicationAsync(applicationId, includeInactive: true);
    }

    /// <summary>
    /// 시스템 역할 조회 (ApplicationId가 null인 역할들)
    /// </summary>
    public async Task<IEnumerable<Role>> GetSystemRolesAsync(
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        return await QueryForOrganization(organizationId)
            .Where(r => r.ApplicationId == null)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 활성화된 역할만 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetActiveRolesAsync(
        Guid organizationId,
        Guid? applicationId = null,
        CancellationToken cancellationToken = default)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.IsActive);

        if (applicationId.HasValue)
        {
            query = query.Where(r =>
                r.ApplicationId == applicationId ||
                r.ApplicationId == null);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 추가 메서드들

    /// <summary>
    /// ConnectedId의 역할 조회
    /// </summary>
    public async Task<List<Role>> GetRolesByConnectedIdAsync(
        Guid connectedId,
        Guid organizationId,
        Guid? applicationId = null,
        CancellationToken cancellationToken = default)
    {
        var query = from r in QueryForOrganization(organizationId)
                    join cr in _context.Set<ConnectedIdRole>()
                        on r.Id equals cr.RoleId
                    where cr.ConnectedId == connectedId && !cr.IsDeleted
                    select r;

        if (applicationId.HasValue)
        {
            query = query.Where(r =>
                r.ApplicationId == applicationId ||
                r.ApplicationId == null);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// ConnectedId가 특정 역할을 가지고 있는지 확인
    /// </summary>
    public async Task<bool> HasRoleAsync(
        Guid connectedId,
        string roleName,
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        return await (from r in QueryForOrganization(organizationId)
                      join cr in _context.Set<ConnectedIdRole>()
                          on r.Id equals cr.RoleId
                      where cr.ConnectedId == connectedId &&
                            r.Name == roleName &&
                            !cr.IsDeleted
                      select r).AnyAsync(cancellationToken);
    }

    /// <summary>
    /// 여러 ConnectedId의 역할 조회 (배치 처리)
    /// </summary>
    public async Task<Dictionary<Guid, List<Role>>> GetRolesByConnectedIdsAsync(
        IEnumerable<Guid> connectedIds,
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        var connectedIdList = connectedIds.ToList();

        var roleAssignments = await (
            from r in QueryForOrganization(organizationId)
            join cr in _context.Set<ConnectedIdRole>()
                on r.Id equals cr.RoleId
            where connectedIdList.Contains(cr.ConnectedId) && !cr.IsDeleted
            select new { cr.ConnectedId, Role = r }
        ).ToListAsync(cancellationToken);

        // 결과를 Dictionary로 변환
        var result = connectedIdList.ToDictionary(
            id => id,
            id => new List<Role>()
        );

        foreach (var assignment in roleAssignments)
        {
            result[assignment.ConnectedId].Add(assignment.Role);
        }

        // 각 역할 목록 정렬
        foreach (var roleList in result.Values)
        {
            roleList.Sort((r1, r2) =>
            {
                var priorityComparison = r1.Priority.CompareTo(r2.Priority);
                return priorityComparison != 0
                    ? priorityComparison
                    : string.Compare(r1.Name, r2.Name, StringComparison.Ordinal);
            });
        }

        return result;
    }

    #endregion

    #region 헬퍼 메서드

    /// <summary>
    /// 특정 루트에서 시작하는 트리 구축
    /// </summary>
    private IEnumerable<Role> BuildTreeFromRoot(
        List<Role> allRoles,
        Role root,
        int maxDepth)
    {
        var result = new List<Role> { root };

        if (maxDepth > 0)
        {
            var children = allRoles.Where(r => r.ParentRoleId == root.Id);
            foreach (var child in children)
            {
                result.AddRange(BuildTreeFromRoot(allRoles, child, maxDepth - 1));
            }
        }

        return result;
    }

    /// <summary>
    /// 계층 구조 빌드
    /// </summary>
    private IEnumerable<Role> BuildHierarchy(List<Role> allRoles)
    {
        var lookup = allRoles.ToLookup(r => r.ParentRoleId);
        var result = new List<Role>();

        // 루트 역할부터 시작
        var rootRoles = lookup[null]
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name);

        foreach (var root in rootRoles)
        {
            result.Add(root);
            AddChildrenRecursively(root, lookup, result);
        }

        return result;
    }

    /// <summary>
    /// 재귀적으로 하위 역할들 추가
    /// </summary>
    private void AddChildrenRecursively(
        Role parent,
        ILookup<Guid?, Role> lookup,
        List<Role> result)
    {
        var children = lookup[parent.Id]
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name);

        foreach (var child in children)
        {
            result.Add(child);
            AddChildrenRecursively(child, lookup, result);
        }
    }

    #endregion

    #region IOrganizationScopedRepository 구현 (BaseRepository에서 상속)

    // BaseRepository에서 이미 구현된 메서드들은 그대로 사용
    // 필요시 override로 커스터마이징 가능

    #endregion
}