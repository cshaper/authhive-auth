using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// Role Repository - 역할 관리 Repository
/// AuthHive v15 계층적 역할 시스템의 핵심 저장소
/// </summary>
public class RoleRepository : BaseRepository<Role>, IRoleRepository
{
    public RoleRepository(AuthDbContext context) : base(context)
    {
    }

    #region 기본 조회

    /// <summary>
    /// RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByRoleKeyAsync(Guid organizationId, string roleKey)
    {
        return await Query()
            .FirstOrDefaultAsync(r => r.RoleKey == roleKey && r.OrganizationId == organizationId);
    }

    /// <summary>
    /// Application별 RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByApplicationAndRoleKeyAsync(Guid organizationId, Guid applicationId, string roleKey)
    {
        return await Query()
            .FirstOrDefaultAsync(r => r.RoleKey == roleKey &&
                                    r.OrganizationId == organizationId &&
                                    r.ApplicationId == applicationId);
    }

    /// <summary>
    /// 이름으로 역할 조회 (기존 메서드)
    /// </summary>
    public async Task<Role?> GetByNameAsync(string name, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .FirstOrDefaultAsync(r => r.Name == name && r.OrganizationId == organizationId, cancellationToken);
    }

    /// <summary>
    /// 조직의 모든 역할 조회 (인터페이스 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetByOrganizationAsync(Guid organizationId, bool includeInactive = false)
    {
        var query = Query().Where(r => r.OrganizationId == organizationId);

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
    /// 조직별 모든 역할 조회 (기존 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetByOrganizationIdAsync(Guid organizationId)
    {
        return await Query()
            .Where(r => r.OrganizationId == organizationId)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// Application별 역할 조회 (인터페이스 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationAsync(Guid applicationId, bool includeInactive = false)
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
    public async Task<IEnumerable<Role>> GetByScopeAsync(Guid organizationId, RoleScope scope, bool includeInactive = false)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.Scope == scope);

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
    public async Task<IEnumerable<Role>> GetByCategoryAsync(Guid organizationId, RoleCategory category, bool includeInactive = false)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.Category == category);

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
    /// 애플리케이션별 역할 조회 (기존 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationIdAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(r => r.ApplicationId == applicationId)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 시스템 역할 조회 (ApplicationId가 null인 역할들)
    /// </summary>
    public async Task<IEnumerable<Role>> GetSystemRolesAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(r => r.OrganizationId == organizationId && r.ApplicationId == null)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 활성화된 역할만 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetActiveRolesAsync(Guid organizationId, Guid? applicationId = null, CancellationToken cancellationToken = default)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.IsActive);

        if (applicationId.HasValue)
        {
            query = query.Where(r => r.ApplicationId == applicationId || r.ApplicationId == null);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 레벨별 조회 메서드

    /// <summary>
    /// 특정 레벨의 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByLevelAsync(Guid organizationId, int level, bool includeInactive = false)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.Level == level);

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
    public async Task<IEnumerable<Role>> GetByMinimumLevelAsync(Guid organizationId, int minimumLevel, bool includeInactive = false)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.Level >= minimumLevel);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderByDescending(r => r.Level) // 높은 레벨부터
            .ThenBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    #endregion

    #region ConnectedId 관련 조회

    /// <summary>
    /// ConnectedId에 할당된 역할 조회 (인터페이스 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetByConnectedIdAsync(Guid connectedId, bool includeInactive = false)
    {
        var query = from r in Query()
                    join cr in _context.Set<ConnectedIdRole>() on r.Id equals cr.RoleId
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

    #region 권한 관련 조회

    /// <summary>
    /// 특정 권한을 가진 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesWithPermissionAsync(Guid organizationId, Guid permissionId)
    {
        return await Query()
            .Join(_context.Set<RolePermission>(),
                  r => r.Id,
                  rp => rp.RoleId,
                  (r, rp) => new { Role = r, RolePermission = rp })
            .Where(joined =>
                joined.RolePermission.PermissionId == permissionId &&
                joined.Role.OrganizationId == organizationId &&
                !joined.RolePermission.IsDeleted)
            .Select(joined => joined.Role)
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

    #region 만료 관련 조회

    /// <summary>
    /// 만료된 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiredRolesAsync(Guid organizationId, DateTime asOfDate)
    {
        return await Query()
            .Where(r => r.OrganizationId == organizationId &&
                       r.ExpiresAt.HasValue &&
                       r.ExpiresAt <= asOfDate)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 곧 만료될 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiringRolesAsync(Guid organizationId, TimeSpan withinTimeSpan)
    {
        var futureDate = DateTime.UtcNow.Add(withinTimeSpan);

        return await Query()
            .Where(r => r.OrganizationId == organizationId &&
                       r.ExpiresAt.HasValue &&
                       r.ExpiresAt <= futureDate &&
                       r.ExpiresAt > DateTime.UtcNow)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync();
    }

    #endregion

    #region 중복 확인 메서드

    /// <summary>
    /// RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsAsync(Guid organizationId, string roleKey, Guid? excludeRoleId = null)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync();
    }

    /// <summary>
    /// Application별 RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsInApplicationAsync(Guid organizationId, Guid applicationId, string roleKey, Guid? excludeRoleId = null)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId &&
                       r.ApplicationId == applicationId &&
                       r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync();
    }

    #endregion

    #region 통계 메서드

    /// <summary>
    /// 조직의 역할 통계 조회
    /// </summary>
    public async Task<RoleStatistics> GetStatisticsAsync(Guid organizationId)
    {
        var roles = await Query()
            .Where(r => r.OrganizationId == organizationId)
            .ToListAsync();

        var now = DateTime.UtcNow;
        var stats = new RoleStatistics
        {
            TotalCount = roles.Count,
            ActiveCount = roles.Count(r => r.IsActive),
            InactiveCount = roles.Count(r => !r.IsActive),
            ExpiredCount = roles.Count(r => r.ExpiresAt.HasValue && r.ExpiresAt <= now),
            LastCreatedAt = roles.Max(r => r.CreatedAt as DateTime?)
        };

        // 카테고리별 분포 (non-nullable enum)
        stats.CountByCategory = roles
            .Where(r => r.Category.HasValue)  // Filter out null categories
            .GroupBy(r => r.Category.Value)   // Use .Value to get non-nullable enum
            .ToDictionary(g => g.Key, g => g.Count());

        // 스코프별 분포 (non-nullable enum)
        stats.CountByScope = roles
            .GroupBy(r => r.Scope)
            .ToDictionary(g => g.Key, g => g.Count());

        // 레벨별 분포
        stats.CountByLevel = roles
            .GroupBy(r => r.Level)
            .ToDictionary(g => g.Key, g => g.Count());

        // 평균 권한 수 계산
        if (roles.Any())
        {
            var permissionCounts = await _context.Set<RolePermission>()
                .Where(rp => roles.Select(r => r.Id).Contains(rp.RoleId) && !rp.IsDeleted)
                .GroupBy(rp => rp.RoleId)
                .Select(g => new { RoleId = g.Key, Count = g.Count() })
                .ToListAsync();

            stats.AveragePermissionCount = permissionCounts.Any()
                ? permissionCounts.Average(pc => pc.Count)
                : 0;

            // 평균 사용자 수 계산
            var userCounts = await _context.Set<ConnectedIdRole>()
                .Where(cr => roles.Select(r => r.Id).Contains(cr.RoleId) && !cr.IsDeleted)
                .GroupBy(cr => cr.RoleId)
                .Select(g => new { RoleId = g.Key, Count = g.Count() })
                .ToListAsync();

            stats.AverageUserCount = userCounts.Any()
                ? userCounts.Average(uc => uc.Count)
                : 0;
        }

        return stats;
    }

    #endregion

    #region 관계 로딩 메서드

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
            query = query.Include(r => r.RolePermissions).ThenInclude(rp => rp.Permission);
        }

        if (includeUsers)
        {
            query = query.Include(r => r.ConnectedIdRoles).ThenInclude(cr => cr.ConnectedId);
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

    #region ConnectedId 기반 역할 조회

    /// <summary>
    /// ConnectedId의 역할 조회
    /// </summary>
    public async Task<List<Role>> GetRolesByConnectedIdAsync(
        Guid connectedId,
        Guid organizationId,
        Guid? applicationId = null,
        CancellationToken cancellationToken = default)
    {
        var query = from r in Query()
                    join cr in _context.Set<ConnectedIdRole>() on r.Id equals cr.RoleId
                    where cr.ConnectedId == connectedId &&
                          r.OrganizationId == organizationId &&
                          !cr.IsDeleted
                    select r;

        if (applicationId.HasValue)
        {
            query = query.Where(r => r.ApplicationId == applicationId || r.ApplicationId == null);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// ConnectedId가 특정 역할을 가지고 있는지 확인
    /// </summary>
    public async Task<bool> HasRoleAsync(Guid connectedId, string roleName, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<ConnectedIdRole>(),
                  r => r.Id,
                  cr => cr.RoleId,
                  (r, cr) => new { Role = r, ConnectedIdRole = cr })
            .AnyAsync(joined =>
                joined.ConnectedIdRole.ConnectedId == connectedId &&
                joined.Role.Name == roleName &&
                joined.Role.OrganizationId == organizationId &&
                !joined.ConnectedIdRole.IsDeleted,
                cancellationToken);
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

        var roleAssignments = await (from r in Query()
                                     join cr in _context.Set<ConnectedIdRole>() on r.Id equals cr.RoleId
                                     where connectedIdList.Contains(cr.ConnectedId) &&
                                           r.OrganizationId == organizationId &&
                                           !cr.IsDeleted
                                     select new { ConnectedId = cr.ConnectedId, Role = r })
            .ToListAsync(cancellationToken);

        var result = connectedIdList.ToDictionary(id => id, id => new List<Role>());

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
                return priorityComparison != 0 ? priorityComparison : string.Compare(r1.Name, r2.Name, StringComparison.Ordinal);
            });
        }

        return result;
    }

    #endregion

    #region 권한 기반 역할 조회

    /// <summary>
    /// 특정 권한을 가진 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesByPermissionAsync(Guid permissionId, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<RolePermission>(),
                  r => r.Id,
                  rp => rp.RoleId,
                  (r, rp) => new { Role = r, RolePermission = rp })
            .Where(joined =>
                joined.RolePermission.PermissionId == permissionId &&
                joined.Role.OrganizationId == organizationId &&
                !joined.RolePermission.IsDeleted)
            .Select(joined => joined.Role)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 권한 스코프를 가진 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesByPermissionScopeAsync(string permissionScope, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<RolePermission>(), r => r.Id, rp => rp.RoleId, (r, rp) => new { Role = r, RolePermission = rp })
            .Join(_context.Set<Permission>(), joined => joined.RolePermission.PermissionId, p => p.Id, (joined, p) => new { joined.Role, Permission = p })
            .Where(final =>
                final.Permission.Scope == permissionScope &&
                final.Role.OrganizationId == organizationId)
            .Select(final => final.Role)
            .Distinct()
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 계층적 역할 관리

    /// <summary>
    /// 하위 역할들 조회 (인터페이스 메서드)
    /// </summary>
    public async Task<IEnumerable<Role>> GetChildRolesAsync(Guid parentRoleId, bool includeInactive = false)
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
    public async Task<IEnumerable<Role>> GetRootRolesAsync(Guid organizationId, bool includeInactive = false)
    {
        var query = Query()
            .Where(r => r.OrganizationId == organizationId && r.ParentRoleId == null);

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
    public async Task<IEnumerable<Role>> GetRoleTreeAsync(Guid organizationId, Guid? rootRoleId = null, int? maxDepth = null)
    {
        var allRoles = await Query()
            .Where(r => r.OrganizationId == organizationId && r.IsActive)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync();

        if (rootRoleId.HasValue)
        {
            var root = allRoles.FirstOrDefault(r => r.Id == rootRoleId);
            if (root == null) return Enumerable.Empty<Role>();

            return BuildTreeFromRoot(allRoles, root, maxDepth ?? int.MaxValue);
        }

        return BuildHierarchy(allRoles);
    }

    /// <summary>
    /// 하위 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetChildRolesAsync(Guid parentRoleId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(r => r.ParentRoleId == parentRoleId)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 상위 역할 조회
    /// </summary>
    public async Task<Role?> GetParentRoleAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        var role = await GetByIdAsync(roleId);
        if (role?.ParentRoleId == null) return null;

        return await GetByIdAsync(role.ParentRoleId.Value);
    }

    /// <summary>
    /// 역할 계층 전체 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRoleHierarchyAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        var allRoles = await Query()
            .Where(r => r.OrganizationId == organizationId)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);

        return BuildHierarchy(allRoles);
    }

    /// <summary>
    /// 특정 역할의 모든 하위 역할 조회 (재귀적)
    /// </summary>
    public async Task<IEnumerable<Role>> GetAllDescendantRolesAsync(Guid parentRoleId, CancellationToken cancellationToken = default)
    {
        var allRoles = await Query().ToListAsync(cancellationToken);
        var descendants = new List<Role>();
        CollectDescendants(allRoles, parentRoleId, descendants);
        return descendants.OrderBy(r => r.Priority).ThenBy(r => r.Name);
    }

    #endregion

    #region 검색 및 필터링

    /// <summary>
    /// 역할 검색
    /// </summary>
    public async Task<IEnumerable<Role>> SearchRolesAsync(
        string searchTerm,
        Guid organizationId,
        Guid? applicationId = null,
        bool? isActive = null,
        CancellationToken cancellationToken = default)
    {
        var query = Query().Where(r => r.OrganizationId == organizationId);

        if (applicationId.HasValue)
        {
            query = query.Where(r => r.ApplicationId == applicationId || r.ApplicationId == null);
        }

        if (isActive.HasValue)
        {
            query = query.Where(r => r.IsActive == isActive.Value);
        }

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(r =>
                r.Name.Contains(searchTerm) ||
                (r.Description != null && r.Description.Contains(searchTerm)));
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 우선순위별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesByPriorityAsync(int priority, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(r => r.Priority == priority && r.OrganizationId == organizationId)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 미사용 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetUnusedRolesAsync(Guid organizationId, int unusedDays = 30, CancellationToken cancellationToken = default)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-unusedDays);

        return await Query()
            .Where(r => r.OrganizationId == organizationId)
            .Where(r => !_context.Set<ConnectedIdRole>().Any(cr => cr.RoleId == r.Id && !cr.IsDeleted))
            .Where(r => r.CreatedAt < cutoffDate)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 통계 및 분석

    /// <summary>
    /// 역할별 사용자 수 통계
    /// </summary>
    public async Task<Dictionary<Guid, int>> GetRoleUsageStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(r => r.OrganizationId == organizationId)
            .Join(_context.Set<ConnectedIdRole>(),
                  r => r.Id,
                  cr => cr.RoleId,
                  (r, cr) => new { RoleId = r.Id, ConnectedIdRole = cr })
            .Where(joined => !joined.ConnectedIdRole.IsDeleted)
            .GroupBy(joined => joined.RoleId)
            .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
    }

    /// <summary>
    /// 애플리케이션별 역할 분포 - nullable 처리
    /// </summary>
    public async Task<Dictionary<string, int>> GetRoleDistributionByApplicationAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        var roles = await Query()
            .Where(r => r.OrganizationId == organizationId)
            .ToListAsync(cancellationToken);

        return roles
            .GroupBy(r => r.ApplicationId?.ToString() ?? "System")
            .ToDictionary(g => g.Key, g => g.Count());
    }

    #endregion

    #region 일괄 작업

    /// <summary>
    /// 역할 일괄 생성
    /// </summary>
    public async Task<int> BulkCreateRolesAsync(IEnumerable<Role> roles, CancellationToken cancellationToken = default)
    {
        var roleList = roles.ToList();

        // 중복 체크 (같은 조직 내에서 동일한 이름의 역할)
        var organizationIds = roleList.Select(r => r.OrganizationId).Distinct();
        var existingRoles = new List<Role>();

        foreach (var orgId in organizationIds)
        {
            var orgRoles = roleList.Where(r => r.OrganizationId == orgId);
            var existingNames = await Query()
                .Where(r => r.OrganizationId == orgId && orgRoles.Select(or => or.Name).Contains(r.Name))
                .Select(r => r.Name)
                .ToListAsync(cancellationToken);

            existingRoles.AddRange(orgRoles.Where(r => existingNames.Contains(r.Name)));
        }

        var newRoles = roleList.Except(existingRoles).ToList();

        if (newRoles.Any())
        {
            await AddRangeAsync(newRoles);
            return newRoles.Count;
        }

        return 0;
    }

    /// <summary>
    /// 역할 상태 일괄 변경
    /// </summary>
    public async Task<int> BulkUpdateStatusAsync(IEnumerable<Guid> roleIds, bool isActive, CancellationToken cancellationToken = default)
    {
        var roles = await Query()
            .Where(r => roleIds.Contains(r.Id))
            .ToListAsync(cancellationToken);

        foreach (var role in roles)
        {
            role.IsActive = isActive;
        }

        if (roles.Any())
        {
            await UpdateRangeAsync(roles);
            return roles.Count;
        }

        return 0;
    }

    /// <summary>
    /// 애플리케이션별 역할 일괄 삭제
    /// </summary>
    public async Task<int> BulkDeleteByApplicationAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        var roles = await Query()
            .Where(r => r.ApplicationId == applicationId)
            .ToListAsync(cancellationToken);

        if (roles.Any())
        {
            await DeleteRangeAsync(roles);
            return roles.Count;
        }

        return 0;
    }

    #endregion

    #region IOrganizationScopedRepository 구현

    public async Task<Role?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .FirstOrDefaultAsync(r => r.Id == id && r.OrganizationId == organizationId);
    }

    public async Task<IEnumerable<Role>> FindByOrganizationAsync(
        Guid organizationId,
        Expression<Func<Role, bool>> predicate)
    {
        return await Query()
            .Where(r => r.OrganizationId == organizationId)
            .Where(predicate)
            .ToListAsync();
    }

    public async Task<(IEnumerable<Role> Items, int TotalCount)> GetPagedByOrganizationAsync(
        Guid organizationId,
        int pageNumber,
        int pageSize,
        Expression<Func<Role, bool>>? predicate = null,
        Expression<Func<Role, object>>? orderBy = null,
        bool isDescending = false)
    {
        var query = Query().Where(r => r.OrganizationId == organizationId);

        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        var totalCount = await query.CountAsync();

        if (orderBy != null)
        {
            query = isDescending
                ? query.OrderByDescending(orderBy)
                : query.OrderBy(orderBy);
        }
        else
        {
            query = query.OrderBy(r => r.Priority).ThenBy(r => r.Name);
        }

        var items = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (items, totalCount);
    }

    public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .AnyAsync(r => r.Id == id && r.OrganizationId == organizationId);
    }

    public async Task<int> CountByOrganizationAsync(
        Guid organizationId,
        Expression<Func<Role, bool>>? predicate = null)
    {
        var query = Query().Where(r => r.OrganizationId == organizationId);

        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        return await query.CountAsync();
    }

    public async Task DeleteAllByOrganizationAsync(Guid organizationId)
    {
        var roles = await Query()
            .Where(r => r.OrganizationId == organizationId)
            .ToListAsync();

        if (roles.Any())
        {
            await DeleteRangeAsync(roles);
        }
    }

    #endregion

    #region 유틸리티

    /// <summary>
    /// 특정 루트에서 시작하는 트리 구축
    /// </summary>
    private IEnumerable<Role> BuildTreeFromRoot(List<Role> allRoles, Role root, int maxDepth)
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
    /// 계층 구조 빌드 (기존 메서드 개선)
    /// </summary>
    private IEnumerable<Role> BuildHierarchy(List<Role> allRoles)
    {
        var lookup = allRoles.ToLookup(r => r.ParentRoleId);
        var result = new List<Role>();

        var rootRoles = lookup[null].OrderBy(r => r.Priority).ThenBy(r => r.Name);

        foreach (var root in rootRoles)
        {
            result.Add(root);
            AddChildrenRecursively(root, lookup, result);
        }

        return result;
    }

    /// <summary>
    /// 재귀적으로 하위 역할들 추가 (기존 메서드)
    /// </summary>
    private void AddChildrenRecursively(Role parent, ILookup<Guid?, Role> lookup, List<Role> result)
    {
        var children = lookup[parent.Id].OrderBy(r => r.Priority).ThenBy(r => r.Name);

        foreach (var child in children)
        {
            result.Add(child);
            AddChildrenRecursively(child, lookup, result);
        }
    }

    /// <summary>
    /// 모든 하위 역할 수집 (재귀적) (기존 메서드)
    /// </summary>
    private void CollectDescendants(List<Role> allRoles, Guid parentId, List<Role> descendants)
    {
        var children = allRoles.Where(r => r.ParentRoleId == parentId);

        foreach (var child in children)
        {
            descendants.Add(child);
            CollectDescendants(allRoles, child.Id, descendants);
        }
    }

    #endregion
}