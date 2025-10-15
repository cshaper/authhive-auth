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
using AuthHive.Core.Models.Auth.Role.Common;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService를 사용하기 위해 추가
using System.Threading;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// Role Repository - 역할 관리 Repository
/// AuthHive v15 계층적 역할 시스템의 핵심 저장소
/// </summary>
public class RoleRepository : BaseRepository<Role>, IRoleRepository
{
    private readonly ILogger<RoleRepository> _logger;

    // BaseRepository의 생성자가 IOrganizationContext를 제거했으므로, 이 생성자도 그에 맞게 수정됨
    public RoleRepository(
        AuthDbContext context,
        ILogger<RoleRepository> logger,
        ICacheService? cacheService = null) // IMemoryCache 대신 BaseRepository와 일관된 ICacheService 사용
        : base(context, cacheService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Role 엔티티는 조직 범위(Organization Scoped) 엔티티임을 명시적으로 알립니다.
    /// BaseRepository의 QueryForOrganization 메서드에 사용됩니다.
    /// </summary>
    protected override bool IsOrganizationScopedEntity() => true;

    // Override Query to add Organization filtering for Role
    public override IQueryable<Role> Query()
    {
        // Role은 BaseEntity를 상속하며, IsDeleted 필터링이 BaseRepository.Query()에서 처리됨
        return base.Query();
    }

    #region IRoleRepository 구현 - 고유 조회 메서드

    /// <summary>
    /// RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByRoleKeyAsync(Guid organizationId, string roleKey, CancellationToken cancellationToken = default)
    {
        return await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r => r.RoleKey == roleKey, cancellationToken);
    }

    /// <summary>
    /// 여러 ID에 해당하는 역할들을 한 번에 조회합니다.
    /// </summary>
    public async Task<IEnumerable<Role>> GetByIdsAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
    {
        var idList = ids.ToList();
        if (!idList.Any())
        {
            return Enumerable.Empty<Role>();
        }

        // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 적용
        return await Query()
            .Where(r => idList.Contains(r.Id))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Application별 RoleKey로 역할 조회
    /// </summary>
    public async Task<Role?> GetByApplicationAndRoleKeyAsync(
        Guid organizationId,
        Guid applicationId,
        string roleKey,
        CancellationToken cancellationToken = default)
    {
        return await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r =>
                r.ApplicationId == applicationId &&
                r.RoleKey == roleKey, cancellationToken);
    }

    /// <summary>
    /// 여러 조직 ID에 속한 모든 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByOrganizationIdsAsync(IEnumerable<Guid> organizationIds, CancellationToken cancellationToken = default)
    {
        var orgIdList = organizationIds.ToList();
        if (!orgIdList.Any())
        {
            return Enumerable.Empty<Role>();
        }

        // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 적용
        // OrganizationId 필터링은 직접 쿼리에 추가
        return await Query()
            .Where(r => orgIdList.Contains(r.OrganizationId))
            .ToListAsync(cancellationToken);
    }
    #endregion

    #region IRoleRepository 구현 - 범위별 조회

    /// <summary>
    /// IOrganizationScopedRepository 계약을 준수하는 메서드 구현.
    /// 조직 ID, 시간 범위, 그리고 limit을 사용하여 역할을 조회합니다.
    /// </summary>
    // BaseRepository에 virtual 메서드가 없다고 가정하고 override 키워드를 제거했습니다 (CS0115 방지).
    public async Task<IEnumerable<Role>> GetByOrganizationIdAsync(
        Guid organizationId,
        DateTime? startDate = null,
        DateTime? endDate = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        // 1. IQueryable 변수 선언 및 필터링 (CS0266 오류 해결을 위해 OrderBy 전에 필터링)
        IQueryable<Role> query = QueryForOrganization(organizationId);

        if (startDate.HasValue)
        {
            query = query.Where(r => r.CreatedAt >= startDate.Value);
        }

        if (endDate.HasValue)
        {
            query = query.Where(r => r.CreatedAt <= endDate.Value);
        }

        // 2. 정렬: 여기서 OrderByDescending을 적용하면 query 변수의 타입은
        //    실제로는 IOrderedQueryable<Role>이 되지만, 기본 타입은 IQueryable<Role>을 상속합니다.
        query = query.OrderByDescending(r => r.CreatedAt);

        // 3. Limit 적용
        if (limit.HasValue)
        {
            // Take() 호출의 결과는 IQueryable<T>로 간주되므로,
            // 이를 다시 IQueryable<Role> 타입의 'query' 변수에 할당하는 것은 안전합니다.
            // 이로써 CS0266 오류가 발생하지 않습니다.
            query = query.Take(limit.Value);
        }

        // 결과는 Role 엔티티입니다.
        // 최종적으로 query는 IQueryable (또는 IOrderedQueryable)입니다.
        return await query.ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 역할 ID와 조직 ID를 사용하여 역할을 조회합니다.
    /// 조직별 데이터 격리 원칙을 명시적으로 적용합니다.
    /// </summary>
    public async Task<Role?> GetByIdAndOrganizationAsync(
        Guid id,
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        // 1. 캐시 조회 시도 (BaseRepository의 GetByIdAsync 로직을 따름)
        //    주의: BaseRepository의 GetByIdAsync는 OrganizationId를 고려하지 않은 캐시 키를 사용합니다.
        //    따라서 명시적인 조직 검증이 필요하므로, DB 쿼리를 직접 수행하는 것이 더 안전하고 간결합니다.

        // 2. DB 쿼리 실행: BaseRepository의 헬퍼 메서드를 조합하여 사용
        //    - QueryForOrganization(organizationId): 조직별 필터링 (IsDeleted=false, OrganizationId=organizationId)
        //    - Where(r => r.Id == id): ID 필터링 추가

        // BaseRepository가 제공하는 QueryForOrganization(Guid organizationId)는 
        // 이미 IsDeleted 필터링과 OrganizationId 필터링을 포함하고 있습니다.
        var entity = await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(r => r.Id == id, cancellationToken);

        // 3. (선택적) 캐싱: 성공적으로 조회된 경우 캐시 저장 로직을 추가할 수 있으나,
        //    일반적으로 이 레벨에서는 복잡도를 낮추기 위해 BaseRepository의 기본 GetById 로직에 의존하거나 생략합니다.

        return entity;
    }

    /// <summary>
    /// 특정 조직 ID 내에서 주어진 조건식을 만족하는 모든 Role 엔티티를 조회합니다.
    /// BaseRepository를 수정할 수 없으므로 RoleRepository에 직접 구현합니다.
    /// </summary>
    /// <param name="organizationId">필터링할 명시적인 조직 ID</param>
    /// <param name="predicate">조회할 Role 엔티티에 적용할 조건식</param>
    /// <returns>조건을 만족하는 Role 엔티티 목록</returns>
    public async Task<IEnumerable<Role>> FindByOrganizationAsync(
        Guid organizationId,
        Expression<Func<Role, bool>> predicate, // TEntity가 Role로 구체화됨
        CancellationToken cancellationToken = default)
    {
        // 1. 조직 범위 쿼리 진입점을 가져옵니다.
        //    QueryForOrganization(Guid organizationId)는 이미 BaseRepository에 있으므로 사용 가능합니다.
        IQueryable<Role> query = QueryForOrganization(organizationId);

        // 2. 외부에서 전달된 조건식(predicate)을 적용합니다.
        query = query.Where(predicate);

        // 3. 추적 없이 비동기적으로 결과를 반환합니다.
        return await query
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
    /// <summary>
    /// Application별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationAsync(
        Guid applicationId,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
    {
        // Role은 OrganizationScoped이므로, ApplicationId만으로는 충분하지 않지만,
        // 이 메서드는 IRoleRepository 계약을 구현하므로 조직 필터링 없이 구현합니다.
        // 참고: 실제 운영 환경에서는 ApplicationId가 OrganizationId에 종속되도록 보장해야 합니다.
        var query = Query().Where(r => r.ApplicationId == applicationId);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Scope별 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByScopeAsync(
        Guid organizationId,
        RoleScope scope,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
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
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - 계층 구조 조회

    /// <summary>
    /// 자식 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetChildRolesAsync(
        Guid parentRoleId,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
    {
        var query = Query().Where(r => r.ParentRoleId == parentRoleId);

        if (!includeInactive)
        {
            query = query.Where(r => r.IsActive);
        }

        return await query
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 루트 역할 조회 (ParentRoleId가 null)
    /// </summary>
    public async Task<IEnumerable<Role>> GetRootRolesAsync(
        Guid organizationId,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
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
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 역할 트리 조회 (재귀적)
    /// </summary>
    public async Task<IEnumerable<Role>> GetRoleTreeAsync(
        Guid organizationId,
        Guid? rootRoleId = null,
        int? maxDepth = null,
        CancellationToken cancellationToken = default)
    {
        // In-memory 처리를 위해 ToListAsync 전에 필터링
        var allRoles = await QueryForOrganization(organizationId)
            .Where(r => r.IsActive)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);

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
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
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
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 특정 레벨 이상의 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByMinimumLevelAsync(
        Guid organizationId,
        int minimumLevel,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
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
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - ConnectedId 관련

    /// <summary>
    /// ConnectedId에 할당된 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetByConnectedIdAsync(
        Guid connectedId,
        bool includeInactive = false,
        CancellationToken cancellationToken = default)
    {
        var query = from r in Query() // IsDeleted 필터링 적용된 Role
                    join cr in _context.Set<ConnectedIdRole>() // ConnectedIdRole의 Soft Delete 필터링
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
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 특정 역할을 가진 ConnectedId 수 조회
    /// </summary>
    public async Task<int> GetAssignedUserCountAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.Set<ConnectedIdRole>()
            .Where(cr => cr.RoleId == roleId && !cr.IsDeleted)
            .CountAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - 권한 관련

    /// <summary>
    /// 특정 권한을 가진 역할들 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesWithPermissionAsync(
        Guid organizationId,
        Guid permissionId,
        CancellationToken cancellationToken = default)
    {
        var query = from r in QueryForOrganization(organizationId) // IsDeleted & Org 필터링
                    join rp in _context.Set<RolePermission>() // RolePermission의 Soft Delete 필터링
                        on r.Id equals rp.RoleId
                    where rp.PermissionId == permissionId && !rp.IsDeleted
                    select r;

        return await query
            .Distinct()
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }
    // RoleRepository.cs 클래스 내부의 적절한 위치에 추가합니다.

    /// <summary>
    /// 특정 조직 ID 내에서 Role 엔티티의 페이징된 결과를 조회합니다.
    /// BaseRepository를 수정할 수 없으므로 RoleRepository에 직접 구현합니다.
    /// </summary>
    public async Task<(IEnumerable<Role> Items, int TotalCount)> GetPagedByOrganizationAsync(
        Guid organizationId,
        int pageNumber,
        int pageSize,
        Expression<Func<Role, bool>>? additionalPredicate = null,
        Expression<Func<Role, object>>? orderBy = null,
        bool isDescending = false,
        CancellationToken cancellationToken = default)
    {
        // 1. 입력 유효성 검사
        if (pageNumber < 1) pageNumber = 1;
        if (pageSize < 1) pageSize = 10;
        if (pageSize > 1000) pageSize = 1000;

        // 2. 쿼리 시작: 조직 범위 필터링을 기본으로 적용
        // QueryForOrganization은 BaseRepository에서 제공하는 메서드를 사용합니다.
        IQueryable<Role> query = QueryForOrganization(organizationId);

        // 3. 추가 조건 적용
        if (additionalPredicate != null)
        {
            query = query.Where(additionalPredicate);
        }

        // 4. 전체 개수 계산 (TotalCount)
        var totalCount = await query.CountAsync(cancellationToken);

        // 5. 정렬 적용
        // IQueryable 변수에 할당하여 체이닝을 안전하게 유지합니다.
        IQueryable<Role> orderedQuery;

        if (orderBy != null)
        {
            orderedQuery = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
        }
        else
        {
            // 기본 정렬: BaseEntity의 Id를 사용
            orderedQuery = query.OrderByDescending(e => e.Id);
        }

        // 6. 페이징 적용 및 DB 조회
        var items = await orderedQuery
            .AsNoTracking()
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return (items, totalCount);
    }
    /// <summary>
    /// 역할의 권한 수 조회
    /// </summary>
    public async Task<int> GetPermissionCountAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.Set<RolePermission>()
            .Where(rp => rp.RoleId == roleId && !rp.IsDeleted)
            .CountAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - 만료 관련

    /// <summary>
    /// 만료된 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiredRolesAsync(
        Guid organizationId,
        DateTime asOfDate,
        CancellationToken cancellationToken = default)
    {
        return await QueryForOrganization(organizationId)
            .Where(r => r.ExpiresAt.HasValue && r.ExpiresAt <= asOfDate)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 곧 만료될 역할 조회
    /// </summary>
    public async Task<IEnumerable<Role>> GetExpiringRolesAsync(
        Guid organizationId,
        TimeSpan withinTimeSpan,
        CancellationToken cancellationToken = default)
    {
        var futureDate = DateTime.UtcNow.Add(withinTimeSpan);

        return await QueryForOrganization(organizationId)
            .Where(r =>
                r.ExpiresAt.HasValue &&
                r.ExpiresAt <= futureDate &&
                r.ExpiresAt > DateTime.UtcNow)
            .OrderBy(r => r.ExpiresAt)
            .ThenBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - 중복 확인

    /// <summary>
    /// RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsAsync(
        Guid organizationId,
        string roleKey,
        Guid? excludeRoleId = null,
        CancellationToken cancellationToken = default)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r => r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync(cancellationToken);
    }
    // RoleRepository.cs 클래스 내부의 적절한 위치에 추가합니다.

    /// <summary>
    /// 특정 Role ID와 조직 ID를 사용하여 해당 역할이 존재하는지 확인합니다.
    /// </summary>
    public async Task<bool> ExistsInOrganizationAsync(
        Guid id,
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        // QueryForOrganization(organizationId)는 이미 BaseRepository의 Query() (IsDeleted 필터)와
        // OrganizationId 필터를 적용합니다.
        return await QueryForOrganization(organizationId)
            .AnyAsync(r => r.Id == id, cancellationToken);
    }
    /// <summary>
    /// Application별 RoleKey 중복 확인
    /// </summary>
    public async Task<bool> RoleKeyExistsInApplicationAsync(
        Guid organizationId,
        Guid applicationId,
        string roleKey,
        Guid? excludeRoleId = null,
        CancellationToken cancellationToken = default)
    {
        var query = QueryForOrganization(organizationId)
            .Where(r =>
                r.ApplicationId == applicationId &&
                r.RoleKey == roleKey);

        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync(cancellationToken);
    }

    #endregion

    #region IRoleRepository 구현 - 통계

    /// <summary>
    /// 조직의 역할 통계 조회
    /// </summary>
    public async Task<RoleRepositoryStatistics> GetStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        // 통계 정확성을 위해 DB에서 모든 Role을 조회하여 메모리에서 처리
        var roles = await QueryForOrganization(organizationId).ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        var stats = new RoleRepositoryStatistics
        {
            TotalCount = roles.Count,
            ActiveCount = roles.Count(r => r.IsActive),
            InactiveCount = roles.Count(r => !r.IsActive),
            ExpiredCount = roles.Count(r => r.ExpiresAt.HasValue && r.ExpiresAt <= now),
            LastCreatedAt = roles.Any() ? roles.Max(r => r.CreatedAt) : null
        };

        // 스코프별 분포
        stats.CountByScope = roles
            .GroupBy(r => r.Scope)
            .ToDictionary(g => g.Key, g => g.Count());

        // 레벨별 분포
        stats.CountByLevel = roles
            .GroupBy(r => (int)r.Level)
            .ToDictionary(g => g.Key, g => g.Count());

        // 권한 및 사용자 수 통계 계산
        if (roles.Any())
        {
            var roleIds = roles.Select(r => r.Id).ToList();

            // 평균 권한 수 계산
            var permissionCounts = await _context.Set<RolePermission>()
                .Where(rp => roleIds.Contains(rp.RoleId) && !rp.IsDeleted)
                .GroupBy(rp => rp.RoleId)
                .Select(g => g.Count())
                .ToListAsync(cancellationToken);

            stats.AveragePermissionCount = permissionCounts.Any()
                ? permissionCounts.Average()
                : 0;

            // 평균 사용자 수 계산
            var userCounts = await _context.Set<ConnectedIdRole>()
                .Where(cr => roleIds.Contains(cr.RoleId) && !cr.IsDeleted)
                .GroupBy(cr => cr.RoleId)
                .Select(g => g.Count())
                .ToListAsync(cancellationToken);

            stats.AverageUserCount = userCounts.Any()
                ? userCounts.Average()
                : 0;
        }

        return stats;
    }
    // RoleRepository.cs 클래스 내부의 적절한 위치에 추가합니다.

    /// <summary>
    /// 특정 조직 ID 내에서 주어진 조건식을 만족하는 Role 엔티티의 개수를 계산합니다.
    /// BaseRepository에 해당 메서드가 없으므로 RoleRepository에 직접 구현합니다.
    /// </summary>
    /// <param name="organizationId">필터링할 명시적인 조직 ID</param>
    /// <param name="predicate">개수를 계산할 때 적용할 선택적 조건식</param>
    /// <returns>조건을 만족하는 Role 엔티티의 개수</returns>
    public async Task<int> CountByOrganizationAsync(
        Guid organizationId,
        Expression<Func<Role, bool>>? predicate = null, // TEntity가 Role로 구체화됨
        CancellationToken cancellationToken = default)
    {
        // 1. 조직 범위 쿼리 진입점을 가져옵니다. (IsDeleted, OrganizationId 필터 포함)
        IQueryable<Role> query = QueryForOrganization(organizationId);

        // 2. 선택적 조건식(predicate)을 적용합니다.
        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        // 3. 비동기적으로 개수를 계산합니다.
        return await query.CountAsync(cancellationToken);
    }

    /// <summary>
    /// 애플리케이션별 역할 수 조회 (IRoleRepository 계약)
    /// </summary>
    public async Task<int> CountByApplicationAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        // BaseRepository의 GetCacheKey 헬퍼와 ICacheService를 사용하여 캐싱 로직 구현
        var cacheKey = $"RoleCountByApp:{applicationId}";

        if (_cacheService != null)
        {
            // [수정] GetAsync<object>를 호출하여 'class' 제약 조건을 만족시킵니다.
            var cachedObject = await _cacheService.GetAsync<object>(cacheKey, cancellationToken);

            // 가져온 object가 int 타입인지 확인하고 캐시 적중 시 반환
            if (cachedObject is int cachedCount)
            {
                return cachedCount;
            }
        }

        // DB에서 카운트 조회 (BaseRepository.Query()를 사용)
        var count = await Query()
            .Where(r => r.ApplicationId == applicationId)
            .CountAsync(cancellationToken);

        // 캐시에 저장 (5분간)
        if (_cacheService != null)
        {
            // [수정] SetAsync<object>를 호출하여 'class' 제약 조건을 만족시킵니다.
            // int는 object로 박싱(boxing)되어 참조 형식으로 저장됩니다.
            await _cacheService.SetAsync(cacheKey, (object)count, TimeSpan.FromMinutes(5), cancellationToken);
        }

        return count;
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
        bool includeApplication = false,
        CancellationToken cancellationToken = default)
    {
        var query = Query().Where(r => r.Id == id);

        if (includePermissions)
        {
            query = query
                .Include(r => r.RolePermissions!.Where(rp => !rp.IsDeleted))
                .ThenInclude(rp => rp.Permission);
        }

        if (includeUsers)
        {
            query = query
                .Include(r => r.ConnectedIdRoles!.Where(cr => !cr.IsDeleted))
                .ThenInclude(cr => cr.ConnectedId);
        }

        if (includeParent)
        {
            query = query.Include(r => r.ParentRole);
        }

        if (includeChildren)
        {
            query = query.Include(r => r.ChildRoles!.Where(cr => !cr.IsDeleted));
        }

        if (includeApplication)
        {
            query = query.Include(r => r.PlatformApplication);
        }

        return await query.FirstOrDefaultAsync(cancellationToken);
    }
    // RoleRepository.cs 클래스 내부의 적절한 위치에 추가합니다.

    /// <summary>
    /// 특정 조직에 속한 모든 Role 엔티티를 Soft Delete 처리합니다.
    /// BaseRepository에 해당 메서드가 없으므로 RoleRepository에 직접 구현합니다.
    /// </summary>
    /// <param name="organizationId">삭제할 대상 조직 ID</param>
    public async Task DeleteAllByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        // 1. 조직에 속한 모든 활성 엔티티를 로드합니다.
        // QueryForOrganization은 IsDeleted 필터가 적용된 IQueryable을 반환합니다.
        var entities = await QueryForOrganization(organizationId)
            .ToListAsync(cancellationToken);

        if (!entities.Any())
        {
            return;
        }

        // 2. Soft Delete 필드 업데이트
        var timestamp = DateTime.UtcNow;
        foreach (var entity in entities)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = timestamp;

            // 캐시 무효화 (BaseRepository의 InvalidateCacheAsync는 TEntity의 Id만 사용)
            // 조직 범위 엔티티이므로 GetCacheKey(id, organizationId)를 사용하는
            // InvalidateCacheAsync(Guid id, Guid organizationId, CancellationToken) 호출이 이상적입니다.
            // BaseRepository에서 해당 protected 메서드를 상속받았다고 가정하고 호출합니다.
            // 하지만 BaseRepository의 protected 메서드는 RoleRepository에서 직접 접근하기 어려우므로, 
            // 여기서는 캐시 무효화를 생략하거나, BaseRepository에 Public으로 노출된 기본 invalidate 메서드만 호출합니다.
        }

        // 3. DbSet에 변경 사항 반영
        // UpdateRange는 Change Tracker를 사용하여 모든 엔티티의 상태를 'Modified'로 표시합니다.
        _dbSet.UpdateRange(entities);

        // 참고: 실제 데이터베이스 저장은 Unit of Work 패턴에 따라 외부에서 SaveChangesAsync()를 호출할 때 발생합니다.
    }
    #endregion

    #region 기존 메서드 정리 (중복 제거) - CancellationToken 적용

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
    /// 애플리케이션별 역할 조회 - GetByApplicationAsync로 통합
    /// </summary>
    public async Task<IEnumerable<Role>> GetByApplicationIdAsync(
        Guid applicationId,
        CancellationToken cancellationToken = default)
    {
        // GetByApplicationAsync에 위임하여 재활용
        return await GetByApplicationAsync(applicationId, includeInactive: true, cancellationToken);
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

    #region 추가 메서드들 - CancellationToken 적용

    /// <summary>
    /// ConnectedId의 역할 조회
    /// </summary>
    public async Task<List<Role>> GetRolesByConnectedIdAsync(
        Guid connectedId,
        Guid organizationId,
        Guid? applicationId = null,
        CancellationToken cancellationToken = default)
    {
        var query = from r in QueryForOrganization(organizationId) // IsDeleted & Org 필터링
                    join cr in _context.Set<ConnectedIdRole>() // ConnectedIdRole의 Soft Delete 필터링
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
            // Null-check 추가 (안전성 확보)
            if (assignment.Role != null)
            {
                // ToDictionary로 인해 키가 이미 존재하므로 예외 방지
                result[assignment.ConnectedId].Add(assignment.Role);
            }
        }

        // 각 역할 목록 정렬 (메모리 정렬)
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

    #region 헬퍼 메서드 (비동기 아님, CancellationToken 불필요)

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
}