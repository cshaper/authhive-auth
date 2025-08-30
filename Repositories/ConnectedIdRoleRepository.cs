using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// ConnectedIdRole Repository - ConnectedId와 Role 매핑 관리 Repository
/// AuthHive v15 권한 시스템의 핵심 연결고리
/// </summary>
public class ConnectedIdRoleRepository : BaseRepository<ConnectedIdRole>, IConnectedIdRoleRepository
{
    public ConnectedIdRoleRepository(AuthDbContext context) : base(context)
    {
    }

    #region 기본 조회 (Legacy Methods - 호환성 유지)

    /// <summary>
    /// ConnectedId와 RoleId로 매핑 조회
    /// </summary>
    public async Task<ConnectedIdRole?> GetByConnectedIdAndRoleAsync(Guid connectedId, Guid roleId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .FirstOrDefaultAsync(cr => cr.ConnectedId == connectedId && cr.RoleId == roleId, cancellationToken);
    }

    /// <summary>
    /// ConnectedId의 모든 역할 매핑 조회 (Legacy)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByConnectedIdAsync(Guid connectedId, bool includeExpired = false, CancellationToken cancellationToken = default)
    {
        var query = Query().Where(cr => cr.ConnectedId == connectedId);

        if (!includeExpired)
        {
            query = query.Where(cr => !cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.Role.Priority)
            .ThenBy(cr => cr.Role.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 특정 역할을 가진 모든 ConnectedId 조회 (Legacy)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByRoleIdAsync(Guid roleId, bool includeExpired = false, CancellationToken cancellationToken = default)
    {
        var query = Query().Where(cr => cr.RoleId == roleId);

        if (!includeExpired)
        {
            query = query.Where(cr => !cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.AssignedAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 조직별 모든 역할 매핑 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByOrganizationIdAsync(Guid organizationId, bool includeExpired = false, CancellationToken cancellationToken = default)
    {
        var query = Query().Where(cr => cr.OrganizationId == organizationId);

        if (!includeExpired)
        {
            query = query.Where(cr => !cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.AssignedAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 애플리케이션별 역할 매핑 조회 (Legacy)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByApplicationIdAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
            .Where(joined => joined.Role.ApplicationId == applicationId)
            .Where(joined => !joined.ConnectedIdRole.ExpiresAt.HasValue || joined.ConnectedIdRole.ExpiresAt > DateTime.UtcNow)
            .Select(joined => joined.ConnectedIdRole)
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.AssignedAt)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 기본 조회 (Interface Implementation)

    /// <summary>
    /// ConnectedId의 활성 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetActiveRolesAsync(
        Guid connectedId,
        Guid? applicationId = null,
        bool includeInherited = true)
    {
        var query = Query()
            .Where(cr => cr.ConnectedId == connectedId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow));

        if (applicationId.HasValue)
        {
            query = query.Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
                        .Where(joined => joined.Role.ApplicationId == applicationId)
                        .Select(joined => joined.ConnectedIdRole);
        }

        if (!includeInherited)
        {
            query = query.Where(cr => !cr.InheritedFromId.HasValue);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.Priority ?? cr.Role.Priority)
            .ThenBy(cr => cr.Role.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 역할별 할당된 ConnectedId 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByRoleAsync(
        Guid roleId,
        Guid? organizationId = null,
        bool activeOnly = true)
    {
        var query = Query().Where(cr => cr.RoleId == roleId);

        if (organizationId.HasValue)
        {
            query = query.Where(cr => cr.OrganizationId == organizationId);
        }

        if (activeOnly)
        {
            query = query.Where(cr => cr.IsActive && (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow));
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.AssignedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 애플리케이션별 역할 할당 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByApplicationAsync(
        Guid applicationId,
        Guid? connectedId = null)
    {
        var query = Query()
            .Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
            .Where(joined => joined.Role.ApplicationId == applicationId)
            .Where(joined => joined.ConnectedIdRole.IsActive &&
                           (!joined.ConnectedIdRole.ExpiresAt.HasValue || joined.ConnectedIdRole.ExpiresAt > DateTime.UtcNow));

        if (connectedId.HasValue)
        {
            query = query.Where(joined => joined.ConnectedIdRole.ConnectedId == connectedId);
        }

        return await query
            .Select(joined => joined.ConnectedIdRole)
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.AssignedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 역할 할당 존재 여부 확인
    /// </summary>
    public async Task<bool> ExistsAsync(
        Guid connectedId,
        Guid roleId,
        Guid? applicationId = null)
    {
        var query = Query()
            .Where(cr => cr.ConnectedId == connectedId &&
                        cr.RoleId == roleId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow));

        if (applicationId.HasValue)
        {
            query = query.Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
                        .Where(joined => joined.Role.ApplicationId == applicationId)
                        .Select(joined => joined.ConnectedIdRole);
        }

        return await query.AnyAsync();
    }

    #endregion

    #region 권한 검증

    /// <summary>
    /// ConnectedId가 특정 역할을 가지고 있는지 확인
    /// </summary>
    public async Task<bool> HasRoleAsync(Guid connectedId, Guid roleId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .AnyAsync(cr => cr.ConnectedId == connectedId &&
                           cr.RoleId == roleId &&
                           cr.IsActive &&
                           (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow),
                     cancellationToken);
    }

    /// <summary>
    /// ConnectedId가 역할 이름을 가지고 있는지 확인
    /// </summary>
    public async Task<bool> HasRoleByNameAsync(Guid connectedId, string roleName, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
            .AnyAsync(joined => joined.ConnectedIdRole.ConnectedId == connectedId &&
                               joined.Role.Name == roleName &&
                               joined.Role.OrganizationId == organizationId &&
                               joined.ConnectedIdRole.IsActive &&
                               (!joined.ConnectedIdRole.ExpiresAt.HasValue || joined.ConnectedIdRole.ExpiresAt > DateTime.UtcNow),
                     cancellationToken);
    }

    /// <summary>
    /// ConnectedId가 최소 레벨 이상의 역할을 가지고 있는지 확인
    /// </summary>
    public async Task<bool> HasMinimumLevelAsync(Guid connectedId, int minimumLevel, Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
            .AnyAsync(joined => joined.ConnectedIdRole.ConnectedId == connectedId &&
                               joined.Role.OrganizationId == organizationId &&
                               joined.Role.Level >= minimumLevel &&
                               joined.Role.IsActive &&
                               joined.ConnectedIdRole.IsActive &&
                               (!joined.ConnectedIdRole.ExpiresAt.HasValue || joined.ConnectedIdRole.ExpiresAt > DateTime.UtcNow),
                     cancellationToken);
    }

    #endregion

    #region 역할 할당 관리

    /// <summary>
    /// ConnectedId에 역할 할당 (Legacy)
    /// </summary>
    public async Task<ConnectedIdRole> AssignConditionalRoleAsync(
        Guid connectedId,
        Guid roleId,
        Guid assignedBy,
        string conditions,
        Guid? applicationId = null)
    {
        var role = await _context.Set<Role>().FindAsync(roleId);
        if (role == null)
            throw new ArgumentException("Role not found", nameof(roleId));

        var assignment = new ConnectedIdRole  // Assignment → assignment (소문자)
        {
            ConnectedId = connectedId,
            RoleId = roleId,
            OrganizationId = role.OrganizationId,
            AssignedByConnectedId = assignedBy,  // AssignedBy → AssignedByConnectedId
            AssignedAt = DateTime.UtcNow,
            ApplicationId = applicationId,       // applicationId 추가
            Conditions = conditions,
            IsConditional = true,
            IsActive = true
        };

        return await AddAsync(assignment);
    }

    /// <summary>
    /// 역할 할당 (Interface version)
    /// </summary>
    public async Task<ConnectedIdRole> AssignRoleAsync(
        Guid connectedId,
        Guid roleId,
        Guid assignedBy,
        Guid? applicationId = null,
        DateTime? expiresAt = null,
        string? reason = null)
    {
        // Get organization ID from role
        var role = await _context.Set<Role>().FindAsync(roleId);
        if (role == null)
            throw new ArgumentException("Role not found", nameof(roleId));

        return await AssignRoleAsync(connectedId, roleId, role.OrganizationId, assignedBy, expiresAt, reason);
    }

    /// <summary>
    /// ConnectedId에서 역할 제거
    /// </summary>
    public async Task<bool> UnassignRoleAsync(Guid connectedId, Guid roleId, CancellationToken cancellationToken = default)
    {
        var assignment = await GetByConnectedIdAndRoleAsync(connectedId, roleId, cancellationToken);
        if (assignment == null) return false;

        await DeleteAsync(assignment);
        return true;
    }

    /// <summary>
    /// 역할 할당 취소
    /// </summary>
    public async Task<bool> RevokeRoleAsync(
        Guid connectedId,
        Guid roleId,
        Guid? applicationId = null,
        string? reason = null)
    {
        return await UnassignRoleAsync(connectedId, roleId);
    }

    /// <summary>
    /// 역할 할당 갱신
    /// </summary>
    public async Task<bool> RenewRoleAsync(Guid roleAssignmentId, DateTime newExpiresAt)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.ExpiresAt = newExpiresAt;
        assignment.IsActive = true;
        await UpdateAsync(assignment);
        return true;
    }

    /// <summary>
    /// 역할 할당 활성화/비활성화
    /// </summary>
    public async Task<bool> SetActiveStatusAsync(Guid roleAssignmentId, bool isActive)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.IsActive = isActive;
        await UpdateAsync(assignment);
        return true;
    }

    /// <summary>
    /// 역할 할당 일괄 생성
    /// </summary>
    public async Task<int> BulkAssignRolesAsync(IEnumerable<ConnectedIdRole> assignments, CancellationToken cancellationToken = default)
    {
        var assignmentList = assignments.ToList();
        var addedCount = 0;

        foreach (var assignment in assignmentList)
        {
            var existing = await GetByConnectedIdAndRoleAsync(assignment.ConnectedId, assignment.RoleId, cancellationToken);
            if (existing == null)
            {
                assignment.IsActive = true;
                await AddAsync(assignment);
                addedCount++;
            }
        }

        return addedCount;
    }

    /// <summary>
    /// ConnectedId의 모든 역할 제거
    /// </summary>
    public async Task<int> UnassignAllRolesAsync(Guid connectedId, CancellationToken cancellationToken = default)
    {
        var assignments = await Query()
            .Where(cr => cr.ConnectedId == connectedId)
            .ToListAsync(cancellationToken);

        if (assignments.Any())
        {
            await DeleteRangeAsync(assignments);
            return assignments.Count;
        }

        return 0;
    }

    /// <summary>
    /// 특정 역할의 모든 할당 제거
    /// </summary>
    public async Task<int> UnassignRoleFromAllAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        var assignments = await Query()
            .Where(cr => cr.RoleId == roleId)
            .ToListAsync(cancellationToken);

        if (assignments.Any())
        {
            await DeleteRangeAsync(assignments);
            return assignments.Count;
        }

        return 0;
    }

    #endregion

    #region 상속 관리

    /// <summary>
    /// 상속된 역할 생성
    /// </summary>
    public async Task<ConnectedIdRole> CreateInheritedRoleAsync(
        Guid sourceAssignmentId,
        Guid targetConnectedId,
        Guid assignedBy)
    {
        var sourceAssignment = await GetByIdAsync(sourceAssignmentId);
        if (sourceAssignment == null)
            throw new ArgumentException("Source assignment not found", nameof(sourceAssignmentId));

        var inheritedAssignment = new ConnectedIdRole
        {
            ConnectedId = targetConnectedId,
            RoleId = sourceAssignment.RoleId,
            OrganizationId = sourceAssignment.OrganizationId,
            AssignedByConnectedId = assignedBy,
            AssignedAt = DateTime.UtcNow,
            InheritedFromId = sourceAssignmentId,
            ExpiresAt = sourceAssignment.ExpiresAt,
            IsActive = true
        };

        return await AddAsync(inheritedAssignment);
    }

    /// <summary>
    /// 상속된 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetInheritedRolesAsync(Guid inheritedFromId)
    {
        return await Query()
            .Where(cr => cr.InheritedFromId == inheritedFromId)
            .Include(cr => cr.Role)
            .ToListAsync();
    }

    /// <summary>
    /// 상속 체인 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetInheritanceChainAsync(Guid roleAssignmentId)
    {
        var result = new List<ConnectedIdRole>();
        var current = await GetByIdAsync(roleAssignmentId);

        while (current != null)
        {
            result.Add(current);
            if (current.InheritedFromId.HasValue)
            {
                current = await GetByIdAsync(current.InheritedFromId.Value);
            }
            else
            {
                break;
            }
        }

        return result;
    }

    /// <summary>
    /// 상속된 역할 동기화
    /// </summary>
    public async Task<int> SyncInheritedRolesAsync(Guid sourceAssignmentId)
    {
        var sourceAssignment = await GetByIdAsync(sourceAssignmentId);
        if (sourceAssignment == null) return 0;

        var inheritedRoles = await GetInheritedRolesAsync(sourceAssignmentId);
        var syncCount = 0;

        foreach (var inherited in inheritedRoles)
        {
            inherited.ExpiresAt = sourceAssignment.ExpiresAt;
            inherited.IsActive = sourceAssignment.IsActive;
            await UpdateAsync(inherited);
            syncCount++;
        }

        return syncCount;
    }

    #endregion

    #region 만료 관리

    /// <summary>
    /// 만료된 역할 할당 조회 (Legacy)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetExpiredAssignmentsAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
    {
        var query = Query()
            .Where(cr => cr.ExpiresAt.HasValue && cr.ExpiresAt <= DateTime.UtcNow);

        if (organizationId.HasValue)
        {
            query = query.Where(cr => cr.OrganizationId == organizationId);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.ExpiresAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 만료된 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetExpiredRolesAsync(
        Guid? organizationId = null,
        bool includeInactive = false)
    {
        var query = Query()
            .Where(cr => cr.ExpiresAt.HasValue && cr.ExpiresAt <= DateTime.UtcNow);

        if (organizationId.HasValue)
        {
            query = query.Where(cr => cr.OrganizationId == organizationId);
        }

        if (!includeInactive)
        {
            query = query.Where(cr => cr.IsActive);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.ExpiresAt)
            .ToListAsync();
    }

    /// <summary>
    /// 곧 만료될 역할 할당 조회 (Legacy)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetExpiringAssignmentsAsync(TimeSpan withinTimeSpan, Guid? organizationId = null, CancellationToken cancellationToken = default)
    {
        var futureDate = DateTime.UtcNow.Add(withinTimeSpan);
        var query = Query()
            .Where(cr => cr.ExpiresAt.HasValue &&
                        cr.ExpiresAt <= futureDate &&
                        cr.ExpiresAt > DateTime.UtcNow);

        if (organizationId.HasValue)
        {
            query = query.Where(cr => cr.OrganizationId == organizationId);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.ExpiresAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// 만료 예정 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetExpiringRolesAsync(
        int daysUntilExpiry,
        Guid? organizationId = null)
    {
        var futureDate = DateTime.UtcNow.AddDays(daysUntilExpiry);
        var query = Query()
            .Where(cr => cr.ExpiresAt.HasValue &&
                        cr.ExpiresAt <= futureDate &&
                        cr.ExpiresAt > DateTime.UtcNow &&
                        cr.IsActive);

        if (organizationId.HasValue)
        {
            query = query.Where(cr => cr.OrganizationId == organizationId);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.ExpiresAt)
            .ToListAsync();
    }

    /// <summary>
    /// 만료된 할당 정리 (Legacy)
    /// </summary>
    public async Task<int> CleanupExpiredAssignmentsAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
    {
        var expiredAssignments = await GetExpiredAssignmentsAsync(organizationId, cancellationToken);
        var expiredList = expiredAssignments.ToList();

        if (expiredList.Any())
        {
            await DeleteRangeAsync(expiredList);
            return expiredList.Count;
        }

        return 0;
    }

    /// <summary>
    /// 만료된 역할 정리
    /// </summary>
    public async Task<int> CleanupExpiredRolesAsync(int batchSize = 100)
    {
        var expiredRoles = await Query()
            .Where(cr => cr.ExpiresAt.HasValue && cr.ExpiresAt <= DateTime.UtcNow)
            .Take(batchSize)
            .ToListAsync();

        if (expiredRoles.Any())
        {
            await DeleteRangeAsync(expiredRoles);
            return expiredRoles.Count;
        }

        return 0;
    }

    /// <summary>
    /// 역할 할당 만료 연장
    /// </summary>
    public async Task<bool> ExtendExpiryAsync(Guid connectedId, Guid roleId, TimeSpan extension, CancellationToken cancellationToken = default)
    {
        var assignment = await GetByConnectedIdAndRoleAsync(connectedId, roleId, cancellationToken);
        if (assignment == null) return false;

        assignment.ExpiresAt = (assignment.ExpiresAt ?? DateTime.UtcNow).Add(extension);
        await UpdateAsync(assignment);
        return true;
    }

    /// <summary>
    /// 역할 만료 처리
    /// </summary>
    public async Task<bool> ExpireRoleAsync(Guid roleAssignmentId, string? reason = null)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.ExpiresAt = DateTime.UtcNow;
        assignment.IsActive = false;
        assignment.Reason = reason ?? assignment.Reason;

        await UpdateAsync(assignment);
        return true;
    }

    #endregion

    #region 우선순위 관리

    /// <summary>
    /// 우선순위별 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetByPriorityAsync(
        Guid connectedId,
        Guid? applicationId = null)
    {
        var query = Query()
            .Where(cr => cr.ConnectedId == connectedId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow));

        if (applicationId.HasValue)
        {
            query = query.Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
                        .Where(joined => joined.Role.ApplicationId == applicationId)
                        .Select(joined => joined.ConnectedIdRole);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderBy(cr => cr.Priority ?? cr.Role.Priority)
            .ThenBy(cr => cr.Role.Name)
            .ToListAsync();
    }

    /// <summary>
    /// 우선순위 업데이트
    /// </summary>
    public async Task<bool> UpdatePriorityAsync(Guid roleAssignmentId, int newPriority)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.Priority = newPriority;
        await UpdateAsync(assignment);
        return true;
    }

    /// <summary>
    /// 최고 우선순위 역할 조회
    /// </summary>
    public async Task<ConnectedIdRole?> GetHighestPriorityRoleAsync(
        Guid connectedId,
        Guid? applicationId = null)
    {
        var roles = await GetByPriorityAsync(connectedId, applicationId);
        return roles.FirstOrDefault();
    }

    #endregion

    #region 조건부 역할

    /// <summary>
    /// 조건 평가
    /// </summary>
    public async Task<bool> EvaluateConditionsAsync(Guid roleAssignmentId, string context)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null || !assignment.IsConditional || string.IsNullOrEmpty(assignment.Conditions))
            return true;

        // TODO: Implement condition evaluation logic based on your business rules
        return true;
    }

    /// <summary>
    /// 조건부 역할 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetConditionalRolesAsync(Guid connectedId)
    {
        return await Query()
            .Where(cr => cr.ConnectedId == connectedId && cr.IsConditional)
            .Include(cr => cr.Role)
            .ToListAsync();
    }

    /// <summary>
    /// 조건 업데이트
    /// </summary>
    public async Task<bool> UpdateConditionsAsync(Guid roleAssignmentId, string newConditions)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.Conditions = newConditions;
        assignment.IsConditional = !string.IsNullOrEmpty(newConditions);
        await UpdateAsync(assignment);
        return true;
    }

    #endregion

    #region 검증 및 확인

    /// <summary>
    /// 역할 할당 검증
    /// </summary>
    public async Task<bool> VerifyRoleAssignmentAsync(Guid roleAssignmentId)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        var isValid = assignment.IsActive &&
                      (!assignment.ExpiresAt.HasValue || assignment.ExpiresAt > DateTime.UtcNow);

        if (assignment.IsConditional)
        {
            isValid = isValid && await EvaluateConditionsAsync(roleAssignmentId, "{}");
        }

        return isValid;
    }

    /// <summary>
    /// 활성 상태 재확인
    /// </summary>
    public async Task<bool> RevalidateActiveStatusAsync(Guid roleAssignmentId)
    {
        var isValid = await VerifyRoleAssignmentAsync(roleAssignmentId);
        var assignment = await GetByIdAsync(roleAssignmentId);

        if (assignment != null && assignment.IsActive != isValid)
        {
            assignment.IsActive = isValid;
            await UpdateAsync(assignment);
        }

        return isValid;
    }

    /// <summary>
    /// 마지막 검증 시간 업데이트
    /// </summary>
    public async Task<bool> UpdateLastVerifiedAsync(Guid roleAssignmentId)
    {
        var assignment = await GetByIdAsync(roleAssignmentId);
        if (assignment == null) return false;

        assignment.LastVerified = DateTime.UtcNow;
        await UpdateAsync(assignment);
        return true;
    }

    /// <summary>
    /// 역할 충돌 확인
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> CheckRoleConflictsAsync(
        Guid connectedId,
        Guid roleId,
        Guid? applicationId = null)
    {
        return await Query()
            .Where(cr => cr.ConnectedId == connectedId &&
                        cr.RoleId != roleId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
            .Include(cr => cr.Role)
            .ToListAsync();
    }

    #endregion

    #region 일괄 작업

    /// <summary>
    /// 역할 일괄 할당
    /// </summary>
    public async Task<int> BulkAssignRoleAsync(
        IEnumerable<Guid> connectedIds,
        Guid roleId,
        Guid assignedBy,
        Guid? applicationId = null)
    {
        var role = await _context.Set<Role>().FindAsync(roleId);
        if (role == null) return 0;

        var assignments = new List<ConnectedIdRole>();
        var connectedIdList = connectedIds.ToList();

        foreach (var connectedId in connectedIdList)
        {
            var existing = await GetByConnectedIdAndRoleAsync(connectedId, roleId);
            if (existing == null)
            {
                assignments.Add(new ConnectedIdRole
                {
                    ConnectedId = connectedId,
                    RoleId = roleId,
                    OrganizationId = role.OrganizationId,
                    AssignedByConnectedId = assignedBy,
                    AssignedAt = DateTime.UtcNow,
                    IsActive = true
                });
            }
        }

        if (assignments.Any())
        {
            await AddRangeAsync(assignments);
            return assignments.Count;
        }

        return 0;
    }

    /// <summary>
    /// 역할 일괄 취소
    /// </summary>
    public async Task<int> BulkRevokeRoleAsync(
        IEnumerable<Guid> connectedIds,
        Guid roleId,
        Guid? applicationId = null)
    {
        var assignments = await Query()
            .Where(cr => connectedIds.Contains(cr.ConnectedId) && cr.RoleId == roleId)
            .ToListAsync();

        if (assignments.Any())
        {
            await DeleteRangeAsync(assignments);
            return assignments.Count;
        }

        return 0;
    }

    /// <summary>
    /// ConnectedId의 모든 역할 제거
    /// </summary>
    public async Task<int> RemoveAllRolesAsync(
        Guid connectedId,
        Guid? applicationId = null)
    {
        var query = Query().Where(cr => cr.ConnectedId == connectedId);

        if (applicationId.HasValue)
        {
            query = query.Join(_context.Set<Role>(), cr => cr.RoleId, r => r.Id, (cr, r) => new { ConnectedIdRole = cr, Role = r })
                        .Where(joined => joined.Role.ApplicationId == applicationId)
                        .Select(joined => joined.ConnectedIdRole);
        }

        var assignments = await query.ToListAsync();

        if (assignments.Any())
        {
            await DeleteRangeAsync(assignments);
            return assignments.Count;
        }

        return 0;
    }

    #endregion

    #region 통계 및 분석

    /// <summary>
    /// ConnectedId별 역할 수 통계
    /// </summary>
    public async Task<Dictionary<Guid, int>> GetRoleCountByConnectedIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(cr => cr.OrganizationId == organizationId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
            .GroupBy(cr => cr.ConnectedId)
            .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
    }

    /// <summary>
    /// 역할별 할당 수 통계
    /// </summary>
    public async Task<Dictionary<Guid, int>> GetAssignmentCountByRoleAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        return await Query()
            .Where(cr => cr.OrganizationId == organizationId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
            .GroupBy(cr => cr.RoleId)
            .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
    }

    /// <summary>
    /// 역할별 할당 통계
    /// </summary>
    public async Task<Dictionary<Guid, int>> GetRoleAssignmentStatisticsAsync(Guid organizationId)
    {
        return await GetAssignmentCountByRoleAsync(organizationId);
    }

    /// <summary>
    /// 할당 유형별 통계
    /// </summary>
    public async Task<Dictionary<RoleAssignmentType, int>> GetAssignmentTypeStatisticsAsync(Guid organizationId)
    {
        var assignments = await Query()
            .Where(cr => cr.OrganizationId == organizationId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
            .ToListAsync();

        return assignments
            .GroupBy(cr => cr.IsConditional ? RoleAssignmentType.Conditional :
                          cr.InheritedFromId.HasValue ? RoleAssignmentType.Inherited :
                          RoleAssignmentType.Direct)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    /// <summary>
    /// 조직 역할 할당 통계
    /// </summary>
    public async Task<RoleAssignmentStatistics> GetAssignmentStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        var assignments = await Query()
            .Where(cr => cr.OrganizationId == organizationId)
            .ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        var activeAssignments = assignments.Where(cr => cr.IsActive && (!cr.ExpiresAt.HasValue || cr.ExpiresAt > now)).ToList();

        return new RoleAssignmentStatistics
        {
            TotalAssignments = assignments.Count,
            ActiveAssignments = activeAssignments.Count,
            ExpiredAssignments = assignments.Count(cr => cr.ExpiresAt.HasValue && cr.ExpiresAt <= now),
            UniqueConnectedIds = activeAssignments.Select(cr => cr.ConnectedId).Distinct().Count(),
            UniqueRoles = activeAssignments.Select(cr => cr.RoleId).Distinct().Count(),
            AverageRolesPerUser = activeAssignments.Any()
                ? (double)activeAssignments.Count / activeAssignments.Select(cr => cr.ConnectedId).Distinct().Count()
                : 0,
            MostAssignedRole = activeAssignments
                .GroupBy(cr => cr.RoleId)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key,
            RecentAssignmentCount = assignments.Count(cr => cr.AssignedAt >= now.AddDays(-7))
        };
    }

    /// <summary>
    /// 역할 사용 트렌드 분석
    /// </summary>
    public async Task<IEnumerable<RoleUsageTrend>> GetRoleUsageTrendsAsync(Guid organizationId, int days = 30, CancellationToken cancellationToken = default)
    {
        var startDate = DateTime.UtcNow.AddDays(-days).Date;

        var assignments = await Query()
            .Where(cr => cr.OrganizationId == organizationId && cr.AssignedAt >= startDate)
            .Include(cr => cr.Role)
            .ToListAsync(cancellationToken);

        return assignments
            .GroupBy(cr => new { cr.RoleId, cr.Role.Name, Date = cr.AssignedAt.Date })
            .Select(g => new RoleUsageTrend
            {
                RoleId = g.Key.RoleId,
                RoleName = g.Key.Name,
                Date = g.Key.Date,
                AssignmentCount = g.Count()
            })
            .OrderBy(t => t.Date)
            .ThenBy(t => t.RoleName);
    }

    /// <summary>
    /// 역할 할당 이력 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdRole>> GetAssignmentHistoryAsync(
        Guid connectedId,
        DateTime? startDate = null,
        DateTime? endDate = null)
    {
        var query = Query().Where(cr => cr.ConnectedId == connectedId);

        if (startDate.HasValue)
        {
            query = query.Where(cr => cr.AssignedAt >= startDate);
        }

        if (endDate.HasValue)
        {
            query = query.Where(cr => cr.AssignedAt <= endDate);
        }

        return await query
            .Include(cr => cr.Role)
            .OrderByDescending(cr => cr.AssignedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 가장 많이 할당된 역할 조회
    /// </summary>
    public async Task<IEnumerable<(Guid RoleId, int Count)>> GetMostAssignedRolesAsync(
        Guid organizationId,
        int limit = 10)
    {
        return await Query()
            .Where(cr => cr.OrganizationId == organizationId &&
                        cr.IsActive &&
                        (!cr.ExpiresAt.HasValue || cr.ExpiresAt > DateTime.UtcNow))
            .GroupBy(cr => cr.RoleId)
            .OrderByDescending(g => g.Count())
            .Take(limit)
            .Select(g => new ValueTuple<Guid, int>(g.Key, g.Count()))
            .ToListAsync();
    }

    #endregion

    #region IOrganizationScopedRepository 구현

    public async Task<IEnumerable<ConnectedIdRole>> GetByOrganizationIdAsync(Guid organizationId)
    {
        return await GetByOrganizationIdAsync(organizationId, false);
    }

    public async Task<ConnectedIdRole?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .FirstOrDefaultAsync(cr => cr.Id == id && cr.OrganizationId == organizationId);
    }

    public async Task<IEnumerable<ConnectedIdRole>> FindByOrganizationAsync(
        Guid organizationId,
        Expression<Func<ConnectedIdRole, bool>> predicate)
    {
        return await Query()
            .Where(cr => cr.OrganizationId == organizationId)
            .Where(predicate)
            .ToListAsync();
    }

    public async Task<(IEnumerable<ConnectedIdRole> Items, int TotalCount)> GetPagedByOrganizationAsync(
        Guid organizationId,
        int pageNumber,
        int pageSize,
        Expression<Func<ConnectedIdRole, bool>>? predicate = null,
        Expression<Func<ConnectedIdRole, object>>? orderBy = null,
        bool isDescending = false)
    {
        var query = Query().Where(cr => cr.OrganizationId == organizationId);

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
            query = query.OrderByDescending(cr => cr.AssignedAt);
        }

        var items = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .Include(cr => cr.Role)
            .ToListAsync();

        return (items, totalCount);
    }

    public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .AnyAsync(cr => cr.Id == id && cr.OrganizationId == organizationId);
    }

    public async Task<int> CountByOrganizationAsync(
        Guid organizationId,
        Expression<Func<ConnectedIdRole, bool>>? predicate = null)
    {
        var query = Query().Where(cr => cr.OrganizationId == organizationId);

        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        return await query.CountAsync();
    }

    public async Task DeleteAllByOrganizationAsync(Guid organizationId)
    {
        var assignments = await Query()
            .Where(cr => cr.OrganizationId == organizationId)
            .ToListAsync();

        if (assignments.Any())
        {
            await DeleteRangeAsync(assignments);
        }
    }

    #endregion
}

/// <summary>
/// 역할 할당 통계 DTO
/// </summary>
public class RoleAssignmentStatistics
{
    public int TotalAssignments { get; set; }
    public int ActiveAssignments { get; set; }
    public int ExpiredAssignments { get; set; }
    public int UniqueConnectedIds { get; set; }
    public int UniqueRoles { get; set; }
    public double AverageRolesPerUser { get; set; }
    public Guid? MostAssignedRole { get; set; }
    public int RecentAssignmentCount { get; set; }
}

/// <summary>
/// 역할 사용 트렌드 DTO
/// </summary>
public class RoleUsageTrend
{
    public Guid RoleId { get; set; }
    public string RoleName { get; set; } = string.Empty;
    public DateTime Date { get; set; }
    public int AssignmentCount { get; set; }
}