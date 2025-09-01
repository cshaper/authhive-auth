using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;

namespace AuthHive.Auth.Repositories.Organization;

/// <summary>
/// 조직 역할 할당 저장소 구현체 - AuthHive v15
/// 조직이 가질 수 있는 다양한 역할(Customer, Provider, Reseller 등)의 할당을 관리합니다.
/// </summary>
public class OrganizationCapabilityAssignmentRepository : 
    OrganizationScopedRepository<OrganizationCapabilityAssignment>, 
    IOrganizationCapabilityAssignmentRepository
{
    public OrganizationCapabilityAssignmentRepository(AuthDbContext context) : base(context)
    {
    }

    /// <summary>
    /// 조직의 모든 역할 조회
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetCapabilitiesAsync(
        Guid organizationId, 
        bool activeOnly = true)
    {
        var query = _dbSet
            .Where(x => x.OrganizationId == organizationId);

        if (activeOnly)
        {
            query = query.Where(x => x.IsActive && 
                               (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow));
        }

        return await query
            .Include(x => x.AssignedBy) // ConnectedId 정보 포함
            .OrderByDescending(x => x.IsPrimary)
            .ThenBy(x => x.AssignedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 역할 보유 여부 확인
    /// </summary>
    public async Task<bool> HasCapabilityAsync(
        Guid organizationId, 
        OrganizationCapability capability)
    {
        return await _dbSet
            .AnyAsync(x => x.OrganizationId == organizationId &&
                          x.CapabilityType == capability &&
                          x.IsActive &&
                          (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow) &&
                          !x.IsDeleted);
    }

    /// <summary>
    /// 주요 역할 조회
    /// </summary>
    public async Task<OrganizationCapabilityAssignment?> GetPrimaryCapabilityAsync(Guid organizationId)
    {
        return await _dbSet
            .Include(x => x.AssignedBy)
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId &&
                                     x.IsPrimary &&
                                     x.IsActive &&
                                     (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow) &&
                                     !x.IsDeleted);
    }

    /// <summary>
    /// 역할 할당
    /// </summary>
    public async Task<OrganizationCapabilityAssignment> AssignCapabilityAsync(
        Guid organizationId,
        OrganizationCapability capability,
        bool isPrimary = false,
        Guid? assignedByConnectedId = null)
    {
        // 기존에 같은 역할이 있는지 확인
        var existing = await _dbSet
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId &&
                                     x.CapabilityType == capability &&
                                     !x.IsDeleted);

        if (existing != null)
        {
            // 기존 역할이 있으면 활성화
            existing.IsActive = true;
            existing.IsPrimary = isPrimary;
            existing.AssignedAt = DateTime.UtcNow;
            existing.AssignedByConnectedId = assignedByConnectedId;
            existing.ExpiresAt = null; // 새로 할당하면 만료일 초기화
            
            await UpdateAsync(existing);
            return existing;
        }

        // 주요 역할로 설정하는 경우, 기존 주요 역할 해제
        if (isPrimary)
        {
            await UnsetPrimaryCapabilitiesAsync(organizationId);
        }

        // 새 역할 할당
        var newAssignment = new OrganizationCapabilityAssignment
        {
            OrganizationId = organizationId,
            CapabilityType = capability,
            IsActive = true,
            IsPrimary = isPrimary,
            AssignedAt = DateTime.UtcNow,
            AssignedByConnectedId = assignedByConnectedId
        };

        return await AddAsync(newAssignment);
    }

    /// <summary>
    /// 역할 제거
    /// </summary>
    public async Task<bool> RemoveCapabilityAsync(
        Guid organizationId, 
        OrganizationCapability capability)
    {
        var assignment = await _dbSet
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId &&
                                     x.CapabilityType == capability &&
                                     !x.IsDeleted);

        if (assignment == null)
            return false;

        // 소프트 삭제
        await SoftDeleteAsync(assignment.Id);
        return true;
    }

    /// <summary>
    /// 주요 역할 설정
    /// </summary>
    public async Task<bool> SetPrimaryCapabilityAsync(
        Guid organizationId, 
        OrganizationCapability capability)
    {
        // 해당 역할이 존재하고 활성화되어 있는지 확인
        var targetAssignment = await _dbSet
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId &&
                                     x.CapabilityType == capability &&
                                     x.IsActive &&
                                     (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow) &&
                                     !x.IsDeleted);

        if (targetAssignment == null)
            return false;

        // 기존 주요 역할들 해제
        await UnsetPrimaryCapabilitiesAsync(organizationId);

        // 새로운 주요 역할 설정
        targetAssignment.IsPrimary = true;
        await UpdateAsync(targetAssignment);

        return true;
    }

    /// <summary>
    /// 만료된 역할 조회
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiredCapabilitiesAsync(
        DateTime asOfDate)
    {
        return await _dbSet
            .Where(x => x.IsActive &&
                       x.ExpiresAt.HasValue &&
                       x.ExpiresAt.Value <= asOfDate &&
                       !x.IsDeleted)
            .Include(x => x.AssignedBy)
            .OrderBy(x => x.OrganizationId)
            .ThenBy(x => x.ExpiresAt)
            .ToListAsync();
    }

    /// <summary>
    /// 역할별 조직 조회
    /// </summary>
    public async Task<IEnumerable<Guid>> GetOrganizationsByCapabilityAsync(
        OrganizationCapability capability)
    {
        return await _dbSet
            .Where(x => x.CapabilityType == capability &&
                       x.IsActive &&
                       (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow) &&
                       !x.IsDeleted)
            .Select(x => x.OrganizationId)
            .Distinct()
            .ToListAsync();
    }

    /// <summary>
    /// 조직별 만료 예정 역할 조회 (알림용)
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiringCapabilitiesAsync(
        Guid organizationId,
        DateTime beforeDate)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId &&
                       x.IsActive &&
                       x.ExpiresAt.HasValue &&
                       x.ExpiresAt.Value <= beforeDate &&
                       x.ExpiresAt.Value > DateTime.UtcNow &&
                       !x.IsDeleted)
            .OrderBy(x => x.ExpiresAt)
            .ToListAsync();
    }

    /// <summary>
    /// 역할별 통계 조회
    /// </summary>
    public async Task<IDictionary<OrganizationCapability, int>> GetCapabilityStatisticsAsync()
    {
        return await _dbSet
            .Where(x => x.IsActive &&
                       (x.ExpiresAt == null || x.ExpiresAt > DateTime.UtcNow) &&
                       !x.IsDeleted)
            .GroupBy(x => x.CapabilityType)
            .ToDictionaryAsync(g => g.Key, g => g.Count());
    }

    /// <summary>
    /// 특정 ConnectedId가 할당한 역할들 조회 (감사용)
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetAssignmentsByAssignerAsync(
        Guid assignedByConnectedId,
        DateTime? fromDate = null,
        DateTime? toDate = null)
    {
        var query = _dbSet
            .Where(x => x.AssignedByConnectedId == assignedByConnectedId &&
                       !x.IsDeleted);

        if (fromDate.HasValue)
            query = query.Where(x => x.AssignedAt >= fromDate.Value);

        if (toDate.HasValue)
            query = query.Where(x => x.AssignedAt <= toDate.Value);

        return await query
            .Include(x => x.AssignedBy)
            .OrderByDescending(x => x.AssignedAt)
            .ToListAsync();
    }

    #region Private Helper Methods

    /// <summary>
    /// 조직의 모든 주요 역할 해제
    /// </summary>
    private async Task UnsetPrimaryCapabilitiesAsync(Guid organizationId)
    {
        var primaryAssignments = await _dbSet
            .Where(x => x.OrganizationId == organizationId &&
                       x.IsPrimary &&
                       !x.IsDeleted)
            .ToListAsync();

        foreach (var assignment in primaryAssignments)
        {
            assignment.IsPrimary = false;
        }

        if (primaryAssignments.Any())
        {
            await UpdateRangeAsync(primaryAssignments);
        }
    }

    #endregion
}

/*
TODO: DbContext OnModelCreating에서 설정
- (OrganizationId, CapabilityType) 복합 유니크 인덱스
- IsActive 인덱스
- ExpiresAt 인덱스
- IsPrimary 인덱스
- AssignedByConnectedId 외래키 인덱스
- AssignedAt 인덱스 (감사/정렬용)
*/