using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories.Organization;

/// <summary>
/// 조직 역할 할당 저장소 구현체 - AuthHive v15
/// 조직이 가질 수 있는 다양한 역할(Customer, Provider, Reseller 등)의 할당을 관리
/// BaseRepository를 상속받아 캐싱, 통계, 조직 스코프 기능을 자동으로 활용
/// </summary>
public class OrganizationCapabilityAssignmentRepository :
    BaseRepository<OrganizationCapabilityAssignment>,
    IOrganizationCapabilityAssignmentRepository
{
    public OrganizationCapabilityAssignmentRepository(
        AuthDbContext context,
        IOrganizationContext organizationContext,
        IMemoryCache? cache = null)
        : base(context, organizationContext, cache)
    {
    }

    #region 조회 메서드

    /// <summary>
    /// 조직의 모든 역할 조회 (캐시 활용)
    /// 조직 프로필 및 권한 체크에서 빈번하게 호출됨
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetCapabilitiesAsync(
        Guid organizationId,
        bool activeOnly = true)
    {
        string cacheKey = $"OrgCapabilities:{organizationId}:{activeOnly}";

        if (_cache != null && _cache.TryGetValue(cacheKey, out IEnumerable<OrganizationCapabilityAssignment>? cached))
        {
            return cached ?? Enumerable.Empty<OrganizationCapabilityAssignment>();
        }

        var query = QueryForOrganization(organizationId);

        if (activeOnly)
        {
            var now = DateTime.UtcNow;
            query = query.Where(x => x.IsActive &&
                                     (x.ExpiresAt == null || x.ExpiresAt > now));
        }

        var result = await query
            .Include(x => x.AssignedBy)
            .OrderByDescending(x => x.IsPrimary)
            .ThenBy(x => x.AssignedAt)
            .ToListAsync();

        if (_cache != null && result.Any())
        {
            _cache.Set(cacheKey, result, TimeSpan.FromMinutes(5));
        }

        return result;
    }

    /// <summary>
    /// 특정 역할 보유 여부 확인 (캐시 활용)
    /// API 권한 체크에서 매우 빈번하게 호출
    /// </summary>
    public async Task<bool> HasCapabilityAsync(
        Guid organizationId,
        string capabilityCode)
    {
        string cacheKey = $"HasCapability:{organizationId}:{capabilityCode}";

        if (_cache != null && _cache.TryGetValue(cacheKey, out bool cachedResult))
        {
            return cachedResult;
        }

        var now = DateTime.UtcNow;
        var hasCapability = await QueryForOrganization(organizationId)
            .Include(x => x.Capability)
            .AnyAsync(x => x.Capability != null &&
                           x.Capability.Code == capabilityCode &&
                           x.IsActive &&
                           (x.ExpiresAt == null || x.ExpiresAt > now));

        if (_cache != null)
        {
            _cache.Set(cacheKey, hasCapability, TimeSpan.FromMinutes(3));
        }

        return hasCapability;
    }

    /// <summary>
    /// 주요 역할 조회
    /// 조직 대시보드 및 결제 플랜 결정에 사용
    /// </summary>
    public async Task<OrganizationCapabilityAssignment?> GetPrimaryCapabilityAsync(Guid organizationId)
    {
        var now = DateTime.UtcNow;
        return await QueryForOrganization(organizationId)
            .Include(x => x.AssignedBy)
            .FirstOrDefaultAsync(x => x.IsPrimary &&
                                      x.IsActive &&
                                      (x.ExpiresAt == null || x.ExpiresAt > now));
    }

    #endregion

    #region 역할 관리

    /// <summary>
    /// 역할 할당
    /// 조직 온보딩 및 관리자의 역할 부여 시 사용
    /// </summary>
    public async Task<OrganizationCapabilityAssignment> AssignCapabilityAsync(
        Guid organizationId,
        Guid capabilityId,
        bool isPrimary = false,
        Guid? assignedByConnectedId = null)
    {
        InvalidateOrganizationCapabilityCache(organizationId);

        var existing = await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(x => x.CapabilityId == capabilityId);

        if (existing != null)
        {
            existing.IsActive = true;
            existing.IsPrimary = isPrimary;
            existing.AssignedAt = DateTime.UtcNow;
            existing.AssignedByConnectedId = assignedByConnectedId;
            existing.ExpiresAt = null;
            existing.IsDeleted = false;
            existing.DeletedAt = null;

            await UpdateAsync(existing);
            return existing;
        }

        if (isPrimary)
        {
            await UnsetPrimaryCapabilitiesAsync(organizationId);
        }

        var newAssignment = new OrganizationCapabilityAssignment
        {
            OrganizationId = organizationId,
            CapabilityId = capabilityId,
            IsActive = true,
            IsPrimary = isPrimary,
            AssignedAt = DateTime.UtcNow,
            AssignedByConnectedId = assignedByConnectedId
        };

        return await AddAsync(newAssignment);
    }
    
    /// <summary>
    /// 역할 제거 (소프트 삭제)
    /// 조직 역할 변경 시 사용
    /// </summary>
    public async Task<bool> RemoveCapabilityAsync(
        Guid organizationId,
        string capabilityCode)
    {
        InvalidateOrganizationCapabilityCache(organizationId);

        var assignment = await QueryForOrganization(organizationId)
            .Include(x => x.Capability)
            .FirstOrDefaultAsync(x => x.Capability != null &&
                                      x.Capability.Code == capabilityCode);

        if (assignment == null)
            return false;

        await DeleteAsync(assignment);
        // SaveChangesAsync is handled by the Unit of Work pattern, typically outside the repository.
        // If not using UoW, you would call: await _context.SaveChangesAsync();
        
        return true;
    }

    public async Task<IEnumerable<Guid>> GetOrganizationsByCapabilityAsync(
        string capabilityCode)
    {
        var now = DateTime.UtcNow;

        return await _dbSet
            .Include(x => x.Capability)
            .Where(x => x.Capability != null &&
                        x.Capability.Code == capabilityCode &&
                        x.IsActive &&
                        (x.ExpiresAt == null || x.ExpiresAt > now) &&
                        !x.IsDeleted)
            .Select(x => x.OrganizationId)
            .Distinct()
            .ToListAsync();
    }

    /// <summary>
    /// 주요 역할 설정
    /// 조직의 주 비즈니스 타입 변경 시 사용
    /// </summary>
    public async Task<bool> SetPrimaryCapabilityAsync(
        Guid organizationId,
        string capabilityCode)
    {
        InvalidateOrganizationCapabilityCache(organizationId);

        var now = DateTime.UtcNow;
        var targetAssignment = await QueryForOrganization(organizationId)
            .Include(x => x.Capability)
            .FirstOrDefaultAsync(x => x.Capability != null &&
                                      x.Capability.Code == capabilityCode &&
                                      x.IsActive &&
                                      (x.ExpiresAt == null || x.ExpiresAt > now));

        if (targetAssignment == null)
            return false;

        await UnsetPrimaryCapabilitiesAsync(organizationId);

        targetAssignment.IsPrimary = true;
        await UpdateAsync(targetAssignment);
        // SaveChangesAsync is handled by the Unit of Work pattern, typically outside the repository.
        // If not using UoW, you would call: await _context.SaveChangesAsync();

        return true;
    }
    
    #endregion

    #region 만료 관리

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

    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiringCapabilitiesAsync(
        Guid organizationId,
        DateTime beforeDate)
    {
        var now = DateTime.UtcNow;

        return await QueryForOrganization(organizationId)
            .Where(x => x.IsActive &&
                        x.ExpiresAt.HasValue &&
                        x.ExpiresAt.Value <= beforeDate &&
                        x.ExpiresAt.Value > now)
            .OrderBy(x => x.ExpiresAt)
            .ToListAsync();
    }

    #endregion

    #region 통계 및 분석

    /// <summary>
    /// 역할별 통계 조회 (캐시 활용)
    /// 관리자 대시보드 통계 위젯에서 사용
    /// </summary>
    public async Task<IDictionary<string, int>> GetCapabilityStatisticsAsync()
    {
        string cacheKey = "CapabilityStatistics:Global";

        if (_cache != null && _cache.TryGetValue(cacheKey, out IDictionary<string, int>? cached))
        {
            return cached ?? new Dictionary<string, int>();
        }

        var now = DateTime.UtcNow;

        var statistics = await _dbSet
            .Include(x => x.Capability)
            // FIXED: Added null check for x.Capability
            .Where(x => x.Capability != null && 
                        x.IsActive &&
                        (x.ExpiresAt == null || x.ExpiresAt > now) &&
                        !x.IsDeleted)
            .GroupBy(x => x.Capability!.Code) // Group by the string Code
            .Select(g => new { Code = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Code, x => x.Count);

        if (_cache != null)
        {
            _cache.Set(cacheKey, statistics, TimeSpan.FromMinutes(10));
        }

        return statistics;
    }

    // REMOVED: Deleted the duplicate GetCapabilityStatisticsAsync method

    #endregion

    #region 감사 추적

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

    #endregion

    #region Private Helper Methods

    private async Task UnsetPrimaryCapabilitiesAsync(Guid organizationId)
    {
        var primaryAssignments = await QueryForOrganization(organizationId)
            .Where(x => x.IsPrimary)
            .ToListAsync();

        if (primaryAssignments.Any())
        {
            foreach (var assignment in primaryAssignments)
            {
                assignment.IsPrimary = false;
            }
            await UpdateRangeAsync(primaryAssignments);
        }
    }

    private void InvalidateOrganizationCapabilityCache(Guid organizationId)
    {
        if (_cache == null) return;

        _cache.Remove($"OrgCapabilities:{organizationId}:true");
        _cache.Remove($"OrgCapabilities:{organizationId}:false");

        var capabilityCodes = new[] {
            SystemCapabilities.Customer,
            SystemCapabilities.Reseller,
            SystemCapabilities.Provider,
            SystemCapabilities.Platform,
            SystemCapabilities.Partner
        };

        foreach (var code in capabilityCodes)
        {
            _cache.Remove($"HasCapability:{organizationId}:{code}");
        }

        _cache.Remove("CapabilityStatistics:Global");
    }
    
    #endregion
}