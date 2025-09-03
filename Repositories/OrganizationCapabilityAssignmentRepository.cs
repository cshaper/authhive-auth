using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;

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
        // 캐시 키 생성
        string cacheKey = $"OrgCapabilities:{organizationId}:{activeOnly}";
        
        if (_cache != null && _cache.TryGetValue(cacheKey, out IEnumerable<OrganizationCapabilityAssignment>? cached))
        {
            return cached ?? Enumerable.Empty<OrganizationCapabilityAssignment>();
        }

        // QueryForOrganization 사용하여 조직 격리 보장
        var query = QueryForOrganization(organizationId);

        if (activeOnly)
        {
            var now = DateTime.UtcNow;
            query = query.Where(x => x.IsActive && 
                                   (x.ExpiresAt == null || x.ExpiresAt > now));
        }

        var result = await query
            .Include(x => x.AssignedBy) // 할당자 정보 포함
            .OrderByDescending(x => x.IsPrimary)
            .ThenBy(x => x.AssignedAt)
            .ToListAsync();

        // 캐시 저장 (5분간 유지 - 권한 체크 빈도가 높음)
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
        OrganizationCapability capability)
    {
        // 캐시 키 생성
        string cacheKey = $"HasCapability:{organizationId}:{capability}";
        
        if (_cache != null && _cache.TryGetValue(cacheKey, out bool cachedResult))
        {
            return cachedResult;
        }

        var now = DateTime.UtcNow;
        var hasCapability = await QueryForOrganization(organizationId)
            .AnyAsync(x => x.CapabilityType == capability &&
                          x.IsActive &&
                          (x.ExpiresAt == null || x.ExpiresAt > now));

        // 캐시 저장 (3분간 유지)
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
        OrganizationCapability capability,
        bool isPrimary = false,
        Guid? assignedByConnectedId = null)
    {
        // 캐시 무효화 (역할 변경 시)
        InvalidateOrganizationCapabilityCache(organizationId);

        // 기존 역할 확인 (소프트 삭제된 것 포함)
        var existing = await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(x => x.CapabilityType == capability);

        if (existing != null)
        {
            // 기존 역할 재활성화
            existing.IsActive = true;
            existing.IsPrimary = isPrimary;
            existing.AssignedAt = DateTime.UtcNow;
            existing.AssignedByConnectedId = assignedByConnectedId;
            existing.ExpiresAt = null; // 새로 할당하면 만료일 초기화
            existing.IsDeleted = false; // 소프트 삭제 복구
            existing.DeletedAt = null;
            
            await UpdateAsync(existing); // BaseRepository의 캐시 무효화 자동 처리
            return existing;
        }

        // 주요 역할 설정 시 기존 주요 역할 해제
        if (isPrimary)
        {
            await UnsetPrimaryCapabilitiesAsync(organizationId);
        }

        // 새 역할 생성
        var newAssignment = new OrganizationCapabilityAssignment
        {
            OrganizationId = organizationId,
            CapabilityType = capability,
            IsActive = true,
            IsPrimary = isPrimary,
            AssignedAt = DateTime.UtcNow,
            AssignedByConnectedId = assignedByConnectedId
        };

        return await AddAsync(newAssignment); // BaseRepository 메서드 활용
    }

    /// <summary>
    /// 역할 제거 (소프트 삭제)
    /// 조직 역할 변경 시 사용
    /// </summary>
    public async Task<bool> RemoveCapabilityAsync(
        Guid organizationId, 
        OrganizationCapability capability)
    {
        // 캐시 무효화
        InvalidateOrganizationCapabilityCache(organizationId);

        var assignment = await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(x => x.CapabilityType == capability);

        if (assignment == null)
            return false;

        // BaseRepository의 소프트 삭제 활용
        await DeleteAsync(assignment);
        await _context.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    /// 주요 역할 설정
    /// 조직의 주 비즈니스 타입 변경 시 사용
    /// </summary>
    public async Task<bool> SetPrimaryCapabilityAsync(
        Guid organizationId, 
        OrganizationCapability capability)
    {
        // 캐시 무효화
        InvalidateOrganizationCapabilityCache(organizationId);

        var now = DateTime.UtcNow;
        
        // 해당 역할이 활성화되어 있는지 확인
        var targetAssignment = await QueryForOrganization(organizationId)
            .FirstOrDefaultAsync(x => x.CapabilityType == capability &&
                                     x.IsActive &&
                                     (x.ExpiresAt == null || x.ExpiresAt > now));

        if (targetAssignment == null)
            return false;

        // 기존 주요 역할들 해제
        await UnsetPrimaryCapabilitiesAsync(organizationId);

        // 새로운 주요 역할 설정
        targetAssignment.IsPrimary = true;
        await UpdateAsync(targetAssignment);
        await _context.SaveChangesAsync();

        return true;
    }

    #endregion

    #region 만료 관리

    /// <summary>
    /// 만료된 역할 조회
    /// 배치 작업으로 정기적인 정리 시 사용
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiredCapabilitiesAsync(
        DateTime asOfDate)
    {
        // 모든 조직에 대해 조회하므로 Query() 직접 사용
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
    /// 조직별 만료 예정 역할 조회
    /// 만료 임박 알림 발송에 사용
    /// </summary>
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
    /// 역할별 조직 조회
    /// 특정 비즈니스 타입의 모든 조직 찾기 (예: 모든 Provider)
    /// </summary>
    public async Task<IEnumerable<Guid>> GetOrganizationsByCapabilityAsync(
        OrganizationCapability capability)
    {
        var now = DateTime.UtcNow;
        
        // 전체 조직 대상이므로 _dbSet 직접 사용
        return await _dbSet
            .Where(x => x.CapabilityType == capability &&
                       x.IsActive &&
                       (x.ExpiresAt == null || x.ExpiresAt > now) &&
                       !x.IsDeleted)
            .Select(x => x.OrganizationId)
            .Distinct()
            .ToListAsync();
    }

    /// <summary>
    /// 역할별 통계 조회 (캐시 활용)
    /// 관리자 대시보드 통계 위젯에서 사용
    /// </summary>
    public async Task<IDictionary<OrganizationCapability, int>> GetCapabilityStatisticsAsync()
    {
        // 캐시 키
        string cacheKey = "CapabilityStatistics:Global";
        
        if (_cache != null && _cache.TryGetValue(cacheKey, out IDictionary<OrganizationCapability, int>? cached))
        {
            return cached ?? new Dictionary<OrganizationCapability, int>();
        }

        var now = DateTime.UtcNow;
        
        // BaseRepository의 GetGroupCountAsync 활용 가능하지만, 
        // ExpiresAt 조건이 복잡하므로 직접 구현
        var statistics = await _dbSet
            .Where(x => x.IsActive &&
                       (x.ExpiresAt == null || x.ExpiresAt > now) &&
                       !x.IsDeleted)
            .GroupBy(x => x.CapabilityType)
            .Select(g => new { Capability = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Capability, x => x.Count);

        // 캐시 저장 (10분간 유지 - 통계는 자주 변하지 않음)
        if (_cache != null)
        {
            _cache.Set(cacheKey, statistics, TimeSpan.FromMinutes(10));
        }

        return statistics;
    }

    #endregion

    #region 감사 추적

    /// <summary>
    /// 특정 사용자가 할당한 역할들 조회
    /// 감사 로그 및 권한 부여 이력 추적에 사용
    /// </summary>
    public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetAssignmentsByAssignerAsync(
        Guid assignedByConnectedId,
        DateTime? fromDate = null,
        DateTime? toDate = null)
    {
        // 전체 조직 대상 감사이므로 _dbSet 직접 사용
        var query = _dbSet
            .Where(x => x.AssignedByConnectedId == assignedByConnectedId &&
                       !x.IsDeleted);

        // 날짜 범위 필터
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

    /// <summary>
    /// 조직의 모든 주요 역할 해제
    /// 새로운 주요 역할 설정 전에 호출
    /// </summary>
    private async Task UnsetPrimaryCapabilitiesAsync(Guid organizationId)
    {
        var primaryAssignments = await QueryForOrganization(organizationId)
            .Where(x => x.IsPrimary)
            .ToListAsync();

        foreach (var assignment in primaryAssignments)
        {
            assignment.IsPrimary = false;
        }

        if (primaryAssignments.Any())
        {
            await UpdateRangeAsync(primaryAssignments); // BaseRepository 메서드 활용
        }
    }

    /// <summary>
    /// 조직의 역할 관련 캐시 무효화
    /// 역할 변경 시 호출하여 캐시 일관성 유지
    /// </summary>
    private void InvalidateOrganizationCapabilityCache(Guid organizationId)
    {
        if (_cache == null) return;

        // 조직별 캐시 키들 무효화
        _cache.Remove($"OrgCapabilities:{organizationId}:true");
        _cache.Remove($"OrgCapabilities:{organizationId}:false");
        
        // 모든 Capability 타입에 대한 HasCapability 캐시 무효화
        foreach (OrganizationCapability capability in Enum.GetValues(typeof(OrganizationCapability)))
        {
            _cache.Remove($"HasCapability:{organizationId}:{capability}");
        }
        
        // 전역 통계 캐시도 무효화
        _cache.Remove("CapabilityStatistics:Global");
    }

    #endregion
}

/*
TODO: DbContext OnModelCreating에서 설정 필요
- (OrganizationId, CapabilityType) 복합 유니크 인덱스 (소프트 삭제 제외)
- IsActive 인덱스 (WHERE 조건 최적화)
- ExpiresAt 인덱스 (만료 체크 최적화)
- IsPrimary 인덱스 (주요 역할 조회 최적화)
- AssignedByConnectedId 외래키 인덱스 (감사 추적)
- AssignedAt 인덱스 (날짜별 정렬/필터링)
- OrganizationId + IsDeleted 복합 인덱스 (조직별 조회 최적화)
*/