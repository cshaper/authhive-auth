using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using Microsoft.EntityFrameworkCore;
using static AuthHive.Core.Constants.Common.CommonConstants;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 역량(역할) 할당 저장소 구현체 (v17 - 리팩토링)
    /// </summary>
    public class OrganizationCapabilityAssignmentRepository :
        BaseRepository<OrganizationCapabilityAssignment>,
        IOrganizationCapabilityAssignmentRepository
    {
        private readonly IDateTimeProvider _dateTimeProvider;

        // [수정] 최신 아키텍처에 맞게 의존성 주입 변경
        public OrganizationCapabilityAssignmentRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            IDateTimeProvider dateTimeProvider)
            : base(context, cacheService)
        {
            _dateTimeProvider = dateTimeProvider;
        }

        // [추가] 조직 범위 엔티티임을 명시
        protected override bool IsOrganizationBaseEntity() => true;

        #region 조회 메서드

        public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetCapabilitiesAsync(
            Guid organizationId,
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"OrgCapabilities:{organizationId}:{activeOnly}";

            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<OrganizationCapabilityAssignment>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var query = QueryForOrganization(organizationId);

            if (activeOnly)
            {
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(x => x.IsActive &&
                                         (x.ExpiresAt == null || x.ExpiresAt > now));
            }

            var result = await query
                .Include(x => x.AssignedBy)
                .OrderByDescending(x => x.IsPrimary)
                .ThenBy(x => x.AssignedAt)
                .ToListAsync(cancellationToken);

            if (_cacheService != null && result.Any())
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(5), cancellationToken);
            }

            return result;
        }

        public async Task<bool> HasCapabilityAsync(
            Guid organizationId,
            string capabilityCode,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"HasCapability:{organizationId}:{capabilityCode}";

            if (_cacheService != null)
            {
                var cachedResultStr = await _cacheService.GetStringAsync(cacheKey, cancellationToken);
                if (bool.TryParse(cachedResultStr, out var cachedResult))
                {
                    return cachedResult;
                }
            }

            var now = _dateTimeProvider.UtcNow;
            var hasCapability = await QueryForOrganization(organizationId)
                .Include(x => x.Capability)
                .AnyAsync(x => x.Capability != null &&
                               x.Capability.Code == capabilityCode &&
                               x.IsActive &&
                               (x.ExpiresAt == null || x.ExpiresAt > now),
                               cancellationToken);

            if (_cacheService != null)
            {
                await _cacheService.SetStringAsync(cacheKey, hasCapability.ToString(), TimeSpan.FromMinutes(3), cancellationToken);
            }

            return hasCapability;
        }

        public async Task<OrganizationCapabilityAssignment?> GetPrimaryCapabilityAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            return await QueryForOrganization(organizationId)
                .Include(x => x.AssignedBy)
                .FirstOrDefaultAsync(x => x.IsPrimary &&
                                          x.IsActive &&
                                          (x.ExpiresAt == null || x.ExpiresAt > now),
                                          cancellationToken);
        }

        #endregion

        #region 역할 관리

        public async Task<OrganizationCapabilityAssignment> AssignCapabilityAsync(
            Guid organizationId,
            Guid capabilityId,
            bool isPrimary = false,
            Guid? assignedByConnectedId = null,
            CancellationToken cancellationToken = default)
        {
            await InvalidateOrganizationCapabilityCacheAsync(organizationId, cancellationToken);

            var existing = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(x => x.CapabilityId == capabilityId, cancellationToken);

            if (existing != null)
            {
                existing.IsActive = true;
                existing.IsPrimary = isPrimary;
                existing.AssignedAt = _dateTimeProvider.UtcNow;
                existing.AssignedByConnectedId = assignedByConnectedId;
                existing.ExpiresAt = null;
                
                await UpdateAsync(existing, cancellationToken);
                return existing;
            }

            if (isPrimary)
            {
                await UnsetPrimaryCapabilitiesAsync(organizationId, cancellationToken);
            }

            var newAssignment = new OrganizationCapabilityAssignment
            {
                OrganizationId = organizationId,
                CapabilityId = capabilityId,
                IsActive = true,
                IsPrimary = isPrimary,
                AssignedAt = _dateTimeProvider.UtcNow,
                AssignedByConnectedId = assignedByConnectedId
            };

            return await AddAsync(newAssignment, cancellationToken);
        }
        
        public async Task<bool> RemoveCapabilityAsync(
            Guid organizationId,
            string capabilityCode,
            CancellationToken cancellationToken = default)
        {
            await InvalidateOrganizationCapabilityCacheAsync(organizationId, cancellationToken);

            var assignment = await QueryForOrganization(organizationId)
                .Include(x => x.Capability)
                .FirstOrDefaultAsync(x => x.Capability != null && x.Capability.Code == capabilityCode, cancellationToken);

            if (assignment == null) return false;

            await DeleteAsync(assignment, cancellationToken);
            return true;
        }

        public async Task<bool> SetPrimaryCapabilityAsync(
            Guid organizationId,
            string capabilityCode,
            CancellationToken cancellationToken = default)
        {
            await InvalidateOrganizationCapabilityCacheAsync(organizationId, cancellationToken);

            var now = _dateTimeProvider.UtcNow;
            var targetAssignment = await QueryForOrganization(organizationId)
                .Include(x => x.Capability)
                .FirstOrDefaultAsync(x => x.Capability != null &&
                                          x.Capability.Code == capabilityCode &&
                                          x.IsActive &&
                                          (x.ExpiresAt == null || x.ExpiresAt > now),
                                          cancellationToken);

            if (targetAssignment == null) return false;

            await UnsetPrimaryCapabilitiesAsync(organizationId, cancellationToken);

            targetAssignment.IsPrimary = true;
            await UpdateAsync(targetAssignment, cancellationToken);
            return true;
        }
        
        #endregion

        #region 만료 관리

        public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiredCapabilitiesAsync(
            DateTime asOfDate, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => x.IsActive &&
                            x.ExpiresAt.HasValue &&
                            x.ExpiresAt.Value <= asOfDate)
                .Include(x => x.AssignedBy)
                .OrderBy(x => x.OrganizationId)
                .ThenBy(x => x.ExpiresAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetExpiringCapabilitiesAsync(
            Guid organizationId, DateTime beforeDate, CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            return await QueryForOrganization(organizationId)
                .Where(x => x.IsActive &&
                            x.ExpiresAt.HasValue &&
                            x.ExpiresAt.Value <= beforeDate &&
                            x.ExpiresAt.Value > now)
                .OrderBy(x => x.ExpiresAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 통계 및 분석

        public async Task<IEnumerable<Guid>> GetOrganizationsByCapabilityAsync(
            string capabilityCode, CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            return await Query()
                .Include(x => x.Capability)
                .Where(x => x.Capability != null &&
                            x.Capability.Code == capabilityCode &&
                            x.IsActive &&
                            (x.ExpiresAt == null || x.ExpiresAt > now))
                .Select(x => x.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        public async Task<IDictionary<string, int>> GetCapabilityStatisticsAsync(CancellationToken cancellationToken = default)
        {
            string cacheKey = "CapabilityStatistics:Global";

            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IDictionary<string, int>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var now = _dateTimeProvider.UtcNow;

            var statistics = await Query()
                .Include(x => x.Capability)
                .Where(x => x.Capability != null && 
                            x.IsActive &&
                            (x.ExpiresAt == null || x.ExpiresAt > now))
                .GroupBy(x => x.Capability!.Code)
                .Select(g => new { Code = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Code, x => x.Count, cancellationToken);

            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, statistics, TimeSpan.FromMinutes(10), cancellationToken);
            }

            return statistics;
        }

        #endregion

        #region 감사 추적

        public async Task<IEnumerable<OrganizationCapabilityAssignment>> GetAssignmentsByAssignerAsync(
            Guid assignedByConnectedId, DateTime? fromDate = null, DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Where(x => x.AssignedByConnectedId == assignedByConnectedId);

            if (fromDate.HasValue)
                query = query.Where(x => x.AssignedAt >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(x => x.AssignedAt <= toDate.Value);

            return await query
                .Include(x => x.AssignedBy)
                .OrderByDescending(x => x.AssignedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Private Helper Methods

        private async Task UnsetPrimaryCapabilitiesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var primaryAssignments = await QueryForOrganization(organizationId)
                .Where(x => x.IsPrimary)
                .ToListAsync(cancellationToken);

            if (primaryAssignments.Any())
            {
                foreach (var assignment in primaryAssignments)
                {
                    assignment.IsPrimary = false;
                }
                await UpdateRangeAsync(primaryAssignments, cancellationToken);
            }
        }

        private async Task InvalidateOrganizationCapabilityCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return;

            var keysToRemove = new List<string>
            {
                $"OrgCapabilities:{organizationId}:true",
                $"OrgCapabilities:{organizationId}:false",
                "CapabilityStatistics:Global"
            };

            var capabilityCodes = new[] {
                SystemCapabilities.Customer, SystemCapabilities.Reseller, SystemCapabilities.Provider,
                SystemCapabilities.Platform, SystemCapabilities.Partner
            };

            foreach (var code in capabilityCodes)
            {
                keysToRemove.Add($"HasCapability:{organizationId}:{code}");
            }

            await _cacheService.RemoveMultipleAsync(keysToRemove, cancellationToken);
        }
        
        #endregion
    }
}

