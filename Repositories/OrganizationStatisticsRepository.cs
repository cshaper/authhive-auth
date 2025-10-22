using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging; // ILogger 추가
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Data.Context;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Entities.Organization; // OrganizationMembership, OrganizationDomain 추가
using AuthHive.Core.Entities.PlatformApplications; // PlatformApplication 추가
using AuthHive.Core.Entities.Auth; // User 추가 (for 2FA)
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가
using AuthHive.Core.Models.Infra.Monitoring; // DTOs (e.g., SecurityEventDto)
using AuthHive.Core.Enums.Infra.Monitoring; // Enums (e.g., SecurityEventType)
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 통계 전용 Repository 구현체 - AuthHive v16
    /// 조직의 다양한 통계 정보를 제공하는 읽기 전용 Repository
    /// [FIXED] BaseRepository 상속 제거, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class OrganizationStatisticsRepository : IOrganizationStatisticsRepository
    {
        private readonly AuthDbContext _context;
        private readonly ICacheService? _cacheService;
        private readonly ILogger<OrganizationStatisticsRepository> _logger; // 로거 추가
        private const string CACHE_KEY_PREFIX = "org_stats_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(10);

        public OrganizationStatisticsRepository(
            AuthDbContext context,
            ICacheService? cacheService, // ICacheService 주입
            ILogger<OrganizationStatisticsRepository> logger) // 로거 주입
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _cacheService = cacheService;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 통계 정보 조회
        /// </summary>
        public async Task<OrganizationStatistics> GetStatisticsAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            Guid orgId = organizationId ?? throw new ArgumentNullException(nameof(organizationId), "Organization ID must be provided explicitly.");

            var cacheKey = $"{CACHE_KEY_PREFIX}stats_{orgId}";

            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<OrganizationStatistics>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var organization = await _context.Set<OrganizationEntity>()
                .AsNoTracking()
                .FirstOrDefaultAsync(o => o.Id == orgId && !o.IsDeleted, cancellationToken)
                ?? throw new InvalidOperationException($"Organization {orgId} not found or is deleted");

            var stats = new OrganizationStatistics
            {
                OrganizationId = orgId,
                OrganizationName = organization.Name,
                OrganizationStatus = organization.Status.ToString(),
                CurrentPlan = organization.Type.ToString(), // TODO: 실제 Plan 정보 조회 로직 필요 (예: PlanSubscription)
                GeneratedAt = DateTime.UtcNow,
                NextRefreshAt = DateTime.UtcNow.Add(_cacheExpiration)
            };

            // 멤버 통계
            var memberStats = await GetMemberStatisticsAsync(orgId, cancellationToken);
            stats.MemberCount = memberStats.TotalMembers;
            stats.ActiveMemberCount = memberStats.ActiveMembers;
            stats.ActiveConnectedIdCount = memberStats.ActiveConnectedIds;
            stats.TwoFactorEnabledPercentage = memberStats.TwoFactorPercentage;

            // 애플리케이션 통계
            var appStats = await GetApplicationStatisticsAsync(orgId, cancellationToken);
            stats.ApplicationCount = appStats.TotalApplications;
            stats.ActiveApplicationCount = appStats.ActiveApplications;

            // 하위 조직 통계
            var hierarchyStats = await GetHierarchyStatisticsAsync(orgId, cancellationToken);
            stats.ChildOrganizationCount = hierarchyStats.ChildCount;
            stats.HierarchyDepth = hierarchyStats.Depth;

            // 활동 통계 (UserActivityLog 또는 AuditLog 테이블 필요)
            _logger.LogWarning("Activity statistics (Last30Days, Last7Days, Today, LastActivityAt) require implementation based on logs for Org {OrgId}.", orgId);
            stats.TotalActivitiesLast30Days = 0;
            stats.TotalActivitiesLast7Days = 0;
            stats.TodayActivityCount = 0;
            stats.LastActivityAt = null;

            // 사용량 통계
            _logger.LogWarning("Usage statistics (MonthlyApiCalls, Storage) require implementation for Org {OrgId}.", orgId);
            stats.MonthlyApiCalls = await GetMonthlyApiCallsAsync(orgId, cancellationToken);
            stats.StorageUsedGB = await GetLogStorageUsageGBAsync(orgId, cancellationToken); // Log 스토리지 사용량 호출
            stats.StorageAllocatedGB = 0m; // TODO: 플랜 정보 기반 할당량 조회 필요

            // 재무 통계 (빌링 시스템 연동 필요)
            _logger.LogWarning("Financial statistics (Cost, Revenue, Balance, Points) require Billing/Point system integration for Org {OrgId}.", orgId);
            stats.MonthlyTotalCost = 0m;
            stats.MonthlyTotalRevenue = 0m;
            stats.OutstandingBalance = 0m;
            stats.PointBalance = 0m;

            // 보안 통계 (보안 로그 집계 필요)
            _logger.LogWarning("Security statistics (Incidents, HighRisk) require security log aggregation for Org {OrgId}.", orgId);
            stats.SecurityIncidentsLast30Days = 0;
            stats.HighRiskActivitiesLast30Days = 0;

            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, stats, _cacheExpiration, cancellationToken);
            }

            return stats;
        }

        /// <summary>
        /// 타입별 조직 수 통계
        /// </summary>
        public async Task<Dictionary<OrganizationType, int>> GetCountByTypeAsync(
            CancellationToken cancellationToken = default)
        {
            return await _context.Set<OrganizationEntity>()
                .Where(o => !o.IsDeleted)
                .GroupBy(o => o.Type)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 상태별 조직 수 통계
        /// </summary>
        public async Task<Dictionary<OrganizationStatus, int>> GetCountByStatusAsync(
            CancellationToken cancellationToken = default)
        {
            return await _context.Set<OrganizationEntity>()
                .Where(o => !o.IsDeleted)
                .GroupBy(o => o.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 조직의 멤버 수 조회
        /// </summary>
        public async Task<int> GetMemberCountAsync(
            Guid organizationId,
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            var query = _context.Set<OrganizationMembership>()
                .Where(m => m.OrganizationId == organizationId && !m.IsDeleted);

            if (activeOnly)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 조직의 애플리케이션 수 조회
        /// </summary>
        public async Task<int> GetApplicationCountAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await _context.Set<PlatformApplicationEntity>()
                .Where(a => a.OrganizationId == organizationId && !a.IsDeleted)
                .CountAsync(cancellationToken);
        }

        /// <summary>
        /// 대시보드 통계 조회
        /// </summary>
        public async Task<DashboardStatistics> GetDashboardStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            // TODO: 서비스 계층에서 구현하는 것을 권장
            _logger.LogWarning("GetDashboardStatisticsAsync aggregates multiple stats; consider implementing this in the Service layer for Org {OrgId}.", organizationId);

            var stats = new DashboardStatistics
            {
                OrganizationId = organizationId,
                GeneratedAt = DateTime.UtcNow,
                StartDate = startDate ?? DateTime.UtcNow.AddDays(-30),
                EndDate = endDate ?? DateTime.UtcNow
            };

            stats.Core = await GetCoreMetricsAsync(organizationId, cancellationToken);
            stats.Activity = await GetActivityMetricsAsync(organizationId, startDate, endDate, cancellationToken);
            stats.Growth = await GetGrowthMetricsAsync(organizationId, cancellationToken);
            stats.Usage = await GetUsageMetricsAsync(organizationId, startDate, endDate, cancellationToken);
            stats.Security = await GetSecurityMetricsAsync(organizationId, cancellationToken);

            return stats;
        }

        /// <summary>
        /// 특정 조직의 활동 로그가 차지하는 현재 스토리지 사용량을 GB 단위로 조회합니다.
        /// </summary>
        public Task<decimal> GetLogStorageUsageGBAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 실제 로그 스토리지 사용량 측정 로직 구현 필요 (인프라 연동 등)
            _logger.LogWarning("GetLogStorageUsageGBAsync requires actual implementation depending on the logging infrastructure for Org {OrgId}.", organizationId);
            return Task.FromResult(0m); // 임시 값
        }


        #region Private Helper Methods

        // 멤버 통계 헬퍼
        private async Task<(int TotalMembers, int ActiveMembers, int ActiveConnectedIds, double TwoFactorPercentage)>
            GetMemberStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var memberships = await _context.Set<OrganizationMembership>()
                .Where(m => m.OrganizationId == organizationId && !m.IsDeleted)
                // [FIXED] Include에 올바른 탐색 속성 'Member' 사용
                .Include(m => m.Member)
                  // [FIXED] 이제 c는 ConnectedId 타입이므로 c.User 접근 가능
                  .ThenInclude(c => c!.User) // c는 ConnectedId 타입, c.User는 User 타입
                .ToListAsync(cancellationToken);

            // --- 나머지 계산 로직 (수정) ---
            var totalMembers = memberships.Count;
            var activeMembers = memberships.Count(m => m.Status == OrganizationMembershipStatus.Active);

            // Active ConnectedId 수 계산 (실제 연결된 사용자)
            // [FIXED] 'Member' 속성 사용
            var activeConnectedIds = memberships
                .Where(m => m.Status == OrganizationMembershipStatus.Active && m.Member != null)
                .Select(m => m.Member!.Id) // ! 사용
                .Distinct()
                .Count();

            // 2FA 활성화 비율 계산 (User 엔티티에 TwoFactorEnabled 속성 가정)
            // [FIXED] 'Member' 속성 사용
            var activeUsersWithConnectedId = memberships
                .Where(m => m.Status == OrganizationMembershipStatus.Active && m.Member?.User != null)
                .Select(m => m.Member!.User!) // !, ! 사용
                .ToList();

            double twoFactorPercentage = 0.0;
            if (activeUsersWithConnectedId.Any())
            {
                int twoFactorEnabledCount = activeUsersWithConnectedId.Count(u => u.TwoFactorEnabled);
                if (activeUsersWithConnectedId.Count > 0) // 0으로 나누기 방지
                {
                    twoFactorPercentage = (double)twoFactorEnabledCount / activeUsersWithConnectedId.Count * 100.0;
                }
            }
            return (totalMembers, activeMembers, activeConnectedIds, twoFactorPercentage);
        }

        // 애플리케이션 통계 헬퍼
        private async Task<(int TotalApplications, int ActiveApplications)>
            GetApplicationStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var totalApplications = await _context.Set<PlatformApplicationEntity>()
                .CountAsync(a => a.OrganizationId == organizationId && !a.IsDeleted, cancellationToken);
            var activeApplications = await _context.Set<PlatformApplicationEntity>()
                .CountAsync(a => a.OrganizationId == organizationId && !a.IsDeleted && a.IsActive, cancellationToken);
            return (totalApplications, activeApplications);
        }

        // 계층 구조 통계 헬퍼
        private async Task<(int ChildCount, int Depth)>
            GetHierarchyStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var childCount = await _context.Set<OrganizationEntity>()
                .CountAsync(o => o.ParentId == organizationId && !o.IsDeleted, cancellationToken);

            var currentLevel = await _context.Set<OrganizationEntity>()
                .Where(o => o.Id == organizationId && !o.IsDeleted)
                .Select(o => o.Level)
                .FirstOrDefaultAsync(cancellationToken);

            // Path 기반 쿼리 (예시: PostgreSQL)
            // EF Core 7.0 이상: EF.Functions.HierarchyId 사용 가능
            var orgPathPrefix = $"/{organizationId}/"; // 자신의 Path 제외
            if (organizationId == Guid.Empty) orgPathPrefix = "/"; // 루트 조직 처리

            var maxDescendantLevel = await _context.Set<OrganizationEntity>()
                .Where(o => o.Path != null && o.Path.StartsWith(orgPathPrefix) && !o.IsDeleted)
                .OrderByDescending(o => o.Level)
                .Select(o => (int?)o.Level)
                .FirstOrDefaultAsync(cancellationToken);

            var depth = maxDescendantLevel.HasValue ? maxDescendantLevel.Value - currentLevel : 0;
            return (childCount, depth);
        }

        // 월간 API 호출 수 (TODO)
        private Task<long> GetMonthlyApiCallsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            _logger.LogWarning("GetMonthlyApiCallsAsync requires actual implementation based on API usage logs for Org {OrgId}.", organizationId);
            return Task.FromResult(0L);
        }

        // 대시보드 - 핵심 메트릭
        private async Task<CoreMetrics> GetCoreMetricsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var metrics = new CoreMetrics
            {
                TotalMembers = await GetMemberCountAsync(organizationId, false, cancellationToken),
                ActiveMembers = await GetMemberCountAsync(organizationId, true, cancellationToken),
                TotalApplications = await GetApplicationCountAsync(organizationId, cancellationToken),
                ActiveApplications = await GetActiveApplicationCountAsync(organizationId, cancellationToken),
                TotalDomains = await GetDomainCountAsync(organizationId, cancellationToken),
                ChildOrganizations = await GetChildOrganizationCountAsync(organizationId, cancellationToken)
            };
            metrics.TotalRoles = await _context.Roles.CountAsync(r => r.OrganizationId == organizationId && !r.IsDeleted, cancellationToken);
            metrics.TotalPermissions = 0; // TODO: Permission 수 집계 로직 필요
            return metrics;
        }

        // 대시보드 - 활성 애플리케이션 수
        private async Task<int> GetActiveApplicationCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<PlatformApplicationEntity>()
                .CountAsync(a => a.OrganizationId == organizationId && a.IsActive && !a.IsDeleted, cancellationToken);
        }

        // 대시보드 - 도메인 수
        private async Task<int> GetDomainCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<OrganizationDomain>()
                .CountAsync(d => d.OrganizationId == organizationId && !d.IsDeleted, cancellationToken);
        }

        // 대시보드 - 자식 조직 수
        private async Task<int> GetChildOrganizationCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<OrganizationEntity>()
                .CountAsync(o => o.ParentId == organizationId && !o.IsDeleted, cancellationToken);
        }

        // 대시보드 - 활동 메트릭 (TODO)
        private Task<ActivityMetrics> GetActivityMetricsAsync(
            Guid organizationId, DateTime? startDate, DateTime? endDate, CancellationToken cancellationToken)
        {
            _logger.LogWarning("GetActivityMetricsAsync requires actual implementation based on activity logs for Org {OrgId}.", organizationId);
            var metrics = new ActivityMetrics { /* Default values or 0 */ };
            return Task.FromResult(metrics);
        }

        // 대시보드 - 성장 메트릭 (TODO)
        private Task<GrowthMetrics> GetGrowthMetricsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            _logger.LogWarning("GetGrowthMetricsAsync requires actual implementation based on logs for Org {OrgId}.", organizationId);
            var metrics = new GrowthMetrics { /* Default values or 0 */ };
            return Task.FromResult(metrics);
        }

        // 대시보드 - 사용량 메트릭 (TODO)
        private Task<DashboardUsageMetrics> GetUsageMetricsAsync(
            Guid organizationId, DateTime? startDate, DateTime? endDate, CancellationToken cancellationToken)
        {
            _logger.LogWarning("GetUsageMetricsAsync requires actual implementation based on usage logs for Org {OrgId}.", organizationId);
            var metrics = new DashboardUsageMetrics { /* Default values or 0 */ };
            return Task.FromResult(metrics);
        }

        // 대시보드 - 보안 메트릭 (TODO)
        private async Task<SecurityMetrics> GetSecurityMetricsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            _logger.LogWarning("GetSecurityMetricsAsync requires actual implementation based on security event logs for Org {OrgId}.", organizationId);

            // 2FA 비율은 여기서 다시 계산 (비효율적일 수 있으므로 서비스 계층 통합 고려)
            var memberStats = await GetMemberStatisticsAsync(organizationId, cancellationToken);
            var metrics = new SecurityMetrics
            {
                FailedLoginAttemptsToday = 0,
                BlockedIpAddresses = 0,
                SuspiciousActivities = 0,
                MfaEnabledUsers = (int)(memberStats.ActiveMembers * (memberStats.TwoFactorPercentage / 100.0)),
                MfaAdoptionRate = memberStats.TwoFactorPercentage,
                SsoEnabledApplications = await _context.OrganizationSSOs.CountAsync(s => s.OrganizationId == organizationId && s.IsActive && !s.IsDeleted, cancellationToken), // SSO 수 조회
                RecentSecurityEvents = new(),
                SecurityEventsByType = new()
            };
            return metrics;
        }

        // 임시 데이터 생성 헬퍼 제거됨

        #endregion
    }
}