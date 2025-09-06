using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Services.Context;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 통계 전용 Repository 구현체 - AuthHive v15
    /// 조직의 다양한 통계 정보를 제공하는 읽기 전용 Repository
    /// </summary>
    public class OrganizationStatisticsRepository : IOrganizationStatisticsRepository
    {
        private readonly AuthDbContext _context;
        private readonly IOrganizationContext _organizationContext;
        private readonly IMemoryCache? _cache;
        private const string CACHE_KEY_PREFIX = "org_stats_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(10);

        public OrganizationStatisticsRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
            _cache = cache;
        }

        /// <summary>
        /// 조직 통계 정보 조회
        /// </summary>
        public async Task<OrganizationStatistics> GetStatisticsAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var orgId = organizationId ?? _organizationContext.CurrentOrganizationId 
                ?? throw new InvalidOperationException("Organization ID is required");

            var cacheKey = $"{CACHE_KEY_PREFIX}stats_{orgId}";
            
            if (_cache != null && _cache.TryGetValue<OrganizationStatistics>(cacheKey, out var cached))
            {
                return cached!;
            }

            var organization = await _context.Set<OrganizationEntity>()
                .AsNoTracking()
                .FirstOrDefaultAsync(o => o.Id == orgId && !o.IsDeleted, cancellationToken)
                ?? throw new InvalidOperationException($"Organization {orgId} not found");

            var stats = new OrganizationStatistics
            {
                OrganizationId = orgId,
                OrganizationName = organization.Name,
                OrganizationStatus = organization.Status.ToString(),
                CurrentPlan = organization.Type.ToString(),
                GeneratedAt = DateTime.UtcNow,
                NextRefreshAt = DateTime.UtcNow.AddMinutes(10)
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

            // Capability 통계
            var capabilityStats = await GetCapabilityStatisticsAsync(orgId, cancellationToken);
            stats.PrimaryCapability = capabilityStats.Primary;
            stats.ActiveCapabilityCount = capabilityStats.ActiveCount;

            // 활동 통계
            var activityStats = await GetActivityStatisticsAsync(orgId, cancellationToken);
            stats.TotalActivitiesLast30Days = activityStats.Last30Days;
            stats.TotalActivitiesLast7Days = activityStats.Last7Days;
            stats.TodayActivityCount = activityStats.Today;
            stats.LastActivityAt = activityStats.LastActivityAt;

            // 사용량 통계 (예시 값)
            stats.MonthlyApiCalls = await GetMonthlyApiCallsAsync(orgId, cancellationToken);
            stats.StorageUsedGB = 2.5m; // 실제 구현 필요
            stats.StorageAllocatedGB = 10m; // 실제 구현 필요

            // 재무 통계 (예시 값)
            stats.MonthlyTotalCost = 1000m; // 실제 구현 필요
            stats.MonthlyTotalRevenue = 5000m; // 실제 구현 필요
            stats.OutstandingBalance = 0m; // 실제 구현 필요
            stats.PointBalance = 1000m; // 실제 구현 필요

            // 보안 통계
            stats.SecurityIncidentsLast30Days = 0; // 실제 구현 필요
            stats.HighRiskActivitiesLast30Days = 0; // 실제 구현 필요

            if (_cache != null)
            {
                _cache.Set(cacheKey, stats, _cacheExpiration);
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
            var query = _context.Set<Core.Entities.Organization.OrganizationMembership>()
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
            return await _context.Set<Core.Entities.PlatformApplications.PlatformApplication>()
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
            var stats = new DashboardStatistics
            {
                OrganizationId = organizationId,
                GeneratedAt = DateTime.UtcNow,
                StartDate = startDate ?? DateTime.UtcNow.AddDays(-30),
                EndDate = endDate ?? DateTime.UtcNow
            };

            // 핵심 메트릭
            stats.Core = await GetCoreMetricsAsync(organizationId, cancellationToken);

            // 활동 메트릭
            stats.Activity = await GetActivityMetricsAsync(organizationId, startDate, endDate, cancellationToken);

            // 성장 메트릭
            stats.Growth = await GetGrowthMetricsAsync(organizationId, cancellationToken);

            // 사용량 메트릭
          
            // 사용량 메트릭
            stats.Usage = await GetUsageMetricsAsync(organizationId, startDate, endDate, cancellationToken);


            // 보안 메트릭
            stats.Security = await GetSecurityMetricsAsync(organizationId, cancellationToken);

            return stats;
        }

        #region Private Helper Methods

        private async Task<(int TotalMembers, int ActiveMembers, int ActiveConnectedIds, double TwoFactorPercentage)> 
            GetMemberStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var memberships = await _context.Set<Core.Entities.Organization.OrganizationMembership>()
                .Where(m => m.OrganizationId == organizationId && !m.IsDeleted)
                .ToListAsync(cancellationToken);

            var totalMembers = memberships.Count;
            var activeMembers = memberships.Count(m => m.Status == OrganizationMembershipStatus.Active);
            
            // ConnectedId 통계는 실제 구현 필요
            var activeConnectedIds = activeMembers; // 임시 값
            var twoFactorPercentage = 60.0; // 임시 값

            return (totalMembers, activeMembers, activeConnectedIds, twoFactorPercentage);
        }

        private async Task<(int TotalApplications, int ActiveApplications)> 
            GetApplicationStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var applications = await _context.Set<Core.Entities.PlatformApplications.PlatformApplication>()
                .Where(a => a.OrganizationId == organizationId && !a.IsDeleted)
                .ToListAsync(cancellationToken);

            return (applications.Count, applications.Count(a => a.IsActive));
        }

        private async Task<(int ChildCount, int Depth)> 
            GetHierarchyStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var childCount = await _context.Set<OrganizationEntity>()
                .CountAsync(o => o.ParentOrganizationId == organizationId && !o.IsDeleted, cancellationToken);

            // 계층 깊이 계산 (재귀적 구현 필요)
            var depth = await CalculateHierarchyDepthAsync(organizationId, cancellationToken);

            return (childCount, depth);
        }

        private async Task<int> CalculateHierarchyDepthAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var children = await _context.Set<OrganizationEntity>()
                .Where(o => o.ParentOrganizationId == organizationId && !o.IsDeleted)
                .Select(o => o.Id)
                .ToListAsync(cancellationToken);

            if (!children.Any())
                return 0;

            var maxDepth = 0;
            foreach (var childId in children)
            {
                var childDepth = await CalculateHierarchyDepthAsync(childId, cancellationToken);
                maxDepth = Math.Max(maxDepth, childDepth);
            }

            return maxDepth + 1;
        }

        private async Task<(OrganizationCapabilityEnum Primary, int ActiveCount)> 
            GetCapabilityStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            // 실제 구현 필요 - 임시 값 반환
            return await Task.FromResult((OrganizationCapabilityEnum.Customer, 1));
        }

        private async Task<(int Last30Days, int Last7Days, int Today, DateTime? LastActivityAt)> 
            GetActivityStatisticsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var now = DateTime.UtcNow;
            var thirtyDaysAgo = now.AddDays(-30);
            var sevenDaysAgo = now.AddDays(-7);
            var todayStart = now.Date;

            // UserActivityLog 테이블 조회 (실제 구현 필요)
            // 임시 값 반환
            return await Task.FromResult((100, 30, 5, (DateTime?)now));
        }

        private async Task<long> GetMonthlyApiCallsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            // API 호출 로그 테이블 조회 (실제 구현 필요)
            return await Task.FromResult(10000L);
        }

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

            // Roles와 Permissions 수 (실제 구현 필요)
            metrics.TotalRoles = 5;
            metrics.TotalPermissions = 20;

            return metrics;
        }

        private async Task<int> GetActiveApplicationCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<Core.Entities.PlatformApplications.PlatformApplication>()
                .CountAsync(a => a.OrganizationId == organizationId && a.IsActive && !a.IsDeleted, cancellationToken);
        }

        private async Task<int> GetDomainCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<Core.Entities.Organization.OrganizationDomain>()
                .CountAsync(d => d.OrganizationId == organizationId && !d.IsDeleted, cancellationToken);
        }

        private async Task<int> GetChildOrganizationCountAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            return await _context.Set<OrganizationEntity>()
                .CountAsync(o => o.ParentOrganizationId == organizationId && !o.IsDeleted, cancellationToken);
        }

        private async Task<ActivityMetrics> GetActivityMetricsAsync(
            Guid organizationId, 
            DateTime? startDate, 
            DateTime? endDate, 
            CancellationToken cancellationToken)
        {
            var now = DateTime.UtcNow;
            var metrics = new ActivityMetrics
            {
                // 실제 구현 필요 - 임시 값
                TodayLogins = 50,
                WeeklyActiveUsers = 150,
                MonthlyActiveUsers = 300,
                TotalApiCalls = 10000,
                AverageSessionDuration = 25.5,
                HourlyBreakdown = GenerateHourlyBreakdown(),
                ActivityByApplication = new Dictionary<string, int>
                {
                    { "Web Portal", 5000 },
                    { "Mobile App", 3000 },
                    { "API", 2000 }
                }
            };

            return await Task.FromResult(metrics);
        }

        private List<HourlyActivity> GenerateHourlyBreakdown()
        {
            var breakdown = new List<HourlyActivity>();
            for (int hour = 0; hour < 24; hour++)
            {
                breakdown.Add(new HourlyActivity
                {
                    Hour = hour,
                    Logins = Random.Shared.Next(0, 20),
                    ApiCalls = Random.Shared.Next(100, 1000),
                    UniqueUsers = Random.Shared.Next(5, 50)
                });
            }
            return breakdown;
        }

        private async Task<GrowthMetrics> GetGrowthMetricsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var metrics = new GrowthMetrics
            {
                // 실제 구현 필요 - 임시 값
                NewMembersToday = 2,
                NewMembersThisWeek = 10,
                NewMembersThisMonth = 25,
                MemberGrowthRate = 5.5,
                ApplicationGrowthRate = 2.3,
                WeeklyTrend = GenerateGrowthTrend(7),
                MonthlyTrend = GenerateGrowthTrend(30)
            };

            return await Task.FromResult(metrics);
        }

        private List<GrowthTrend> GenerateGrowthTrend(int days)
        {
            var trends = new List<GrowthTrend>();
            var now = DateTime.UtcNow;
            
            for (int i = days - 1; i >= 0; i--)
            {
                trends.Add(new GrowthTrend
                {
                    Period = now.AddDays(-i).Date,
                    Members = 300 - (i * 2),
                    Applications = 10 + (days - i),
                    ActiveUsers = 150 + Random.Shared.Next(-10, 10),
                    ApiCalls = 10000 + Random.Shared.Next(-1000, 1000)
                });
            }
            
            return trends;
        }

        private async Task<DashboardUsageMetrics> GetUsageMetricsAsync(
            Guid organizationId,
            DateTime? startDate,
            DateTime? endDate,
            CancellationToken cancellationToken)
        {
            var metrics = new DashboardUsageMetrics
            {
                // 실제 구현 필요 - 임시 값
                TotalApiCalls = 100000,
                SuccessfulApiCalls = 98000,
                FailedApiCalls = 2000,
                AverageResponseTime = 125.5,
                PeakUsageTime = "14:00-15:00",
                StorageUsedGB = 2.5m,
                StorageAllocatedGB = 10m,
                BandwidthUsedGB = 15.7m,
                DatabaseConnections = 25,
                ApiUsageTrend = GenerateApiUsageTrend()
            };

            return await Task.FromResult(metrics);
        }

        private List<ApiUsageTrend> GenerateApiUsageTrend()
        {
            var trends = new List<ApiUsageTrend>();
            var now = DateTime.UtcNow;
            
            for (int i = 6; i >= 0; i--)
            {
                var total = Random.Shared.Next(8000, 12000);
                trends.Add(new ApiUsageTrend
                {
                    Date = now.AddDays(-i).Date,
                    TotalCalls = total,
                    SuccessfulCalls = (long)(total * 0.98),
                    FailedCalls = (long)(total * 0.02),
                    AverageResponseTime = 100 + Random.Shared.Next(0, 50)
                });
            }
            
            return trends;
        }

        private async Task<SecurityMetrics> GetSecurityMetricsAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var metrics = new SecurityMetrics
            {
                // 실제 구현 필요 - 임시 값
                FailedLoginAttemptsToday = 5,
                BlockedIpAddresses = 2,
                SuspiciousActivities = 1,
                MfaEnabledUsers = 180,
                MfaAdoptionRate = 60.0,
                SsoEnabledApplications = 3,
                RecentSecurityEvents = GenerateSecurityEvents(),
                SecurityEventsByType = new Dictionary<string, int>
                {
                    { "Failed Login", 5 },
                    { "Suspicious Activity", 1 },
                    { "Password Reset", 3 }
                }
            };

            return await Task.FromResult(metrics);
        }

        private List<SecurityEvent> GenerateSecurityEvents()
        {
            return new List<SecurityEvent>
            {
                new SecurityEvent
                {
                    OccurredAt = DateTime.UtcNow.AddHours(-2),
                    EventType = "Failed Login",
                    Description = "Multiple failed login attempts",
                    IpAddress = "192.168.1.100",
                    Severity = "Medium"
                },
                new SecurityEvent
                {
                    OccurredAt = DateTime.UtcNow.AddHours(-5),
                    EventType = "Password Reset",
                    Description = "User requested password reset",
                    UserId = Guid.NewGuid().ToString(),
                    Severity = "Low"
                }
            };
        }

        #endregion
    }
}