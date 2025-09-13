using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Auth.Permissions.Common;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using AuthHive.Core.Models.Core.Audit;


namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 권한 통계 및 분석 서비스
    /// 권한 사용 패턴, 성능 메트릭, 보안 분석 등을 제공
    /// </summary>
    public class PermissionStatisticsService
    {
        private readonly IPermissionRepository _permissionRepository;
        private readonly IPermissionValidationLogRepository _validationLogRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IMemoryCache _cache;
        private readonly ILogger<PermissionStatisticsService> _logger;

        public PermissionStatisticsService(
            IPermissionRepository permissionRepository,
            IPermissionValidationLogRepository validationLogRepository,
            IRoleRepository roleRepository,
            IPlatformApplicationRepository applicationRepository,
            IOrganizationRepository organizationRepository,
            IRolePermissionRepository rolePermissionRepository,
            IMemoryCache cache,
            ILogger<PermissionStatisticsService> logger)
        {
            _permissionRepository = permissionRepository;
            _validationLogRepository = validationLogRepository;
            _roleRepository = roleRepository;
            _applicationRepository = applicationRepository;
            _organizationRepository = organizationRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _cache = cache;
            _logger = logger;
        }

        #region 권한 사용 통계

        /// <summary>
        /// 조직의 권한 사용 통계 조회
        /// </summary>
        public async Task<PermissionUsageStatistics> GetUsageStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var cacheKey = $"permission:usage:stats:{organizationId}:{startDate?.Ticks}:{endDate?.Ticks}";

            return await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5);

                var statistics = new PermissionUsageStatistics
                {
                    OrganizationId = organizationId,
                    StartDate = startDate ?? DateTime.UtcNow.AddDays(-30),
                    EndDate = endDate ?? DateTime.UtcNow
                };

                // 전체 권한 수
                var allPermissions = await _permissionRepository.GetActivePermissionsAsync();
                statistics.TotalPermissions = allPermissions?.Count() ?? 0;

                // 사용된 권한 수 (검증 로그 기반)
                var usageFrequency = await _validationLogRepository.GetPermissionUsageFrequencyAsync(
                    organizationId,
                    (int)(statistics.EndDate - statistics.StartDate).TotalDays);

                // null 체크 추가
                if (usageFrequency == null)
                {
                    usageFrequency = new Dictionary<string, int>();
                }

                statistics.ActivePermissions = usageFrequency.Count;
                statistics.UnusedPermissions = statistics.TotalPermissions - statistics.ActivePermissions;

                // 가장 많이 사용된 권한 Top 10
                statistics.MostUsedPermissions = usageFrequency
                    .OrderByDescending(kvp => kvp.Value)
                    .Take(10)
                    .Select(kvp => new PermissionUsageItem
                    {
                        Scope = kvp.Key,
                        UsageCount = kvp.Value
                    })
                    .ToList();

                // 카테고리별 사용 통계
                foreach (PermissionCategory category in Enum.GetValues<PermissionCategory>())
                {
                    var categoryPermissions = await _permissionRepository.GetByCategoryAsync(category);
                    if (categoryPermissions == null || !categoryPermissions.Any())
                    {
                        statistics.UsageByCategory[category] = 0;
                        continue;
                    }

                    var categoryScopes = categoryPermissions.Select(p => p.Scope).ToHashSet();
                    var categoryUsage = usageFrequency
                        .Where(kvp => categoryScopes.Contains(kvp.Key))
                        .Sum(kvp => kvp.Value);

                    statistics.UsageByCategory[category] = categoryUsage;
                }

                // 시간대별 사용 패턴
                for (var date = statistics.StartDate.Date; date <= statistics.EndDate.Date; date = date.AddDays(1))
                {
                    var hourlyPattern = await _validationLogRepository.GetHourlyValidationPatternAsync(
                        organizationId, date);

                    if (hourlyPattern == null || !hourlyPattern.Any())
                        continue;

                    // 피크 시간대 찾기
                    var peakHour = hourlyPattern.OrderByDescending(kvp => kvp.Value).FirstOrDefault();
                    if (peakHour.Value > 0)
                    {
                        statistics.PeakUsageHours.Add(new DateTime(date.Year, date.Month, date.Day, peakHour.Key, 0, 0));
                    }
                }

                return statistics;
            }) ?? new PermissionUsageStatistics  // null 반환 시 기본 객체 반환
            {
                OrganizationId = organizationId,
                StartDate = startDate ?? DateTime.UtcNow.AddDays(-30),
                EndDate = endDate ?? DateTime.UtcNow
            };
        }

        /// <summary>
        /// 특정 권한의 상세 사용 통계
        /// </summary>
        public async Task<PermissionDetailStatistics> GetPermissionDetailStatisticsAsync(
            Guid permissionId,
            int days = 30)
        {
            var permission = await _permissionRepository.GetByIdAsync(permissionId);
            if (permission == null)
            {
                throw new ArgumentException("Permission not found", nameof(permissionId));
            }

            var statistics = new PermissionDetailStatistics
            {
                PermissionId = permissionId,
                Scope = permission.Scope,
                Name = permission.Name,
                Category = permission.Category,
                Level = (int)permission.Level
            };

            // 최근 검증 로그
            var recentLogs = await _validationLogRepository.GetRecentByPermissionIdAsync(permissionId, days);
            var logsList = recentLogs.ToList();

            statistics.TotalValidations = logsList.Count;
            statistics.SuccessfulValidations = logsList.Count(l => l.IsAllowed);
            statistics.FailedValidations = logsList.Count(l => !l.IsAllowed);
            statistics.SuccessRate = statistics.TotalValidations > 0
                ? (double)statistics.SuccessfulValidations / statistics.TotalValidations * 100
                : 0;

            // 고유 사용자 수
            statistics.UniqueUsers = logsList.Select(l => l.ConnectedId).Distinct().Count();

            // 사용하는 역할들
            // FindAsync()를 사용하여 DB 레벨에서 필터링
            var rolePermissions = await _rolePermissionRepository.FindAsync(
                rp => rp.PermissionId == permissionId);

            var roleIds = rolePermissions.Select(rp => rp.RoleId).Distinct().ToList();

            var assignedRoles = new List<string>();
            foreach (var roleId in roleIds)
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role != null)
                {
                    assignedRoles.Add(role.Name);
                }
            }
            statistics.AssignedRoles = assignedRoles;

            // 마지막 사용 시간
            var lastValidation = await _validationLogRepository.GetLastValidationAsync(permissionId);
            statistics.LastUsedAt = lastValidation?.Timestamp;

            // 평균 검증 시간
            var logsWithDuration = logsList.Where(l => l.ValidationDurationMs.HasValue).ToList();
            if (logsWithDuration.Any())
            {
                statistics.AverageValidationTimeMs = logsWithDuration.Average(l => l.ValidationDurationMs!.Value);
            }

            // 거부 사유 분석
            var deniedLogs = logsList.Where(l => !l.IsAllowed && !string.IsNullOrEmpty(l.DenialReason)).ToList();
            statistics.TopDenialReasons = deniedLogs
                .GroupBy(l => l.DenialReason!)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new DenialReasonItem
                {
                    Reason = g.Key,
                    Count = g.Count()
                })
                .ToList();

            return statistics;
        }

        #endregion

        #region 성능 분석

        /// <summary>
        /// 권한 검증 성능 메트릭 조회
        /// </summary>
        public async Task<PermissionPerformanceMetrics> GetPerformanceMetricsAsync(
            Guid organizationId,
            int days = 7)
        {
            var metrics = new PermissionPerformanceMetrics
            {
                OrganizationId = organizationId,
                Period = TimeSpan.FromDays(days)
            };

            // 평균 검증 시간
            metrics.AverageValidationTimeMs = await _validationLogRepository
                .GetAverageValidationTimeAsync(organizationId, days);

            // 캐시 히트율
            metrics.CacheHitRate = await _validationLogRepository
                .CalculateCacheHitRateAsync(organizationId, days);

            // 캐시 상태별 통계
            var cacheStats = await _validationLogRepository.GetCacheStatusStatisticsAsync(
                organizationId,
                DateTime.UtcNow.AddDays(-days),
                DateTime.UtcNow);

            metrics.CacheStatistics = cacheStats;

            // 느린 검증 조회 (100ms 이상)
            var slowValidations = await _validationLogRepository
                .GetSlowValidationsAsync(100, organizationId, 50);

            metrics.SlowValidationCount = slowValidations.Count();
            metrics.SlowValidationScopes = slowValidations
                .GroupBy(l => l.RequestedScope)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => new SlowValidationItem
                {
                    Scope = g.Key,
                    Count = g.Count(),
                    AverageTimeMs = g.Average(l => l.ValidationDurationMs ?? 0)
                })
                .ToList();

            // 검증 결과별 통계
            var validationResults = await _validationLogRepository
                .GetValidationResultStatisticsAsync(organizationId, days);

            metrics.ValidationResultDistribution = validationResults;

            return metrics;
        }

        /// <summary>
        /// 권한별 성능 순위
        /// </summary>
        public async Task<IEnumerable<PermissionPerformanceRanking>> GetPerformanceRankingAsync(
            Guid organizationId,
            int topN = 20)
        {
            var usageFrequency = await _validationLogRepository
                .GetPermissionUsageFrequencyAsync(organizationId, 30);

            var rankings = new List<PermissionPerformanceRanking>();

            foreach (var (scope, count) in usageFrequency.Take(topN))
            {
                var permissions = await _permissionRepository.GetByScopesAsync(new[] { scope });
                var permission = permissions.FirstOrDefault();

                if (permission != null)
                {
                    rankings.Add(new PermissionPerformanceRanking
                    {
                        PermissionId = permission.Id,
                        Scope = scope,
                        Name = permission.Name,
                        UsageCount = count,
                        Category = permission.Category,
                        Level = (int)permission.Level
                    });
                }
            }

            return rankings.OrderByDescending(r => r.UsageCount);
        }

        #endregion

        #region 보안 분석

        /// <summary>
        /// 권한 관련 보안 위험 분석
        /// </summary>
        public async Task<PermissionSecurityAnalysis> AnalyzeSecurityRisksAsync(
            Guid organizationId)
        {
            var analysis = new PermissionSecurityAnalysis
            {
                OrganizationId = organizationId,
                AnalyzedAt = DateTime.UtcNow
            };

            // 과도한 권한 할당 검사
            var roles = await _roleRepository.GetByOrganizationAsync(organizationId);
            foreach (var role in roles)
            {
                var permissionCount = await _roleRepository.GetPermissionCountAsync(role.Id);
                if (permissionCount > 50) // 임계값
                {
                    analysis.OverPrivilegedRoles.Add(new OverPrivilegedRole
                    {
                        RoleId = role.Id,
                        RoleName = role.Name,
                        PermissionCount = permissionCount
                    });
                }
            }

            // 사용되지 않는 권한
            var unusedPermissions = await _validationLogRepository
                .FindUnusedPermissionsAsync(organizationId, 90);
            analysis.UnusedPermissions = unusedPermissions.ToList();

            // 거부율이 높은 권한
            var deniedScopes = await _validationLogRepository
                .GetMostDeniedScopesAsync(organizationId, 10);

            analysis.HighDenialPermissions = deniedScopes
                .Where(d => d.DenialCount > 10)
                .Select(d => new HighDenialPermission
                {
                    Scope = d.Scope,
                    DenialCount = d.DenialCount
                })
                .ToList();

            // 의심스러운 접근 패턴
            var abnormalAttempts = await _validationLogRepository
                .GetAbnormalAccessAttemptsAsync(organizationId, 5, 5);

            if (abnormalAttempts.Any())
            {
                analysis.SuspiciousActivityDetected = true;
                analysis.SuspiciousActivities = abnormalAttempts
                    .GroupBy(l => l.ConnectedId)
                    .Select(g => new SuspiciousActivity
                    {
                        Id = Guid.NewGuid(),
                        UserId = g.Key,  // ConnectedId 대신 UserId 사용
                        Count = g.Count(),  // AttemptCount 대신 Count 사용
                        LastOccurrence = g.Max(l => l.Timestamp),  // LastAttemptAt 대신 LastOccurrence 사용
                        FirstOccurrence = g.Min(l => l.Timestamp),
                        Type = "Abnormal Permission Access",
                        Description = $"Abnormal access attempts detected for user {g.Key}",
                        RiskScore = g.Count() > 10 ? "High" : "Medium"
                    })
                    .ToList();
            }

            // 위험 점수 계산
            analysis.RiskScore = CalculateRiskScore(analysis);

            return analysis;
        }

        /// <summary>
        /// 권한 충돌 감지
        /// </summary>
        public async Task<IEnumerable<PermissionConflict>> DetectPermissionConflictsAsync(
            Guid organizationId)
        {
            var conflicts = new List<PermissionConflict>();

            // GetActivePermissionsAsync 사용
            var permissions = await _permissionRepository.GetActivePermissionsAsync();

            // 상호 배타적인 권한 체크
            var exclusiveGroups = new Dictionary<string, List<PermissionEntity>>
            {
                ["user_management"] = new(),
                ["data_access"] = new(),
                ["system_admin"] = new()
            };

            foreach (var permission in permissions)
            {
                if (permission.Scope.Contains("user:delete") || permission.Scope.Contains("user:create"))
                    exclusiveGroups["user_management"].Add(permission);

                if (permission.Scope.Contains("data:read") || permission.Scope.Contains("data:write"))
                    exclusiveGroups["data_access"].Add(permission);

                if (permission.Scope.Contains("system:") || (int)permission.Level >= 4)
                    exclusiveGroups["system_admin"].Add(permission);
            }

            // 역할별로 충돌 검사
            var roles = await _roleRepository.GetByOrganizationAsync(organizationId);

            foreach (var role in roles)
            {
                // GetByRoleIdAsync 대신 GetByRoleAsync 사용
                var rolePermissions = await _rolePermissionRepository.GetByRoleAsync(
                    role.Id,
                    true,  // activeOnly
                    true); // includeInherited

                var permissionIds = rolePermissions.Select(rp => rp.PermissionId).ToHashSet();

                foreach (var group in exclusiveGroups)
                {
                    var conflictingPermissions = group.Value
                        .Where(p => permissionIds.Contains(p.Id))
                        .ToList();

                    if (conflictingPermissions.Count > 1)
                    {
                        conflicts.Add(new PermissionConflict
                        {
                            RoleId = role.Id,
                            RoleName = role.Name,
                            ConflictType = $"Multiple {group.Key} permissions",
                            ConflictingPermissions = conflictingPermissions
                                .Select(p => p.Scope)
                                .ToList()
                        });
                    }
                }
            }

            return conflicts;
        }
        #endregion

        #region 트렌드 분석

        /// <summary>
        /// 권한 사용 트렌드 분석
        /// </summary>
        public async Task<PermissionUsageTrend> AnalyzeUsageTrendAsync(
            Guid organizationId,
            int weeks = 4)
        {
            var trend = new PermissionUsageTrend
            {
                OrganizationId = organizationId,
                Period = TimeSpan.FromDays(weeks * 7)
            };

            var weeklyTrends = await _validationLogRepository
                .GetWeeklyTrendsAsync(organizationId, weeks);

            trend.WeeklyData = weeklyTrends.Select(wt => new WeeklyTrendData
            {
                WeekStart = wt.WeekStartDate,
                WeekEnd = wt.WeekEndDate,
                TotalValidations = wt.TotalValidations,
                SuccessRate = wt.TotalValidations > 0
                    ? (double)wt.SuccessfulValidations / wt.TotalValidations * 100
                    : 0,
                UniqueUsers = wt.UniqueUsers
            }).ToList();

            // 성장률 계산
            if (trend.WeeklyData.Count >= 2)
            {
                var lastWeek = trend.WeeklyData.Last();
                var previousWeek = trend.WeeklyData[trend.WeeklyData.Count - 2];

                if (previousWeek.TotalValidations > 0)
                {
                    trend.GrowthRate = ((double)lastWeek.TotalValidations - previousWeek.TotalValidations)
                        / previousWeek.TotalValidations * 100;
                }
            }

            // 새로 추가된 권한 - FindAsync 사용
            var recentPermissions = await _permissionRepository.FindAsync(
                p => p.CreatedAt >= DateTime.UtcNow.AddDays(-weeks * 7));
            trend.NewPermissionsAdded = recentPermissions.Count();

            // 비활성화된 권한 - FindAsync 사용
            var inactivePermissions = await _permissionRepository.FindAsync(
                p => !p.IsActive && p.UpdatedAt >= DateTime.UtcNow.AddDays(-weeks * 7));
            trend.PermissionsDeactivated = inactivePermissions.Count();

            return trend;
        }
        #endregion

        #region Helper Methods

        private int CalculateRiskScore(PermissionSecurityAnalysis analysis)
        {
            int score = 0;

            // 과도한 권한 역할
            score += analysis.OverPrivilegedRoles.Count * 10;

            // 사용되지 않는 권한
            score += Math.Min(analysis.UnusedPermissions.Count * 2, 20);

            // 높은 거부율 권한
            score += analysis.HighDenialPermissions.Count * 5;

            // 의심스러운 활동
            if (analysis.SuspiciousActivityDetected)
                score += 30;

            return Math.Min(score, 100); // 최대 100점
        }

        #endregion
    }
}