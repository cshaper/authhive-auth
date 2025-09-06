using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 권한 검증 감사 로그 Repository 구현체
    /// 모든 권한 검증 요청과 결과를 추적하여 보안 감사 및 컴플라이언스에 활용
    /// </summary>
    public class AuthorizationAuditLogRepository : BaseRepository<AuthorizationAuditLog>, IAuthorizationAuditLogRepository
    {
        public AuthorizationAuditLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회

        /// <summary>
        /// ConnectedId별 감사 로그 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? since = null,
            int? limit = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.ConnectedId == connectedId);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync();
        }

        /// <summary>
        /// 리소스별 감사 로그 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByResourceAsync(
            string resource,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.Resource == resource);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 액션별 감사 로그 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByActionAsync(
            string action,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.Action == action);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 리소스와 액션으로 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByResourceAndActionAsync(
            string resource,
            string action,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.Resource == resource && log.Action == action);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 특정 리소스 ID에 대한 감사 로그
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByResourceIdAsync(
            Guid resourceId,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.ResourceId == resourceId);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 애플리케이션별 감사 로그 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByApplicationAsync(
            Guid applicationId,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.ApplicationId == applicationId);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        #endregion

        #region 권한 거부 분석

        /// <summary>
        /// 거부된 권한 요청 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetDeniedRequestsAsync(
            Guid? connectedId = null,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => !log.IsAllowed);

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 거부 사유별 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetByDenialReasonAsync(
            PermissionValidationResult reason,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.DenialReason == reason);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 반복적인 권한 거부 패턴 감지
        /// </summary>
        public async Task<IEnumerable<RepeatedDenialPattern>> DetectRepeatedDenialsAsync(
            DateTime since,
            int threshold = 3)
        {
            var deniedLogs = await Query()
                .Where(log => !log.IsAllowed && log.Timestamp >= since)
                .ToListAsync();

            var patterns = deniedLogs
                .GroupBy(log => new { log.ConnectedId, log.Resource, log.Action })
                .Where(g => g.Count() >= threshold)
                .Select(g => new RepeatedDenialPattern
                {
                    ConnectedId = g.Key.ConnectedId,
                    Resource = g.Key.Resource,
                    Action = g.Key.Action,
                    DenialCount = g.Count(),
                    FirstDenial = g.Min(l => l.Timestamp),
                    LastDenial = g.Max(l => l.Timestamp),
                    Reasons = g.Where(l => l.DenialReason.HasValue)
                              .Select(l => l.DenialReason!.Value)
                              .Distinct()
                              .ToList()
                });

            return patterns;
        }

        /// <summary>
        /// 권한 에스컬레이션 시도 감지
        /// </summary>
        public async Task<IEnumerable<EscalationAttempt>> DetectEscalationAttemptsAsync(
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            
            // 높은 위험도 점수와 거부된 요청
            query = query.Where(log => !log.IsAllowed && log.RiskScore >= 70);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            var logs = await query.ToListAsync();

            return logs.Select(log => new EscalationAttempt
            {
                ConnectedId = log.ConnectedId,
                AttemptedResource = $"{log.Resource}:{log.Action}",
                CurrentPermissions = log.EvaluatedPermissions ?? "",
                AttemptedAt = log.Timestamp,
                RiskScore = log.RiskScore
            });
        }

        #endregion

        #region 보안 분석

        /// <summary>
        /// 보안 경고가 발생한 로그 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetSecurityAlertsAsync(
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.SecurityAlert);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        /// <summary>
        /// 높은 위험도 요청 조회
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetHighRiskRequestsAsync(
            int minRiskScore = 70,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.RiskScore >= minRiskScore);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.RiskScore)
                             .ThenByDescending(log => log.Timestamp)
                             .ToListAsync();
        }

        /// <summary>
        /// 비정상 접근 패턴 감지
        /// </summary>
        public async Task<IEnumerable<AbnormalAccessPattern>> DetectAbnormalPatternsAsync(
            Guid? connectedId = null,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            var logs = await query.ToListAsync();
            var patterns = new List<AbnormalAccessPattern>();

            // 짧은 시간에 너무 많은 요청
            var highFrequencyUsers = logs
                .GroupBy(l => l.ConnectedId)
                .Where(g => g.Count() > 100) // 임계값
                .Select(g => new AbnormalAccessPattern
                {
                    ConnectedId = g.Key,
                    PatternType = "HighFrequency",
                    Description = $"Excessive requests: {g.Count()} in period",
                    AffectedResources = g.Select(l => l.Resource).Distinct().ToList(),
                    DetectedAt = DateTime.UtcNow
                });

            patterns.AddRange(highFrequencyUsers);

            // 연속 실패 패턴
            var consecutiveFailures = logs
                .Where(l => l.ConsecutiveFailures > 5)
                .GroupBy(l => l.ConnectedId)
                .Select(g => new AbnormalAccessPattern
                {
                    ConnectedId = g.Key,
                    PatternType = "ConsecutiveFailures",
                    Description = $"Multiple consecutive failures detected",
                    AffectedResources = g.Select(l => l.Resource).Distinct().ToList(),
                    DetectedAt = DateTime.UtcNow
                });

            patterns.AddRange(consecutiveFailures);

            return patterns;
        }

        /// <summary>
        /// 민감한 리소스 접근 로그
        /// </summary>
        public async Task<IEnumerable<AuthorizationAuditLog>> GetSensitiveResourceAccessAsync(
            List<string> sensitiveResources,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => sensitiveResources.Contains(log.Resource));

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync();
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 권한 검증 통계
        /// </summary>
        public async Task<AuthorizationStatistics> GetStatisticsAsync(
            DateTime from,
            DateTime to,
            Guid? organizationId = null)
        {
            IQueryable<AuthorizationAuditLog> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(log => log.Timestamp >= from && log.Timestamp <= to);

            var logs = await query.ToListAsync();

            var stats = new AuthorizationStatistics
            {
                TotalRequests = logs.Count,
                AllowedRequests = logs.Count(l => l.IsAllowed),
                DeniedRequests = logs.Count(l => !l.IsAllowed),
                AllowRate = logs.Any() ? (double)logs.Count(l => l.IsAllowed) / logs.Count * 100 : 0,
                RequestsByResource = logs.GroupBy(l => l.Resource)
                    .ToDictionary(g => g.Key, g => g.Count()),
                RequestsByAction = logs.GroupBy(l => l.Action)
                    .ToDictionary(g => g.Key, g => g.Count()),
                DenialReasons = logs.Where(l => l.DenialReason.HasValue)
                    .GroupBy(l => l.DenialReason!.Value)
                    .ToDictionary(g => g.Key, g => g.Count()),
                CacheHitRate = CalculateCacheHitRate(logs),
                AverageProcessingTimeMs = logs.Where(l => l.ProcessingTimeMs.HasValue)
                    .Select(l => l.ProcessingTimeMs!.Value)
                    .DefaultIfEmpty(0)
                    .Average()
            };

            return stats;
        }

        /// <summary>
        /// 리소스별 접근 빈도
        /// </summary>
        public async Task<Dictionary<string, int>> GetResourceAccessFrequencyAsync(
            DateTime? since = null,
            int topCount = 20)
        {
            IQueryable<AuthorizationAuditLog> query = Query();

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query
                .GroupBy(log => log.Resource)
                .Select(g => new { Resource = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(topCount)
                .ToDictionaryAsync(x => x.Resource, x => x.Count);
        }

        /// <summary>
        /// 액션별 사용 빈도
        /// </summary>
        public async Task<Dictionary<string, int>> GetActionUsageFrequencyAsync(
            DateTime? since = null,
            int topCount = 20)
        {
            IQueryable<AuthorizationAuditLog> query = Query();

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            return await query
                .GroupBy(log => log.Action)
                .Select(g => new { Action = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(topCount)
                .ToDictionaryAsync(x => x.Action, x => x.Count);
        }

        /// <summary>
        /// 시간대별 권한 검증 분포
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyDistributionAsync(
            DateTime date,
            Guid? organizationId = null)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            IQueryable<AuthorizationAuditLog> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(log => log.Timestamp >= startDate && log.Timestamp < endDate);

            var logs = await query.ToListAsync();

            return Enumerable.Range(0, 24)
                .ToDictionary(
                    hour => hour,
                    hour => logs.Count(l => l.Timestamp.Hour == hour)
                );
        }

        /// <summary>
        /// 사용자별 권한 사용 패턴
        /// </summary>
        public async Task<UserAuthorizationPattern> GetUserPatternAsync(
            Guid connectedId,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.ConnectedId == connectedId);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            var logs = await query.ToListAsync();

            return new UserAuthorizationPattern
            {
                ConnectedId = connectedId,
                FrequentResources = logs.GroupBy(l => l.Resource)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .Select(g => g.Key)
                    .ToList(),
                FrequentActions = logs.GroupBy(l => l.Action)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .Select(g => g.Key)
                    .ToList(),
                HourlyActivity = logs.GroupBy(l => l.Timestamp.Hour)
                    .ToDictionary(g => g.Key, g => g.Count()),
                TotalRequests = logs.Count,
                SuccessRate = logs.Any() ? (double)logs.Count(l => l.IsAllowed) / logs.Count * 100 : 0
            };
        }

        /// <summary>
        /// 캐시 효율성 분석
        /// </summary>
        public async Task<CacheEfficiencyAnalysis> AnalyzeCacheEfficiencyAsync(
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            var logs = await query.Where(log => log.CacheStatus != null).ToListAsync();

            var cacheHits = logs.Count(l => l.CacheStatus == PermissionCacheStatus.Hit);
            var cacheMisses = logs.Count(l => l.CacheStatus == PermissionCacheStatus.Miss);

            return new CacheEfficiencyAnalysis
            {
                TotalRequests = logs.Count,
                CacheHits = cacheHits,
                CacheMisses = cacheMisses,
                HitRate = logs.Any() ? (double)cacheHits / logs.Count * 100 : 0,
                AverageHitTimeMs = logs.Where(l => l.CacheStatus == PermissionCacheStatus.Hit && l.ProcessingTimeMs.HasValue)
                    .Select(l => l.ProcessingTimeMs!.Value)
                    .DefaultIfEmpty(0)
                    .Average(),
                AverageMissTimeMs = logs.Where(l => l.CacheStatus == PermissionCacheStatus.Miss && l.ProcessingTimeMs.HasValue)
                    .Select(l => l.ProcessingTimeMs!.Value)
                    .DefaultIfEmpty(0)
                    .Average(),
                MostCachedPermissions = logs.Where(l => l.CacheStatus == PermissionCacheStatus.Hit && l.FullScope != null)
                    .GroupBy(l => l.FullScope!)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .Select(g => g.Key)
                    .ToList()
            };
        }

        #endregion

        #region 컴플라이언스

        /// <summary>
        /// 컴플라이언스 보고서용 데이터 조회
        /// </summary>
        public async Task<ComplianceReport> GetComplianceReportDataAsync(
            DateTime from,
            DateTime to,
            List<string> requiredResources)
        {
            var logs = await Query()
                .Where(log => log.Timestamp >= from && log.Timestamp <= to)
                .ToListAsync();

            var sensitiveAccesses = logs
                .Where(l => requiredResources.Contains(l.Resource))
                .Select(l => new SensitiveResourceAccess
                {
                    ConnectedId = l.ConnectedId,
                    Resource = l.Resource,
                    AccessedAt = l.Timestamp,
                    WasAllowed = l.IsAllowed
                })
                .ToList();

            var violations = logs
                .Where(l => !l.IsAllowed && l.SecurityAlert)
                .Select(l => new PolicyViolation
                {
                    ConnectedId = l.ConnectedId,
                    PolicyName = l.DenialReason?.ToString() ?? "Unknown",
                    ViolationType = l.DenialCode ?? "UNAUTHORIZED",
                    OccurredAt = l.Timestamp
                })
                .ToList();

            return new ComplianceReport
            {
                GeneratedAt = DateTime.UtcNow,
                PeriodStart = from,
                PeriodEnd = to,
                TotalAccessRequests = logs.Count,
                UnauthorizedAttempts = logs.Count(l => !l.IsAllowed),
                SensitiveAccesses = sensitiveAccesses,
                Violations = violations
            };
        }

        /// <summary>
        /// 감사 추적 체인 조회
        /// </summary>
        public async Task<AuditTrailChain> GetAuditTrailChainAsync(
            Guid connectedId,
            Guid resourceId,
            DateTime? since = null)
        {
            IQueryable<AuthorizationAuditLog> query = Query();
            query = query.Where(log => log.ConnectedId == connectedId && log.ResourceId == resourceId);

            if (since.HasValue)
                query = query.Where(log => log.Timestamp >= since.Value);

            var events = await query.OrderBy(log => log.Timestamp).ToListAsync();

            return new AuditTrailChain
            {
                ConnectedId = connectedId,
                ResourceId = resourceId,
                Events = events,
                FirstAccess = events.FirstOrDefault()?.Timestamp ?? DateTime.MinValue,
                LastAccess = events.LastOrDefault()?.Timestamp ?? DateTime.MinValue
            };
        }

        #endregion

        #region 정리 작업

        /// <summary>
        /// 오래된 로그 정리
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(DateTime before)
        {
            var logsToDelete = await Query()
                .Where(log => log.Timestamp < before)
                .ToListAsync();

            if (logsToDelete.Any())
            {
                _dbSet.RemoveRange(logsToDelete);
                return await _context.SaveChangesAsync();
            }

            return 0;
        }

        /// <summary>
        /// 로그 아카이브
        /// </summary>
        public async Task<int> ArchiveLogsAsync(DateTime before, string archiveLocation)
        {
            var logsToArchive = await Query()
                .Where(log => log.Timestamp < before)
                .ToListAsync();

            if (!logsToArchive.Any())
                return 0;

            // 실제 아카이브 로직은 Service 레이어에서 처리
            // 여기서는 로그를 아카이브 상태로 표시만
            foreach (var log in logsToArchive)
            {
                // 메타데이터에 아카이브 정보 추가
                var metadata = new Dictionary<string, object>
                {
                    ["ArchivedAt"] = DateTime.UtcNow,
                    ["ArchiveLocation"] = archiveLocation
                };

                log.Context = System.Text.Json.JsonSerializer.Serialize(metadata);
            }

            _dbSet.UpdateRange(logsToArchive);
            return await _context.SaveChangesAsync();
        }

        #endregion

        #region Private Helper Methods

        private double CalculateCacheHitRate(List<AuthorizationAuditLog> logs)
        {
            var logsWithCacheStatus = logs.Where(l => l.CacheStatus != null).ToList();
            if (!logsWithCacheStatus.Any())
                return 0;

            var hits = logsWithCacheStatus.Count(l => l.CacheStatus == PermissionCacheStatus.Hit);
            return (double)hits / logsWithCacheStatus.Count * 100;
        }

        #endregion
    }
}