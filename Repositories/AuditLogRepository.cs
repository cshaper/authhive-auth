using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Core.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Auth.Authentication.Common;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 최적화된 감사 로그 저장소 - BaseRepository 패턴 완전 활용
    /// AuthHive v15.5
    /// 
    /// 특징:
    /// - BaseRepository의 모든 기능을 최대한 활용
    /// - 중복 코드 제거 및 성능 최적화
    /// - 조직 스코핑 자동 처리
    /// - 캐시 시스템 통합
    /// - 일관성 있는 메서드 명명
    /// </summary>
    public class AuditLogRepository : BaseRepository<AuditLog>, IAuditLogRepository
    {
        private readonly ILogger<AuditLogRepository> _logger;

        // 감사 로그 특화 캐시 설정
        private readonly MemoryCacheEntryOptions _auditCacheOptions = new()
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(2),
            SlidingExpiration = TimeSpan.FromMinutes(30),
            Priority = CacheItemPriority.High
        };

        public AuditLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AuditLogRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 감사 로그는 시스템 전역 엔티티로 처리 (조직 스코핑 비활성화)
        /// 단, 애플리케이션별로는 필터링 가능
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;

        #region 기본 조회 - BaseRepository 기능 활용

        /// <summary>엔티티별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByEntityAsync(
            string entityType,
            Guid entityId,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildEntityPredicate(entityType, entityId.ToString(), fromDate, toDate);
            var logs = await FindAsync(predicate);
            return logs.OrderBy(log => log.Timestamp);
        }

        /// <summary>사용자별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByUserAsync(
            Guid userId,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildUserPredicate(userId, fromDate, toDate);

            if (limit.HasValue)
            {
                // BaseRepository의 Query() 활용하여 직접 제한
                var query = Query()
                    .Where(predicate)
                    .OrderByDescending(log => log.Timestamp)
                    .Take(limit.Value);

                return await query.ToListAsync(cancellationToken);
            }

            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        /// <summary>ConnectedId별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            return await GetByUserAsync(connectedId, fromDate, toDate, limit, cancellationToken);
        }

        /// <summary>조직(애플리케이션)별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByOrganizationAsync(
            Guid organizationId,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildOrganizationPredicate(organizationId, fromDate, toDate);

            if (limit.HasValue)
            {
                var query = Query()
                    .Where(predicate)
                    .OrderByDescending(log => log.Timestamp)
                    .Take(limit.Value);

                return await query.ToListAsync(cancellationToken);
            }

            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        #endregion

        #region 액션 타입별 조회 - BaseRepository 기능 활용

        /// <summary>액션 타입별 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByActionAsync(
            string actionType,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildActionPredicate(actionType, fromDate, toDate);
            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        /// <summary>중요 이벤트 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetCriticalEventsAsync(
            Guid? organizationId = null,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            var criticalActions = new[]
            {
                "Login", "Logout", "PasswordChanged", "PermissionChanged",
                "RoleAssigned", "RoleRevoked", "OrganizationCreated",
                "OrganizationDeleted", "UserCreated", "UserDeleted",
                "SystemStartup", "SystemShutdown", "ConfigurationChanged"
            };

            var predicate = BuildMultiActionPredicate(criticalActions, organizationId, fromDate, toDate);
            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        /// <summary>보안 이벤트 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetSecurityEventsAsync(
            Guid? organizationId = null,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            var securityActions = new[]
            {
                "LoginFailed", "PasswordChanged", "AccountLocked",
                "SuspiciousActivity", "UnauthorizedAccess", "SecurityBreach",
                "MfaEnabled", "MfaDisabled", "TokenRevoked"
            };

            var predicate = BuildMultiActionPredicate(securityActions, organizationId, fromDate, toDate);
            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        #endregion

        #region 변경 추적 - BaseRepository 기능 활용

        /// <summary>엔티티 변경 이력 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetEntityHistoryAsync(
            string entityType,
            Guid entityId,
            CancellationToken cancellationToken = default)
        {
            var logs = await Query()
                .Where(log => log.ResourceType == entityType && log.ResourceId == entityId.ToString())
                .Include(log => log.AuditTrailDetails)
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);

            return logs;
        }

        /// <summary>특정 필드 변경 이력 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetFieldChangesAsync(
            string entityType,
            Guid entityId,
            string fieldName,
            CancellationToken cancellationToken = default)
        {
            var logs = await Query()
                .Where(log =>
                    log.ResourceType == entityType &&
                    log.ResourceId == entityId.ToString() &&
                    log.AuditTrailDetails.Any(detail => detail.FieldName == fieldName))
                .Include(log => log.AuditTrailDetails.Where(detail => detail.FieldName == fieldName))
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);

            return logs;
        }

        #endregion

        #region IP 및 세션 추적 - BaseRepository 기능 활용

        /// <summary>IP 주소별 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return Enumerable.Empty<AuditLog>();

            var predicate = BuildIpPredicate(ipAddress, fromDate, toDate);
            var logs = await FindAsync(predicate);
            return logs.OrderByDescending(log => log.Timestamp);
        }

        /// <summary>세션별 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetBySessionIdAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return Enumerable.Empty<AuditLog>();

            var logs = await FindAsync(log => log.RequestId == sessionId);
            return logs.OrderBy(log => log.Timestamp);
        }

        /// <summary>의심스러운 활동 감지 - BaseRepository의 통계 기능 활용</summary>
        public async Task<IEnumerable<SuspiciousActivity>> DetectSuspiciousActivitiesAsync(
            DateTime fromDate,
            DateTime toDate,
            CancellationToken cancellationToken = default)
        {
            var result = new List<SuspiciousActivity>();

            // 1. 동일 IP에서 여러 사용자 로그인 시도 - BaseRepository 그룹 통계 활용
            var ipLoginStats = await GetGroupCountAsync(
                log => log.IPAddress!,
                log => log.Timestamp >= fromDate &&
                       log.Timestamp <= toDate &&
                       log.Action == "Login" &&
                       !string.IsNullOrEmpty(log.IPAddress) &&
                       log.PerformedByConnectedId.HasValue);

            var suspiciousIps = ipLoginStats.Where(kvp => kvp.Value > 5);

            foreach (var ip in suspiciousIps)
            {
                var ipLogs = await FindAsync(log =>
                    log.IPAddress == ip.Key &&
                    log.Timestamp >= fromDate &&
                    log.Timestamp <= toDate);

                var distinctUsers = ipLogs.Where(l => l.PerformedByConnectedId.HasValue)
                                         .Select(l => l.PerformedByConnectedId!.Value)
                                         .Distinct()
                                         .Count();

                if (distinctUsers > 5)
                {
                    result.Add(new SuspiciousActivity
                    {
                        Type = "MultipleAccountsFromSameIP",
                        IpAddress = ip.Key,
                        Count = distinctUsers,
                        FirstOccurrence = ipLogs.Min(l => l.Timestamp),
                        LastOccurrence = ipLogs.Max(l => l.Timestamp)
                    });
                }
            }

            // 2. 무차별 로그인 시도
            var failedLogins = await FindAsync(log =>
                log.Timestamp >= fromDate &&
                log.Timestamp <= toDate &&
                log.Action == "LoginFailed" &&
                log.PerformedByConnectedId.HasValue);

            var bruteForceCandidates = failedLogins
                .GroupBy(log => new { log.PerformedByConnectedId, log.IPAddress })
                .Where(g => g.Count() > 10);

            foreach (var group in bruteForceCandidates)
            {
                result.Add(new SuspiciousActivity
                {
                    Type = "BruteForceAttempt",
                    UserId = group.Key.PerformedByConnectedId,
                    IpAddress = group.Key.IPAddress,
                    Count = group.Count(),
                    FirstOccurrence = group.Min(l => l.Timestamp),
                    LastOccurrence = group.Max(l => l.Timestamp)
                });
            }

            return result.OrderByDescending(sa => sa.LastOccurrence);
        }

        #endregion

        #region 통계 및 분석 - BaseRepository 통계 기능 최대 활용

        /// <summary>감사 로그 통계</summary>
        public async Task<AuditLogStatistics> GetStatisticsAsync(
            Guid? organizationId,
            DateTime fromDate,
            DateTime toDate,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 통계 메서드들 활용
            var basePredicate = BuildDateRangePredicate(fromDate, toDate);
            var orgPredicate = organizationId.HasValue
                ? CombinePredicates(basePredicate, log => log.ApplicationId == organizationId.Value)
                : basePredicate;

            var totalLogs = await CountAsync(orgPredicate);

            // 액션별 통계 - BaseRepository의 GetGroupCountAsync 활용
            var actionStats = await GetGroupCountAsync(
                log => log.Action,
                orgPredicate);

            // 엔티티별 통계
            var entityStats = await GetGroupCountAsync(
                log => log.ResourceType ?? "Unknown",
                CombinePredicates(orgPredicate, log => log.ResourceType != null));

            // 고유 사용자 수
            var uniqueUserLogs = await FindAsync(CombinePredicates(
                orgPredicate,
                log => log.PerformedByConnectedId.HasValue));

            var uniqueUsers = uniqueUserLogs
                .Select(log => log.PerformedByConnectedId!.Value)
                .Distinct()
                .Count();

            // 보안/중요 이벤트 카운트
            var securityActions = new[] { "LoginFailed", "AccountLocked", "SuspiciousActivity", "UnauthorizedAccess", "SecurityBreach" };
            var securityEvents = await CountAsync(CombinePredicates(
                orgPredicate,
                log => securityActions.Contains(log.Action)));

            var criticalActions = new[] { "Login", "Logout", "PasswordChanged", "PermissionChanged", "RoleAssigned", "RoleRevoked" };
            var criticalEvents = await CountAsync(CombinePredicates(
                orgPredicate,
                log => criticalActions.Contains(log.Action)));

            return new AuditLogStatistics
            {
                TotalLogs = totalLogs,
                ByAction = actionStats,
                ByEntity = entityStats,
                UniqueUsers = uniqueUsers,
                SecurityEvents = securityEvents,
                CriticalEvents = criticalEvents,
                GeneratedAt = DateTime.UtcNow
            };
        }

        /// <summary>액션별 빈도 분석 - BaseRepository 활용</summary>
        public async Task<Dictionary<string, int>> GetActionFrequencyAsync(
            DateTime fromDate,
            DateTime toDate,
            CancellationToken cancellationToken = default)
        {
            return await GetGroupCountAsync(
                log => log.Action,
                BuildDateRangePredicate(fromDate, toDate));
        }

        /// <summary>시간대별 활동 분석 - BaseRepository 활용</summary>
        public async Task<Dictionary<int, int>> GetHourlyActivityAsync(
            DateTime date,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            var predicate = BuildDateRangePredicate(startDate, endDate);
            if (organizationId.HasValue)
            {
                predicate = CombinePredicates(predicate, log => log.ApplicationId == organizationId.Value);
            }

            return await GetGroupCountAsync(
                log => log.Timestamp.Hour,
                predicate);
        }

        #endregion

        #region 검색 및 필터 - BaseRepository 페이징 활용

        /// <summary>감사 로그 검색 - BaseRepository의 GetPagedAsync 완전 활용</summary>
        public async Task<PagedResult<AuditLog>> SearchAsync(
            string? keyword = null,
            string? entityType = null,
            string? actionType = null,
            Guid? userId = null,
            Guid? organizationId = null,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildSearchPredicate(
                keyword, entityType, actionType, userId, organizationId, fromDate, toDate);

            // BaseRepository의 GetPagedAsync 직접 활용
            var (items, totalCount) = await GetPagedAsync(
                pageNumber,
                pageSize,
                predicate,
                log => log.Timestamp,
                isDescending: true);

            return new PagedResult<AuditLog>(items, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 컴플라이언스 - BaseRepository 기능 활용

        /// <summary>컴플라이언스 보고서용 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetForComplianceReportAsync(
            Guid organizationId,
            DateTime fromDate,
            DateTime toDate,
            string[] requiredActions,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildCompliancePredicate(organizationId, fromDate, toDate, requiredActions);
            var logs = await FindAsync(predicate);
            return logs.OrderBy(log => log.Timestamp);
        }

        /// <summary>데이터 접근 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetDataAccessLogsAsync(
            Guid organizationId,
            string dataCategory,
            DateTime fromDate,
            DateTime toDate,
            CancellationToken cancellationToken = default)
        {
            var dataAccessActions = new[] { "Read", "Export", "Download", "View", "Access" };
            var predicate = BuildDataAccessPredicate(organizationId, dataCategory, fromDate, toDate, dataAccessActions);

            var logs = await FindAsync(predicate);
            return logs.OrderBy(log => log.Timestamp);
        }

        #endregion

        #region 보관 및 정리

        /// <summary>오래된 로그 아카이빙 대상 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetLogsForArchivingAsync(
            DateTime olderThan,
            int batchSize = 1000,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query() 활용
            var logs = await Query()
                .Where(log => log.Timestamp < olderThan)
                .OrderBy(log => log.Timestamp)
                .Take(batchSize)
                .ToListAsync(cancellationToken);

            return logs;
        }

        /// <summary>아카이빙 완료 표시</summary>
        public async Task<bool> MarkAsArchivedAsync(
            IEnumerable<Guid> logIds,
            string archiveLocation,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var logIdList = logIds.ToList();
                if (!logIdList.Any()) return true;

                var logs = await Query()
                    .Where(log => logIdList.Contains(log.Id))
                    .ToListAsync(cancellationToken);

                foreach (var log in logs)
                {
                    // AuditLog 엔티티에 아카이브 속성이 있다고 가정
                    // log.IsArchived = true;
                    // log.ArchiveLocation = archiveLocation;
                    // log.ArchivedAt = DateTime.UtcNow;

                    // 임시로 메타데이터에 저장
                    log.Metadata = $"{log.Metadata};Archived:{archiveLocation}:{DateTime.UtcNow:yyyy-MM-dd}";
                }

                // BaseRepository의 UpdateRangeAsync 활용
                await UpdateRangeAsync(logs);
                await _context.SaveChangesAsync(cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to mark logs as archived. LogIds: {LogIds}, Archive location: {Location}",
                    string.Join(",", logIds), archiveLocation);
                return false;
            }
        }

        #endregion

        #region Predicate 헬퍼 메서드들 - 중복 제거 및 재사용성

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildEntityPredicate(
            string entityType, string entityId, DateTime? fromDate, DateTime? toDate)
        {
            var basePredicate = System.Linq.Expressions.Expression.Lambda<Func<AuditLog, bool>>(
                System.Linq.Expressions.Expression.AndAlso(
                    System.Linq.Expressions.Expression.Equal(
                        System.Linq.Expressions.Expression.Property(
                            System.Linq.Expressions.Expression.Parameter(typeof(AuditLog), "log"), "ResourceType"),
                        System.Linq.Expressions.Expression.Constant(entityType)),
                    System.Linq.Expressions.Expression.Equal(
                        System.Linq.Expressions.Expression.Property(
                            System.Linq.Expressions.Expression.Parameter(typeof(AuditLog), "log"), "ResourceId"),
                        System.Linq.Expressions.Expression.Constant(entityId))),
                System.Linq.Expressions.Expression.Parameter(typeof(AuditLog), "log"));

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildUserPredicate(
            Guid userId, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> basePredicate =
                log => log.PerformedByConnectedId == userId;

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildOrganizationPredicate(
            Guid organizationId, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> basePredicate =
                log => log.ApplicationId == organizationId;

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildActionPredicate(
            string actionType, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> basePredicate =
                log => log.Action == actionType;

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildMultiActionPredicate(
            string[] actions, Guid? organizationId, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> basePredicate =
                log => actions.Contains(log.Action);

            if (organizationId.HasValue)
            {
                basePredicate = CombinePredicates(basePredicate, log => log.ApplicationId == organizationId.Value);
            }

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildIpPredicate(
            string ipAddress, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> basePredicate =
                log => log.IPAddress == ipAddress;

            return AddDateRangeToExpression(basePredicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildDateRangePredicate(
            DateTime fromDate, DateTime toDate)
        {
            return log => log.Timestamp >= fromDate && log.Timestamp <= toDate;
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildSearchPredicate(
            string? keyword, string? entityType, string? actionType, Guid? userId,
            Guid? organizationId, DateTime? fromDate, DateTime? toDate)
        {
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> predicate = log => true;

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                predicate = CombinePredicates(predicate, log =>
                    log.Action.Contains(keyword) ||
                    (log.ResourceType != null && log.ResourceType.Contains(keyword)) ||
                    (log.Metadata != null && log.Metadata.Contains(keyword)));
            }

            if (!string.IsNullOrWhiteSpace(entityType))
                predicate = CombinePredicates(predicate, log => log.ResourceType == entityType);

            if (!string.IsNullOrWhiteSpace(actionType))
                predicate = CombinePredicates(predicate, log => log.Action == actionType);

            if (userId.HasValue)
                predicate = CombinePredicates(predicate, log => log.PerformedByConnectedId == userId.Value);

            if (organizationId.HasValue)
                predicate = CombinePredicates(predicate, log => log.ApplicationId == organizationId.Value);

            return AddDateRangeToExpression(predicate, fromDate, toDate);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildCompliancePredicate(
            Guid organizationId, DateTime fromDate, DateTime toDate, string[] requiredActions)
        {
            return log =>
                log.ApplicationId == organizationId &&
                log.Timestamp >= fromDate &&
                log.Timestamp <= toDate &&
                requiredActions.Contains(log.Action);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> BuildDataAccessPredicate(
            Guid organizationId, string dataCategory, DateTime fromDate, DateTime toDate, string[] dataAccessActions)
        {
            return log =>
                log.ApplicationId == organizationId &&
                log.Timestamp >= fromDate &&
                log.Timestamp <= toDate &&
                dataAccessActions.Contains(log.Action) &&
                log.ResourceType != null && log.ResourceType.Contains(dataCategory);
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> AddDateRangeToExpression(
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> predicate,
            DateTime? fromDate, DateTime? toDate)
        {
            if (fromDate.HasValue)
                predicate = CombinePredicates(predicate, log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                predicate = CombinePredicates(predicate, log => log.Timestamp <= toDate.Value);

            return predicate;
        }

        private System.Linq.Expressions.Expression<Func<AuditLog, bool>> CombinePredicates(
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> predicate1,
            System.Linq.Expressions.Expression<Func<AuditLog, bool>> predicate2)
        {
            var parameter = System.Linq.Expressions.Expression.Parameter(typeof(AuditLog), "log");
            var body = System.Linq.Expressions.Expression.AndAlso(
                System.Linq.Expressions.Expression.Invoke(predicate1, parameter),
                System.Linq.Expressions.Expression.Invoke(predicate2, parameter));

            return System.Linq.Expressions.Expression.Lambda<Func<AuditLog, bool>>(body, parameter);
        }

        public async Task<IEnumerable<AuditLog>> GetAuditLogsAsync(Guid? userId, Guid? applicationId, DateTime from, DateTime to)
        {
            var query = _context.AuditLogs.AsQueryable();

            if (userId.HasValue)
            {
                query = query.Where(log => log.PerformedByConnectedId == userId.Value);
            }

            // 1. 변수명을 매개변수와 동일하게 'applicationId' (소문자)로 수정
            // 2. '!= null' 대신 '.HasValue'를 사용하는 것이 더 명확한 표현입니다.
            if (applicationId.HasValue)
            {
                // 3. '.value'가 아닌 '.Value' (대문자 V)로 실제 값에 접근합니다.
                query = query.Where(log => log.ApplicationId == applicationId.Value);
            }

            return await query
                .Where(log => log.Timestamp >= from && log.Timestamp <= to)
                .OrderByDescending(log => log.Timestamp)
                .ToListAsync();
        }

        public Task<int> CleanupOldLogsAsync(DateTime olderThan)
        {
            throw new NotImplementedException();
        }

        public Task<int> MarkAsArchivedAsync(DateTime from, DateTime to)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}