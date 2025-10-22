using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Auth.Permissions.Common;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Globalization; // CultureInfo for GetWeeklyTrendsAsync

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// PermissionValidationLog Repository - 권한 검증 로그 관리 Repository
    /// AuthHive v16: BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// 서비스 계층 로직 메서드 제거됨
    /// </summary>
    public class PermissionValidationLogRepository : BaseRepository<PermissionValidationLog>, IPermissionValidationLogRepository
    {
         private readonly ILogger<PermissionValidationLogRepository> _logger;

        public PermissionValidationLogRepository(
            AuthDbContext context,
            ICacheService? cacheService = null,
            ILogger<PermissionValidationLogRepository> logger = null!)
            : base(context, cacheService)
        {
             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 조회 (CancellationToken 추가)

        public async Task<PagedResult<PermissionValidationLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var (items, totalCount) = await GetPagedAsync(
                pageNumber,
                pageSize,
                predicate: log => log.ConnectedId == connectedId &&
                                 (!startDate.HasValue || log.Timestamp >= startDate.Value) &&
                                 (!endDate.HasValue || log.Timestamp <= endDate.Value),
                orderBy: log => log.Timestamp,
                isDescending: true,
                cancellationToken: cancellationToken);

            return PagedResult<PermissionValidationLog>.Create(items, totalCount, pageNumber, pageSize);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetByApplicationAsync(
            Guid applicationId,
            bool? isAllowed = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ApplicationId == applicationId);
            if (isAllowed.HasValue) query = query.Where(log => log.IsAllowed == isAllowed.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetByScopeAsync(
            string requestedScope,
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(log => log.RequestedScope == requestedScope);

            if (startDate.HasValue) query = query.Where(log => log.Timestamp >= startDate.Value);
            if (endDate.HasValue) query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetBySessionAsync(
            Guid sessionId,
            CancellationToken cancellationToken = default)
        {
            // [FIXED] CS0019: Guid? 와 string 비교 수정 (Guid? 끼리 비교)
            return await Query()
                .Where(log => log.SessionId == sessionId) // SessionId가 Guid? 이므로 Guid와 직접 비교
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.Session) // Session 탐색 속성 (이름 확인 필요)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetRecentByPermissionIdAsync(
            Guid permissionId,
            int days,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-days);
            var permissionScope = await _context.Set<Permission>()
                .Where(p => p.Id == permissionId && !p.IsDeleted)
                .Select(p => p.Scope)
                .FirstOrDefaultAsync(cancellationToken);

            if (permissionScope == null) return Enumerable.Empty<PermissionValidationLog>();

            return await Query()
                .Where(log => log.RequestedScope == permissionScope && log.Timestamp >= startDate)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<PermissionValidationLog?> GetLastValidationAsync(
            Guid permissionId,
            CancellationToken cancellationToken = default)
        {
             var permissionScope = await _context.Set<Permission>()
                 .Where(p => p.Id == permissionId && !p.IsDeleted)
                 .Select(p => p.Scope)
                 .FirstOrDefaultAsync(cancellationToken);

            if (permissionScope == null) return null;

            return await Query()
                .Where(log => log.RequestedScope == permissionScope)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<int> CountByOrganizationAsync(
            Guid organizationId,
            Guid permissionId,
            CancellationToken cancellationToken = default)
        {
             var permissionScope = await _context.Set<Permission>()
                 .Where(p => p.Id == permissionId && !p.IsDeleted)
                 .Select(p => p.Scope)
                 .FirstOrDefaultAsync(cancellationToken);

            if (permissionScope == null) return 0;
            return await CountAsync(log => log.OrganizationId == organizationId && log.RequestedScope == permissionScope, cancellationToken);
        }

        public async Task<int> CountByApplicationAsync(
            Guid applicationId,
            Guid permissionId,
            CancellationToken cancellationToken = default)
        {
            var permissionScope = await _context.Set<Permission>()
                 .Where(p => p.Id == permissionId && !p.IsDeleted)
                 .Select(p => p.Scope)
                 .FirstOrDefaultAsync(cancellationToken);

            if (permissionScope == null) return 0;
            return await CountAsync(log => log.ApplicationId == applicationId && log.RequestedScope == permissionScope, cancellationToken);
        }

        #endregion

        #region 로그 기록 (CancellationToken 추가)

        public async Task<PermissionValidationLog> LogValidationAsync(
            PermissionValidationLog log,
            CancellationToken cancellationToken = default)
        {
            if (log.Id == Guid.Empty) log.Id = Guid.NewGuid();
            if (log.Timestamp == default) log.Timestamp = DateTime.UtcNow;
            if (log.CreatedAt == default) log.CreatedAt = DateTime.UtcNow;
            if (log.OrganizationId == Guid.Empty && log.ConnectedId != Guid.Empty)
            {
                 try { log.OrganizationId = await GetOrganizationIdForConnectedIdAsync(log.ConnectedId, cancellationToken); }
                 catch(ArgumentException ex) { _logger.LogWarning(ex, "Could not set OrganizationId for log entry."); }
            }
            return await AddAsync(log, cancellationToken);
        }

        public async Task<PermissionValidationLog> LogSuccessfulValidationAsync(
            Guid connectedId,
            string requestedScope,
            Guid? applicationId,
            int durationMs,
            PermissionCacheStatus cacheStatus,
            CancellationToken cancellationToken = default)
        {
            var organizationId = await GetOrganizationIdForConnectedIdAsync(connectedId, cancellationToken);
            var log = new PermissionValidationLog
            {
                ConnectedId = connectedId, ApplicationId = applicationId, RequestedScope = requestedScope,
                IsAllowed = true, ValidationResult = PermissionValidationResult.Granted,
                ValidationDurationMs = durationMs, CacheStatus = cacheStatus, OrganizationId = organizationId
            };
            return await LogValidationAsync(log, cancellationToken);
        }

        public async Task<PermissionValidationLog> LogFailedValidationAsync(
            Guid connectedId,
            string requestedScope,
            PermissionValidationResult validationResult,
            string denialReason,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
             var organizationId = await GetOrganizationIdForConnectedIdAsync(connectedId, cancellationToken);
            var log = new PermissionValidationLog
            {
                ConnectedId = connectedId, ApplicationId = applicationId, RequestedScope = requestedScope,
                IsAllowed = false, ValidationResult = validationResult, DenialReason = denialReason,
                OrganizationId = organizationId
            };
            return await LogValidationAsync(log, cancellationToken);
        }

        public async Task<PermissionValidationLog> LogResourceAccessAsync(
            Guid connectedId,
            ResourceType resourceType,
            Guid resourceId,
            string requestedScope,
            bool isAllowed,
            CancellationToken cancellationToken = default)
        {
            var organizationId = await GetOrganizationIdForConnectedIdAsync(connectedId, cancellationToken);
            var log = new PermissionValidationLog
            {
                ConnectedId = connectedId, RequestedScope = requestedScope, IsAllowed = isAllowed,
                // [FIXED] CS0029: string 대신 Enum 타입 직접 할당
                ResourceType = resourceType,
                // [FIXED] CS0029: string 대신 Guid? 타입 직접 할당
                ResourceId = resourceId,
                ValidationResult = isAllowed ? PermissionValidationResult.Granted : PermissionValidationResult.ResourceAccessDenied,
                OrganizationId = organizationId
            };
            return await LogValidationAsync(log, cancellationToken);
        }

        private async Task<Guid> GetOrganizationIdForConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken)
        {
             var orgId = await _context.Set<ConnectedId>()
                 .Where(c => c.Id == connectedId)
                 .Select(c => c.OrganizationId)
                 .FirstOrDefaultAsync(cancellationToken);

             if (orgId == Guid.Empty) throw new ArgumentException($"OrganizationId not found for ConnectedId {connectedId}", nameof(connectedId));
             return orgId;
        }

        #endregion

        #region 거부 분석 (기본 조회, CancellationToken 추가)

        public async Task<IEnumerable<PermissionValidationLog>> GetDeniedValidationsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(log => !log.IsAllowed);
            if (startDate.HasValue) query = query.Where(log => log.Timestamp >= startDate.Value);
            if (endDate.HasValue) query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<Dictionary<string, int>> GetDenialReasonStatisticsAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var results = await QueryForOrganization(organizationId)
                .Where(log => !log.IsAllowed && log.Timestamp >= startDate && !string.IsNullOrEmpty(log.DenialReason))
                .GroupBy(log => log.DenialReason!)
                .Select(g => new { Reason = g.Key, Count = g.Count() })
                .ToListAsync(cancellationToken);
            return results.ToDictionary(x => x.Reason, x => x.Count);
        }

        public async Task<IEnumerable<(string Scope, int DenialCount)>> GetMostDeniedScopesAsync(
            Guid organizationId,
            int limit = 10,
            CancellationToken cancellationToken = default)
        {
             var results = await QueryForOrganization(organizationId)
                 .Where(log => !log.IsAllowed && !string.IsNullOrEmpty(log.RequestedScope))
                 .GroupBy(log => log.RequestedScope!)
                 .Select(g => new { Scope = g.Key, Count = g.Count() })
                 .OrderByDescending(x => x.Count)
                 .Take(limit)
                 .ToListAsync(cancellationToken);
             return results.Select(x => (x.Scope, x.Count));
        }

        #endregion

        #region 성능 분석 (기본 조회, CancellationToken 추가)

        public async Task<double> GetAverageValidationTimeAsync(
            Guid organizationId,
            int period = 7,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var avgTime = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate && log.ValidationDurationMs.HasValue)
                .AverageAsync(log => log.ValidationDurationMs, cancellationToken);
            return avgTime ?? 0;
        }

        public async Task<Dictionary<PermissionCacheStatus, int>> GetCacheStatusStatisticsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default)
        {
            var results = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate && log.Timestamp <= endDate && log.CacheStatus.HasValue)
                .GroupBy(log => log.CacheStatus!.Value)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToListAsync(cancellationToken);
            return results.ToDictionary(x => x.Status, x => x.Count);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetSlowValidationsAsync(
            int thresholdMs,
            Guid organizationId,
            int limit = 50,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(log => log.ValidationDurationMs.HasValue && log.ValidationDurationMs >= thresholdMs)
                .OrderByDescending(log => log.ValidationDurationMs)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 결과 분석 (기본 조회, CancellationToken 추가)

        public async Task<Dictionary<PermissionValidationResult, int>> GetValidationResultStatisticsAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
             var results = await QueryForOrganization(organizationId)
                 .Where(log => log.Timestamp >= startDate)
                 .GroupBy(log => log.ValidationResult)
                 .Select(g => new { Result = g.Key, Count = g.Count() })
                 .ToListAsync(cancellationToken);
             return results.ToDictionary(x => x.Result, x => x.Count);
        }

        public async Task<Dictionary<ConnectedIdValidationResult, int>> GetConnectedIdValidationStatisticsAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
             var results = await QueryForOrganization(organizationId)
                 .Where(log => log.Timestamp >= startDate && log.ConnectedIdValidationResult.HasValue)
                 .GroupBy(log => log.ConnectedIdValidationResult!.Value)
                 .Select(g => new { Result = g.Key, Count = g.Count() })
                 .ToListAsync(cancellationToken);
             return results.ToDictionary(x => x.Result, x => x.Count);
        }

        #endregion

        #region 리소스 접근 분석 (기본 조회, CancellationToken 추가)

        public async Task<Dictionary<ResourceType, int>> GetResourceAccessStatisticsAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
             var startDate = DateTime.UtcNow.AddDays(-period);
             // [FIXED] Nullable Enum GroupBy 처리
             var results = await QueryForOrganization(organizationId)
                 .Where(log => log.Timestamp >= startDate && log.ResourceType.HasValue) // HasValue 체크
                 .GroupBy(log => log.ResourceType!.Value) // !.Value 사용
                 .Select(g => new { TypeEnum = g.Key, Count = g.Count() })
                 .ToListAsync(cancellationToken);

             return results.ToDictionary(x => x.TypeEnum, x => x.Count);
        }

        public async Task<IEnumerable<PermissionValidationLog>> GetResourceAccessHistoryAsync(
            ResourceType resourceType,
            Guid resourceId,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            // [FIXED] Guid? 와 Guid 비교 수정
            return await Query()
                .Where(log => log.ResourceType == resourceType && log.ResourceId == resourceId) // Enum/Guid 직접 비교
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<(Guid ResourceId, int AccessCount)>> GetMostAccessedResourcesAsync(
            Guid organizationId,
            ResourceType resourceType,
            int limit = 10,
            CancellationToken cancellationToken = default)
        {
             // [FIXED] Nullable Guid GroupBy 처리
             var results = await QueryForOrganization(organizationId)
                 .Where(log => log.ResourceType == resourceType && log.ResourceId.HasValue) // HasValue 체크
                 .GroupBy(log => log.ResourceId!.Value) // !.Value 사용
                 .Select(g => new { ResourceId = g.Key, Count = g.Count() })
                 .OrderByDescending(x => x.Count)
                 .Take(limit)
                 .ToListAsync(cancellationToken);

             return results.Select(x => (x.ResourceId, x.Count));
        }

        #endregion

        #region 역할 및 권한 분석 (기본 조회, CancellationToken 추가)

        public async Task<Dictionary<string, int>> GetPermissionUsageFrequencyAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
             var results = await QueryForOrganization(organizationId)
                 .Where(log => log.Timestamp >= startDate && !string.IsNullOrEmpty(log.RequestedScope))
                 .GroupBy(log => log.RequestedScope!)
                 .Select(g => new { Scope = g.Key, Count = g.Count() })
                 .ToListAsync(cancellationToken);
             return results.ToDictionary(x => x.Scope, x => x.Count);
        }

        #endregion

        #region 일괄 작업 (CancellationToken 추가)

        public async Task<int> BulkLogAsync(
            IEnumerable<PermissionValidationLog> logs,
            CancellationToken cancellationToken = default)
        {
            if (logs == null || !logs.Any()) return 0;
            var logList = logs.ToList();
            var timestamp = DateTime.UtcNow;

            foreach (var log in logList)
            {
                if (log.Id == Guid.Empty) log.Id = Guid.NewGuid();
                if (log.Timestamp == default) log.Timestamp = timestamp;
                if (log.CreatedAt == default) log.CreatedAt = timestamp;
                if (log.OrganizationId == Guid.Empty && log.ConnectedId != Guid.Empty)
                {
                     try { log.OrganizationId = await GetOrganizationIdForConnectedIdAsync(log.ConnectedId, cancellationToken); }
                     catch(ArgumentException ex) { _logger.LogWarning(ex, "Could not set OrganizationId for log entry during bulk insert."); }
                }
            }
            await AddRangeAsync(logList, cancellationToken);
            return logList.Count;
        }

        public async Task<int> CleanupOldLogsAsync(
            int olderThanDays,
            int batchSize = 1000,
            CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("CleanupOldLogsAsync starting for logs older than {Days} days.", olderThanDays);
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            int totalDeleted = 0;
            bool moreToDelete = true;

            while(moreToDelete && !cancellationToken.IsCancellationRequested)
            {
                 var oldLogs = await _dbSet
                     .Where(log => log.Timestamp < cutoffDate)
                     .OrderBy(log => log.Timestamp)
                     .Take(batchSize)
                     .ToListAsync(cancellationToken);

                 if (!oldLogs.Any()) { moreToDelete = false; break; }

                 _context.RemoveRange(oldLogs); // 물리적 삭제
                 int deletedInBatch = await _context.SaveChangesAsync(cancellationToken);
                 totalDeleted += deletedInBatch;
                 _logger.LogInformation("Deleted {Count} logs in cleanup batch.", deletedInBatch);

                 await Task.Delay(100, cancellationToken);
            }
             _logger.LogInformation("CleanupOldLogsAsync finished. Total logs deleted: {TotalCount}", totalDeleted);
            return totalDeleted;
        }

        #endregion

        // [FIXED] 서비스 계층 로직 메서드 제거됨
    }
}