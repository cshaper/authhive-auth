// Path: AuthHive.Auth/Repositories/AuditLogRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Audit.Repository;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 최적화된 감사 로그 저장소 - BaseRepository 패턴 완전 활용 (Refactored)
    /// AuthHive v15.5
    /// </summary>
    public class AuditLogRepository : BaseRepository<AuditLog>, IAuditLogRepository
    {
        private readonly ILogger<AuditLogRepository> _logger;

        public AuditLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AuditLogRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override bool IsOrganizationScopedEntity() => false;

        #region 검색 및 필터

        /// <summary>
        /// 감사 로그 검색 - BaseRepository의 기능을 활용하여 최적화
        /// </summary>
        /// <summary>
        /// 감사 로그 검색 - BaseRepository의 기능을 활용하여 최적화
        /// </summary>
        public async Task<PagedResult<AuditLog>> SearchAsync(
            Guid? organizationId,
            Guid? userId,
            string? action,
            Guid? connectedId,
            Guid? applicationId,
            DateTime? startDate,
            DateTime? endDate,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var predicate = BuildSearchPredicate(action, connectedId, applicationId, startDate, endDate);

            // ✨ 1. GetPagedAsync를 한 번만 호출하고, 결과를 (items, totalCount)로 바로 받습니다. (Deconstruction)
            var (items, totalCount) = await GetPagedAsync(
                pageNumber,
                pageSize,
                predicate,
                log => log.Timestamp,
                isDescending: true); // CancellationToken을 지원하지 않으므로 제거

            // ✨ 2. 이제 올바른 타입의 변수들을 사용하여 PagedResult를 생성합니다.
            return new PagedResult<AuditLog>(items, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 보관 및 정리

        /// <summary>
        /// 오래된 로그를 효율적으로 일괄 삭제합니다.
        /// </summary>
        public Task<int> CleanupOldLogsAsync(DateTime olderThan, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Cleaning up audit logs older than {Date}", olderThan);
            // EF Core 7.0+의 ExecuteDeleteAsync를 사용하여 DB에서 직접 대량 삭제 수행 (매우 효율적)
            return _context.AuditLogs
                .Where(log => log.Timestamp < olderThan)
                .ExecuteDeleteAsync(cancellationToken);
        }

        /// <summary>
        /// 지정된 로그 ID 목록을 아카이브된 것으로 표시합니다.
        /// </summary>
        public async Task<bool> MarkAsArchivedAsync(
            IEnumerable<Guid> logIds,
            string archiveLocation,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var logIdList = logIds.ToList();
                if (!logIdList.Any()) return true;

                // EF Core 7.0+의 ExecuteUpdateAsync를 사용하여 DB에서 직접 대량 업데이트 수행
                var updatedCount = await _context.AuditLogs
                    .Where(log => logIdList.Contains(log.Id))
                    .ExecuteUpdateAsync(s => s.SetProperty(
                        b => b.Metadata,
                        b => $"{b.Metadata};Archived:{archiveLocation}:{DateTime.UtcNow:yyyy-MM-dd}"),
                        cancellationToken);

                _logger.LogInformation("{Count} audit logs marked as archived to {Location}", updatedCount, archiveLocation);
                return updatedCount > 0;
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

        #region Predicate 헬퍼 메서드들

        private Expression<Func<AuditLog, bool>> BuildSearchPredicate(
            string? action, Guid? connectedId,
            Guid? applicationId, DateTime? fromDate, DateTime? toDate)
        {
            Expression<Func<AuditLog, bool>> predicate = log => true;

            if (!string.IsNullOrWhiteSpace(action))
                predicate = CombinePredicates(predicate, log => log.Action == action);

            if (connectedId.HasValue)
                predicate = CombinePredicates(predicate, log => log.PerformedByConnectedId == connectedId.Value);

            if (applicationId.HasValue)
                predicate = CombinePredicates(predicate, log => log.ApplicationId == applicationId.Value);

            return AddDateRangeToExpression(predicate, fromDate, toDate);
        }

        private Expression<Func<AuditLog, bool>> AddDateRangeToExpression(
            Expression<Func<AuditLog, bool>> predicate,
            DateTime? fromDate, DateTime? toDate)
        {
            if (fromDate.HasValue)
                predicate = CombinePredicates(predicate, log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                predicate = CombinePredicates(predicate, log => log.Timestamp <= toDate.Value);

            return predicate;
        }

        private Expression<Func<AuditLog, bool>> CombinePredicates(
            Expression<Func<AuditLog, bool>> predicate1,
            Expression<Func<AuditLog, bool>> predicate2)
        {
            var parameter = Expression.Parameter(typeof(AuditLog), "log");
            var body = Expression.AndAlso(
                Expression.Invoke(predicate1, parameter),
                Expression.Invoke(predicate2, parameter));

            return Expression.Lambda<Func<AuditLog, bool>>(body, parameter);
        }

        #endregion
    }
}