using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Entities.Auth;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 활동 로그 저장소 구현 - AuthHive v16.2
    /// 
    /// [v16.2 변경 사항]
    /// 1. CS0534 오류 해결: BaseRepository의 abstract 메서드인
    ///    IsOrganizationBaseEntity()를 'false'로 명시적 구현
    /// 
    /// [v16.1 변경 사항]
    /// 1. IOrganizationScopedRepository 상속 제거에 따른 로직 수정
    /// 2. ICacheService 통합
    /// 3. IOrganizationContext 의존성 제거
    /// </summary>
    public class UserActivityLogRepository : BaseRepository<UserActivityLog>, IUserActivityLogRepository
    {
        private readonly ILogger<UserActivityLogRepository> _logger;

        public UserActivityLogRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<UserActivityLogRepository> logger)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [v16.2 수정] BaseRepository의 abstract 메서드를 구현합니다.
        /// UserActivityLog 엔티티는 SystemGlobalBaseEntity를 상속하며,
        /// OrganizationId가 nullable이므로 조직 범위 엔티티(OrganizationBaseEntity)가 아닙니다.
        /// 따라서 'false'를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity()
        {
            return false;
        }

        /// <summary>
        /// 조직별 활동 로그 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByOrganizationIdAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] QueryForOrganization() 대신 Query()와 Where()를 명시적으로 사용
            var query = Query().Where(log => log.OrganizationId == organizationId);

            query = ApplyTimeAndLimitFilter(query, startDate, endDate, limit)
                .OrderByDescending(log => log.Timestamp);
            return await query.ToListAsync(cancellationToken);
        }

        #region 기본 조회
        /// <summary>
        /// ID와 조직 ID를 기준으로 단일 활동 로그 조회 (널 허용 public API)
        /// </summary>
        public async Task<UserActivityLog?> GetByIdAndOrganizationAsync(
            Guid id,
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.OrganizationId == organizationId && log.Id == id);

            var log = await query
                .FirstOrDefaultAsync(cancellationToken);

            return log;
        }
        /// <summary>
        /// ConnectedId별 활동 로그 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ConnectedId == connectedId);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, limit)
                .OrderByDescending(log => log.Timestamp);
            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직 범위 내에서 지정된 조건(predicate)에 따라 활동 로그를 검색합니다.
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> FindByOrganizationAsync(
            Guid organizationId,
            Expression<Func<UserActivityLog, bool>> predicate,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.OrganizationId == organizationId);
            query = query.Where(predicate);
            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직 ID를 기준으로 엔티티를 검색하고 페이징 처리합니다.
        /// </summary>
        public async Task<(IEnumerable<UserActivityLog> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber,
            int pageSize,
            Expression<Func<UserActivityLog, bool>>? additionalPredicate = null,
            Expression<Func<UserActivityLog, object>>? orderBy = null,
            bool isDescending = false,
            CancellationToken cancellationToken = default)
        {
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000;

            var query = Query().Where(log => log.OrganizationId == organizationId);

            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            if (orderBy != null)
            {
                query = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(e => e.Id);
            }

            var items = await query
                .AsNoTracking()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }

        /// <summary>
        /// 특정 ID의 엔티티가 주어진 조직 ID에 속하는지 여부를 확인합니다.
        /// </summary>
        public async Task<bool> ExistsInOrganizationAsync(
            Guid id,
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.OrganizationId == organizationId);

            return await query
                .AnyAsync(log => log.Id == id, cancellationToken);
        }

        /// <summary>
        /// 조직 ID를 기준으로 해당 조직에 속한 모든 활동 로그를 소프트 삭제 처리합니다.
        /// </summary>
        public async Task DeleteAllByOrganizationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var entitiesToDelete = await Query()
                .Where(log => log.OrganizationId == organizationId)
                .ToListAsync(cancellationToken);

            if (!entitiesToDelete.Any())
            {
                return;
            }

            var now = DateTime.UtcNow;
            foreach (var entity in entitiesToDelete)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = now;
                entity.UpdatedAt = now;
            }

            await UpdateRangeAsync(entitiesToDelete, cancellationToken);

            // UoW 원칙에 따라 SaveChangesAsync()는 서비스 레이어에서 호출합니다.
        }

        /// <summary>
        /// 애플리케이션별 활동 로그 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByApplicationIdAsync(
            Guid applicationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ApplicationId == applicationId);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, limit)
                .OrderByDescending(log => log.Timestamp);
            return await query.ToListAsync(cancellationToken);
        }

        #endregion

        #region 활동 유형별 조회

        /// <summary>
        /// 활동 유형별 로그 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByActivityTypeAsync(
            UserActivityType activityType,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? Query().Where(log => log.OrganizationId == organizationId.Value)
                : Query();

            query = query.Where(log => log.ActivityType == activityType);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, null);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 최근 활동 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetRecentActivitiesAsync(
            Guid connectedId,
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(log => log.ConnectedId == connectedId)
                .OrderByDescending(log => log.Timestamp)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 보안 관련 조회

        /// <summary>
        /// 고위험 활동 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetHighRiskActivitiesAsync(
            int minRiskScore,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? Query().Where(log => log.OrganizationId == organizationId.Value)
                : Query();

            query = query.Where(log => log.RiskScore >= minRiskScore);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, null);

            return await query
                .OrderByDescending(log => log.RiskScore)
                .ThenByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 실패한 활동 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetFailedActivitiesAsync(
            Guid? connectedId = null,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? Query().Where(log => log.OrganizationId == organizationId.Value)
                : Query();

            query = query.Where(log => !log.IsSuccessful);

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            query = ApplyTimeAndLimitFilter(query, startDate, endDate, null);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        /// <summary>
        /// IP 주소별 활동 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return Enumerable.Empty<UserActivityLog>();

            var query = Query().Where(log => log.IpAddress == ipAddress);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, null);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        #endregion

        #region 세션 관련

        /// <summary>
        /// 세션별 활동 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetBySessionIdAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return Enumerable.Empty<UserActivityLog>();

            return await Query()
                .Where(log => log.SessionId == sessionId)
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 페이징 및 검색 (개선)

        /// <summary>
        /// 활동 로그 검색 (BaseRepository 페이징 및 필터링 활용)
        /// </summary>
        public async Task<PagedResult<UserActivityLog>> SearchAsync(
            SearchUserActivityLogsRequest request,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserActivityLog> query;

            // 삭제된 항목 포함 여부 처리
            if (request.IncludeDeleted)
            {
                query = _dbSet.AsQueryable(); // IsDeleted 필터 무시
                if (request.OrganizationId.HasValue)
                {
                    // UserActivityLog.OrganizationId (Guid?) 사용
                    query = query.Where(e => e.OrganizationId == request.OrganizationId.Value);
                }
            }
            else
            {
                // 기본 Query() 사용 (IsDeleted == false 필터 포함)
                query = request.OrganizationId.HasValue
                    ? Query().Where(log => log.OrganizationId == request.OrganizationId.Value)
                    : Query();
            }

            query = ApplySearchFilters(query, request);
            query = ApplySorting(query, request.SortBy, request.SortDescending);

            var totalCount = await query.CountAsync(cancellationToken);
            var logs = await query
                .AsNoTracking()
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<UserActivityLog>
            {
                Items = logs,
                TotalCount = totalCount,
                PageNumber = request.PageNumber,
                PageSize = request.PageSize
            };
        }
        /// <summary>
        /// 조직 ID를 기준으로 엔티티의 개수를 계산합니다.
        /// </summary>
        public async Task<int> CountByOrganizationAsync(
            Guid organizationId,
            Expression<Func<UserActivityLog, bool>>? predicate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.OrganizationId == organizationId);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync(cancellationToken);
        }
        #endregion

        #region 집계

        /// <summary>
        /// 활동 수 집계
        /// </summary>
        public Task<int> GetActivityCountAsync(
            Guid? connectedId = null,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? Query().Where(log => log.OrganizationId == organizationId.Value)
                : Query();

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return query.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 고유 사용자 수
        /// </summary>
        public Task<int> GetUniqueUserCountAsync(
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? Query().Where(log => log.OrganizationId == organizationId.Value)
                : Query();

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return query
                .Select(log => log.ConnectedId)
                .Distinct()
                .CountAsync(cancellationToken);
        }

        #endregion

        #region Private 헬퍼 메서드

        /// <summary>
        /// SearchAsync를 위한 필터링 로직
        /// </summary>
        private IQueryable<UserActivityLog> ApplySearchFilters(IQueryable<UserActivityLog> query, SearchUserActivityLogsRequest request)
        {
            if (request.UserId.HasValue)
            {
                query = query.Where(log => _context.Set<ConnectedId>()
                    .Any(c => c.UserId == request.UserId.Value && c.Id == log.ConnectedId && !c.IsDeleted));
            }

            if (request.ConnectedId.HasValue)
                query = query.Where(log => log.ConnectedId == request.ConnectedId.Value);

            if (request.ApplicationId.HasValue)
                query = query.Where(log => log.ApplicationId == request.ApplicationId.Value);

            if (!string.IsNullOrWhiteSpace(request.ActivityType) && Enum.TryParse<UserActivityType>(request.ActivityType, true, out var activityType))
            {
                query = query.Where(log => log.ActivityType == activityType);
            }

            if (request.StartDate.HasValue)
                query = query.Where(log => log.Timestamp >= request.StartDate.Value);
            if (request.EndDate.HasValue)
                query = query.Where(log => log.Timestamp <= request.EndDate.Value);

            if (!string.IsNullOrWhiteSpace(request.IpAddress))
                query = query.Where(log => log.IpAddress == request.IpAddress);

            if (request.IsSuccessful.HasValue)
                query = query.Where(log => log.IsSuccessful == request.IsSuccessful.Value);

            if (request.MinRiskScore.HasValue)
                query = query.Where(log => log.RiskScore >= request.MinRiskScore.Value);
            if (request.MaxRiskScore.HasValue)
                query = query.Where(log => log.RiskScore <= request.MaxRiskScore.Value);

            if (!string.IsNullOrWhiteSpace(request.SessionId))
                query = query.Where(log => log.SessionId == request.SessionId);

            if (!string.IsNullOrWhiteSpace(request.ResourceType))
                query = query.Where(log => log.ResourceType == request.ResourceType);

            if (!string.IsNullOrWhiteSpace(request.SearchTerm))
            {
                var keyword = request.SearchTerm.ToLower();
                query = query.Where(log =>
                    (log.ActivityDescription != null && log.ActivityDescription.ToLower().Contains(keyword)) ||
                    (log.ResourceType != null && log.ResourceType.ToLower().Contains(keyword)) ||
                    (log.ResourceId != null && log.ResourceId.ToLower().Contains(keyword)));
            }

            return query;
        }

        /// <summary>
        /// 공통적인 시간 및 개수 제한 필터를 적용합니다.
        /// </summary>
        private IQueryable<UserActivityLog> ApplyTimeAndLimitFilter(
            IQueryable<UserActivityLog> query,
            DateTime? startDate,
            DateTime? endDate,
            int? limit)
        {
            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return query;
        }

        /// <summary>
        /// 동적 정렬을 적용합니다.
        /// </summary>
        private IQueryable<UserActivityLog> ApplySorting(
            IQueryable<UserActivityLog> query,
            string? sortBy,
            bool descending)
        {
            var sortColumn = sortBy?.ToLowerInvariant() ?? "timestamp";

            switch (sortColumn)
            {
                case "activitytype":
                    return descending
                        ? query.OrderByDescending(log => log.ActivityType).ThenByDescending(log => log.Timestamp)
                        : query.OrderBy(log => log.ActivityType).ThenByDescending(log => log.Timestamp);
                case "riskscore":
                    return descending
                        ? query.OrderByDescending(log => log.RiskScore).ThenByDescending(log => log.Timestamp)
                        : query.OrderBy(log => log.RiskScore).ThenByDescending(log => log.Timestamp);
                case "issuccessful":
                    return descending
                        ? query.OrderByDescending(log => log.IsSuccessful).ThenByDescending(log => log.Timestamp)
                        : query.OrderBy(log => log.IsSuccessful).ThenByDescending(log => log.Timestamp);
                default: // "timestamp" 포함
                    return descending
                        ? query.OrderByDescending(log => log.Timestamp)
                        : query.OrderBy(log => log.Timestamp);
            }
        }

        #endregion
    }
}