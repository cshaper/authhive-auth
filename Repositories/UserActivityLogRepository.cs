// Path: AuthHive.Auth/Repositories/UserActivityLogRepository.cs
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
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 활동 로그 저장소 구현 - AuthHive v16 (BaseRepository v15.5 적용)
    /// 사용자의 애플리케이션 사용 패턴 추적, 행동 분석, 보안 위험 탐지를 담당
    /// </summary>
    public class UserActivityLogRepository : BaseRepository<UserActivityLog>, IUserActivityLogRepository
    {
        private readonly ILogger<UserActivityLogRepository> _logger;

        public UserActivityLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserActivityLogRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

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
        /// 조직별 활동 로그 조회
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> GetByOrganizationIdAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            query = ApplyTimeAndLimitFilter(query, startDate, endDate, limit)
                .OrderByDescending(log => log.Timestamp);
            return await query.ToListAsync(cancellationToken);
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
                ? QueryForOrganization(organizationId.Value)
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
                ? QueryForOrganization(organizationId.Value)
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
                ? QueryForOrganization(organizationId.Value)
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
            // 1. 기본 쿼리 설정 (조직 컨텍스트 기반)
            var query = request.OrganizationId.HasValue
                ? QueryForOrganization(request.OrganizationId.Value)
                : Query();
            
            // 삭제된 항목 포함 여부 처리
            if(request.IncludeDeleted)
            {
                 query = _dbSet.AsQueryable();
                 if(request.OrganizationId.HasValue)
                 {
                     query = query.Where(e => EF.Property<Guid>(e, "OrganizationId") == request.OrganizationId.Value);
                 }
            }

            // 2. 동적 필터링 적용
            query = ApplySearchFilters(query, request);

            // 3. 정렬 적용
            query = ApplySorting(query, request.SortBy, request.SortDescending);

            // 4. 페이징 실행
            var totalCount = await query.CountAsync(cancellationToken);
            var logs = await query
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
                ? QueryForOrganization(organizationId.Value)
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
                ? QueryForOrganization(organizationId.Value)
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
            // UserId 필터 (ConnectedIds를 통해 간접적으로 필터링)
            if (request.UserId.HasValue)
            {
                // 참고: 이 쿼리는 데이터가 많을 경우 성능 저하를 유발할 수 있습니다.
                // ConnectedId를 미리 조회하여 IN 절로 변경하는 것을 고려할 수 있습니다.
                query = query.Where(log => _context.ConnectedIds
                    .Any(c => c.UserId == request.UserId.Value && c.Id == log.ConnectedId && !c.IsDeleted));
            }

            if (request.ConnectedId.HasValue)
                query = query.Where(log => log.ConnectedId == request.ConnectedId.Value);

            if (request.ApplicationId.HasValue)
                query = query.Where(log => log.ApplicationId == request.ApplicationId.Value);

            // ActivityType 필터 (Enum 파싱으로 안정성 확보)
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

            // 검색 키워드 필터 (BaseSearchRequest의 SearchTerm 사용)
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
            // 기본 정렬은 Timestamp 내림차순
            var sortColumn = sortBy?.ToLowerInvariant() ?? "timestamp";

            // 참고: ThenBy를 추가하여 정렬 안정성 확보 (예: 위험점수가 같으면 시간순으로)
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

        // IsOrganizationScopedEntity override는 BaseRepository에 동일한 구현이 있으므로 제거합니다.
        // UserActivityLog가 OrganizationScopedEntity를 상속하는 한, 이 override는 필요 없습니다.
    }
}