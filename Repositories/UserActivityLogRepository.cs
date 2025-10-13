// Path: AuthHive.Auth/Repositories/UserActivityLogRepository.cs
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
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Entities.Auth;
using System.Linq.Expressions; // ICacheService를 사용한다고 가정

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 활동 로그 저장소 구현 - AuthHive v16
    /// 사용자의 애플리케이션 사용 패턴 추적, 행동 분석, 보안 위험 탐지를 담당
    /// </summary>
    public class UserActivityLogRepository : BaseRepository<UserActivityLog>, IUserActivityLogRepository
    {
        private readonly ILogger<UserActivityLogRepository> _logger;
        private readonly IOrganizationContext _organizationContext;

        public UserActivityLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserActivityLogRepository> logger)
            : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
        }

        /// <summary>
        /// UserActivityLog 엔티티는 특정 조직에 속하므로, 멀티테넌시 필터링을 위해 true를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
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
            // BaseRepository의 QueryForOrganization 활용
            var query = QueryForOrganization(organizationId);
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

            var query = QueryForOrganization(organizationId);
            var log = await query
                .Where(log => log.Id == id)
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

        // Path: Authhive.auth/Repositories/UserActivityLogRepository.cs

        /// <summary>
        /// 조직 범위 내에서 지정된 조건(predicate)에 따라 활동 로그를 검색합니다.
        /// </summary>
        public async Task<IEnumerable<UserActivityLog>> FindByOrganizationAsync(
            Guid organizationId,
            Expression<Func<UserActivityLog, bool>> predicate,
            CancellationToken cancellationToken = default)
        {
            // 1. 조직 필터 적용 (BaseRepository 헬퍼 사용)
            var query = QueryForOrganization(organizationId);

            // 2. 추가 조건 (predicate) 적용
            query = query.Where(predicate);

            // 3. 비동기 조회 및 목록 반환
            return await query.ToListAsync(cancellationToken);
        }
        // Path: Authhive.auth/Repositories/UserActivityLogRepository.cs (또는 BaseRepository에서 상속받지 않았다면)

        /// <summary>
        /// 조직 ID를 기준으로 엔티티를 검색하고 페이징 처리합니다.
        /// CancellationToken을 포함하여 비동기 작업 취소를 지원합니다.
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
            // 1. 페이지 유효성 검사 및 안전 장치
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000;

            // 2. 조직 범위 필터 적용
            var query = QueryForOrganization(organizationId);

            // 3. 추가 조건 적용
            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }

            // 4. 전체 항목 수 계산 (CancellationToken 전달)
            var totalCount = await query.CountAsync(cancellationToken);

            // 5. 정렬 적용
            if (orderBy != null)
            {
                query = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
            }
            else
            {
                // 기본 정렬: BaseEntity의 Id를 내림차순으로 사용
                query = query.OrderByDescending(e => e.Id);
            }

            // 6. 페이징 적용 및 데이터 조회 (CancellationToken 전달)
            var items = await query
                .AsNoTracking()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }

        /// <summary>
        /// 특정 ID의 엔티티가 주어진 조직 ID에 속하는지 여부를 확인합니다.
        /// 멀티테넌시 데이터 접근 제어를 위해 사용됩니다.
        /// </summary>
        /// <param name="id">엔티티의 고유 ID</param>
        /// <param name="organizationId">엔티티가 속해야 할 조직 ID</param>
        /// <returns>조직 내에 엔티티가 존재하면 true, 아니면 false</returns>
        public async Task<bool> ExistsInOrganizationAsync(
            Guid id,
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // 1. 조직 범위 쿼리 생성
            var query = QueryForOrganization(organizationId);

            // 2. ID 조건을 추가하여 엔티티 존재 여부 확인
            return await query
                .AnyAsync(log => log.Id == id, cancellationToken);
        }
        /// <summary>
        /// 조직 ID를 기준으로 해당 조직에 속한 모든 활동 로그를 소프트 삭제 처리합니다.
        /// 이는 대량 데이터 삭제 시 데이터베이스 부하를 줄이고 데이터 복구를 용이하게 합니다.
        /// </summary>
        /// <param name="organizationId">삭제할 활동 로그가 속한 조직의 ID</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰</param>
        /// <returns>삭제 처리된 엔티티의 개수를 포함한 Task</returns>
        public async Task DeleteAllByOrganizationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // 1. 조직 범위 쿼리 생성: 해당 조직의 삭제되지 않은 모든 로그를 가져옵니다.
            var entitiesToDelete = await QueryForOrganization(organizationId)
                .ToListAsync(cancellationToken);

            if (!entitiesToDelete.Any())
            {
                // 삭제할 엔티티가 없으면 즉시 종료
                return;
            }

            // 2. 모든 엔티티를 소프트 삭제 상태로 변경
            var now = DateTime.UtcNow;
            foreach (var entity in entitiesToDelete)
            {
                // BaseRepository의 DeleteAsync 로직과 유사하게 필드를 직접 업데이트합니다.
                entity.IsDeleted = true;
                entity.DeletedAt = now;

                // 참고: UserActivityLog가 OrganizationScopedEntity를 상속하므로
                // AuditableEntity 필드도 업데이트 가능합니다 (Updated/DeletedByConnectedId 등).
                entity.UpdatedAt = now;

                // 만약 BaseRepository에 캐시 무효화 로직이 있다면, 여기서 호출합니다.
                // BaseRepository의 UpdateRangeAsync가 캐시 무효화까지 담당한다고 가정하고 생략합니다.
            }

            // 3. 변경된 상태를 DB에 일괄 반영
            // BaseRepository의 UpdateRangeAsync를 사용하면, 컨텍스트의 ChangeTracker를 통해
            // 모든 엔티티가 Modified 상태로 일괄 업데이트됩니다.
            await UpdateRangeAsync(entitiesToDelete, cancellationToken);

            // 4. 변경사항 저장
            await _context.SaveChangesAsync(cancellationToken);

            // 💡 이 메서드는 계약상 Task를 반환해야 하므로, Task.CompletedTask가 아닌 void Task로 간주하여 구현합니다.
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
            if (request.IncludeDeleted)
            {
                // BaseRepository의 _dbSet 필드를 직접 참조한다고 가정
                query = _dbSet.AsQueryable();

                // QueryForOrganization 헬퍼의 로직을 수동으로 적용
                if (request.OrganizationId.HasValue)
                {
                    // OrganizationId 필터링
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
        /// <summary>
        /// 조직 ID를 기준으로 엔티티의 개수를 계산합니다.
        /// 선택적인 predicate(조건)를 추가로 적용할 수 있으며, CancellationToken을 지원합니다.
        /// </summary>
        /// <param name="organizationId">조회할 조직의 ID</param>
        /// <param name="predicate">선택적 필터 조건 (예: log => log.RiskScore > 50)</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰</param>
        /// <returns>조건에 맞는 엔티티의 개수</returns>
        public async Task<int> CountByOrganizationAsync(
            Guid organizationId,
            Expression<Func<UserActivityLog, bool>>? predicate = null,
            CancellationToken cancellationToken = default)
        {
            // 1. 조직 범위 쿼리 생성 (OrganizationId 및 IsDeleted 필터 자동 적용)
            var query = QueryForOrganization(organizationId);

            // 2. 추가 조건(predicate) 적용
            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            // 3. 비동기적으로 개수 계산 (CancellationToken 전달)
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
                // ConnectedIds Set에 접근하기 위해 _context를 사용
                query = query.Where(log => _context.Set<ConnectedId>()
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
                // 널 체크된 람다 표현식으로 변환 (EF Core가 SQL로 변환 가능하도록)
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