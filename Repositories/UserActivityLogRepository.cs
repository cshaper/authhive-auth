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
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 활동 로그 저장소 구현 - AuthHive v15
    /// 
    /// 사용자의 애플리케이션 사용 패턴 추적, 행동 분석, 보안 위험 탐지를 담당합니다.
    /// AuditLog(시스템 변경 감사)와 달리 사용자 행동/이벤트에 초점을 맞춥니다.
    /// </summary>
    public class UserActivityLogRepository : BaseRepository<UserActivityLog>, IUserActivityLogRepository
    {
        private readonly ILogger<UserActivityLogRepository> _logger;

        public UserActivityLogRepository(
            AuthDbContext context,
            ILogger<UserActivityLogRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>ConnectedId별 활동 로그 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ConnectedId == connectedId);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>조직별 활동 로그 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetByOrganizationIdAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.OrganizationId == organizationId);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>애플리케이션별 활동 로그 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetByApplicationIdAsync(
            Guid applicationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ApplicationId == applicationId);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync(cancellationToken);
        }

        #endregion

        #region 활동 유형별 조회

        /// <summary>활동 유형별 로그 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetByActivityTypeAsync(
            UserActivityType activityType,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.ActivityType == activityType);

            if (organizationId.HasValue)
                query = query.Where(log => log.OrganizationId == organizationId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        /// <summary>최근 활동 조회</summary>
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

        /// <summary>고위험 활동 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetHighRiskActivitiesAsync(
            int minRiskScore,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.RiskScore >= minRiskScore);

            if (organizationId.HasValue)
                query = query.Where(log => log.OrganizationId == organizationId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query
                .OrderByDescending(log => log.RiskScore)
                .ThenByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>실패한 활동 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetFailedActivitiesAsync(
            Guid? connectedId = null,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => !log.IsSuccessful);

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            if (organizationId.HasValue)
                query = query.Where(log => log.OrganizationId == organizationId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        /// <summary>IP 주소별 활동 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return new List<UserActivityLog>();

            var query = Query().Where(log => log.IPAddress == ipAddress);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query.OrderByDescending(log => log.Timestamp).ToListAsync(cancellationToken);
        }

        #endregion

        #region 세션 관련

        /// <summary>세션별 활동 조회</summary>
        public async Task<IEnumerable<UserActivityLog>> GetBySessionIdAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return new List<UserActivityLog>();

            return await Query()
                .Where(log => log.SessionId == sessionId)
                .OrderBy(log => log.Timestamp) // 세션 내에서는 시간순으로 정렬
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 페이징 및 검색

        /// <summary>활동 로그 검색</summary>
        public async Task<PagedResult<UserActivityLog>> SearchAsync(
            SearchUserActivityLogsRequest request,
            CancellationToken cancellationToken = default)
        {
            // 요청 유효성 검증
            request.ValidatePagination();
            request.ValidateSortDirection();

            var query = Query();

            // UserId 필터 (ConnectedId를 통한 간접 조회)
            if (request.UserId.HasValue)
            {
                query = query.Where(log => _context.ConnectedIds
                    .Any(c => c.UserId == request.UserId.Value && c.Id == log.ConnectedId && !c.IsDeleted));
            }

            // ConnectedId 필터
            if (request.ConnectedId.HasValue)
                query = query.Where(log => log.ConnectedId == request.ConnectedId.Value);

            // 애플리케이션 필터
            if (request.ApplicationId.HasValue)
                query = query.Where(log => log.ApplicationId == request.ApplicationId.Value);

            // 활동 유형 필터 (문자열로 비교)
            if (!string.IsNullOrWhiteSpace(request.ActivityType))
            {
                // ActivityType enum을 문자열로 변환하여 비교
                query = query.Where(log => log.ActivityType.ToString() == request.ActivityType);
            }

            // 시간 범위 필터
            if (request.StartDate.HasValue)
                query = query.Where(log => log.Timestamp >= request.StartDate.Value);

            if (request.EndDate.HasValue)
                query = query.Where(log => log.Timestamp <= request.EndDate.Value);

            // IP 주소 필터
            if (!string.IsNullOrWhiteSpace(request.IpAddress))
                query = query.Where(log => log.IPAddress == request.IpAddress);

            // 검색 키워드 필터
            if (!string.IsNullOrWhiteSpace(request.SearchKeyword))
            {
                query = query.Where(log => 
                    (log.ActivityDescription != null && log.ActivityDescription.Contains(request.SearchKeyword)) ||
                    (log.ResourceType != null && log.ResourceType.Contains(request.SearchKeyword)) ||
                    (log.ResourceId != null && log.ResourceId.Contains(request.SearchKeyword)));
            }

            // 활성 상태 필터 (IsSuccessful로 매핑)
            if (request.IsActive.HasValue)
                query = query.Where(log => log.IsSuccessful == request.IsActive.Value);

            // 삭제된 항목 포함 처리
            if (!request.IncludeDeleted)
                query = query.Where(log => !log.IsDeleted);

            // 정렬 적용
            var sortDescending = request.SortDirection?.ToLower() == "desc";
            query = ApplySorting(query, request.SortBy, sortDescending);

            var totalCount = await query.CountAsync(cancellationToken);
            var logs = await query
                .Skip(request.GetSkip())
                .Take(request.GetTake())
                .ToListAsync(cancellationToken);

            return PagedResult<UserActivityLog>.Create(logs, totalCount, request.PageNumber, request.PageSize);
        }

        /// <summary>정렬 적용</summary>
        private IQueryable<UserActivityLog> ApplySorting(IQueryable<UserActivityLog> query, string? sortBy, bool descending)
        {
            return sortBy?.ToLower() switch
            {
                "timestamp" => descending 
                    ? query.OrderByDescending(log => log.Timestamp)
                    : query.OrderBy(log => log.Timestamp),
                "activitytype" => descending 
                    ? query.OrderByDescending(log => log.ActivityType)
                    : query.OrderBy(log => log.ActivityType),
                "riskscore" => descending 
                    ? query.OrderByDescending(log => log.RiskScore)
                    : query.OrderBy(log => log.RiskScore),
                "issuccessful" => descending 
                    ? query.OrderByDescending(log => log.IsSuccessful)
                    : query.OrderBy(log => log.IsSuccessful),
                _ => descending 
                    ? query.OrderByDescending(log => log.Timestamp)
                    : query.OrderBy(log => log.Timestamp)
            };
        }

        #endregion

        #region 집계

        /// <summary>활동 수 집계</summary>
        public async Task<int> GetActivityCountAsync(
            Guid? connectedId = null,
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query();

            if (connectedId.HasValue)
                query = query.Where(log => log.ConnectedId == connectedId.Value);

            if (organizationId.HasValue)
                query = query.Where(log => log.OrganizationId == organizationId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query.CountAsync(cancellationToken);
        }

        /// <summary>고유 사용자 수</summary>
        public async Task<int> GetUniqueUserCountAsync(
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query();

            if (organizationId.HasValue)
                query = query.Where(log => log.OrganizationId == organizationId.Value);

            if (startDate.HasValue)
                query = query.Where(log => log.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.Timestamp <= endDate.Value);

            return await query.Select(log => log.ConnectedId).Distinct().CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>기본 쿼리 (소프트 삭제된 항목 제외)</summary>
        private new IQueryable<UserActivityLog> Query()
        {
            return _context.UserActivityLogs.Where(log => !log.IsDeleted);
        }

        #endregion
    }
}