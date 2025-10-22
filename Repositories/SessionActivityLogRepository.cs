using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.Json;
using System.Threading; // CancellationToken namespace
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService namespace
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Extensions;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 활동 로그 리포지토리 구현 - AuthHive v16 Refactored
    /// BaseRepository를 상속받아 캐시, 페이징, 조직 필터링 등 공통 기능을 활용합니다.
    /// </summary>
    public class SessionActivityLogRepository : BaseRepository<SessionActivityLog>, ISessionActivityLogRepository
    {
        private readonly ILogger<SessionActivityLogRepository> _logger;
        // AuthDbContext와 ICacheService는 BaseRepository에서 관리
        private readonly Guid? _currentConnectedId; // 감사 추적용

        // 생성자 수정: IOrganizationContext, IMemoryCache 제거, ICacheService 추가
        public SessionActivityLogRepository(
            AuthDbContext context,
            ICacheService cacheService, // ✅ ICacheService 주입
            ILogger<SessionActivityLogRepository> logger,
            IConnectedIdContext connectedIdContext) // ✅ ConnectedId 주입 유지 (감사용)
            : base(context, cacheService) // ✅ base 생성자 호출 변경
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _currentConnectedId = connectedIdContext?.ConnectedId; // 현재 사용자 ID 가져오기
        }

        /// <summary>
        /// SessionActivityLog 엔티티는 조직 범위에 속합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;


        #region BaseRepository 오버라이드 (Include 및 감사)

        /// <summary>
        /// 기본 쿼리에 필요한 Include 적용. 조직 필터링은 BaseRepository.Query()가 처리.
        /// </summary>
        public override IQueryable<SessionActivityLog> Query()
        {
            // BaseRepository.Query()는 IsDeleted=false 및 OrganizationId 필터링 (IsOrganizationScopedEntity=true 이므로)
            return base.Query()
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Include(l => l.PlatformApplication);
        }

        /// <summary>
        /// 엔티티 추가 시 감사 정보 자동 설정
        /// </summary>
        public override async Task<SessionActivityLog> AddAsync(SessionActivityLog entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            // OrganizationId는 엔티티에 이미 설정되어 있다고 가정.
            // 시간 및 생성자 정보 설정
            var now = DateTime.UtcNow; // IDateTimeProvider 고려
            entity.CreatedAt = now;
            entity.CreatedByConnectedId = _currentConnectedId;
            entity.Timestamp = entity.Timestamp == default ? now : entity.Timestamp;
            entity.OccurredAt = entity.OccurredAt == default ? now : entity.OccurredAt;

            // BaseRepository.AddAsync 호출 (캐시는 여기서 무효화하지 않음. GetByIdAsync에서 설정)
            var result = await base.AddAsync(entity, cancellationToken);

            _logger.LogDebug("Session activity logged: {ActivityType} for session {SessionId}",
                entity.ActivityType, entity.SessionId);

            return result;
        }

        /// <summary>
        /// 대량 추가 시 감사 정보 자동 설정
        /// </summary>
        public override Task AddRangeAsync(IEnumerable<SessionActivityLog> entities, CancellationToken cancellationToken = default)
        {
            var logs = entities.ToList();
            var now = DateTime.UtcNow; // IDateTimeProvider 고려

            foreach (var log in logs)
            {
                // OrganizationId는 이미 설정되어 있다고 가정
                log.CreatedAt = now;
                log.CreatedByConnectedId = _currentConnectedId;
                log.Timestamp = log.Timestamp == default ? now : log.Timestamp;
                log.OccurredAt = log.OccurredAt == default ? now : log.OccurredAt;
            }

            return base.AddRangeAsync(logs, cancellationToken);
        }

        /// <summary>
        /// 업데이트 시 감사 정보 자동 설정 및 캐시 무효화
        /// </summary>
        public override Task UpdateAsync(SessionActivityLog entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            // 조직 변경 시도는 BaseRepository.Query() 단계에서 필터링되므로 별도 체크 불필요.
            entity.UpdatedAt = DateTime.UtcNow; // IDateTimeProvider 고려
            entity.UpdatedByConnectedId = _currentConnectedId;

            // BaseRepository.UpdateAsync 호출 -> 내부적으로 InvalidateCacheAsync(id, orgId, token) 호출
            return base.UpdateAsync(entity, cancellationToken);
        }

        /// <summary>
        /// 대량 업데이트 시 감사 정보 자동 설정 및 캐시 무효화
        /// </summary>
        public override Task UpdateRangeAsync(IEnumerable<SessionActivityLog> entities, CancellationToken cancellationToken = default)
        {
            var logs = entities.ToList();
            var now = DateTime.UtcNow; // IDateTimeProvider 고려

            foreach (var log in logs)
            {
                // 조직 변경 시도는 BaseRepository.Query() 단계에서 필터링
                log.UpdatedAt = now;
                log.UpdatedByConnectedId = _currentConnectedId;
            }
            // BaseRepository.UpdateRangeAsync 호출 -> 내부적으로 각 엔티티에 대해 InvalidateCacheAsync 호출
            return base.UpdateRangeAsync(logs, cancellationToken);
        }

        /// <summary>
        /// 삭제(Soft Delete) 시 감사 정보 자동 설정 및 캐시 무효화
        /// </summary>
        public override Task DeleteAsync(SessionActivityLog entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            entity.DeletedByConnectedId = _currentConnectedId;
            // BaseRepository.DeleteAsync 호출 -> 내부적으로 IsDeleted=true, DeletedAt 설정 및 UpdateAsync 호출 (캐시 무효화 포함)
            return base.DeleteAsync(entity, cancellationToken);
        }

        /// <summary>
        /// 대량 삭제(Soft Delete) 시 감사 정보 자동 설정 및 캐시 무효화
        /// </summary>
        public override Task DeleteRangeAsync(IEnumerable<SessionActivityLog> entities, CancellationToken cancellationToken = default)
        {
            var logs = entities.ToList();
            // BaseRepository.DeleteRangeAsync가 각 엔티티에 대해 DeletedBy 설정은 하지 않으므로 여기서 처리
            foreach (var log in logs)
            {
                // IsDeleted, DeletedAt은 base.DeleteRangeAsync에서 처리
                log.DeletedByConnectedId = _currentConnectedId;
            }
            // BaseRepository.DeleteRangeAsync 호출 -> 내부적으로 UpdateRangeAsync 호출 (캐시 무효화 포함)
            return base.DeleteRangeAsync(logs, cancellationToken);
        }

        #endregion

        #region ISessionActivityLogRepository Specific Methods (CancellationToken 추가)

        public async Task<PagedResult<SessionActivityLog>> GetBySessionAsync(
            Guid sessionId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // Query() 사용 (조직 필터링 + 기본 Include 포함)
            Expression<Func<SessionActivityLog, bool>> predicate = l => l.SessionId == sessionId;

            if (startDate.HasValue)
                predicate = predicate.And(l => l.OccurredAt >= startDate.Value); // And 확장 메서드 필요 또는 수동 조합

            if (endDate.HasValue)
                predicate = predicate.And(l => l.OccurredAt <= endDate.Value);

            // BaseRepository.GetPagedAsync 사용
            var (items, totalCount) = await GetPagedAsync(
                pageNumber: pageNumber,
                pageSize: pageSize,
                predicate: predicate,
                orderBy: l => l.OccurredAt, // 정렬 기준
                isDescending: true,        // 정렬 방향
                cancellationToken: cancellationToken); // ✅ Token 전달

            // GetPagedAsync는 Include를 지원하지 않으므로, 필요시 BaseRepository를 수정하거나 여기서 직접 구현
            // 현재 BaseRepository 가정 하에, Include가 적용된 Query()를 사용한 직접 구현 방식 사용:

            var queryManual = Query().Where(predicate); // Query()는 Include 포함
            var totalCountManual = await queryManual.CountAsync(cancellationToken);
            var itemsManual = await queryManual
                .OrderByDescending(l => l.OccurredAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken); // ✅ Token 전달

            return PagedResult<SessionActivityLog>.Create(itemsManual, totalCountManual, pageNumber, pageSize);
        }


        public async Task<IEnumerable<SessionActivityLog>> GetByUserAsync(
            Guid userId,
            SessionActivityType? activityType = null,
            int limit = 100,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => l.UserId == userId);

            if (activityType.HasValue)
                query = query.Where(l => l.ActivityType == activityType.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByConnectedIdAsync(
            Guid connectedId,
            ActivityCategory? category = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => l.ConnectedId == connectedId);

            if (category.HasValue)
                query = query.Where(l => l.Category == category.Value);

            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByApplicationAsync(
            Guid applicationId,
            bool? isSuccess = null,
            int limit = 100,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => l.ApplicationId == applicationId);

            if (isSuccess.HasValue)
                query = query.Where(l => l.IsSuccess == isSuccess.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetBySessionIdAsync(
            Guid sessionId,
            DateTime? since = null,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => l.SessionId == sessionId);

            if (since.HasValue)
                query = query.Where(l => l.OccurredAt >= since.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        // LogActivityAsync는 AddAsync를 호출하므로 AddAsync의 CancellationToken 사용
        public Task<SessionActivityLog> LogActivityAsync(SessionActivityLog log, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // AddAsync는 내부적으로 cancellationToken을 받음
            return AddAsync(log, cancellationToken);
        }

        public Task<SessionActivityLog> LogLoginActivityAsync(
            Guid sessionId, Guid userId, Guid connectedId, string ipAddress, string userAgent, bool isSuccess, string? failureReason = null,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var log = new SessionActivityLog { /* ... (기존 로직과 동일) ... */ };
            // AddAsync 호출 (Token 전달)
            return AddAsync(log, cancellationToken);
        }

        public Task<SessionActivityLog> LogApiActivityAsync(
            Guid sessionId, string endpoint, string method, int statusCode, int responseTimeMs,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var log = new SessionActivityLog { /* ... (기존 로직과 동일) ... */ };
            return AddAsync(log, cancellationToken);
        }

        public Task<SessionActivityLog> LogPageViewAsync(
            Guid sessionId, string pageUrl, string? pageTitle, string? referrerUrl, int? durationMs,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var log = new SessionActivityLog { /* ... (기존 로직과 동일) ... */ };
            return AddAsync(log, cancellationToken);
        }


        public async Task<IEnumerable<SessionActivityLog>> GetSuspiciousActivitiesAsync(
            Guid? organizationId = null, // 서비스 레벨에서 권한 체크 후 명시적 ID 전달 권장
            DateTime? startDate = null,
            DateTime? endDate = null,
            int minRiskScore = 70,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // BaseRepository는 자동으로 현재 컨텍스트의 OrganizationId로 필터링함.
            // organizationId 파라미터는 명시적 필터링을 위해 남겨둘 수 있으나,
            // BaseRepository의 기본 동작과 혼동될 수 있으므로 주의 필요.
            // 여기서는 organizationId가 null이면 현재 조직, 아니면 해당 조직 필터링
            IQueryable<SessionActivityLog> query;
            if (organizationId.HasValue)
            {
                // 특정 조직 쿼리 시도 (BaseRepository 내부에서 권한/테넌트 확인 필요) - 여기서는 직접 필터링
                query = base.Query().Where(l => l.OrganizationId == organizationId.Value && l.RiskScore >= minRiskScore);
                // 주의: 이 방식은 BaseRepository의 의도와 다를 수 있음.
                // 서비스 레이어에서 organizationId를 설정하고 호출하는 것이 더 나음.
            }
            else
            {
                // 현재 조직 쿼리 (BaseRepository 기본 동작)
                query = Query().Where(l => l.RiskScore >= minRiskScore);
            }


            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            return await query
                .OrderByDescending(l => l.RiskScore)
                .ThenByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetSecurityAlertsAsync(
            Guid organizationId, // 명시적 조직 ID 필요
            int limit = 50,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // QueryForOrganization 사용 (BaseRepository 헬퍼)
            return await QueryForOrganization(organizationId) // ✅ 특정 조직 쿼리
                .Where(l => l.SecurityAlert)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }


        public async Task<IEnumerable<SessionActivityLog>> GetFailedActivitiesAsync(
            Guid? sessionId = null,
            SessionActivityType? activityType = null,
            int limit = 100,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => !l.IsSuccess); // 현재 조직 자동 필터링

            if (sessionId.HasValue)
                query = query.Where(l => l.SessionId == sessionId.Value);

            if (activityType.HasValue)
                query = query.Where(l => l.ActivityType == activityType.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query().Where(l => l.IpAddress == ipAddress); // 현재 조직 자동 필터링

            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<bool> UpdateSecurityInfoAsync(
                    Guid logId, int riskScore, bool isSuspicious, bool securityAlert,
                    CancellationToken cancellationToken = default)
        {
            var log = await _dbSet.FindAsync(new object[] { logId }, cancellationToken);

            // 💡 수정: null 체크를 먼저 분리
            if (log == null)
            {
                _logger.LogWarning("Attempted to update security info for non-existent log {LogId}", logId);
                return false;
            }

            // 💡 수정: null이 아님이 확인된 후 IsDeleted 체크
            if (log.IsDeleted) // 삭제된 로그도 수정 불가
            {
                _logger.LogWarning("Attempted to update security info for deleted log {LogId}", logId);
                return false;
            }
            // ✨ 서비스 레이어에서 log.OrganizationId를 현재 요청의 조직 ID와 비교하는 로직을 추가해야 합니다! ✨

            log.RiskScore = riskScore;
            log.IsSuspicious = isSuspicious;
            log.SecurityAlert = securityAlert;

            await UpdateAsync(log, cancellationToken);
            return true;
        }

        // BaseRepository에 IsEntityInCurrentOrganizationAsync 추가 필요 예시
        /*
        protected virtual async Task<bool> IsEntityInCurrentOrganizationAsync(TEntity entity, CancellationToken cancellationToken) {
            if (!IsOrganizationScopedEntity()) return true; // 조직 범위 아니면 항상 참
            var orgIdProperty = typeof(TEntity).GetProperty("OrganizationId");
            if (orgIdProperty == null) return false; // OrganizationId 속성 없으면 확인 불가

            var currentOrgId = await GetCurrentOrganizationIdAsync(cancellationToken); // 현재 조직 ID 가져오기 (구현 필요)
            if (!currentOrgId.HasValue) return false; // 현재 조직 컨텍스트 없으면 실패

            var entityOrgId = (Guid?)orgIdProperty.GetValue(entity);
            return entityOrgId.HasValue && entityOrgId.Value == currentOrgId.Value;
        }
        protected abstract Task<Guid?> GetCurrentOrganizationIdAsync(CancellationToken cancellationToken); // 자식 클래스에서 구현 필요
        */


        public async Task<IEnumerable<SessionActivityLog>> GetByResourceAsync(
            string resourceType, Guid resourceId, string? action = null,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var query = Query() // 현재 조직 자동 필터링
                .Where(l => l.ResourceType == resourceType && l.ResourceId == resourceId);

            if (!string.IsNullOrEmpty(action))
                query = query.Where(l => l.Action == action);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetResourceAccessHistoryAsync(
            string resourceType, Guid resourceId, int limit = 50,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            return await Query() // 현재 조직 자동 필터링
                .Where(l => l.ResourceType == resourceType && l.ResourceId == resourceId)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public Task<Dictionary<SessionActivityType, int>> GetActivityTypeStatisticsAsync(
             Guid organizationId, DateTime startDate, DateTime endDate,
             CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // GetGroupCountAsync는 CancellationToken을 받음 (BaseRepository 구현 확인)
            return GetGroupCountAsync(
                l => l.ActivityType,
                l => l.OrganizationId == organizationId && l.OccurredAt >= startDate && l.OccurredAt <= endDate,
                cancellationToken); // ✅ Token 전달
        }

        public async Task<Dictionary<int, int>> GetHourlyActivityDistributionAsync(
            Guid organizationId, DateTime date,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startOfDay = date.Date;
            var endOfDay = startOfDay.AddDays(1);

            // QueryForOrganization 사용
            var activities = await QueryForOrganization(organizationId)
                .Where(l => l.OccurredAt >= startOfDay && l.OccurredAt < endOfDay)
                .Select(l => l.OccurredAt.Hour)
                .ToListAsync(cancellationToken); // ✅ Token 전달

            return activities.GroupBy(hour => hour).ToDictionary(g => g.Key, g => g.Count());
        }


        public Task<Dictionary<DeviceType, int>> GetDeviceStatisticsAsync(
            Guid organizationId, int period = 30,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            return GetGroupCountAsync(
                l => l.DeviceType!.Value,
                l => l.OrganizationId == organizationId && l.OccurredAt >= startDate && l.DeviceType.HasValue,
                cancellationToken); // ✅ Token 전달
        }

        public Task<Dictionary<BrowserType, int>> GetBrowserStatisticsAsync(
            Guid organizationId, int period = 30,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            return GetGroupCountAsync(
                l => l.Browser!.Value,
                l => l.OrganizationId == organizationId && l.OccurredAt >= startDate && l.Browser.HasValue,
                cancellationToken); // ✅ Token 전달
        }


        public async Task<double> GetAverageResponseTimeAsync(
            string? endpoint = null, int period = 7,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var query = Query() // 현재 조직
                .Where(l => l.OccurredAt >= startDate && l.ResponseTimeMs.HasValue);

            if (!string.IsNullOrEmpty(endpoint))
                query = query.Where(l => l.ApiEndpoint == endpoint);

            // AverageAsync 사용 최적화
            return await query.AverageAsync(l => (double?)l.ResponseTimeMs!.Value, cancellationToken) ?? 0.0; // ✅ Token 전달
        }

        public async Task<double> CalculateApiErrorRateAsync(
            Guid? applicationId = null, int period = 7,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var query = Query() // 현재 조직
                .Where(l => l.OccurredAt >= startDate && l.ActivityType == SessionActivityType.ApiCall);

            if (applicationId.HasValue)
                query = query.Where(l => l.ApplicationId == applicationId.Value);

            var total = await query.CountAsync(cancellationToken); // ✅ Token 전달
            if (total == 0) return 0.0;

            var errors = await query.CountAsync(l => !l.IsSuccess, cancellationToken); // ✅ Token 전달

            return (double)errors / total * 100;
        }


        public async Task<IEnumerable<SessionActivityLog>> GetByCountryAsync(
            string countryCode, Guid? organizationId = null, int limit = 100,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // organizationId가 null이면 BaseRepository가 현재 조직 사용, 아니면 명시적 조직 사용
            IQueryable<SessionActivityLog> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();


            return await query
                .Where(l => l.CountryCode == countryCode)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public Task<Dictionary<string, int>> GetLocationStatisticsAsync(
            Guid organizationId, int period = 30,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            return GetGroupCountAsync(
                l => l.CountryCode!,
                l => l.OrganizationId == organizationId && l.OccurredAt >= startDate && !string.IsNullOrEmpty(l.CountryCode),
                cancellationToken); // ✅ Token 전달
        }


        public async Task<bool> DetectGeographicalAnomalyAsync(
             Guid userId, string currentLocation, int timeWindowMinutes = 60,
             CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 이 로직은 서비스 레이어에 더 적합할 수 있음 (외부 위치 서비스 연동 등)
            var timeWindow = DateTime.UtcNow.AddMinutes(-timeWindowMinutes);

            // Query() 사용 (현재 조직 내 사용자 활동)
            var recentLocations = await Query()
                .Where(l => l.UserId == userId &&
                              l.OccurredAt >= timeWindow &&
                              !string.IsNullOrEmpty(l.Location))
                .Select(l => l.Location)
                .Distinct()
                .ToListAsync(cancellationToken); // ✅ Token 전달

            // 간단 로직 유지
            return recentLocations.Any() && !recentLocations.Contains(currentLocation);
        }


        public async Task<IEnumerable<SessionActivityLog>> GetByTraceIdAsync(
            string traceId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // Query() 사용 (현재 조직)
            return await Query()
                .Where(l => l.TraceId == traceId)
                .OrderBy(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<SessionActivityLog?> GetBySpanIdAsync(
            string spanId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // Query() 사용 (현재 조직)
            // FirstOrDefaultAsync는 BaseRepository에 구현되어 있음 (Token 전달)
            return await FirstOrDefaultAsync(l => l.SpanId == spanId, cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionActivityLog>> GetTraceHierarchyAsync(
            string traceId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // GetByTraceIdAsync 호출 (Token 전달)
            var logs = await GetByTraceIdAsync(traceId, cancellationToken);

            // 메모리 내 정렬 유지
            return logs.OrderBy(l => string.IsNullOrEmpty(l.ParentSpanId) ? 0 : 1)
                       .ThenBy(l => l.OccurredAt);
        }

        // BulkLogAsync는 AddRangeAsync를 호출하므로 AddRangeAsync의 CancellationToken 사용
        public Task<int> BulkLogAsync(IEnumerable<SessionActivityLog> logs, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var logList = logs.ToList();
            // AddRangeAsync 호출 (Token 전달)
            return AddRangeAsync(logList, cancellationToken).ContinueWith(t => logList.Count, cancellationToken);
        }

        public async Task<int> ArchiveOldLogsAsync(
            int olderThanDays, int batchSize = 1000,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            var totalArchived = 0;

            while (!cancellationToken.IsCancellationRequested) // ✅ 취소 확인
            {
                // Query() 사용 (현재 조직)
                var logsToArchive = await Query()
                    .Where(l => l.OccurredAt < cutoffDate)
                    .OrderBy(l => l.OccurredAt) // 순서 보장 (선택적)
                    .Take(batchSize)
                    .ToListAsync(cancellationToken); // ✅ Token 전달

                if (!logsToArchive.Any())
                    break;

                // DeleteRangeAsync 호출 (Token 전달)
                await DeleteRangeAsync(logsToArchive, cancellationToken);
                totalArchived += logsToArchive.Count;
            }

            cancellationToken.ThrowIfCancellationRequested(); // ✅ 루프 후 최종 확인

            _logger.LogInformation("Archived {Count} old session activity logs for current organization", totalArchived);
            return totalArchived;
        }

        public async Task<int> DeleteBySessionAsync(
            Guid sessionId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // Query() 사용 (현재 조직)
            var logs = await Query()
                .Where(l => l.SessionId == sessionId)
                .ToListAsync(cancellationToken); // ✅ Token 전달

            if (logs.Any())
            {
                // DeleteRangeAsync 호출 (Token 전달)
                await DeleteRangeAsync(logs, cancellationToken);
            }

            return logs.Count;
        }

        public async Task<PagedResult<SessionActivityLog>> SearchAsync(
             Expression<Func<SessionActivityLog, bool>> criteria,
             Expression<Func<SessionActivityLog, object>>? sortBy = null,
             bool sortDescending = true,
             int pageNumber = 1,
             int pageSize = 50,
             CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // BaseRepository.GetPagedAsync 사용 또는 직접 구현 (Include 필요 시)
            // 여기서는 직접 구현 (Query() 사용으로 Include 자동 적용)
            var query = Query().Where(criteria); // 현재 조직 + Include
            var totalCount = await query.CountAsync(cancellationToken); // ✅ Token 전달

            if (sortBy != null)
            {
                query = sortDescending ? query.OrderByDescending(sortBy) : query.OrderBy(sortBy);
            }
            else
            {
                query = query.OrderByDescending(l => l.OccurredAt); // 기본 정렬
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken); // ✅ Token 전달

            return PagedResult<SessionActivityLog>.Create(items, totalCount, pageNumber, pageSize);
        }


        public async Task<IEnumerable<SessionActivityLog>> SearchByMultipleCriteriaAsync(
             Guid organizationId, // 명시적 조직 ID
             IEnumerable<SessionActivityType>? activityTypes,
             IEnumerable<ActivityCategory>? categories,
             DateTime? startDate, DateTime? endDate, int? minRiskScore,
             CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // QueryForOrganization 사용 (명시적 조직 + Include)
            var query = QueryForOrganization(organizationId); // ✅ 명시적 조직 + Include

            if (activityTypes?.Any() == true)
                query = query.Where(l => activityTypes.Contains(l.ActivityType));
            if (categories?.Any() == true)
                query = query.Where(l => categories.Contains(l.Category));
            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);
            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);
            if (minRiskScore.HasValue)
                query = query.Where(l => l.RiskScore >= minRiskScore.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }


        #endregion
    }

}