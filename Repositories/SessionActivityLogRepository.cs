using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 활동 로그 리포지토리 구현 - AuthHive v15
    /// BaseRepository를 상속받아 캐시, 페이징 등 공통 기능을 활용합니다.
    /// </summary>
    public class SessionActivityLogRepository : BaseRepository<SessionActivityLog>, ISessionActivityLogRepository
    {
        private readonly ILogger<SessionActivityLogRepository> _logger;
        private readonly Guid _currentOrganizationId;
        private readonly Guid? _currentConnectedId;
        private readonly IConnectedIdContext _connectedIdContext;

        public SessionActivityLogRepository(
            AuthDbContext context,
            ILogger<SessionActivityLogRepository> logger,
            IOrganizationContext organizationContext,
            IConnectedIdContext connectedIdContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache) // ✅ 수정: organizationContext 추가
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _currentOrganizationId = organizationContext?.OrganizationId ?? throw new ArgumentNullException(nameof(organizationContext));
            _currentConnectedId = connectedIdContext?.ConnectedId;
            _connectedIdContext = connectedIdContext ?? throw new ArgumentNullException(nameof(connectedIdContext));
        }

        #region BaseRepository 메서드 오버라이드 (조직 필터링 적용)

        /// <summary>
        /// 기본 쿼리에 조직 필터링과 Include 적용
        /// </summary>
        public override IQueryable<SessionActivityLog> Query()
        {
            return base.Query()
                .Where(l => l.OrganizationId == _currentOrganizationId)
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Include(l => l.PlatformApplication);
        }

        /// <summary>
        /// 엔티티 추가 시 조직 정보 자동 설정
        /// </summary>
        public override async Task<SessionActivityLog> AddAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            // 조직 및 감사 정보 자동 설정
            entity.OrganizationId = _currentOrganizationId;
            entity.CreatedAt = DateTime.UtcNow;
            entity.CreatedByConnectedId = _currentConnectedId;
            entity.Timestamp = entity.Timestamp == default ? DateTime.UtcNow : entity.Timestamp;
            entity.OccurredAt = entity.OccurredAt == default ? DateTime.UtcNow : entity.OccurredAt;

            var result = await base.AddAsync(entity);
            
            _logger.LogDebug("Session activity logged: {ActivityType} for session {SessionId}",
                entity.ActivityType, entity.SessionId);

            return result;
        }

        /// <summary>
        /// 대량 추가 시 조직 정보 자동 설정
        /// </summary>
        public override async Task AddRangeAsync(IEnumerable<SessionActivityLog> entities)
        {
            var logs = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var log in logs)
            {
                log.OrganizationId = _currentOrganizationId;
                log.CreatedAt = now;
                log.CreatedByConnectedId = _currentConnectedId;
                log.Timestamp = log.Timestamp == default ? now : log.Timestamp;
                log.OccurredAt = log.OccurredAt == default ? now : log.OccurredAt;
            }

            await base.AddRangeAsync(logs);
        }

        /// <summary>
        /// 업데이트 시 감사 정보 자동 설정
        /// </summary>
        public override Task UpdateAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            if (entity.OrganizationId != _currentOrganizationId)
            {
                throw new UnauthorizedAccessException("Cannot update log from different organization");
            }

            entity.UpdatedAt = DateTime.UtcNow;
            entity.UpdatedByConnectedId = _currentConnectedId;

            return base.UpdateAsync(entity);
        }

        /// <summary>
        /// 대량 업데이트 시 감사 정보 자동 설정
        /// </summary>
        public override Task UpdateRangeAsync(IEnumerable<SessionActivityLog> entities)
        {
            var logs = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var log in logs)
            {
                if (log.OrganizationId != _currentOrganizationId)
                {
                    throw new UnauthorizedAccessException($"Cannot update log {log.Id} from different organization");
                }

                log.UpdatedAt = now;
                log.UpdatedByConnectedId = _currentConnectedId;
            }

            return base.UpdateRangeAsync(logs);
        }

        /// <summary>
        /// 삭제 시 감사 정보 자동 설정
        /// </summary>
        public override Task DeleteAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            entity.DeletedByConnectedId = _currentConnectedId;
            
            return base.DeleteAsync(entity);
        }

        /// <summary>
        /// 대량 삭제 시 감사 정보 자동 설정
        /// </summary>
        public override Task DeleteRangeAsync(IEnumerable<SessionActivityLog> entities)
        {
            var logs = entities.ToList();

            foreach (var log in logs)
            {
                if (log.OrganizationId == _currentOrganizationId)
                {
                    log.DeletedByConnectedId = _currentConnectedId;
                }
            }

            return base.DeleteRangeAsync(logs);
        }

        #endregion

        #region ISessionActivityLogRepository Specific Methods

        public async Task<PagedResult<SessionActivityLog>> GetBySessionAsync(
            Guid sessionId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int pageNumber = 1,
            int pageSize = 50)
        {
            var query = Query().Where(l => l.SessionId == sessionId);

            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            var totalCount = await query.CountAsync();

            var items = await query
                .OrderByDescending(l => l.OccurredAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new PagedResult<SessionActivityLog>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize
            };
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByUserAsync(
            Guid userId,
            SessionActivityType? activityType = null,
            int limit = 100)
        {
            var query = Query().Where(l => l.UserId == userId);

            if (activityType.HasValue)
                query = query.Where(l => l.ActivityType == activityType.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByConnectedIdAsync(
            Guid connectedId,
            ActivityCategory? category = null,
            DateTime? startDate = null,
            DateTime? endDate = null)
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
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByApplicationAsync(
            Guid applicationId,
            bool? isSuccess = null,
            int limit = 100)
        {
            var query = Query().Where(l => l.ApplicationId == applicationId);

            if (isSuccess.HasValue)
                query = query.Where(l => l.IsSuccess == isSuccess.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetBySessionIdAsync(Guid sessionId, DateTime? since = null)
        {
            var query = Query().Where(l => l.SessionId == sessionId);

            if (since.HasValue)
                query = query.Where(l => l.OccurredAt >= since.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<SessionActivityLog> LogActivityAsync(SessionActivityLog log)
        {
            return await AddAsync(log);
        }

        public async Task<SessionActivityLog> LogLoginActivityAsync(
            Guid sessionId,
            Guid userId,
            Guid connectedId,
            string ipAddress,
            string userAgent,
            bool isSuccess,
            string? failureReason = null)
        {
            var log = new SessionActivityLog
            {
                SessionId = sessionId,
                UserId = userId,
                ConnectedId = connectedId,
                ActivityType = SessionActivityType.Login,
                Category = ActivityCategory.Authentication,
                Description = isSuccess ? "User logged in successfully" : "Login attempt failed",
                IPAddress = ipAddress,
                UserAgent = userAgent,
                IsSuccess = isSuccess,
                FailureReason = failureReason,
                OccurredAt = DateTime.UtcNow,
                Timestamp = DateTime.UtcNow,
                Details = JsonSerializer.Serialize(new
                {
                    loginMethod = "standard",
                    timestamp = DateTime.UtcNow.ToString("O")
                })
            };

            return await AddAsync(log);
        }

        public async Task<SessionActivityLog> LogApiActivityAsync(
            Guid sessionId,
            string endpoint,
            string method,
            int statusCode,
            int responseTimeMs)
        {
            var log = new SessionActivityLog
            {
                SessionId = sessionId,
                ActivityType = SessionActivityType.ApiCall,
                Category = ActivityCategory.Api,
                Description = $"{method} {endpoint} - {statusCode}",
                ApiEndpoint = endpoint,
                HttpMethod = method,
                HttpStatusCode = statusCode,
                ResponseTimeMs = responseTimeMs,
                IsSuccess = statusCode >= 200 && statusCode < 300,
                OccurredAt = DateTime.UtcNow,
                Timestamp = DateTime.UtcNow,
                DurationMs = responseTimeMs,
                Details = JsonSerializer.Serialize(new
                {
                    endpoint,
                    method,
                    statusCode,
                    responseTimeMs
                })
            };

            return await AddAsync(log);
        }

        public async Task<SessionActivityLog> LogPageViewAsync(
            Guid sessionId,
            string pageUrl,
            string? pageTitle,
            string? referrerUrl,
            int? durationMs)
        {
            var log = new SessionActivityLog
            {
                SessionId = sessionId,
                ActivityType = SessionActivityType.PageView,
                Category = ActivityCategory.Navigation,
                Description = $"Page view: {pageTitle ?? pageUrl}",
                PageUrl = pageUrl,
                PageTitle = pageTitle,
                ReferrerUrl = referrerUrl,
                DurationMs = durationMs,
                IsSuccess = true,
                OccurredAt = DateTime.UtcNow,
                Timestamp = DateTime.UtcNow,
                Details = JsonSerializer.Serialize(new
                {
                    pageUrl,
                    pageTitle = pageTitle ?? "",
                    referrerUrl = referrerUrl ?? "",
                    durationMs = durationMs ?? 0
                })
            };

            return await AddAsync(log);
        }

        public async Task<IEnumerable<SessionActivityLog>> GetSuspiciousActivitiesAsync(
            Guid? organizationId = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int minRiskScore = 70)
        {
            // Repository는 현재 조직의 데이터에만 접근하도록 제한
            // 다른 조직의 데이터가 필요한 경우 서비스 레이어에서 처리해야 함
            if (organizationId.HasValue && organizationId.Value != _currentOrganizationId)
            {
                throw new UnauthorizedAccessException(
                    "Repository cannot access data from different organization. " +
                    "Cross-organization queries should be handled at service layer with proper authorization.");
            }

            var query = Query().Where(l => l.RiskScore >= minRiskScore);

            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            return await query
                .OrderByDescending(l => l.RiskScore)
                .ThenByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetSecurityAlertsAsync(
            Guid organizationId,
            int limit = 50)
        {
            return await _dbSet
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId &&
                           l.SecurityAlert &&
                           !l.IsDeleted)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetFailedActivitiesAsync(
            Guid? sessionId = null,
            SessionActivityType? activityType = null,
            int limit = 100)
        {
            var query = Query().Where(l => !l.IsSuccess);

            if (sessionId.HasValue)
                query = query.Where(l => l.SessionId == sessionId.Value);

            if (activityType.HasValue)
                query = query.Where(l => l.ActivityType == activityType.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var query = Query().Where(l => l.IPAddress == ipAddress);

            if (startDate.HasValue)
                query = query.Where(l => l.OccurredAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.OccurredAt <= endDate.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<bool> UpdateSecurityInfoAsync(
            Guid logId,
            int riskScore,
            bool isSuspicious,
            bool securityAlert)
        {
            var log = await GetByIdAsync(logId);
            if (log == null)
                return false;

            log.RiskScore = riskScore;
            log.IsSuspicious = isSuspicious;
            log.SecurityAlert = securityAlert;

            await UpdateAsync(log);
            return true;
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByResourceAsync(
            string resourceType,
            Guid resourceId,
            string? action = null)
        {
            var query = Query()
                .Where(l => l.ResourceType == resourceType && l.ResourceId == resourceId);

            if (!string.IsNullOrEmpty(action))
                query = query.Where(l => l.Action == action);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetResourceAccessHistoryAsync(
            string resourceType,
            Guid resourceId,
            int limit = 50)
        {
            return await Query()
                .Where(l => l.ResourceType == resourceType && l.ResourceId == resourceId)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        // BaseRepository의 통계 메서드를 활용한 특화 구현들
        public async Task<Dictionary<SessionActivityType, int>> GetActivityTypeStatisticsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            return await GetGroupCountAsync(
                l => l.ActivityType,
                l => l.OrganizationId == organizationId &&
                     l.OccurredAt >= startDate &&
                     l.OccurredAt <= endDate);
        }

        public async Task<Dictionary<int, int>> GetHourlyActivityDistributionAsync(
            Guid organizationId,
            DateTime date)
        {
            var startOfDay = date.Date;
            var endOfDay = startOfDay.AddDays(1);

            var activities = await _dbSet
                .Where(l => l.OrganizationId == organizationId &&
                           l.OccurredAt >= startOfDay &&
                           l.OccurredAt < endOfDay &&
                           !l.IsDeleted)
                .Select(l => l.OccurredAt.Hour)
                .ToListAsync();

            return activities
                .GroupBy(hour => hour)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        public async Task<Dictionary<DeviceType, int>> GetDeviceStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await GetGroupCountAsync(
                l => l.DeviceType!.Value,
                l => l.OrganizationId == organizationId &&
                     l.OccurredAt >= startDate &&
                     l.DeviceType.HasValue);
        }

        public async Task<Dictionary<BrowserType, int>> GetBrowserStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await GetGroupCountAsync(
                l => l.Browser!.Value,
                l => l.OrganizationId == organizationId &&
                     l.OccurredAt >= startDate &&
                     l.Browser.HasValue);
        }

        public async Task<double> GetAverageResponseTimeAsync(
            string? endpoint = null,
            int period = 7)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var query = Query()
                .Where(l => l.OccurredAt >= startDate && l.ResponseTimeMs.HasValue);

            if (!string.IsNullOrEmpty(endpoint))
                query = query.Where(l => l.ApiEndpoint == endpoint);

            var times = await query.Select(l => l.ResponseTimeMs!.Value).ToListAsync();

            return times.Any() ? times.Average() : 0.0;
        }

        public async Task<double> CalculateApiErrorRateAsync(
            Guid? applicationId = null,
            int period = 7)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var query = Query()
                .Where(l => l.OccurredAt >= startDate && l.ActivityType == SessionActivityType.ApiCall);

            if (applicationId.HasValue)
                query = query.Where(l => l.ApplicationId == applicationId.Value);

            var total = await query.CountAsync();
            if (total == 0) return 0.0;

            var errors = await query.CountAsync(l => !l.IsSuccess);

            return (double)errors / total * 100;
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByCountryAsync(
            string countryCode,
            Guid? organizationId = null,
            int limit = 100)
        {
            var orgId = organizationId ?? _currentOrganizationId;

            return await _dbSet
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == orgId &&
                           l.CountryCode == countryCode &&
                           !l.IsDeleted)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<Dictionary<string, int>> GetLocationStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await GetGroupCountAsync(
                l => l.CountryCode!,
                l => l.OrganizationId == organizationId &&
                     l.OccurredAt >= startDate &&
                     !string.IsNullOrEmpty(l.CountryCode));
        }

        public async Task<bool> DetectGeographicalAnomalyAsync(
            Guid userId,
            string currentLocation,
            int timeWindowMinutes = 60)
        {
            var timeWindow = DateTime.UtcNow.AddMinutes(-timeWindowMinutes);

            var recentLocations = await Query()
                .Where(l => l.UserId == userId &&
                           l.OccurredAt >= timeWindow &&
                           !string.IsNullOrEmpty(l.Location))
                .Select(l => l.Location)
                .Distinct()
                .ToListAsync();

            // 간단한 이상 징후 감지: 짧은 시간 내 다른 위치에서 활동
            if (recentLocations.Any() && !recentLocations.Contains(currentLocation))
            {
                // 실제 구현에서는 거리 계산 등 더 정교한 로직 필요
                return true;
            }

            return false;
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByTraceIdAsync(string traceId)
        {
            return await Query()
                .Where(l => l.TraceId == traceId)
                .OrderBy(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<SessionActivityLog?> GetBySpanIdAsync(string spanId)
        {
            return await Query()
                .Where(l => l.SpanId == spanId)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetTraceHierarchyAsync(string traceId)
        {
            var logs = await GetByTraceIdAsync(traceId);
            
            // 간단한 계층 구조 정렬 (ParentSpanId 기반)
            return logs.OrderBy(l => string.IsNullOrEmpty(l.ParentSpanId) ? 0 : 1)
                      .ThenBy(l => l.OccurredAt);
        }

        public async Task<int> BulkLogAsync(IEnumerable<SessionActivityLog> logs)
        {
            var logList = logs.ToList();
            await AddRangeAsync(logList);
            return logList.Count;
        }

        public async Task<int> ArchiveOldLogsAsync(int olderThanDays, int batchSize = 1000)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            var totalArchived = 0;

            while (true)
            {
                var logsToArchive = await Query()
                    .Where(l => l.OccurredAt < cutoffDate)
                    .Take(batchSize)
                    .ToListAsync();

                if (!logsToArchive.Any())
                    break;

                // 실제 구현에서는 아카이브 테이블로 이동
                // 여기서는 소프트 삭제로 처리
                await DeleteRangeAsync(logsToArchive);
                totalArchived += logsToArchive.Count;
            }

            _logger.LogInformation("Archived {Count} old session activity logs", totalArchived);
            return totalArchived;
        }

        public async Task<int> DeleteBySessionAsync(Guid sessionId)
        {
            var logs = await Query()
                .Where(l => l.SessionId == sessionId)
                .ToListAsync();

            if (logs.Any())
            {
                await DeleteRangeAsync(logs);
            }

            return logs.Count;
        }

        public async Task<PagedResult<SessionActivityLog>> SearchAsync(
            Expression<Func<SessionActivityLog, bool>> criteria,
            Expression<Func<SessionActivityLog, object>>? sortBy = null,
            bool sortDescending = true,
            int pageNumber = 1,
            int pageSize = 50)
        {
            var query = Query().Where(criteria);

            var totalCount = await query.CountAsync();

            if (sortBy != null)
            {
                query = sortDescending
                    ? query.OrderByDescending(sortBy)
                    : query.OrderBy(sortBy);
            }
            else
            {
                query = query.OrderByDescending(l => l.OccurredAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new PagedResult<SessionActivityLog>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize
            };
        }

        public async Task<IEnumerable<SessionActivityLog>> SearchByMultipleCriteriaAsync(
            Guid organizationId,
            IEnumerable<SessionActivityType>? activityTypes,
            IEnumerable<ActivityCategory>? categories,
            DateTime? startDate,
            DateTime? endDate,
            int? minRiskScore)
        {
            var query = _dbSet
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted);

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
                .ToListAsync();
        }

        #endregion
    }
}