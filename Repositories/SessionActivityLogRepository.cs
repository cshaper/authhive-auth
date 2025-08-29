using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 활동 로그 리포지토리 구현 - AuthHive v15
    /// </summary>
    public class SessionActivityLogRepository : ISessionActivityLogRepository
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<SessionActivityLogRepository> _logger;
        private readonly Guid _currentOrganizationId;
        private readonly Guid? _currentConnectedId;

        public SessionActivityLogRepository(
            AuthDbContext context,
            ILogger<SessionActivityLogRepository> logger,
            IOrganizationContext organizationContext,
            IConnectedIdContext connectedIdContext)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _currentOrganizationId = organizationContext?.OrganizationId ?? throw new ArgumentNullException(nameof(organizationContext));
            _currentConnectedId = connectedIdContext?.ConnectedId;
        }

        #region IRepository<SessionActivityLog> Implementation

        public async Task<SessionActivityLog?> GetByIdAsync(Guid id)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Include(l => l.PlatformApplication)
                .Where(l => l.OrganizationId == _currentOrganizationId)
                .FirstOrDefaultAsync(l => l.Id == id && !l.IsDeleted);
        }

        public async Task<IEnumerable<SessionActivityLog>> GetAllAsync()
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> FindAsync(Expression<Func<SessionActivityLog, bool>> predicate)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<SessionActivityLog?> FirstOrDefaultAsync(Expression<Func<SessionActivityLog, bool>> predicate)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .Where(predicate)
                .FirstOrDefaultAsync();
        }

        public async Task<bool> AnyAsync(Expression<Func<SessionActivityLog, bool>> predicate)
        {
            return await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .AnyAsync(predicate);
        }

        public async Task<int> CountAsync(Expression<Func<SessionActivityLog, bool>>? predicate = null)
        {
            var query = _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync();
        }

        public async Task<(IEnumerable<SessionActivityLog> Items, int TotalCount)> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<SessionActivityLog, bool>>? predicate = null,
            Expression<Func<SessionActivityLog, object>>? orderBy = null,
            bool isDescending = false)
        {
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending
                    ? query.OrderByDescending(orderBy)
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(l => l.OccurredAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<SessionActivityLog> AddAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            entity.OrganizationId = _currentOrganizationId;
            entity.CreatedAt = DateTime.UtcNow;
            entity.CreatedByConnectedId = _currentConnectedId;
            entity.Timestamp = entity.Timestamp == default ? DateTime.UtcNow : entity.Timestamp;
            entity.OccurredAt = entity.OccurredAt == default ? DateTime.UtcNow : entity.OccurredAt;

            _context.SessionActivityLogs.Add(entity);
            await _context.SaveChangesAsync();

            _logger.LogDebug("Session activity logged: {ActivityType} for session {SessionId}",
                entity.ActivityType, entity.SessionId);

            return entity;
        }

        public async Task AddRangeAsync(IEnumerable<SessionActivityLog> entities)
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

            _context.SessionActivityLogs.AddRange(logs);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            if (entity.OrganizationId != _currentOrganizationId)
            {
                throw new UnauthorizedAccessException("Cannot update log from different organization");
            }

            entity.UpdatedAt = DateTime.UtcNow;
            entity.UpdatedByConnectedId = _currentConnectedId;

            _context.Entry(entity).State = EntityState.Modified;
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRangeAsync(IEnumerable<SessionActivityLog> entities)
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
                _context.Entry(log).State = EntityState.Modified;
            }

            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var log = await GetByIdAsync(id);
            if (log == null)
                return;

            await DeleteAsync(log);
        }

        public async Task DeleteAsync(SessionActivityLog entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            entity.DeletedByConnectedId = _currentConnectedId;

            await UpdateAsync(entity);
        }

        public async Task DeleteRangeAsync(IEnumerable<SessionActivityLog> entities)
        {
            var logs = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var log in logs)
            {
                if (log.OrganizationId == _currentOrganizationId)
                {
                    log.IsDeleted = true;
                    log.DeletedAt = now;
                    log.DeletedByConnectedId = _currentConnectedId;
                    _context.Entry(log).State = EntityState.Modified;
                }
            }

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteAsync(Guid id)
        {
            await DeleteAsync(id);
        }

        public async Task<bool> ExistsAsync(Guid id)
        {
            return await _context.SessionActivityLogs
                .AnyAsync(l => l.OrganizationId == _currentOrganizationId && l.Id == id && !l.IsDeleted);
        }

        public async Task<bool> ExistsAsync(Expression<Func<SessionActivityLog, bool>> predicate)
        {
            return await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .AnyAsync(predicate);
        }

        #endregion

        #region IOrganizationScopedRepository Implementation

        public async Task<IEnumerable<SessionActivityLog>> GetByOrganizationIdAsync(Guid organizationId)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted)
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<SessionActivityLog?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId)
                .FirstOrDefaultAsync(l => l.Id == id && !l.IsDeleted);
        }

        public async Task<IEnumerable<SessionActivityLog>> FindByOrganizationAsync(
            Guid organizationId,
            Expression<Func<SessionActivityLog, bool>> predicate)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<(IEnumerable<SessionActivityLog> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber,
            int pageSize,
            Expression<Func<SessionActivityLog, bool>>? additionalPredicate = null,
            Expression<Func<SessionActivityLog, object>>? orderBy = null,
            bool isDescending = false)
        {
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted);

            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending
                    ? query.OrderByDescending(orderBy)
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(l => l.OccurredAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _context.SessionActivityLogs
                .AnyAsync(l => l.OrganizationId == organizationId && l.Id == id && !l.IsDeleted);
        }

        public async Task<int> CountByOrganizationAsync(
            Guid organizationId,
            Expression<Func<SessionActivityLog, bool>>? predicate = null)
        {
            var query = _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync();
        }

        public async Task DeleteAllByOrganizationAsync(Guid organizationId)
        {
            var logs = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId && !l.IsDeleted)
                .ToListAsync();

            foreach (var log in logs)
            {
                log.IsDeleted = true;
                log.DeletedAt = DateTime.UtcNow;
                log.DeletedByConnectedId = _currentConnectedId;
            }

            if (logs.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Deleted {Count} session activity logs for organization {OrganizationId}",
                    logs.Count, organizationId);
            }
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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.SessionId == sessionId &&
                           !l.IsDeleted);

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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.UserId == userId &&
                           !l.IsDeleted);

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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.ConnectedId == connectedId &&
                           !l.IsDeleted);

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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Include(l => l.PlatformApplication)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.ApplicationId == applicationId &&
                           !l.IsDeleted);

            if (isSuccess.HasValue)
                query = query.Where(l => l.IsSuccess == isSuccess.Value);

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetBySessionIdAsync(Guid sessionId, DateTime? since = null)
        {
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.SessionId == sessionId &&
                           !l.IsDeleted);

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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => !l.IsDeleted && l.RiskScore >= minRiskScore);

            if (organizationId.HasValue)
                query = query.Where(l => l.OrganizationId == organizationId.Value);
            else
                query = query.Where(l => l.OrganizationId == _currentOrganizationId);

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
            return await _context.SessionActivityLogs
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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           !l.IsSuccess &&
                           !l.IsDeleted);

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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.IPAddress == ipAddress &&
                           !l.IsDeleted);

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
            log.UpdatedAt = DateTime.UtcNow;
            log.UpdatedByConnectedId = _currentConnectedId;

            await UpdateAsync(log);
            return true;
        }

        public async Task<IEnumerable<SessionActivityLog>> GetByResourceAsync(
            string resourceType,
            Guid resourceId,
            string? action = null)
        {
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.ResourceType == resourceType &&
                           l.ResourceId == resourceId &&
                           !l.IsDeleted);

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
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.ResourceType == resourceType &&
                           l.ResourceId == resourceId &&
                           !l.IsDeleted)
                .OrderByDescending(l => l.OccurredAt)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<Dictionary<SessionActivityType, int>> GetActivityTypeStatisticsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            var result = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId &&
                           l.OccurredAt >= startDate &&
                           l.OccurredAt <= endDate &&
                           !l.IsDeleted)
                .GroupBy(l => l.ActivityType)
                .Select(g => new { ActivityType = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.ActivityType, x => x.Count);

            return result;
        }

        public async Task<Dictionary<int, int>> GetHourlyActivityDistributionAsync(
            Guid organizationId,
            DateTime date)
        {
            var startOfDay = date.Date;
            var endOfDay = startOfDay.AddDays(1);

            var activities = await _context.SessionActivityLogs
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

            var result = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId &&
                           l.OccurredAt >= startDate &&
                           l.DeviceType.HasValue &&
                           !l.IsDeleted)
                .GroupBy(l => l.DeviceType!.Value)
                .Select(g => new { DeviceType = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.DeviceType, x => x.Count);

            return result;
        }

        public async Task<Dictionary<BrowserType, int>> GetBrowserStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var result = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId &&
                           l.OccurredAt >= startDate &&
                           l.Browser.HasValue &&
                           !l.IsDeleted)
                .GroupBy(l => l.Browser!.Value)
                .Select(g => new { BrowserType = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.BrowserType, x => x.Count);

            return result;
        }

        public async Task<double> GetAverageResponseTimeAsync(
            string? endpoint = null,
            int period = 7)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var query = _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.OccurredAt >= startDate &&
                           l.ResponseTimeMs.HasValue &&
                           !l.IsDeleted);

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

            var query = _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.OccurredAt >= startDate &&
                           l.ActivityType == SessionActivityType.ApiCall &&
                           !l.IsDeleted);

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

            return await _context.SessionActivityLogs
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

            var result = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == organizationId &&
                           l.OccurredAt >= startDate &&
                           !string.IsNullOrEmpty(l.CountryCode) &&
                           !l.IsDeleted)
                .GroupBy(l => l.CountryCode!)
                .Select(g => new { CountryCode = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.CountryCode, x => x.Count);

            return result;
        }

        public async Task<bool> DetectGeographicalAnomalyAsync(
            Guid userId,
            string currentLocation,
            int timeWindowMinutes = 60)
        {
            var timeWindow = DateTime.UtcNow.AddMinutes(-timeWindowMinutes);

            var recentLocations = await _context.SessionActivityLogs
                .Where(l => l.UserId == userId &&
                           l.OccurredAt >= timeWindow &&
                           !string.IsNullOrEmpty(l.Location) &&
                           !l.IsDeleted)
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
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.TraceId == traceId &&
                           !l.IsDeleted)
                .OrderBy(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task<SessionActivityLog?> GetBySpanIdAsync(string spanId)
        {
            return await _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.SpanId == spanId &&
                           !l.IsDeleted)
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
                var logsToArchive = await _context.SessionActivityLogs
                    .Where(l => l.OrganizationId == _currentOrganizationId &&
                               l.OccurredAt < cutoffDate &&
                               !l.IsDeleted)
                    .Take(batchSize)
                    .ToListAsync();

                if (!logsToArchive.Any())
                    break;

                // 실제 구현에서는 아카이브 테이블로 이동
                // 여기서는 소프트 삭제로 처리
                foreach (var log in logsToArchive)
                {
                    log.IsDeleted = true;
                    log.DeletedAt = DateTime.UtcNow;
                    log.DeletedByConnectedId = _currentConnectedId;
                }

                await _context.SaveChangesAsync();
                totalArchived += logsToArchive.Count;
            }

            _logger.LogInformation("Archived {Count} old session activity logs", totalArchived);
            return totalArchived;
        }

        public async Task<int> DeleteBySessionAsync(Guid sessionId)
        {
            var logs = await _context.SessionActivityLogs
                .Where(l => l.OrganizationId == _currentOrganizationId &&
                           l.SessionId == sessionId &&
                           !l.IsDeleted)
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
            var query = _context.SessionActivityLogs
                .Include(l => l.Session)
                .Include(l => l.User)
                .Include(l => l.Connected)
                .Where(l => l.OrganizationId == _currentOrganizationId && !l.IsDeleted)
                .Where(criteria);

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
            var query = _context.SessionActivityLogs
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