using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 저장소 구현 - AuthHive v15
    /// 전역 세션과 조직별 세션을 모두 관리합니다.
    /// </summary>
    public class SessionRepository : BaseRepository<SessionEntity>, ISessionRepository
    {
        private readonly ILogger<SessionRepository> _logger;

        public SessionRepository(
            AuthDbContext context,
            ILogger<SessionRepository> logger) : base(context)
        {
            _logger = logger;
        }

        #region 전역 세션 관리

        public async Task<SessionEntity?> GetGlobalSessionAsync(Guid userId)
        {
            return await Query()
                .Where(s => s.UserId == userId && 
                           s.Level == SessionLevel.Global &&
                           s.Status == SessionStatus.Active)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveGlobalSessionsAsync()
        {
            return await Query()
                .Where(s => s.Level == SessionLevel.Global &&
                           s.Status == SessionStatus.Active)
                .ToListAsync();
        }

        #endregion

        #region 조직별 세션 관리

        public async Task<IEnumerable<SessionEntity>> GetByOrganizationAsync(
            Guid organizationId,
            bool activeOnly = true)
        {
            var query = Query()
                .Where(s => s.OrganizationId == organizationId);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        public async Task<SessionEntity?> GetByConnectedIdAsync(Guid connectedId)
        {
            return await Query()
                .Where(s => s.ConnectedId == connectedId &&
                           s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetChildSessionsAsync(
            Guid parentSessionId,
            bool activeOnly = true)
        {
            var query = Query()
                .Where(s => s.ParentSessionId == parentSessionId);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        #endregion

        #region 공통 메서드

        public async Task<SessionEntity?> GetByTokenAsync(string sessionToken)
        {
            if (string.IsNullOrWhiteSpace(sessionToken))
                return null;

            return await Query()
                .Where(s => s.SessionToken == sessionToken &&
                           s.Status == SessionStatus.Active &&
                           s.ExpiresAt > DateTime.UtcNow)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsByUserAsync(Guid userId)
        {
            return await Query()
                .Where(s => s.UserId == userId &&
                           s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsAsync(Guid connectedId)
        {
            return await Query()
                .Where(s => s.ConnectedId == connectedId &&
                           s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();
        }

        public async Task<int> BulkEndSessionsAsync(
            IEnumerable<Guid> sessionIds,
            SessionEndReason reason)
        {
            var sessionIdsList = sessionIds.ToList();
            if (!sessionIdsList.Any())
                return 0;

            var sessions = await Query()
                .Where(s => sessionIdsList.Contains(s.Id))
                .ToListAsync();

            foreach (var session in sessions)
            {
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = DateTime.UtcNow;
                session.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            return sessions.Count;
        }

        public async Task<IEnumerable<SessionEntity>> GetByApplicationAsync(
            Guid applicationId,
            bool activeOnly = true)
        {
            var query = Query()
                .Where(s => s.ApplicationId == applicationId);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetExpiredSessionsAsync(
            DateTime? since = null)
        {
            var query = Query()
                .Where(s => s.ExpiresAt < DateTime.UtcNow &&
                           s.Status != SessionStatus.Terminated);

            if (since.HasValue)
            {
                query = query.Where(s => s.ExpiresAt >= since.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetInactiveSessionsAsync(
            DateTime inactiveSince)
        {
            return await Query()
                .Where(s => s.LastActivityAt < inactiveSince &&
                           s.Status == SessionStatus.Active)
                .ToListAsync();
        }

        public async Task UpdateSessionStatusAsync(
            Guid sessionId,
            SessionStatus status)
        {
            var session = await GetByIdAsync(sessionId);
            if (session != null)
            {
                session.Status = status;
                session.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(session);
            }
        }

        public async Task UpdateLastActivityAsync(
            Guid sessionId,
            DateTime? activityTime = null)
        {
            var session = await GetByIdAsync(sessionId);
            if (session != null)
            {
                session.LastActivityAt = activityTime ?? DateTime.UtcNow;
                await UpdateAsync(session);
            }
        }

        public async Task EndSessionAsync(
            Guid sessionId,
            SessionEndReason reason,
            DateTime? endedAt = null)
        {
            var session = await GetByIdAsync(sessionId);
            if (session != null)
            {
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = endedAt ?? DateTime.UtcNow;
                session.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(session);
            }
        }

        public async Task<int> GetConcurrentSessionCountAsync(
            Guid userId,
            SessionLevel? level = null)
        {
            var query = Query()
                .Where(s => s.UserId == userId &&
                           s.Status == SessionStatus.Active);

            if (level.HasValue)
            {
                query = query.Where(s => s.Level == level.Value);
            }

            return await query.CountAsync();
        }

        public async Task AddActivityLogAsync(SessionActivityLog log)
        {
            await _context.Set<SessionActivityLog>().AddAsync(log);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<SessionActivityLog>> GetActivityLogsAsync(
            Guid sessionId,
            DateTime? since = null)
        {
            var query = _context.Set<SessionActivityLog>()
                .Where(l => l.SessionId == sessionId);

            if (since.HasValue)
            {
                query = query.Where(l => l.OccurredAt >= since.Value);
            }

            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync();
        }

        public async Task SetActiveChildSessionAsync(
            Guid parentSessionId,
            Guid childSessionId)
        {
            var parentSession = await GetByIdAsync(parentSessionId);
            if (parentSession != null)
            {
                parentSession.ActiveChildSessionId = childSessionId;
                parentSession.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(parentSession);
            }
        }

        public async Task<IEnumerable<SessionEntity>> GetByLevelAsync(
            SessionLevel level,
            bool activeOnly = true)
        {
            var query = Query()
                .Where(s => s.Level == level);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetByTypeAsync(
            SessionType type,
            bool activeOnly = true)
        {
            var query = Query()
                .Where(s => s.SessionType == type);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        #endregion

        #region IQueryable 메서드

        public IQueryable<SessionEntity> GetQueryable(bool includeDeleted = false)
        {
            var query = _context.Set<SessionEntity>().AsQueryable();

            if (!includeDeleted)
            {
                query = query.Where(s => !s.IsDeleted);
            }

            return query;
        }

        public IQueryable<SessionEntity> GetOrganizationQueryable(
            Guid organizationId,
            bool includeDeleted = false)
        {
            var query = GetQueryable(includeDeleted);
            return query.Where(s => s.OrganizationId == organizationId);
        }

        #endregion

        #region 관계 로딩

        public async Task<SessionEntity?> GetWithRelatedDataAsync(
            Guid sessionId,
            bool includeUser = false,
            bool includeOrganization = false,
            bool includeConnectedId = false,
            bool includeParentSession = false,
            bool includeChildSessions = false)
        {
            var query = Query().Where(s => s.Id == sessionId);

            if (includeUser)
            {
                query = query.Include(s => s.User);
            }

            if (includeOrganization)
            {
                query = query.Include(s => s.Organization);
            }

            if (includeConnectedId)
            {
                query = query.Include(s => s.ConnectedIdNavigation);
            }

            if (includeParentSession)
            {
                query = query.Include(s => s.ParentSession);
            }

            if (includeChildSessions)
            {
                query = query.Include(s => s.ChildSessions);
            }

            return await query.FirstOrDefaultAsync();
        }

        #endregion
    }
}