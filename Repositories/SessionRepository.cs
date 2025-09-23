using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 저장소 구현 - AuthHive v15
    /// 전역 세션과 조직별 세션을 모두 관리합니다.
    /// BaseRepository의 기능을 최대한 활용하도록 리팩토링됨
    /// </summary>
    public class SessionRepository : BaseRepository<SessionEntity>, ISessionRepository
    {
        private readonly ILogger<SessionRepository> _logger;

        public SessionRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<SessionRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 전역 세션 관리

        public async Task<SessionEntity?> GetGlobalSessionAsync(Guid userId)
        {
            // 전역 세션은 조직 필터링을 우회해야 하므로 _dbSet 직접 사용
            return await _dbSet
                .Where(s => !s.IsDeleted &&
                           s.UserId == userId &&
                           s.Level == SessionLevel.Global &&
                           s.Status == SessionStatus.Active)
                .FirstOrDefaultAsync();
        }
        public async Task<IEnumerable<SessionEntity>> GetByUserIdAsync(Guid userId)
        {
            return await _context.Sessions
                .Include(s => s.Organization)
                .Where(s => s.UserId == userId)
                .ToListAsync();
        }
        public async Task<IEnumerable<SessionEntity>> GetActiveGlobalSessionsAsync()
        {
            // 전역 세션 조회 - 조직 필터링 우회
            return await _dbSet
                .Where(s => !s.IsDeleted &&
                           s.Level == SessionLevel.Global &&
                           s.Status == SessionStatus.Active)
                .ToListAsync();
        }

        #endregion

        #region 조직별 세션 관리

        public async Task<IEnumerable<SessionEntity>> GetByOrganizationAsync(
            Guid organizationId,
            bool activeOnly = true)
        {
            // BaseRepository의 QueryForOrganization 활용
            var query = QueryForOrganization(organizationId);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync();
        }

        public async Task<SessionEntity?> GetByConnectedIdAsync(Guid connectedId)
        {
            // 현재 조직 컨텍스트 내에서 검색
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

            // 토큰 조회는 전역적으로 수행 (조직 관계없이)
            return await _dbSet
                .Where(s => !s.IsDeleted &&
                           s.SessionToken == sessionToken &&
                           s.Status == SessionStatus.Active &&
                           s.ExpiresAt > DateTime.UtcNow)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsByUserAsync(Guid userId)
        {
            // 사용자의 모든 활성 세션 (전역 + 모든 조직)
            return await _dbSet
                .Where(s => !s.IsDeleted &&
                           s.UserId == userId &&
                           s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsAsync(Guid connectedId)
        {
            // 현재 조직 컨텍스트 내에서 활성 세션 조회
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

            var sessions = await _dbSet
                .Where(s => sessionIdsList.Contains(s.Id))
                .ToListAsync();

            var timestamp = DateTime.UtcNow;
            foreach (var session in sessions)
            {
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = timestamp;
                session.UpdatedAt = timestamp;
            }

            await _context.SaveChangesAsync();

            // 캐시 무효화
            foreach (var session in sessions)
            {
                InvalidateCache(session.Id);
            }

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
            // 만료된 세션은 전역적으로 조회
            var query = _dbSet
                .Where(s => !s.IsDeleted &&
                           s.ExpiresAt < DateTime.UtcNow &&
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
            // 비활성 세션은 전역적으로 조회
            return await _dbSet
                .Where(s => !s.IsDeleted &&
                           s.LastActivityAt < inactiveSince &&
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
                await _context.SaveChangesAsync();
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
                session.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(session);
                await _context.SaveChangesAsync();
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
                var timestamp = DateTime.UtcNow;
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = endedAt ?? timestamp;
                session.UpdatedAt = timestamp;
                await UpdateAsync(session);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<int> GetConcurrentSessionCountAsync(
            Guid userId,
            SessionLevel? level = null)
        {
            // 사용자의 동시 세션 수는 전역적으로 카운트
            var query = _dbSet
                .Where(s => !s.IsDeleted &&
                           s.UserId == userId &&
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
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<SessionEntity>> GetByLevelAsync(
            SessionLevel level,
            bool activeOnly = true)
        {
            // 레벨별 조회는 전역적으로 수행
            var query = _dbSet
                .Where(s => !s.IsDeleted && s.Level == level);

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

        #region IQueryable 메서드 (BaseRepository 활용)

        // GetQueryable은 Query() 메서드로 대체
        public IQueryable<SessionEntity> GetQueryable(bool includeDeleted = false)
        {
            if (includeDeleted)
            {
                return _dbSet.AsQueryable();
            }

            // 조직 컨텍스트가 없을 때는 전역 쿼리
            return _organizationContext.CurrentOrganizationId == null
                ? _dbSet.Where(e => !e.IsDeleted)
                : Query();
        }

        public IQueryable<SessionEntity> GetOrganizationQueryable(
            Guid organizationId,
            bool includeDeleted = false)
        {
            // BaseRepository의 QueryForOrganization 활용
            if (includeDeleted)
            {
                return _dbSet.Where(s => s.OrganizationId == organizationId);
            }

            return QueryForOrganization(organizationId);
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
            // 전역 조회 (특정 ID로 조회하므로)
            var query = _dbSet.Where(s => !s.IsDeleted && s.Id == sessionId);

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

        #region Override 메서드

        /// <summary>
        /// SessionEntity는 조직 스코프이지만 전역 세션도 있어서 특별 처리 필요
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            // SessionEntity는 조직별/전역 모두 가능하므로 
            // 컨텍스트에 따라 다르게 처리
            return _organizationContext.CurrentOrganizationId.HasValue;
        }

        #endregion
    }
}