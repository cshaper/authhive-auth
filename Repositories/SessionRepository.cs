using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading; // CancellationToken 네임스페이스
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 네임스페이스
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Infra; // PagedResult

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 세션 저장소 구현 - AuthHive v16 Refactored
    /// 전역 세션과 조직별 세션을 관리하며 BaseRepository의 기능을 활용합니다.
    /// </summary>
    public class SessionRepository : BaseRepository<SessionEntity>, ISessionRepository
    {
        private readonly ILogger<SessionRepository> _logger;
        private readonly Guid? _currentConnectedId; // 감사 추적용
        private readonly IDateTimeProvider _dateTimeProvider;

        public SessionRepository(
            AuthDbContext context,
            ICacheService cacheService,
            ILogger<SessionRepository> logger,
            IPrincipalAccessor connectedIdContext,
            IDateTimeProvider dateTimeProvider) // ✅ ConnectedId 주입 유지 (감사용)
            : base(context, cacheService) // ✅ base 생성자 호출 변경
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _currentConnectedId = connectedIdContext?.ConnectedId;
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
        }

        /// <summary>
        /// SessionEntity는 조직 범위일 수도 있고 아닐 수도 있습니다.
        /// 기본적으로 조직 범위로 처리하고, 전역 세션은 별도 메서드에서 _dbSet을 직접 사용합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region BaseRepository 오버라이드 (감사 필드 및 캐시)

        // Query() 재정의 제거 - BaseRepository가 조직 필터링 처리 (IsOrganizationBaseEntity = true)

        public override Task<SessionEntity> AddAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            var now = _dateTimeProvider.UtcNow; // ✨ 수정
            entity.CreatedAt = now;
            entity.CreatedByConnectedId = _currentConnectedId;

            if (entity.LastActivityAt == default)
            {
                entity.LastActivityAt = now; // ✨ 수정
            }

            return base.AddAsync(entity, cancellationToken);
        }

        public override Task AddRangeAsync(IEnumerable<SessionEntity> entities, CancellationToken cancellationToken = default)
        {
            var sessions = entities.ToList();
            var now = _dateTimeProvider.UtcNow;

            foreach (var session in sessions)
            {
                session.CreatedAt = now;
                session.CreatedByConnectedId = _currentConnectedId;

                // 💡 수정: ??= 대신 일반 할당 사용
                if (session.LastActivityAt == default) // 초기값인지 확인 (선택적)
                {
                    session.LastActivityAt = now;
                }
                // 또는 무조건 현재 시간으로 덮어쓰기:
                // session.LastActivityAt = now;
            }
            return base.AddRangeAsync(sessions, cancellationToken);
        }
        public override Task UpdateAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            entity.UpdatedAt = _dateTimeProvider.UtcNow;
            entity.UpdatedByConnectedId = _currentConnectedId;

            // BaseRepository.UpdateAsync는 내부적으로 InvalidateCacheAsync(id, token) 호출
            // 조직 범위 엔티티이므로 조직별 캐시 무효화가 필요할 수 있으나,
            // 전역/조직 구분이 복잡하므로 ID 기반 캐시만 무효화 (필요시 GetCacheKey(id, orgId) 오버라이드)
            return base.UpdateAsync(entity, cancellationToken);
        }

        public override Task UpdateRangeAsync(IEnumerable<SessionEntity> entities, CancellationToken cancellationToken = default)
        {
            var sessions = entities.ToList();
            var now = _dateTimeProvider.UtcNow;
            foreach (var session in sessions)
            {
                session.UpdatedAt = now;
                session.UpdatedByConnectedId = _currentConnectedId;
            }
            return base.UpdateRangeAsync(sessions, cancellationToken);
        }

        public override Task DeleteAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));
            entity.DeletedByConnectedId = _currentConnectedId;
            return base.DeleteAsync(entity, cancellationToken);
        }

        public override Task DeleteRangeAsync(IEnumerable<SessionEntity> entities, CancellationToken cancellationToken = default)
        {
            var sessions = entities.ToList();
            foreach (var session in sessions)
            {
                session.DeletedByConnectedId = _currentConnectedId;
            }
            return base.DeleteRangeAsync(sessions, cancellationToken);
        }

        #endregion

        #region 전역 세션 관리 (조직 필터링 우회 - _dbSet 직접 사용)

        public async Task<SessionEntity?> GetGlobalSessionAsync(Guid userId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 전역 세션 + 활성 상태
            return await _dbSet.AsNoTracking() // 읽기 전용
                .Where(s => !s.IsDeleted &&
                              s.UserId == userId &&
                              s.Level == SessionLevel.Global &&
                              s.Status == SessionStatus.Active)
                .FirstOrDefaultAsync(cancellationToken); // ✅ Token 전달
        }

        // GetByUserIdAsync는 사용자의 모든 세션(전역+조직)을 반환해야 할 수 있음.
        public async Task<IEnumerable<SessionEntity>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // IsDeleted = false 조건 추가
            return await _dbSet.AsNoTracking()
                .Include(s => s.Organization) // 조직 정보 포함 (null일 수 있음)
                .Where(s => !s.IsDeleted && s.UserId == userId)
                .OrderByDescending(s => s.LastActivityAt) // 최신 활동 순
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveGlobalSessionsAsync(CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 모든 활성 전역 세션
            return await _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted &&
                              s.Level == SessionLevel.Global &&
                              s.Status == SessionStatus.Active)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 조직별 세션 관리 (BaseRepository Query() 또는 QueryForOrganization() 사용)

        public async Task<IEnumerable<SessionEntity>> GetByOrganizationAsync(
            Guid organizationId, bool activeOnly = true, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 특정 조직 조회
            var query = QueryForOrganization(organizationId).AsNoTracking();

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<SessionEntity?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 현재 조직 컨텍스트 내 활성 세션 조회
            // BaseRepository의 Query()는 자동으로 현재 조직 필터링
            return await Query().AsNoTracking()
                .Where(s => s.ConnectedId == connectedId && s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .FirstOrDefaultAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetChildSessionsAsync(
            Guid parentSessionId, bool activeOnly = true, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 부모 세션 ID 기준 조회 (조직 필터링은 ParentSession 기준으로 이미 될 수 있음)
            // Query() 사용 시 현재 조직 필터링이 적용될 수 있으므로 _dbSet 사용 고려
            var query = _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted && s.ParentSessionId == parentSessionId);
            // 만약 자식 세션도 부모와 같은 조직이어야 한다면 Query() 사용 가능

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 세션 조회 메서드

        public async Task<SessionEntity?> GetByTokenAsync(string sessionToken, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            if (string.IsNullOrWhiteSpace(sessionToken)) return null;

            // 토큰 조회는 전역적으로 (조직 필터링 없이) + 활성 + 만료되지 않음
            var now = DateTime.UtcNow; // IDateTimeProvider
            return await _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted &&
                              s.SessionToken == sessionToken &&
                              s.Status == SessionStatus.Active &&
                              s.ExpiresAt > now)
                .FirstOrDefaultAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsByUserAsync(Guid userId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 사용자의 모든 활성 세션 (전역 + 모든 조직) - _dbSet 사용
            return await _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted &&
                              s.UserId == userId &&
                              s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetActiveSessionsAsync(Guid connectedId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 현재 조직 내 활성 세션 조회 - Query() 사용
            return await Query().AsNoTracking()
                .Where(s => s.ConnectedId == connectedId && s.Status == SessionStatus.Active)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetByApplicationAsync(
            Guid applicationId, bool activeOnly = true, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 현재 조직 내 특정 애플리케이션 세션 조회 - Query() 사용
            var query = Query().AsNoTracking()
                .Where(s => s.ApplicationId == applicationId);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetByLevelAsync(
            SessionLevel level, bool activeOnly = true, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 레벨별 조회는 전역적으로 (_dbSet 사용)
            var query = _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted && s.Level == level);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetByTypeAsync(
            SessionType type, bool activeOnly = true, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 현재 조직 내 타입별 조회 - Query() 사용
            var query = Query().AsNoTracking()
                .Where(s => s.SessionType == type);

            if (activeOnly)
            {
                query = query.Where(s => s.Status == SessionStatus.Active);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 세션 상태 관리

        public async Task UpdateSessionStatusAsync(
            Guid sessionId, SessionStatus status, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 상태 변경이므로 추적 필요 -> FindAsync 사용
            var session = await _dbSet.FindAsync(new object[] { sessionId }, cancellationToken); // ✅ Token 전달
            if (session != null && !session.IsDeleted) // 삭제된 세션은 변경 불가
            {
                session.Status = status;
                // UpdateAsync 호출 (감사 필드 설정 및 캐시 무효화)
                await UpdateAsync(session, cancellationToken); // ✅ Token 전달
                // SaveChangesAsync 제거
            }
            else
            {
                _logger.LogWarning("Attempted to update status for non-existent or deleted session {SessionId}", sessionId);
            }
        }

        public async Task UpdateLastActivityAsync(
            Guid sessionId, DateTime? activityTime = null, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var session = await _dbSet.FindAsync(new object[] { sessionId }, cancellationToken); // ✅ Token 전달
            if (session != null && !session.IsDeleted && session.Status == SessionStatus.Active) // 활성 세션만 업데이트
            {
                session.LastActivityAt = activityTime ?? DateTime.UtcNow; // IDateTimeProvider
                // UpdateAsync 호출
                await UpdateAsync(session, cancellationToken); // ✅ Token 전달
                // SaveChangesAsync 제거
            }
            else
            {
                _logger.LogWarning("Attempted to update last activity for non-existent, deleted, or inactive session {SessionId}", sessionId);
            }
        }

        public async Task EndSessionAsync(
            Guid sessionId, SessionEndReason reason, DateTime? endedAt = null, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var session = await _dbSet.FindAsync(new object[] { sessionId }, cancellationToken); // ✅ Token 전달
            if (session != null && !session.IsDeleted && session.Status != SessionStatus.Terminated) // 이미 종료된 세션 제외
            {
                var timestamp = DateTime.UtcNow; // IDateTimeProvider
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = endedAt ?? timestamp;
                // UpdateAsync 호출
                await UpdateAsync(session, cancellationToken); // ✅ Token 전달
                // SaveChangesAsync 제거
            }
            else
            {
                _logger.LogWarning("Attempted to end non-existent, deleted, or already terminated session {SessionId}", sessionId);
            }
        }

        public async Task<int> BulkEndSessionsAsync(
            IEnumerable<Guid> sessionIds, SessionEndReason reason, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var sessionIdsList = sessionIds.ToList();
            if (!sessionIdsList.Any()) return 0;

            // 추적 필요
            var sessions = await _dbSet
                .Where(s => sessionIdsList.Contains(s.Id) && !s.IsDeleted && s.Status != SessionStatus.Terminated)
                .ToListAsync(cancellationToken); // ✅ Token 전달

            var timestamp = DateTime.UtcNow; // IDateTimeProvider
            foreach (var session in sessions)
            {
                session.Status = SessionStatus.Terminated;
                session.EndReason = reason;
                session.EndedAt = timestamp;
                // UpdatedAt, UpdatedBy 등은 UpdateRangeAsync에서 처리됨
            }

            if (sessions.Any())
            {
                // UpdateRangeAsync 호출 (Token 전달)
                await UpdateRangeAsync(sessions, cancellationToken);
                // SaveChangesAsync 제거
            }

            return sessions.Count;
        }


        public async Task SetActiveChildSessionAsync(
            Guid parentSessionId, Guid childSessionId, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            var parentSession = await _dbSet.FindAsync(new object[] { parentSessionId }, cancellationToken); // ✅ Token 전달
            if (parentSession != null && !parentSession.IsDeleted && parentSession.Level == SessionLevel.Global) // 전역 세션만 해당
            {
                parentSession.ActiveChildSessionId = childSessionId;
                // UpdateAsync 호출
                await UpdateAsync(parentSession, cancellationToken); // ✅ Token 전달
                // SaveChangesAsync 제거
            }
            else
            {
                _logger.LogWarning("Attempted to set active child session for non-existent, deleted, or non-global parent session {ParentSessionId}", parentSessionId);
            }
        }

        #endregion

        #region 세션 정리 및 유지보수

        public async Task<IEnumerable<SessionEntity>> GetExpiredSessionsAsync(DateTime? since = null, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 전역적으로 조회 (_dbSet 사용)
            var now = DateTime.UtcNow; // IDateTimeProvider
            var query = _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted &&
                              s.ExpiresAt < now &&
                              s.Status != SessionStatus.Terminated); // 종료되지 않은 만료 세션

            if (since.HasValue)
            {
                query = query.Where(s => s.ExpiresAt >= since.Value);
            }

            return await query.ToListAsync(cancellationToken); // ✅ Token 전달
        }

        public async Task<IEnumerable<SessionEntity>> GetInactiveSessionsAsync(DateTime inactiveSince, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 전역적으로 조회 (_dbSet 사용)
            return await _dbSet.AsNoTracking()
                .Where(s => !s.IsDeleted &&
                              s.Status == SessionStatus.Active && // 활성 상태이지만
                              s.LastActivityAt < inactiveSince)   // 마지막 활동이 오래된 세션
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 통계 및 모니터링

        public async Task<int> GetConcurrentSessionCountAsync(
            Guid userId, SessionLevel? level = null, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 전역적으로 카운트 (_dbSet 사용)
            var query = _dbSet
                .Where(s => !s.IsDeleted &&
                              s.UserId == userId &&
                              s.Status == SessionStatus.Active);

            if (level.HasValue)
            {
                query = query.Where(s => s.Level == level.Value);
            }

            return await query.CountAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 활동 로그 관리 (SessionActivityLogRepository로 책임 이동 권장)

        // 세션 리포지토리가 직접 활동 로그를 관리하는 것은 책임 분리 원칙에 어긋날 수 있음.
        // SessionActivityLogRepository를 사용하는 것이 좋음. 아래는 임시 구현.

        public async Task AddActivityLogAsync(SessionActivityLog log, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // TODO: ISessionActivityLogRepository.LogActivityAsync 호출로 대체 권장
            if (log.OrganizationId == Guid.Empty)
            { // 조직 ID가 없으면 세션에서 가져오기 시도
                var session = await GetByIdAsync(log.SessionId, cancellationToken);
                if (session?.OrganizationId != null) log.OrganizationId = session.OrganizationId.Value;
            }
            await _context.Set<SessionActivityLog>().AddAsync(log, cancellationToken); // ✅ Token 전달
            // SaveChangesAsync 제거
            _logger.LogWarning("AddActivityLogAsync called within SessionRepository. Consider moving logic to SessionActivityLogRepository.");
        }

        public async Task<IEnumerable<SessionActivityLog>> GetActivityLogsAsync(
            Guid sessionId, DateTime? since = null, CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // TODO: ISessionActivityLogRepository.GetBySessionIdAsync 호출로 대체 권장
            var query = _context.Set<SessionActivityLog>().AsNoTracking()
                .Where(l => !l.IsDeleted && l.SessionId == sessionId); // IsDeleted 추가

            if (since.HasValue)
            {
                query = query.Where(l => l.OccurredAt >= since.Value);
            }

            _logger.LogWarning("GetActivityLogsAsync called within SessionRepository. Consider moving logic to SessionActivityLogRepository.");
            return await query
                .OrderByDescending(l => l.OccurredAt)
                .ToListAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 관계 로딩

        public async Task<SessionEntity?> GetWithRelatedDataAsync(
            Guid sessionId, bool includeUser = false, bool includeOrganization = false, bool includeConnectedId = false, bool includeParentSession = false, bool includeChildSessions = false,
            CancellationToken cancellationToken = default) // ✅ Token 추가
        {
            // 전역 조회 (_dbSet 사용)
            var query = _dbSet.Where(s => !s.IsDeleted && s.Id == sessionId);

            if (includeUser) query = query.Include(s => s.User);
            if (includeOrganization) query = query.Include(s => s.Organization);
            if (includeConnectedId) query = query.Include(s => s.ConnectedIdNavigation);
            if (includeParentSession) query = query.Include(s => s.ParentSession);
            if (includeChildSessions) query = query.Include(s => s.ChildSessions);

            return await query.FirstOrDefaultAsync(cancellationToken); // ✅ Token 전달
        }

        #endregion

        #region 쿼리 가능한 컬렉션 (BaseRepository 활용)

        public IQueryable<SessionEntity> GetQueryable(bool includeDeleted = false)
        {
            // Query()는 삭제되지 않은 현재 조직 세션을 반환.
            // includeDeleted=true 이거나 전역 세션이 필요하면 _dbSet 사용.
            if (includeDeleted)
            {
                // 조직 필터링 없이 삭제된 것 포함
                return _dbSet.AsQueryable();
            }
            // 삭제되지 않은 전역 + 현재 조직 세션 반환 (Query()만 쓰면 전역 세션 누락)
            // TODO: 정확한 요구사항 확인 필요. 여기서는 삭제 안된 모든 세션 반환으로 수정
            return _dbSet.Where(e => !e.IsDeleted);

            // 이전 로직: 현재 조직 컨텍스트 기반 분기 (IOrganizationContext 제거로 불가)
            // return Query(); // 기본값: 삭제 안된 현재 조직 세션
        }

        public IQueryable<SessionEntity> GetOrganizationQueryable(
            Guid organizationId, bool includeDeleted = false)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId);
            if (!includeDeleted)
            {
                query = query.Where(s => !s.IsDeleted);
            }
            return query;
            // BaseRepository의 QueryForOrganization은 IsDeleted=false를 포함하므로
            // includeDeleted=true 처리가 어려움. 따라서 _dbSet 직접 사용.
        }

        #endregion
    }
}