using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Models.Common;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using AuthHive.Core.Models.Business.Platform.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 저장소 구현체 - BaseRepository 기반 최적화 버전
    /// v16.0: BaseRepository 완전 통합, 중복 제거, 캐시 활용 강화
    /// </summary>
    public class ConnectedIdRepository : BaseRepository<ConnectedId>, IConnectedIdRepository
    {
        public ConnectedIdRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache) 
        { 
        }

        #region 고유 조회 메서드 (BaseRepository 활용)

        /// <summary>
        /// 사용자 ID와 조직 ID로 ConnectedId 조회 - 캐시 최적화
        /// </summary>
        public async Task<ConnectedId?> GetByUserAndOrganizationAsync(Guid userId, Guid organizationId)
        {
            // 캐시 키 생성
            if (_cache != null)
            {
                string cacheKey = $"ConnectedId:UserOrg:{userId}:{organizationId}";
                if (_cache.TryGetValue(cacheKey, out ConnectedId? cachedResult))
                {
                    return cachedResult;
                }
            }

            // BaseRepository의 Query() 활용 - 조직 필터링 자동 적용 안됨 (다른 조직 조회 필요)
            var result = await _dbSet
                .Where(c => c.UserId == userId 
                    && c.OrganizationId == organizationId 
                    && !c.IsDeleted)
                .AsNoTracking()
                .FirstOrDefaultAsync();

            // 결과 캐시
            if (result != null && _cache != null)
            {
                string cacheKey = $"ConnectedId:UserOrg:{userId}:{organizationId}";
                _cache.Set(cacheKey, result, _defaultCacheOptions);
            }

            return result;
        }

        /// <summary>
        /// ConnectedId를 User 및 Organization 정보와 함께 상세 조회
        /// BaseRepository의 Query() 사용하여 조직 필터링 자동 적용
        /// </summary>
        public async Task<ConnectedId?> GetWithDetailsAsync(Guid connectedId)
        {
            return await Query()
                .Include(c => c.User)
                .Include(c => c.Organization)
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == connectedId);
        }

        /// <summary>
        /// 특정 User ID에 속한 모든 ConnectedId 조회 - BaseRepository FindAsync 활용
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByUserIdAsync(Guid userId)
        {
            // BaseRepository의 FindAsync 활용하되, 조직 필터링 우회 필요
            return await _dbSet
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 모든 ConnectedId 조회 (BaseRepository와 중복이므로 제거 검토)
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetAllByUserIdAsync(Guid userId)
        {
            // GetByUserIdAsync와 완전 동일한 로직 - 중복 제거 필요
            return await GetByUserIdAsync(userId);
        }

        #endregion

        #region 상태별 조회 메서드 (BaseRepository 통계 기능 활용)

        /// <summary>
        /// 조직 내 특정 상태의 ConnectedId 조회 - BaseRepository FindAsync 활용
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndStatusAsync(
            Guid organizationId, 
            ConnectedIdStatus status)
        {
            // 현재 조직 컨텍스트와 다른 조직 조회 시 명시적 처리 필요
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == status)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 조직 내 특정 멤버십 타입의 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndMembershipTypeAsync(
            Guid organizationId, 
            MembershipType membershipType)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.MembershipType == membershipType && c.Status == ConnectedIdStatus.Active)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 초대 관련 메서드 (BaseRepository FindAsync 활용)

        /// <summary>
        /// 특정 ConnectedId가 초대한 멤버 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetInvitedMembersAsync(Guid connectedId)
        {
            // BaseRepository의 FindAsync 활용
            return await FindAsync(c => c.InvitedByConnectedId == connectedId);
        }

        /// <summary>
        /// 대기 중인 초대 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetPendingInvitationsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Pending && c.InvitedAt != null)
                .OrderByDescending(c => c.InvitedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 활동 관련 메서드 (BaseRepository 통계 기능과 통합 가능)

        /// <summary>
        /// 비활성 ConnectedId 조회 - BaseRepository FindAsync + 날짜 조건
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetInactiveConnectedIdsAsync(
            Guid organizationId, 
            DateTime inactiveSince)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Active
                    && (c.LastActiveAt == null || c.LastActiveAt < inactiveSince))
                .OrderBy(c => c.LastActiveAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 최근 활동한 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetRecentlyActiveAsync(
            Guid organizationId, 
            int topCount = 10)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Active && c.LastActiveAt != null)
                .OrderByDescending(c => c.LastActiveAt)
                .Take(topCount)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 중복 확인 메서드 (BaseRepository AnyAsync 활용)

        /// <summary>
        /// 사용자가 이미 조직 멤버인지 확인 - BaseRepository AnyAsync 활용
        /// </summary>
        public async Task<bool> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            // BaseRepository의 AnyAsync는 현재 조직만 확인하므로 직접 구현
            return await _dbSet.AnyAsync(c => 
                c.UserId == userId 
                && c.OrganizationId == organizationId 
                && c.Status == ConnectedIdStatus.Active
                && !c.IsDeleted);
        }

        #endregion

        #region 관계 로딩 메서드

        /// <summary>
        /// 관련 엔티티를 포함하여 조회 - 기존 로직 유지
        /// </summary>
        public async Task<ConnectedId?> GetWithRelatedDataAsync(
            Guid id,
            bool includeUser = false,
            bool includeOrganization = false,
            bool includeRoles = false,
            bool includeSessions = false)
        {
            IQueryable<ConnectedId> query = Query(); // BaseRepository Query() 활용
            
            if (includeUser)
                query = query.Include(c => c.User);
                
            if (includeOrganization)
                query = query.Include(c => c.Organization);
                
            if (includeRoles)
                query = query.Include(c => c.RoleAssignments)
                    .ThenInclude(cr => cr.Role);
                
            if (includeSessions)
                query = query.Include(c => c.Sessions.Where(s => s.Status == SessionStatus.Active));
            
            return await query
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == id);
        }

        #endregion

        #region 통계 메서드 (IStatisticsRepository 구현)

        /// <summary>
        /// ConnectedId 통계 조회 - BaseRepository 통계 기능 활용 강화
        /// </summary>
        public async Task<ConnectedIdStatistics?> GetStatisticsAsync(StatisticsQuery query)
        {
            if (query.OrganizationId == null)
            {
                throw new ArgumentNullException(nameof(query.OrganizationId), 
                    "OrganizationId is required for ConnectedId statistics.");
            }

            // BaseRepository의 GetGroupCountAsync 활용 가능한 부분들
            var baseQuery = QueryForOrganization(query.OrganizationId.Value)
                .Where(c => c.CreatedAt >= query.StartDate && c.CreatedAt < query.EndDate);

            // 상태별 통계 - BaseRepository GetGroupCountAsync 활용
            var statusCounts = await baseQuery
                .GroupBy(c => c.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count);

            // 멤버십 타입별 통계
            var membershipTypeCounts = await baseQuery
                .GroupBy(c => c.MembershipType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count);

            // 기본 통계 데이터 (기존 로직 유지)
            var statsData = await baseQuery
                .GroupBy(c => 1)
                .Select(g => new
                {
                    TotalMemberCount = g.Count(),
                    LastJoinedAt = g.Max(c => (DateTime?)c.JoinedAt),
                    NewMembersLast30Days = g.Count(c => c.JoinedAt >= DateTime.UtcNow.AddDays(-30)),
                    ActiveUsersLast7Days = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.AddDays(-7)),
                    ActiveUsersToday = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.Date)
                })
                .FirstOrDefaultAsync();

            if (statsData == null)
            {
                return new ConnectedIdStatistics 
                { 
                    OrganizationId = query.OrganizationId.Value, 
                    GeneratedAt = DateTime.UtcNow 
                };
            }
            
            var stats = new ConnectedIdStatistics
            {
                OrganizationId = query.OrganizationId.Value,
                TotalMemberCount = statsData.TotalMemberCount,
                LastJoinedAt = statsData.LastJoinedAt,
                NewMembersLast30Days = statsData.NewMembersLast30Days,
                ActiveUsersLast7Days = statsData.ActiveUsersLast7Days,
                ActiveUsersToday = statsData.ActiveUsersToday,
                GeneratedAt = DateTime.UtcNow
            };

            // 상태별 통계 설정
            foreach (var statusCount in statusCounts)
            {
                stats.CountByStatus[statusCount.Key] = statusCount.Value;
                
                // 개별 카운트 설정 (기존 호환성)
                switch (statusCount.Key)
                {
                    case ConnectedIdStatus.Active:
                        stats.ActiveMemberCount = statusCount.Value;
                        break;
                    case ConnectedIdStatus.Inactive:
                        stats.InactiveMemberCount = statusCount.Value;
                        break;
                    case ConnectedIdStatus.Suspended:
                        stats.SuspendedCount = statusCount.Value;
                        break;
                    case ConnectedIdStatus.Pending:
                        stats.PendingCount = statusCount.Value;
                        break;
                }
            }

            // 멤버십 타입별 통계 설정
            foreach (var typeCount in membershipTypeCounts)
            {
                stats.CountByMembershipType[typeCount.Key] = typeCount.Value;
            }

            return stats;
        }

        #endregion

        #region 캐시 설정 (BaseRepository 확장)

        // BaseRepository의 기본 캐시 설정을 ConnectedId에 맞게 확장
        private readonly MemoryCacheEntryOptions _defaultCacheOptions = new()
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
            SlidingExpiration = TimeSpan.FromMinutes(5),
            Priority = CacheItemPriority.Normal
        };

        /// <summary>
        /// ConnectedId 특화 캐시 무효화
        /// </summary>
        protected override void InvalidateCache(Guid entityId)
        {
            base.InvalidateCache(entityId); // 기본 캐시 무효화
            
            if (_cache == null) return;

            // ConnectedId 특화 캐시 키들 무효화
            var entity = _dbSet.Find(entityId);
            if (entity != null)
            {
                string userOrgCacheKey = $"ConnectedId:UserOrg:{entity.UserId}:{entity.OrganizationId}";
                _cache.Remove(userOrgCacheKey);
            }
        }

        #endregion
    }
}