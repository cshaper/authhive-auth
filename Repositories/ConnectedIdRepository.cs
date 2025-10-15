using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Models.Common;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading; // CancellationToken 사용
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Business.Platform.Common;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 저장소 구현체 - BaseRepository 기반 최적화 버전 (ICacheService 적용)
    /// </summary>
    // 💡 CS0534 해결: BaseRepository가 요구하는 추상 메서드를 구현해야 합니다.
    public class ConnectedIdRepository : BaseRepository<ConnectedId>, IConnectedIdRepository
    {
        private readonly IOrganizationContext _organizationContext; // 💡 CS0103 해결을 위해 BaseRepository에서 Protected로 선언되었거나, 여기서 다시 선언이 필요합니다. (BaseRepository에서 상속받는다고 가정)

        // 💡 CS1729 해결: BaseRepository는 IOrganizationContext와 ICacheService를 받습니다.
        public ConnectedIdRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ICacheService? cacheService = null)
            : base(context) // BaseRepository 생성자 호출
        {
            _organizationContext = organizationContext; // 💡 CS0103 해결: BaseRepository가 아닌 여기서 필드를 사용한다면 선언 및 할당 필요
        }

        // 💡 CS0534 해결: BaseRepository<T>에 이 메서드가 추상 메서드로 정의되어 있다면 반드시 구현해야 합니다.
        // ConnectedId는 OrganizationId를 필수로 가지는 조직 범위 엔티티입니다.
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
        }

        #region 고유 조회 메서드 (ICacheService 활용)

        /// <summary>
        /// 사용자 ID와 조직 ID로 ConnectedId 조회 - 캐시 최적화 (ICacheService 사용)
        /// </summary>
        public async Task<ConnectedId?> GetByUserAndOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            // 1. 캐시 키 생성
            string cacheKey = $"ConnectedId:UserOrg:{userId}:{organizationId}";

            if (_cacheService != null)
            {
                // 2. ICacheService에서 조회 (CancellationToken 전달)
                var cachedResult = await _cacheService.GetAsync<ConnectedId>(cacheKey, cancellationToken);

                if (cachedResult != null)
                {
                    return cachedResult;
                }
            }

            // 3. DB 조회 (RLS를 우회하는 논리적 조회)
            var result = await _dbSet
                .Where(c => c.UserId == userId
                    && c.OrganizationId == organizationId
                    && !c.IsDeleted)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken); // CancellationToken 전달

            // 4. 결과 캐시 (BaseRepository의 기본 TTL 15분 사용)
            if (result != null && _cacheService != null)
            {
                // CancellationToken 전달
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return result;
        }

        /// <summary>
        /// ConnectedId를 User 및 Organization 정보와 함께 상세 조회
        /// BaseRepository의 Query() 사용하여 조직 필터링 자동 적용
        /// </summary>


        /// <summary>
        /// 특정 User ID에 속한 모든 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 조직 필터링(RLS)을 우회하고 _dbSet을 사용합니다.
            return await _dbSet
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        /// <summary>
        /// 모든 ConnectedId 조회 (IConnectedIdRepository 인터페이스의 GetAllByUserIdAsync를 구현)
        /// Note: 이 메서드는 인터페이스에 정의되어 있지 않아 주석 처리하거나, GetByUserIdAsync를 활용하도록 수정합니다.
        /// </summary>
        // public async Task<IEnumerable<ConnectedId>> GetAllByUserIdAsync(Guid userId)
        // {
        //     // 인터페이스에 이 메서드가 정의되어 있지 않으므로 주석 처리하거나 GetByUserIdAsync로 대체해야 합니다.
        //     // return await GetByUserIdAsync(userId);
        // }
        // 💡 주: 이 메서드는 인터페이스에 존재하지 않으므로 (GetByUserIdAsync만 존재), 삭제했습니다.

        #endregion

        #region 상태별 조회 메서드

        /// <summary>
        /// 조직 내 특정 상태의 ConnectedId 조회 - BaseRepository QueryForOrganization 활용
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndStatusAsync(
            Guid organizationId,
            ConnectedIdStatus status,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 QueryForOrganization 활용
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == status)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        /// <summary>
        /// 조직 내 특정 멤버십 타입의 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndMembershipTypeAsync(
            Guid organizationId,
            MembershipType membershipType,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.MembershipType == membershipType && c.Status == ConnectedIdStatus.Active)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        #endregion

        #region 초대 관련 메서드

        /// <summary>
        /// 특정 ConnectedId가 초대한 멤버 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetInvitedMembersAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 FindAsync 활용 (현재 컨텍스트의 조직 필터링)
            return await FindAsync(c => c.InvitedByConnectedId == connectedId, cancellationToken); // CancellationToken 전달
        }

        /// <summary>
        /// 대기 중인 초대 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetPendingInvitationsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Pending && c.InvitedAt != null)
                .OrderByDescending(c => c.InvitedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        #endregion

        #region 활동 관련 메서드

        /// <summary>
        /// 비활성 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetInactiveConnectedIdsAsync(
            Guid organizationId,
            DateTime inactiveSince,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Active
                    && (c.LastActiveAt == null || c.LastActiveAt < inactiveSince))
                .OrderBy(c => c.LastActiveAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        /// <summary>
        /// 최근 활동한 ConnectedId 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetRecentlyActiveAsync(
            Guid organizationId,
            int topCount = 10,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Active && c.LastActiveAt != null)
                .OrderByDescending(c => c.LastActiveAt)
                .Take(topCount)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 전달
        }

        #endregion

        #region 중복 확인 메서드

        /// <summary>
        /// 사용자가 이미 조직 멤버인지 확인
        /// </summary>
        public async Task<bool> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 RLS를 우회하고 직접 DBSet(_dbSet)을 사용하여 정확한 확인
            return await _dbSet.AnyAsync(c =>
                c.UserId == userId
                && c.OrganizationId == organizationId
                && c.Status == ConnectedIdStatus.Active
                && !c.IsDeleted, cancellationToken); // CancellationToken 전달
        }

        #endregion

        #region 통계 메서드 (IStatisticsRepository 구현)

        /// <summary>
        /// ConnectedId 통계 조회 - BaseRepository 통계 기능 활용 강화
        /// </summary>
        #region 통계 메서드 (IStatisticsRepository 구현)

        /// <summary>
        /// ConnectedId 통계 조회 - BaseRepository 통계 기능 활용 강화
        /// </summary>
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

            // 💡 CS0266 에러 해결: query.OrganizationId가 null이 아님이 보장되었으므로 .Value를 사용하여 Guid 값을 추출합니다.
            var organizationId = query.OrganizationId.Value;

            var baseQuery = QueryForOrganization(organizationId) // 추출된 Non-nullable Guid 사용
                .Where(c => c.CreatedAt >= query.StartDate && c.CreatedAt < query.EndDate);

            // 상태별 통계
            var statusCounts = await baseQuery
                .GroupBy(c => c.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count);

            // 멤버십 타입별 통계
            var membershipTypeCounts = await baseQuery
                .GroupBy(c => c.MembershipType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count);

            // 기본 통계 데이터
            var statsData = await baseQuery
                .GroupBy(c => 1)
                .Select(g => new
                {
                    TotalMemberCount = g.Count(),
                    LastJoinedAt = g.Max(c => (DateTime?)c.JoinedAt),
                    // DateTime.UtcNow는 IDateTimeProvider를 통해 주입받아야 하지만, 통계 쿼리에서는 DB의 현재 시각에 의존할 수 있습니다.
                    // ⚠️ TODO: IStatisticsRepository 인터페이스에 CancellationToken 및 IDateTimeProvider 지원이 필요함.
                    NewMembersLast30Days = g.Count(c => c.JoinedAt >= DateTime.UtcNow.AddDays(-30)),
                    ActiveUsersLast7Days = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.AddDays(-7)),
                    ActiveUsersToday = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.Date)
                })
                .FirstOrDefaultAsync();

            if (statsData == null)
            {
                return new ConnectedIdStatistics
                {
                    OrganizationId = organizationId, // Non-nullable Guid 사용
                    GeneratedAt = DateTime.UtcNow
                };
            }

            var stats = new ConnectedIdStatistics
            {
                OrganizationId = organizationId, // Non-nullable Guid 사용
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

        #endregion
        #endregion

        #region 캐시 설정 (특화 캐시 무효화)

        /// <summary>
        /// ConnectedId 특화 캐시 무효화 (BaseRepository의 InvalidateCacheAsync를 재활용하여 구현)
        /// </summary>
        public async Task InvalidateConnectedIdSpecificCacheAsync(Guid connectedId)
        {
            if (_cacheService == null) return;
            if (!_organizationContext.CurrentOrganizationId.HasValue)
            {
                // If there's no current organization ID, we can't build the cache key, so we exit.
                return;
            }

            // 💡 CS0103 해결: BaseRepository 내부에 _organizationContext가 Protected로 정의되어 있다고 가정합니다. 
            // 만약 BaseRepository에서 접근할 수 없다면, 이 필드를 ConnectedIdRepository에 선언해야 합니다.
            Guid currentOrgId = _organizationContext.CurrentOrganizationId.Value;

            // ConnectedId의 특정 조회 캐시 키를 무효화
            // BaseRepository의 캐시 키 생성 규칙을 따름
            string userOrgCacheKey = $"ConnectedId:UserOrg:{connectedId}:{currentOrgId}";
            await _cacheService.RemoveAsync(userOrgCacheKey);
        }

        public async Task<ConnectedId?> GetWithDetailsAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // User와 Organization 정보를 함께 가져옵니다.
            return await _context.ConnectedIds
                .Include(c => c.User)
                .Include(c => c.Organization)
                .AsNoTracking() // 읽기 전용 쿼리이므로 성능을 위해 추가
                .FirstOrDefaultAsync(c => c.Id == connectedId, cancellationToken);
        }

        #endregion
    }
}