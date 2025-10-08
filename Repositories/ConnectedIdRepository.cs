using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
// using Microsoft.Extensions.Caching.Memory; // ❌ IMemoryCache 제거됨
using AuthHive.Core.Interfaces.Infra.Cache; // ⭐️ ICacheService 추가
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
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 저장소 구현체 - BaseRepository 기반 최적화 버전 (ICacheService 적용)
    /// </summary>
    public class ConnectedIdRepository : BaseRepository<ConnectedId>, IConnectedIdRepository
    {
        // IMemoryCache가 ICacheService로 변경됨에 따라, 생성자 시그니처를 BaseRepository에 맞게 수정합니다.
        public ConnectedIdRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            ICacheService? cacheService = null) // ⭐️ ICacheService로 변경
            : base(context, organizationContext, cacheService) 
        { 
        }
        
        // BaseRepository의 _cacheService를 사용하도록 로직을 수정합니다.
        
        #region 고유 조회 메서드 (ICacheService 활용)

        /// <summary>
        /// 사용자 ID와 조직 ID로 ConnectedId 조회 - 캐시 최적화 (ICacheService 사용)
        /// </summary>
        public async Task<ConnectedId?> GetByUserAndOrganizationAsync(Guid userId, Guid organizationId)
        {
            // 1. 캐시 키 생성
            string cacheKey = $"ConnectedId:UserOrg:{userId}:{organizationId}";
            
            if (_cacheService != null)
            {
                // 2. ICacheService에서 조회
                var cachedResult = await _cacheService.GetAsync<ConnectedId>(cacheKey);

                if (cachedResult != null)
                {
                    return cachedResult;
                }
            }
            
            // 3. DB 조회 (BaseRepository Query() 사용 안 함 - 조직 필터링 우회 필요)
            var result = await _dbSet
                .Where(c => c.UserId == userId 
                    && c.OrganizationId == organizationId 
                    && !c.IsDeleted)
                .AsNoTracking()
                .FirstOrDefaultAsync();

            // 4. 결과 캐시 (BaseRepository의 기본 TTL 15분 사용)
            if (result != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(15));
            }

            return result;
        }

        /// <summary>
        /// ConnectedId를 User 및 Organization 정보와 함께 상세 조회
        /// BaseRepository의 Query() 사용하여 조직 필터링 자동 적용
        /// </summary>
        public async Task<ConnectedId?> GetWithDetailsAsync(Guid connectedId)
        {
            // ⭐️ BaseRepository의 IQueryable Query()를 사용하여 RLS 필터링은 유지합니다.
            return await Query()
                .Include(c => c.User)
                .Include(c => c.Organization)
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == connectedId);
        }

        /// <summary>
        /// 특정 User ID에 속한 모든 ConnectedId 조회 - BaseRepository FindAsync 활용 우회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByUserIdAsync(Guid userId)
        {
            // BaseRepository의 조직 필터링(RLS)을 우회하여 사용자의 모든 ConnectedId를 조회합니다.
            return await _dbSet
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 모든 ConnectedId 조회 (IConnectedIdRepository 인터페이스의 GetAllByUserIdAsync를 구현)
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetAllByUserIdAsync(Guid userId)
        {
            // GetByUserIdAsync를 호출하여 로직 재활용
            return await GetByUserIdAsync(userId);
        }

        #endregion

        #region 상태별 조회 메서드

        /// <summary>
        /// 조직 내 특정 상태의 ConnectedId 조회 - BaseRepository QueryForOrganization 활용
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndStatusAsync(
            Guid organizationId, 
            ConnectedIdStatus status)
        {
            // BaseRepository의 QueryForOrganization 활용
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

        #region 초대 관련 메서드

        /// <summary>
        /// 특정 ConnectedId가 초대한 멤버 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedId>> GetInvitedMembersAsync(Guid connectedId)
        {
            // BaseRepository의 FindAsync 활용 (현재 컨텍스트의 조직 필터링)
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

        #region 활동 관련 메서드

        /// <summary>
        /// 비활성 ConnectedId 조회
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

        #region 중복 확인 메서드

        /// <summary>
        /// 사용자가 이미 조직 멤버인지 확인
        /// </summary>
        public async Task<bool> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            // BaseRepository의 RLS를 우회하고 직접 DBSet(_dbSet)을 사용하여 정확한 확인
            return await _dbSet.AnyAsync(c => 
                c.UserId == userId 
                && c.OrganizationId == organizationId 
                && c.Status == ConnectedIdStatus.Active
                && !c.IsDeleted);
        }

        #endregion

        #region 관계 로딩 메서드 (GetWithRelatedDataAsync와 통합됨)
        // Note: 이 메서드는 GetWithDetailsAsync로 대체되었습니다.
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

            var baseQuery = QueryForOrganization(query.OrganizationId.Value)
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

        #region 캐시 설정 (특화 캐시 무효화)

        /// <summary>
        /// ConnectedId 특화 캐시 무효화 (BaseRepository의 InvalidateCacheAsync를 재활용하여 구현)
        /// </summary>
        public async Task InvalidateConnectedIdSpecificCacheAsync(Guid connectedId)
        {
            if (_cacheService == null) return;

            // ConnectedId의 특정 조회 캐시 키를 무효화
            // BaseRepository의 캐시 키 생성 규칙을 따름
            string userOrgCacheKey = $"ConnectedId:UserOrg:{connectedId}:{_organizationContext.CurrentOrganizationId}";
            await _cacheService.RemoveAsync(userOrgCacheKey);
        }

        #endregion
    }
}