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
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Models.Auth.ConnectedId.ReadModels;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 저장소 구현체 - BaseRepository 기반 최적화 버전 (ICacheService 적용)
    /// </summary>
    public class ConnectedIdRepository : BaseRepository<ConnectedId>, IConnectedIdRepository
    {
        private readonly IOrganizationContext _organizationContext;

        public ConnectedIdRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ICacheService? cacheService = null)
            : base(context, cacheService) // 💡 BaseRepository에 cacheService 전달
        {
            _organizationContext = organizationContext;
        }

        protected override bool IsOrganizationBaseEntity()
        {
            return true;
        }

        #region 고유 조회 메서드 (ICacheService 활용)

        public async Task<ConnectedId?> GetByUserAndOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"ConnectedId:UserOrg:{userId}:{organizationId}";

            if (_cacheService != null)
            {
                var cachedResult = await _cacheService.GetAsync<ConnectedId>(cacheKey, cancellationToken);
                if (cachedResult != null) return cachedResult;
            }

            var result = await _dbSet
                .Where(c => c.UserId == userId
                    && c.OrganizationId == organizationId
                    && !c.IsDeleted)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);

            if (result != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return result;
        }

        public async Task<IEnumerable<ConnectedId>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 상태별 조회 메서드

        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndStatusAsync(
            Guid organizationId,
            ConnectedIdStatus status,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == status)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndMembershipTypeAsync(
            Guid organizationId,
            MembershipType membershipType,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.MembershipType == membershipType && c.Status == ConnectedIdStatus.Active)
                .OrderBy(c => c.JoinedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 초대 관련 메서드

        public async Task<IEnumerable<ConnectedId>> GetInvitedMembersAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await FindAsync(c => c.InvitedByConnectedId == connectedId, cancellationToken);
        }

        public async Task<IEnumerable<ConnectedId>> GetPendingInvitationsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(c => c.Status == ConnectedIdStatus.Pending && c.InvitedAt != null)
                .OrderByDescending(c => c.InvitedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 활동 관련 메서드

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
                .ToListAsync(cancellationToken);
        }

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
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 중복 확인 메서드

        public async Task<bool> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await _dbSet.AnyAsync(c =>
                c.UserId == userId
                && c.OrganizationId == organizationId
                && c.Status == ConnectedIdStatus.Active
                && !c.IsDeleted, cancellationToken);
        }

        #endregion


        #region 통계 메서드 (IStatisticsRepository 구현)

        /// <summary>
        /// ConnectedId 통계 조회 - v17 Immutable Read Model (get; init;) 방식 적용
        /// </summary>
        public async Task<ConnectedIdStatisticsReadModel?> GetStatisticsAsync(StatisticsQuery query)
        {
            // ... (쿼리 준비) ...
            if (query.OrganizationId == null)
            {
                throw new ArgumentNullException(nameof(query.OrganizationId),
                    "OrganizationId is required for ConnectedId statistics.");
            }

            var organizationId = query.OrganizationId.Value;
            var baseQuery = QueryForOrganization(organizationId)
                .Where(c => c.CreatedAt >= query.StartDate && c.CreatedAt < query.EndDate);

            // ... (Task 쿼리 실행) ...
            var statusCountsTask = baseQuery
                .GroupBy(c => c.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count);

            var membershipTypeCountsTask = baseQuery
                .GroupBy(c => c.MembershipType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count);

            var statsDataTask = baseQuery
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

            await Task.WhenAll(statusCountsTask, membershipTypeCountsTask, statsDataTask);

            var statusCounts = await statusCountsTask;
            var membershipTypeCounts = await membershipTypeCountsTask;
            var statsData = await statsDataTask;

            var generatedAt = DateTime.UtcNow;

            // 💡 1. (데이터 없는 경우) 객체 초기화
            if (statsData == null)
            {
                return new ConnectedIdStatisticsReadModel
                {
                    Id = Guid.NewGuid(),              // 'required' Id (BaseDto)
                    OrganizationId = organizationId,  // 'required' OrganizationId (OrganizationScopedDto)
                    GeneratedAt = generatedAt,
                    CountByMembershipType = new Dictionary<MembershipType, int>(),
                    CountByStatus = new Dictionary<ConnectedIdStatus, int>()
                };
            }

            // ... (변수 준비) ...
            int activeMemberCount = statusCounts.TryGetValue(ConnectedIdStatus.Active, out var active) ? active : 0;
            int inactiveMemberCount = statusCounts.TryGetValue(ConnectedIdStatus.Inactive, out var inactive) ? inactive : 0;
            int pendingCount = statusCounts.TryGetValue(ConnectedIdStatus.Pending, out var pending) ? pending : 0;
            int suspendedCount = statusCounts.TryGetValue(ConnectedIdStatus.Suspended, out var suspended) ? suspended : 0;

            // 💡 2. (데이터 있는 경우) 객체 초기화
            return new ConnectedIdStatisticsReadModel
            {
                Id = Guid.NewGuid(),              // 'required' Id (BaseDto)
                OrganizationId = organizationId,  // 'required' OrganizationId (OrganizationScopedDto)
                TotalMemberCount = statsData.TotalMemberCount,
                ActiveMemberCount = activeMemberCount,
                InactiveMemberCount = inactiveMemberCount,
                PendingCount = pendingCount,
                SuspendedCount = suspendedCount,
                NewMembersLast30Days = statsData.NewMembersLast30Days,
                ActiveUsersLast7Days = statsData.ActiveUsersLast7Days,
                ActiveUsersToday = statsData.ActiveUsersToday,
                GeneratedAt = generatedAt,
                CountByMembershipType = membershipTypeCounts,
                CountByStatus = statusCounts,
                LastJoinedAt = statsData.LastJoinedAt
            };
        }

        #endregion


        #region 캐시 설정 (특화 캐시 무효화)

        /// <summary>
        /// ConnectedId 특화 캐시 무효화
        /// userId 파라미터를 Guid? (nullable)로 변경
        /// </summary>
        public async Task InvalidateConnectedIdSpecificCacheAsync(Guid connectedId, Guid? userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return;

            // 1. GetByUserAndOrganizationAsync 캐시 키 무효화
            // 💡 CS1503 해결: userId가 null이 아닐 때만 캐시 키를 생성하고 무효화
            if (userId.HasValue)
            {
                string userOrgCacheKey = $"ConnectedId:UserOrg:{userId.Value}:{organizationId}";
                await _cacheService.RemoveAsync(userOrgCacheKey, cancellationToken);
            }

            // 2. BaseRepository의 GetByIdAsync 캐시 키 (BaseRepository의 키 생성 규칙을 따라야 함)
            string baseCacheKey = $"ConnectedId:{connectedId}"; // 💡 BaseRepository의 키 규칙에 따라 수정 필요
            await _cacheService.RemoveAsync(baseCacheKey, cancellationToken);
        }

        // 💡 CS1503 (356라인) 오류 해결:
        // InvalidateConnectedIdSpecificCacheAsync가 Guid?를 받도록 수정되었으므로,
        // entity.UserId (Guid?)를 그대로 전달할 수 있습니다.
        public override async Task UpdateAsync(ConnectedId entity, CancellationToken cancellationToken = default)
        {
            await base.UpdateAsync(entity, cancellationToken);
            await InvalidateConnectedIdSpecificCacheAsync(entity.Id, entity.UserId, entity.OrganizationId, cancellationToken);
        }

        // 💡 CS1503 (363라인) 오류 해결:
        // entity.UserId (Guid?)를 그대로 전달할 수 있습니다.
        public override async Task DeleteAsync(ConnectedId entity, CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(entity, cancellationToken);
            await InvalidateConnectedIdSpecificCacheAsync(entity.Id, entity.UserId, entity.OrganizationId, cancellationToken);
        }


        public async Task<ConnectedId?> GetWithDetailsAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await _context.ConnectedIds
                .Include(c => c.User)
                .Include(c => c.Organization)
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == connectedId, cancellationToken);
        }

        #endregion
    }
}