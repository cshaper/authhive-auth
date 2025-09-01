using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Models.Common; // StatisticsQuery를 위해 추가

namespace AuthHive.Auth.Repositories
{
    public class ConnectedIdRepository : OrganizationScopedRepository<ConnectedId>, IConnectedIdRepository
    {
        public ConnectedIdRepository(AuthDbContext context) : base(context) { }

        public async Task<ConnectedId?> GetByUserAndOrganizationAsync(Guid userId, Guid organizationId)
        {
            return await _dbSet
                .Where(c => c.UserId == userId 
                    && c.OrganizationId == organizationId 
                    && !c.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetByUserIdAsync(Guid userId)
        {
            return await _dbSet
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndStatusAsync(
            Guid organizationId, 
            ConnectedIdStatus status)
        {
            return await _dbSet
                .Where(c => c.OrganizationId == organizationId 
                    && c.Status == status 
                    && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetByOrganizationAndMembershipTypeAsync(
            Guid organizationId, 
            MembershipType membershipType)
        {
            return await _dbSet
                .Where(c => c.OrganizationId == organizationId 
                    && c.MembershipType == membershipType 
                    && c.Status == ConnectedIdStatus.Active
                    && !c.IsDeleted)
                .OrderBy(c => c.JoinedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetInvitedMembersAsync(Guid connectedId)
        {
            return await _dbSet
                .Where(c => c.InvitedByConnectedId == connectedId && !c.IsDeleted)
                .OrderByDescending(c => c.InvitedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetPendingInvitationsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(c => c.OrganizationId == organizationId 
                    && c.Status == ConnectedIdStatus.Pending
                    && c.InvitedAt != null
                    && !c.IsDeleted)
                .OrderByDescending(c => c.InvitedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetInactiveConnectedIdsAsync(
            Guid organizationId, 
            DateTime inactiveSince)
        {
            return await _dbSet
                .Where(c => c.OrganizationId == organizationId 
                    && c.Status == ConnectedIdStatus.Active
                    && (c.LastActiveAt == null || c.LastActiveAt < inactiveSince)
                    && !c.IsDeleted)
                .OrderBy(c => c.LastActiveAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<ConnectedId>> GetRecentlyActiveAsync(
            Guid organizationId, 
            int topCount = 10)
        {
            return await _dbSet
                .Where(c => c.OrganizationId == organizationId 
                    && c.Status == ConnectedIdStatus.Active
                    && c.LastActiveAt != null
                    && !c.IsDeleted)
                .OrderByDescending(c => c.LastActiveAt)
                .Take(topCount)
                .ToListAsync();
        }
        
        // ✨ [변경] 표준 인터페이스 구현 및 성능 최적화
        public async Task<ConnectedIdStatistics?> GetStatisticsAsync(StatisticsQuery query)
        {
            if (query.OrganizationId == null)
            {
                // 조직 ID가 없는 통계는 지원하지 않는 경우. 혹은 시스템 전체 통계를 구현할 수도 있음.
                // 여기서는 null을 반환하거나 예외를 던지는 것이 적절합니다.
                throw new ArgumentNullException(nameof(query.OrganizationId), "OrganizationId is required for ConnectedId statistics.");
            }

            var dbQuery = _dbSet.Where(c => c.OrganizationId == query.OrganizationId && !c.IsDeleted);

            // StatisticsQuery에 포함된 기간 필터 적용
            dbQuery = dbQuery.Where(c => c.CreatedAt >= query.StartDate && c.CreatedAt < query.EndDate);

            // 단 한 번의 쿼리로 모든 집계 데이터를 계산
            var statsData = await dbQuery
                .GroupBy(c => 1) // 모든 데이터를 단일 그룹으로 묶어 집계
                .Select(g => new
                {
                    TotalMemberCount = g.Count(),
                    ActiveMemberCount = g.Count(c => c.Status == ConnectedIdStatus.Active),
                    InactiveMemberCount = g.Count(c => c.Status == ConnectedIdStatus.Inactive),
                    SuspendedCount = g.Count(c => c.Status == ConnectedIdStatus.Suspended),
                    PendingCount = g.Count(c => c.Status == ConnectedIdStatus.Pending),
                    OwnerCount = g.Count(c => c.MembershipType == MembershipType.Owner),
                    AdminCount = g.Count(c => c.MembershipType == MembershipType.Admin),
                    MemberCount = g.Count(c => c.MembershipType == MembershipType.Member),
                    GuestCount = g.Count(c => c.MembershipType == MembershipType.Guest),
                    LastJoinedAt = g.Max(c => (DateTime?)c.JoinedAt),
                    NewMembersLast30Days = g.Count(c => c.JoinedAt >= DateTime.UtcNow.AddDays(-30)),
                    ActiveUsersLast7Days = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.AddDays(-7)),
                    ActiveUsersToday = g.Count(c => c.LastActiveAt >= DateTime.UtcNow.Date)
                })
                .FirstOrDefaultAsync();

            if (statsData == null)
            {
                // 해당 기간/조직에 멤버가 한 명도 없을 경우 빈 통계 객체 반환
                return new ConnectedIdStatistics { OrganizationId = query.OrganizationId.Value, GeneratedAt = DateTime.UtcNow };
            }
            
            var stats = new ConnectedIdStatistics
            {
                OrganizationId = query.OrganizationId.Value,
                TotalMemberCount = statsData.TotalMemberCount,
                ActiveMemberCount = statsData.ActiveMemberCount,
                InactiveMemberCount = statsData.InactiveMemberCount,
                SuspendedCount = statsData.SuspendedCount,
                PendingCount = statsData.PendingCount,
                LastJoinedAt = statsData.LastJoinedAt,
                NewMembersLast30Days = statsData.NewMembersLast30Days,
                ActiveUsersLast7Days = statsData.ActiveUsersLast7Days,
                ActiveUsersToday = statsData.ActiveUsersToday,
                GeneratedAt = DateTime.UtcNow
            };

            stats.CountByMembershipType[MembershipType.Owner] = statsData.OwnerCount;
            stats.CountByMembershipType[MembershipType.Admin] = statsData.AdminCount;
            stats.CountByMembershipType[MembershipType.Member] = statsData.MemberCount;
            stats.CountByMembershipType[MembershipType.Guest] = statsData.GuestCount;
            
            stats.CountByStatus[ConnectedIdStatus.Active] = statsData.ActiveMemberCount;
            stats.CountByStatus[ConnectedIdStatus.Inactive] = statsData.InactiveMemberCount;
            stats.CountByStatus[ConnectedIdStatus.Suspended] = statsData.SuspendedCount;
            stats.CountByStatus[ConnectedIdStatus.Pending] = statsData.PendingCount;

            return stats;
        }

        public async Task<bool> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            return await _dbSet.AnyAsync(c => 
                c.UserId == userId 
                && c.OrganizationId == organizationId 
                && c.Status == ConnectedIdStatus.Active
                && !c.IsDeleted);
        }

        public async Task<ConnectedId?> GetWithRelatedDataAsync(
            Guid id,
            bool includeUser = false,
            bool includeOrganization = false,
            bool includeRoles = false,
            bool includeSessions = false)
        {
            IQueryable<ConnectedId> query = _dbSet;
            
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
                .Where(c => c.Id == id && !c.IsDeleted)
                .FirstOrDefaultAsync();
        }
    }
}