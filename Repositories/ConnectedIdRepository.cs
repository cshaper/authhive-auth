// Path: AuthHive.Auth/Repositories/ConnectedIdRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Enums.Auth;

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

        public async Task<ConnectedIdStatistics> GetStatisticsAsync(Guid organizationId)
        {
            var query = _dbSet.Where(c => c.OrganizationId == organizationId && !c.IsDeleted);
            
            var stats = new ConnectedIdStatistics
            {
                OrganizationId = organizationId,
                TotalMemberCount = await query.CountAsync(),
                ActiveMemberCount = await query.CountAsync(c => c.Status == ConnectedIdStatus.Active),
                InactiveMemberCount = await query.CountAsync(c => c.Status == ConnectedIdStatus.Inactive),
                SuspendedCount = await query.CountAsync(c => c.Status == ConnectedIdStatus.Suspended),
                PendingCount = await query.CountAsync(c => c.Status == ConnectedIdStatus.Pending)
            };
            
            // MembershipType별 카운트
            stats.CountByMembershipType[MembershipType.Owner] = await query.CountAsync(c => c.MembershipType == MembershipType.Owner);
            stats.CountByMembershipType[MembershipType.Admin] = await query.CountAsync(c => c.MembershipType == MembershipType.Admin);
            stats.CountByMembershipType[MembershipType.Member] = await query.CountAsync(c => c.MembershipType == MembershipType.Member);
            stats.CountByMembershipType[MembershipType.Guest] = await query.CountAsync(c => c.MembershipType == MembershipType.Guest);
            
            // Status별 카운트
            stats.CountByStatus[ConnectedIdStatus.Active] = stats.ActiveMemberCount;
            stats.CountByStatus[ConnectedIdStatus.Inactive] = stats.InactiveMemberCount;
            stats.CountByStatus[ConnectedIdStatus.Suspended] = stats.SuspendedCount;
            stats.CountByStatus[ConnectedIdStatus.Pending] = stats.PendingCount;
            
            // 최근 가입 정보
            stats.LastJoinedAt = await query
                .OrderByDescending(c => c.JoinedAt)
                .Select(c => (DateTime?)c.JoinedAt)
                .FirstOrDefaultAsync();
            
            // 최근 30일 신규 가입
            var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
            stats.NewMembersLast30Days = await query.CountAsync(c => c.JoinedAt >= thirtyDaysAgo);
            
            // 최근 7일 활성 사용자
            var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
            stats.ActiveUsersLast7Days = await query.CountAsync(c => c.LastActiveAt >= sevenDaysAgo);
            
            // 오늘 활성 사용자
            var today = DateTime.UtcNow.Date;
            stats.ActiveUsersToday = await query.CountAsync(c => c.LastActiveAt >= today);
            
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
                query = query.Include(c => c.Sessions.Where(s => s.Status == SessionEnums.SessionStatus.Active));
            
            return await query
                .Where(c => c.Id == id && !c.IsDeleted)
                .FirstOrDefaultAsync();
        }
    }
}