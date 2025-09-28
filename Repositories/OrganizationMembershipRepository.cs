using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationMembership Repository 구현체 - AuthHive v15
    /// 조직 멤버십의 CRUD 및 관계 관리를 담당합니다.
    /// </summary>
    public class OrganizationMembershipRepository : BaseRepository<OrganizationMembership>, IOrganizationMembershipRepository
    {
        public OrganizationMembershipRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache) { }

        #region 기본 멤버십 조회

        public async Task<IEnumerable<OrganizationMembership>> GetMembersAsync(
            Guid organizationId,
            bool includeInactive = false)
        {
            var query = QueryForOrganization(organizationId);

            if (!includeInactive)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query
                .Include(m => m.Member)
                .Include(m => m.InvitedBy)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        public async Task<OrganizationMembership?> GetMembershipAsync(
            Guid organizationId,
            Guid connectedId)
        {
            return await QueryForOrganization(organizationId)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .FirstOrDefaultAsync(m => m.ConnectedId == connectedId);
        }

        public async Task<bool> IsMemberAsync(Guid organizationId, Guid connectedId)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(m =>
                    m.ConnectedId == connectedId &&
                    m.Status == OrganizationMembershipStatus.Active);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetOrganizationsForConnectedIdAsync(
            Guid connectedId,
            bool includeInactive = false)
        {
            var query = _dbSet.Where(m => m.ConnectedId == connectedId && !m.IsDeleted);

            if (!includeInactive)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query
                .Include(m => m.Organization)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        #endregion

        #region 상태 및 역할별 조회

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByStatusAsync(
            Guid organizationId,
            OrganizationMembershipStatus status)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.Status == status
            );
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByRoleAsync(
            Guid organizationId,
            OrganizationMemberRole role)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.MemberRole == role
            );
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByTypeAsync(
            Guid organizationId,
            OrganizationMembershipType membershipType)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.MembershipType == membershipType
            );
        }

        public async Task<IEnumerable<OrganizationMembership>> GetAdministratorsAsync(Guid organizationId)
        {
            var adminRoles = new[]
            {
                OrganizationMemberRole.Owner,
                OrganizationMemberRole.Admin,
                OrganizationMemberRole.Manager
            };

            return await QueryForOrganization(organizationId)
                .Where(m => adminRoles.Contains(m.MemberRole) &&
                              m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .OrderBy(m => m.MemberRole)
                .ThenBy(m => m.JoinedAt)
                .ToListAsync();
        }
        #endregion

        #region 초대 관리

        public async Task<OrganizationMembership?> GetByInvitationTokenAsync(string invitationToken)
        {
            if (string.IsNullOrWhiteSpace(invitationToken))
                return null;

            return await _dbSet
                .Include(m => m.Organization)
                .Include(m => m.InvitedBy)
                .FirstOrDefaultAsync(m =>
                    m.InvitationToken == invitationToken &&
                    !m.IsDeleted);
        }

        public async Task<bool> AcceptInvitationAsync(string invitationToken, Guid connectedId)
        {
            var membership = await GetByInvitationTokenAsync(invitationToken);
            if (membership == null || membership.ConnectedId != connectedId)
                return false;

            membership.Status = OrganizationMembershipStatus.Active;
            membership.AcceptedAt = DateTime.UtcNow;
            membership.InvitationToken = null;
            membership.UpdatedByConnectedId = connectedId;
            membership.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion

        #region 만료 및 비활성 관리

        public async Task<IEnumerable<OrganizationMembership>> GetExpiredMembershipsAsync(DateTime asOfDate)
        {
            return await _dbSet
                .Where(m => m.ExpiresAt.HasValue &&
                              m.ExpiresAt.Value <= asOfDate &&
                              m.Status == OrganizationMembershipStatus.Active &&
                              !m.IsDeleted)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .ToListAsync();
        }

        public async Task<IEnumerable<OrganizationMembership>> GetInactiveMembersAsync(
            Guid organizationId,
            int inactiveDays)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active &&
                              (m.LastActivityAt == null || m.LastActivityAt < cutoffDate))
                .Include(m => m.Member)
                .OrderBy(m => m.LastActivityAt ?? m.JoinedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<OrganizationMembership>> GetExpiringMembershipsAsync(int daysBeforeExpiration)
        {
            var targetDate = DateTime.UtcNow.AddDays(daysBeforeExpiration);

            return await _dbSet
                .Where(m => m.ExpiresAt.HasValue &&
                              m.ExpiresAt.Value <= targetDate &&
                              m.ExpiresAt.Value > DateTime.UtcNow &&
                              m.Status == OrganizationMembershipStatus.Active &&
                              !m.IsDeleted)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .OrderBy(m => m.ExpiresAt)
                .ToListAsync();
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// ✨ [재추가된 메서드] 역할별 멤버 수 통계
        /// 인터페이스에 정의된 멤버이므로 반드시 구현해야 합니다.
        /// </summary>
        public async Task<Dictionary<OrganizationMemberRole, int>> GetMemberCountByRoleAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active && !m.IsDeleted)
                .GroupBy(m => m.MemberRole)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        public async Task<IEnumerable<OrganizationMembership>> GetRecentMembersAsync(
            Guid organizationId,
            int count = 10)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .OrderByDescending(m => m.JoinedAt)
                .Take(count)
                .ToListAsync();
        } 
        public Task<int> GetMemberCountAsync(Guid organizationId)
        {
            // TODO: 조직의 전체 멤버 수를 조회하는 로직 구현
            // 예시: return await _context.Set<OrganizationMembership>()
            //                        .CountAsync(m => m.OrganizationId == organizationId && m.IsActive);
            throw new NotImplementedException();
        }
        #endregion

        #region 멤버십 업데이트

        public async Task<bool> UpdateMemberStatusAsync(
            Guid organizationId,
            Guid connectedId,
            OrganizationMembershipStatus status,
            Guid? updatedByConnectedId = null)
        {
            var membership = await GetMembershipAsync(organizationId, connectedId);
            if (membership == null) return false;

            membership.Status = status;
            membership.UpdatedByConnectedId = updatedByConnectedId;
            membership.UpdatedAt = DateTime.UtcNow;

            if (status == OrganizationMembershipStatus.Inactive)
            {
                membership.DeactivatedAt = DateTime.UtcNow;
                membership.DeactivatedByConnectedId = updatedByConnectedId;
            }

            await UpdateAsync(membership);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> UpdateLastActivityAsync(Guid organizationId, Guid connectedId)
        {
            var membership = await GetMembershipAsync(organizationId, connectedId);
            if (membership == null) return false;

            membership.LastActivityAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion
    }
}