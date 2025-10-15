using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra.Cache; // ✅ Correct: Using ICacheService
using System.Threading; // ✅ Correct: For CancellationToken

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationMembership Repository 구현체 - AuthHive v16 아키텍처 적용
    /// 조직 멤버십의 CRUD 및 관계 관리를 담당합니다.
    /// </summary>
    public class OrganizationMembershipRepository : BaseRepository<OrganizationMembership>, IOrganizationMembershipRepository
    {
        // ✅ Correct: The constructor now aligns with the new BaseRepository.
        // It no longer depends on IOrganizationContext and uses ICacheService.
        public OrganizationMembershipRepository(
            AuthDbContext context,
            ICacheService? cacheService)
            : base(context) { }

        // ✅ Correct: Implemented the mandatory abstract method from BaseRepository.
        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 멤버십 조회

        public async Task<IEnumerable<OrganizationMembership>> GetMembersAsync(
            Guid organizationId,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);

            if (!includeInactive)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query
                .Include(m => m.Member)
                .ThenInclude(c => c.User) // Include User for display purposes
                .Include(m => m.InvitedBy)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<OrganizationMembership?> GetMembershipAsync(
            Guid organizationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .FirstOrDefaultAsync(m => m.ConnectedId == connectedId, cancellationToken);
        }

        public async Task<bool> IsMemberAsync(
            Guid organizationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(m =>
                    m.ConnectedId == connectedId &&
                    m.Status == OrganizationMembershipStatus.Active, cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetOrganizationsForConnectedIdAsync(
            Guid connectedId,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(m => m.ConnectedId == connectedId);

            if (!includeInactive)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query
                .Include(m => m.Organization)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> IsMemberByEmailAsync(
            Guid organizationId,
            string email,
            string? username,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active);

            if (!string.IsNullOrEmpty(username))
            {
                // ✅ Add explicit null checks inside the AnyAsync predicate
                return await query.AnyAsync(m =>
                    m.Member != null &&
                    m.Member.User != null &&
                    (m.Member.User.Email == email || m.Member.User.Username == username),
                    cancellationToken);
            }
            else
            {
                // ✅ Add explicit null checks inside the AnyAsync predicate here as well
                return await query.AnyAsync(m =>
                    m.Member != null &&
                    m.Member.User != null &&
                    m.Member.User.Email == email,
                    cancellationToken);
            }
        }

        #endregion

        #region 상태 및 역할별 조회

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByStatusAsync(
            Guid organizationId,
            OrganizationMembershipStatus status,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == status)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByRoleAsync(
            Guid organizationId,
            OrganizationMemberRole role,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.MemberRole == role)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByTypeAsync(
            Guid organizationId,
            OrganizationMembershipType membershipType,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.MembershipType == membershipType)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetAdministratorsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var adminRoles = new[] { OrganizationMemberRole.Owner, OrganizationMemberRole.Admin };

            return await QueryForOrganization(organizationId)
                .Where(m => adminRoles.Contains(m.MemberRole) && m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .OrderBy(m => m.MemberRole)
                .ThenBy(m => m.JoinedAt)
                .ToListAsync(cancellationToken);
        }
        #endregion

        #region 초대 관리

        public async Task<OrganizationMembership?> GetByInvitationTokenAsync(
            string invitationToken,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(invitationToken))
                return null;

            // Use Query() to ensure soft-deleted items are excluded.
            return await Query()
                .Include(m => m.Organization)
                .Include(m => m.InvitedBy)
                .FirstOrDefaultAsync(m => m.InvitationToken == invitationToken, cancellationToken);
        }

        // Note: This method modifies state and saves. This is acceptable in a repository
        // when not using a separate Unit of Work service.
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

            await UpdateAsync(membership); // Marks entity as modified and invalidates cache
            await _context.SaveChangesAsync(); // Commits the change to the database
            return true;
        }

        #endregion

        #region 만료 및 비활성 관리

        public async Task<IEnumerable<OrganizationMembership>> GetExpiredMembershipsAsync(
            DateTime asOfDate,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(m => m.ExpiresAt.HasValue &&
                              m.ExpiresAt.Value <= asOfDate &&
                              m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetInactiveMembersAsync(
            Guid organizationId,
            int inactiveDays,
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active &&
                              (m.LastActivityAt == null || m.LastActivityAt < cutoffDate))
                .Include(m => m.Member)
                .OrderBy(m => m.LastActivityAt ?? m.JoinedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetExpiringMembershipsAsync(
            int daysBeforeExpiration,
            CancellationToken cancellationToken = default)
        {
            var targetDate = DateTime.UtcNow.AddDays(daysBeforeExpiration);

            return await Query()
                .Where(m => m.ExpiresAt.HasValue &&
                              m.ExpiresAt.Value <= targetDate &&
                              m.ExpiresAt.Value > DateTime.UtcNow &&
                              m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .OrderBy(m => m.ExpiresAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 통계 및 분석

        public async Task<Dictionary<OrganizationMemberRole, int>> GetMemberCountByRoleAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active)
                .GroupBy(m => m.MemberRole)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetRecentMembersAsync(
            Guid organizationId,
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active)
                .Include(m => m.Member)
                .OrderByDescending(m => m.JoinedAt)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        // ✅ Correct: Implemented the missing GetMemberCountAsync method.
        public async Task<int> GetMemberCountAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .CountAsync(m => m.Status == OrganizationMembershipStatus.Active, cancellationToken);
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