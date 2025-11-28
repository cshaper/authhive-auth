using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra.Cache;
using System.Threading;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationMembership Repository 구현체 - AuthHive v16.1 아키텍처 적용
    /// 
    /// [v16.1 변경 사항]
    /// 1. (필수) 생성자에서 ICacheService를 BaseRepository로 전달하도록 수정
    /// 2. (UoW) 리포지토리 내의 _context.SaveChangesAsync() 호출 제거 (서비스 레이어 책임)
    /// </summary>
    public class OrganizationMembershipRepository : BaseRepository<OrganizationMembership>, IOrganizationMembershipRepository
    {
        public OrganizationMembershipRepository(
            AuthDbContext context,
            ICacheService? cacheService)
            // 💡 [v16.1 수정] cacheService를 base()로 전달해야 캐시가 동작합니다.
            : base(context, cacheService) 
        { }

        // ✅ v16.1: IsOrganizationBaseEntity()는 true가 맞습니다.
        protected override bool IsOrganizationBaseEntity() => true;

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

            // 💡 비용 최적화: AsNoTracking()을 추가하여 변경 추적 오버헤드 제거
            return await query
                .AsNoTracking() 
                .Include(m => m.Member)
                .ThenInclude(c => c!.User) // User는 Nullable일 수 있으므로 Null 전파
                .Include(m => m.InvitedBy)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<OrganizationMembership?> GetMembershipAsync(
            Guid organizationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            // 💡 GetMembershipAsync는 상태 수정을 위해 추적이 필요할 수 있으므로 AsNoTracking() 생략
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
                .AsNoTracking()
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
                return await query.AnyAsync(m =>
                    m.Member != null &&
                    m.Member.User != null &&
                    (m.Member.User.Email == email || m.Member.User.Username == username),
                    cancellationToken);
            }
            else
            {
                return await query.AnyAsync(m =>
                    m.Member != null &&
                    m.Member.User != null &&
                    m.Member.User.Email == email,
                    cancellationToken);
            }
        }

        #endregion

        #region 상태 및 역할별 조회 (AsNoTracking() 추가)

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByStatusAsync(
            Guid organizationId,
            OrganizationMembershipStatus status,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == status)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByRoleAsync(
            Guid organizationId,
            OrganizationMemberRole role,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.MemberRole == role)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetMembersByTypeAsync(
            Guid organizationId,
            OrganizationMembershipType membershipType,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.MembershipType == membershipType)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMembership>> GetAdministratorsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var adminRoles = new[] { OrganizationMemberRole.Owner, OrganizationMemberRole.Admin };

            return await QueryForOrganization(organizationId)
                .Where(m => adminRoles.Contains(m.MemberRole) && m.Status == OrganizationMembershipStatus.Active)
                .AsNoTracking()
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

            // 초대 수락은 상태 수정을 동반하므로 AsNoTracking() 생략
            return await Query()
                .Include(m => m.Organization)
                .Include(m => m.InvitedBy)
                .FirstOrDefaultAsync(m => m.InvitationToken == invitationToken, cancellationToken);
        }
        
        // 💡 [v16.1] 이 메서드는 IOrganizationMembershipRepository 인터페이스에 없습니다.
        // 인터페이스에 추가하거나, 서비스 레이어로 로직을 이동해야 합니다.
        // 우선 UoW 원칙만 적용합니다.
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
            
            // 💡 [v16.1 삭제] UoW 원칙(5번)에 따라 SaveChanges는 서비스 레이어의 책임입니다.
            // await _context.SaveChangesAsync(); 
            return true;
        }

        #endregion

        #region 만료 및 비활성 관리 (AsNoTracking() 추가)

        public async Task<IEnumerable<OrganizationMembership>> GetExpiredMembershipsAsync(
            DateTime asOfDate,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(m => m.ExpiresAt.HasValue &&
                            m.ExpiresAt.Value <= asOfDate &&
                            m.Status == OrganizationMembershipStatus.Active)
                .AsNoTracking()
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
                .AsNoTracking()
                .Include(m => m.Member)
                .OrderBy(m => m.LastActivityAt ?? m.JoinedAt)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 이 메서드는 IOrganizationMembershipRepository 인터페이스에 없습니다.
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
                .AsNoTracking()
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
            // 💡 비용 최적화: 통계 쿼리는 AsNoTracking()이 필요 없습니다.
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active)
                .GroupBy(m => m.MemberRole)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        }
        
        // 💡 [v16.1] 이 메서드는 IOrganizationMembershipRepository 인터페이스에 없습니다.
        public async Task<IEnumerable<OrganizationMembership>> GetRecentMembersAsync(
            Guid organizationId,
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(m => m.Status == OrganizationMembershipStatus.Active)
                .AsNoTracking()
                .Include(m => m.Member)
                .OrderByDescending(m => m.JoinedAt)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        public async Task<int> GetMemberCountAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // 💡 [v16.1] 3. 가격 정책(Pricing) 검증을 위해 서비스 레이어가 이 메서드를 사용합니다.
            // 리포지토리는 정확한 카운트만 제공하면 됩니다.
            return await QueryForOrganization(organizationId)
                .CountAsync(m => m.Status == OrganizationMembershipStatus.Active, cancellationToken);
        }
        #endregion

        #region 멤버십 업데이트 (UoW 수정)

        // 💡 [v16.1] 이 메서드는 IOrganizationMembershipRepository 인터페이스에 없습니다.
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
            
            // 💡 [v16.1 삭제] UoW 원칙(5번)에 따라 SaveChanges는 서비스 레이어의 책임입니다.
            // await _context.SaveChangesAsync();
            return true;
        }

        // 💡 [v16.1] 이 메서드는 IOrganizationMembershipRepository 인터페이스에 없습니다.
        public async Task<bool> UpdateLastActivityAsync(Guid organizationId, Guid connectedId)
        {
            var membership = await GetMembershipAsync(organizationId, connectedId);
            if (membership == null) return false;

            membership.LastActivityAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            
            // 💡 [v16.1 삭제] UoW 원칙(5번)에 따라 SaveChanges는 서비스 레이어의 책임입니다.
            // await _context.SaveChangesAsync();
            return true;
        }

        #endregion
    }
}