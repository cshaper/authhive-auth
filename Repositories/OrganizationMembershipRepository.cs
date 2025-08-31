// Path: AuthHive.Auth/Repositories/OrganizationMembershipRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationMembership Repository 구현체 - AuthHive v15
    /// 조직 멤버십의 CRUD 및 관계 관리를 담당합니다.
    /// </summary>
    public class OrganizationMembershipRepository : OrganizationScopedRepository<OrganizationMembership>, IOrganizationMembershipRepository
    {
        public OrganizationMembershipRepository(AuthDbContext context) : base(context)
        {
        }

        #region IOrganizationMembershipRepository 구현

        /// <summary>
        /// 조직의 모든 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersAsync(Guid organizationId, bool includeInactive = false)
        {
            var query = _dbSet.Where(m => m.OrganizationId == organizationId && !m.IsDeleted);

            if (!includeInactive)
            {
                query = query.Where(m => m.Status == OrganizationMembershipStatus.Active);
            }

            return await query
                .Include(m => m.Member) // ConnectedId 정보 포함
                .Include(m => m.InvitedBy)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 상태별 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByStatusAsync(Guid organizationId, OrganizationMembershipStatus status)
        {
            return await _dbSet
                .Where(m => m.OrganizationId == organizationId && 
                           m.Status == status && 
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 역할별 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByRoleAsync(Guid organizationId, OrganizationMemberRole role)
        {
            return await _dbSet
                .Where(m => m.OrganizationId == organizationId && 
                           m.MemberRole == role.ToString() && 
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// ConnectedId가 속한 모든 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetOrganizationsForConnectedIdAsync(Guid connectedId, bool includeInactive = false)
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

        /// <summary>
        /// 특정 멤버십 조회
        /// </summary>
        public async Task<OrganizationMembership?> GetMembershipAsync(Guid organizationId, Guid connectedId)
        {
            return await _dbSet
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .FirstOrDefaultAsync(m => 
                    m.OrganizationId == organizationId && 
                    m.ConnectedId == connectedId && 
                    !m.IsDeleted);
        }

        /// <summary>
        /// 멤버십 존재 여부 확인
        /// </summary>
        public async Task<bool> IsMemberAsync(Guid organizationId, Guid connectedId)
        {
            return await _dbSet.AnyAsync(m => 
                m.OrganizationId == organizationId && 
                m.ConnectedId == connectedId && 
                m.Status == OrganizationMembershipStatus.Active &&
                !m.IsDeleted);
        }

        /// <summary>
        /// 초대 토큰으로 멤버십 조회
        /// </summary>
        public async Task<OrganizationMembership?> GetByInvitationTokenAsync(string invitationToken)
        {
            return await _dbSet
                .Include(m => m.Organization)
                .Include(m => m.InvitedBy)
                .FirstOrDefaultAsync(m => 
                    m.InvitationToken == invitationToken && 
                    !m.IsDeleted);
        }

        /// <summary>
        /// 만료된 멤버십 조회
        /// </summary>
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

        /// <summary>
        /// 비활성 멤버 조회 (특정 기간 동안 활동 없음)
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetInactiveMembersAsync(Guid organizationId, int inactiveDays)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await _dbSet
                .Where(m => m.OrganizationId == organizationId &&
                           m.Status == OrganizationMembershipStatus.Active &&
                           (m.LastActivityAt == null || m.LastActivityAt < cutoffDate) &&
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderBy(m => m.LastActivityAt ?? m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 멤버십 타입별 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByTypeAsync(Guid organizationId, OrganizationMembershipType membershipType)
        {
            return await _dbSet
                .Where(m => m.OrganizationId == organizationId && 
                           m.MembershipType == membershipType &&
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderBy(m => m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 관리자 권한을 가진 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetAdministratorsAsync(Guid organizationId)
        {
            var adminRoles = new[] { "Owner", "Admin", "Manager" };

            return await _dbSet
                .Where(m => m.OrganizationId == organizationId &&
                           adminRoles.Contains(m.MemberRole) &&
                           m.Status == OrganizationMembershipStatus.Active &&
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderBy(m => m.MemberRole) // Owner, Admin, Manager 순서
                .ThenBy(m => m.JoinedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 역할별 멤버 수 통계
        /// </summary>
        public async Task<Dictionary<OrganizationMemberRole, int>> GetMemberCountByRoleAsync(Guid organizationId)
        {
            var result = new Dictionary<OrganizationMemberRole, int>();

            var roleStats = await _dbSet
                .Where(m => m.OrganizationId == organizationId && 
                           m.Status == OrganizationMembershipStatus.Active &&
                           !m.IsDeleted)
                .GroupBy(m => m.MemberRole)
                .Select(g => new { Role = g.Key, Count = g.Count() })
                .ToListAsync();

            foreach (var stat in roleStats)
            {
                if (Enum.TryParse<OrganizationMemberRole>(stat.Role, out var roleEnum))
                {
                    result[roleEnum] = stat.Count;
                }
            }

            return result;
        }

        #endregion

        #region 추가 유틸리티 메서드

        /// <summary>
        /// 특정 ConnectedId의 조직 내 역할 조회
        /// </summary>
        public async Task<string?> GetMemberRoleAsync(Guid organizationId, Guid connectedId)
        {
            var membership = await _dbSet
                .FirstOrDefaultAsync(m => 
                    m.OrganizationId == organizationId && 
                    m.ConnectedId == connectedId && 
                    m.Status == OrganizationMembershipStatus.Active &&
                    !m.IsDeleted);

            return membership?.MemberRole;
        }

        /// <summary>
        /// 멤버의 권한 레벨 조회
        /// </summary>
        public async Task<int?> GetMemberAccessLevelAsync(Guid organizationId, Guid connectedId)
        {
            var membership = await _dbSet
                .FirstOrDefaultAsync(m => 
                    m.OrganizationId == organizationId && 
                    m.ConnectedId == connectedId && 
                    m.Status == OrganizationMembershipStatus.Active &&
                    !m.IsDeleted);

            return membership?.AccessLevel;
        }

        /// <summary>
        /// 멤버십 상태 업데이트
        /// </summary>
        public async Task<bool> UpdateMemberStatusAsync(Guid organizationId, Guid connectedId, OrganizationMembershipStatus status, Guid? updatedByConnectedId = null)
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
            return true;
        }

        /// <summary>
        /// 마지막 활동 시간 업데이트
        /// </summary>
        public async Task<bool> UpdateLastActivityAsync(Guid organizationId, Guid connectedId)
        {
            var membership = await _dbSet
                .FirstOrDefaultAsync(m => 
                    m.OrganizationId == organizationId && 
                    m.ConnectedId == connectedId && 
                    !m.IsDeleted);

            if (membership == null) return false;

            membership.LastActivityAt = DateTime.UtcNow;
            
            _dbSet.Update(membership);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 초대 토큰 생성 및 설정
        /// </summary>
        public async Task<string> GenerateInvitationTokenAsync(Guid organizationId, Guid connectedId, Guid invitedByConnectedId)
        {
            var membership = await GetMembershipAsync(organizationId, connectedId);
            if (membership == null) throw new InvalidOperationException("Membership not found");

            var token = Guid.NewGuid().ToString("N")[..16]; // 16자리 토큰
            
            membership.InvitationToken = token;
            membership.InvitedByConnectedId = invitedByConnectedId;
            membership.Status = OrganizationMembershipStatus.Invited;
            membership.UpdatedByConnectedId = invitedByConnectedId;
            membership.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            return token;
        }

        /// <summary>
        /// 초대 수락
        /// </summary>
        public async Task<bool> AcceptInvitationAsync(string invitationToken, Guid connectedId)
        {
            var membership = await GetByInvitationTokenAsync(invitationToken);
            if (membership == null || membership.ConnectedId != connectedId) return false;

            membership.Status = OrganizationMembershipStatus.Active;
            membership.AcceptedAt = DateTime.UtcNow;
            membership.InvitationToken = null; // 토큰 무효화
            membership.UpdatedByConnectedId = connectedId;
            membership.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            return true;
        }

        /// <summary>
        /// 조직별 멤버 수 조회
        /// </summary>
        public async Task<int> GetMemberCountAsync(Guid organizationId, OrganizationMembershipStatus? status = null)
        {
            var query = _dbSet.Where(m => m.OrganizationId == organizationId && !m.IsDeleted);

            if (status.HasValue)
            {
                query = query.Where(m => m.Status == status.Value);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 멤버십 일괄 상태 변경
        /// </summary>
        public async Task<int> BulkUpdateStatusAsync(IEnumerable<Guid> membershipIds, OrganizationMembershipStatus status, Guid? updatedByConnectedId = null)
        {
            var memberships = await _dbSet
                .Where(m => membershipIds.Contains(m.Id) && !m.IsDeleted)
                .ToListAsync();

            var timestamp = DateTime.UtcNow;
            foreach (var membership in memberships)
            {
                membership.Status = status;
                membership.UpdatedByConnectedId = updatedByConnectedId;
                membership.UpdatedAt = timestamp;

                if (status == OrganizationMembershipStatus.Inactive)
                {
                    membership.DeactivatedAt = timestamp;
                    membership.DeactivatedByConnectedId = updatedByConnectedId;
                }
            }

            _dbSet.UpdateRange(memberships);
            await _context.SaveChangesAsync();

            return memberships.Count;
        }

        /// <summary>
        /// 만료 임박 멤버십 조회 (만료 N일 전)
        /// </summary>
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

        /// <summary>
        /// 최근 가입한 멤버들 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetRecentMembersAsync(Guid organizationId, int count = 10)
        {
            return await _dbSet
                .Where(m => m.OrganizationId == organizationId && 
                           m.Status == OrganizationMembershipStatus.Active &&
                           !m.IsDeleted)
                .Include(m => m.Member)
                .OrderByDescending(m => m.JoinedAt)
                .Take(count)
                .ToListAsync();
        }

        #endregion
    }
}