using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Base;

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

        /// <summary>
        /// 조직의 모든 멤버 조회
        /// 사용 시점: 멤버 목록 페이지, 권한 관리 대시보드
        /// </summary>
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

        /// <summary>
        /// 특정 멤버십 조회
        /// 사용 시점: 멤버 상세 정보 조회, 권한 검증
        /// </summary>
        public async Task<OrganizationMembership?> GetMembershipAsync(
            Guid organizationId, 
            Guid connectedId)
        {
            return await QueryForOrganization(organizationId)
                .Include(m => m.Member)
                .Include(m => m.Organization)
                .FirstOrDefaultAsync(m => m.ConnectedId == connectedId);
        }

        /// <summary>
        /// 멤버십 존재 여부 확인
        /// 사용 시점: API 권한 검증, 빠른 멤버십 체크
        /// </summary>
        public async Task<bool> IsMemberAsync(Guid organizationId, Guid connectedId)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(m => 
                    m.ConnectedId == connectedId && 
                    m.Status == OrganizationMembershipStatus.Active);
        }

        /// <summary>
        /// ConnectedId가 속한 모든 조직 조회
        /// 사용 시점: 조직 전환 UI, 사용자 대시보드
        /// </summary>
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

        /// <summary>
        /// 상태별 멤버 조회
        /// 사용 시점: 초대 대기 목록, 비활성 멤버 관리
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByStatusAsync(
            Guid organizationId, 
            OrganizationMembershipStatus status)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.Status == status
            );
        }

        /// <summary>
        /// 역할별 멤버 조회
        /// 사용 시점: 역할 기반 알림, 권한 그룹 관리
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByRoleAsync(
            Guid organizationId, 
            OrganizationMemberRole role)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.MemberRole == role.ToString()
            );
        }

        /// <summary>
        /// 멤버십 타입별 조회
        /// 사용 시점: 정규직/계약직 구분, 외부 협력자 관리
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetMembersByTypeAsync(
            Guid organizationId, 
            OrganizationMembershipType membershipType)
        {
            return await FindByOrganizationAsync(
                organizationId,
                m => m.MembershipType == membershipType
            );
        }

        /// <summary>
        /// 관리자 권한을 가진 멤버 조회
        /// 사용 시점: 긴급 연락처 목록, 승인 권한자 목록
        /// </summary>
        public async Task<IEnumerable<OrganizationMembership>> GetAdministratorsAsync(Guid organizationId)
        {
            var adminRoles = new[] { "Owner", "Admin", "Manager" };

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

        /// <summary>
        /// 초대 토큰으로 멤버십 조회
        /// 사용 시점: 초대 링크 클릭, 이메일 초대 수락
        /// </summary>
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

        /// <summary>
        /// 초대 수락
        /// 사용 시점: 초대 링크 확인 후 가입 완료
        /// </summary>
        public async Task<bool> AcceptInvitationAsync(string invitationToken, Guid connectedId)
        {
            var membership = await GetByInvitationTokenAsync(invitationToken);
            if (membership == null || membership.ConnectedId != connectedId) 
                return false;

            membership.Status = OrganizationMembershipStatus.Active;
            membership.AcceptedAt = DateTime.UtcNow;
            membership.InvitationToken = null; // 토큰 무효화
            membership.UpdatedByConnectedId = connectedId;
            membership.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(membership);
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion

        #region 만료 및 비활성 관리

        /// <summary>
        /// 만료된 멤버십 조회
        /// 사용 시점: 일일 배치 작업으로 만료 처리
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
        /// 비활성 멤버 조회
        /// 사용 시점: 장기 미접속자 관리, 라이선스 최적화
        /// </summary>
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

        /// <summary>
        /// 만료 임박 멤버십 조회
        /// 사용 시점: 갱신 알림 발송, 만료 예고
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

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 역할별 멤버 수 통계
        /// 사용 시점: 대시보드 통계, 조직 구조 분석
        /// </summary>
        public async Task<Dictionary<OrganizationMemberRole, int>> GetMemberCountByRoleAsync(Guid organizationId)
        {
            var roleStats = await GetGroupCountAsync(
                m => m.MemberRole,
                m => m.OrganizationId == organizationId && 
                     m.Status == OrganizationMembershipStatus.Active
            );

            var result = new Dictionary<OrganizationMemberRole, int>();
            foreach (var stat in roleStats)
            {
                if (Enum.TryParse<OrganizationMemberRole>(stat.Key, out var roleEnum))
                {
                    result[roleEnum] = stat.Value;
                }
            }

            return result;
        }

        /// <summary>
        /// 최근 가입한 멤버들 조회
        /// 사용 시점: 신규 멤버 온보딩, 활동 로그
        /// </summary>
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

        #endregion

        #region 멤버십 업데이트

        /// <summary>
        /// 멤버십 상태 업데이트
        /// 사용 시점: 활성화/비활성화, 일시 정지
        /// </summary>
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

        /// <summary>
        /// 마지막 활동 시간 업데이트
        /// 사용 시점: API 호출 시, 로그인 시
        /// </summary>
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