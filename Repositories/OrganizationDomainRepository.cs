using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 도메인 Repository 구현체 - AuthHive v15
    /// 도메인 소유권 검증, SSL 관리, DNS 설정 등 도메인 관련 모든 데이터 접근을 담당합니다.
    /// </summary>
    public class OrganizationDomainRepository : OrganizationScopedRepository<OrganizationDomain>, IOrganizationDomainRepository
    {
        public OrganizationDomainRepository(AuthDbContext context) : base(context) { }

        #region IOrganizationDomainRepository 구현

        /// <summary>
        /// 도메인 이름으로 도메인 조회
        /// </summary>
        /// <param name="domain">도메인 이름 (예: example.com)</param>
        /// <returns>도메인 엔티티 또는 null</returns>
        public async Task<OrganizationDomain?> GetByDomainAsync(string domain)
        {
            return await _dbSet
                .Include(d => d.Organization)
                .Include(d => d.VerifiedBy)
                .FirstOrDefaultAsync(d => d.Domain == domain && !d.IsDeleted);
        }

        /// <summary>
        /// 도메인 존재 여부 확인
        /// </summary>
        /// <param name="domain">도메인 이름</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> IsDomainExistsAsync(string domain)
        {
            return await _dbSet
                .AnyAsync(d => d.Domain == domain && !d.IsDeleted);
        }

        /// <summary>
        /// 검증 토큰으로 도메인 조회
        /// </summary>
        /// <param name="verificationToken">검증 토큰</param>
        /// <returns>도메인 엔티티 또는 null</returns>
        public async Task<OrganizationDomain?> GetByVerificationTokenAsync(string verificationToken)
        {
            if (string.IsNullOrWhiteSpace(verificationToken))
                return null;

            return await _dbSet
                .Include(d => d.Organization)
                .FirstOrDefaultAsync(d => d.VerificationToken == verificationToken && !d.IsDeleted);
        }

        /// <summary>
        /// 도메인 검증 시도 횟수 증가
        /// </summary>
        /// <param name="domainId">도메인 ID</param>
        /// <returns>증가 성공 여부</returns>
        public async Task<bool> IncrementVerificationAttemptAsync(Guid domainId)
        {
            var domain = await _dbSet.FirstOrDefaultAsync(d => d.Id == domainId && !d.IsDeleted);
            if (domain == null)
                return false;

            domain.VerificationAttemptCount++;
            domain.LastVerificationAttempt = DateTime.UtcNow;

            try
            {
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 추가 조회 메서드들 (Query 기능 통합)

        /// <summary>
        /// 도메인 타입별 도메인 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetByTypeAsync(Guid organizationId, DomainType domainType)
        {
            return await _dbSet
                .Where(d => d.OrganizationId == organizationId && 
                           d.DomainType == domainType && 
                           !d.IsDeleted)
                .OrderBy(d => d.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 검증된 도메인 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetVerifiedDomainsAsync(Guid organizationId)
        {
            return await _dbSet
                .Include(d => d.VerifiedBy)
                .Where(d => d.OrganizationId == organizationId && 
                           d.IsVerified && 
                           !d.IsDeleted)
                .OrderBy(d => d.VerifiedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 활성 도메인 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetActiveDomainsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(d => d.OrganizationId == organizationId && 
                           d.IsActive && 
                           !d.IsDeleted)
                .OrderBy(d => d.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 기본(Primary) 도메인 조회
        /// </summary>
        public async Task<OrganizationDomain?> GetPrimaryDomainAsync(Guid organizationId)
        {
            return await _dbSet
                .FirstOrDefaultAsync(d => d.OrganizationId == organizationId && 
                                         d.DomainType == DomainType.Primary && 
                                         d.IsActive && 
                                         d.IsVerified &&
                                         !d.IsDeleted);
        }

        /// <summary>
        /// 만료 임박 SSL 인증서 도메인 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetExpiringCertificatesAsync(int daysBeforeExpiry = 30)
        {
            var expiryThreshold = DateTime.UtcNow.AddDays(daysBeforeExpiry);
            
            return await _dbSet
                .Include(d => d.Organization)
                .Where(d => d.SSLEnabled && 
                           d.CertificateExpiry.HasValue && 
                           d.CertificateExpiry <= expiryThreshold && 
                           d.IsActive && 
                           !d.IsDeleted)
                .OrderBy(d => d.CertificateExpiry)
                .ToListAsync();
        }

        /// <summary>
        /// SSL이 활성화된 도메인 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetSslEnabledDomainsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(d => d.OrganizationId == organizationId && 
                           d.SSLEnabled && 
                           d.IsActive && 
                           !d.IsDeleted)
                .OrderBy(d => d.CertificateExpiry)
                .ToListAsync();
        }

        #endregion

        #region 추가 도메인 관리 메서드

        /// <summary>
        /// 조직의 활성 도메인 목록 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <returns>활성 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetActiveDomainsByOrganizationAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(d => d.OrganizationId == organizationId && d.IsActive && !d.IsDeleted)
                .OrderBy(d => d.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 조직의 검증된 도메인 목록 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <returns>검증된 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetVerifiedDomainsByOrganizationAsync(Guid organizationId)
        {
            return await _dbSet
                .Include(d => d.VerifiedBy)
                .Where(d => d.OrganizationId == organizationId && d.IsVerified && !d.IsDeleted)
                .OrderBy(d => d.VerifiedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 도메인 타입별 도메인 조회
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="domainType">도메인 타입</param>
        /// <returns>해당 타입의 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetDomainsByTypeAsync(Guid organizationId, DomainType domainType)
        {
            return await _dbSet
                .Where(d => d.OrganizationId == organizationId && 
                           d.DomainType == domainType && 
                           !d.IsDeleted)
                .OrderBy(d => d.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// SSL 인증서 만료 임박 도메인 조회
        /// </summary>
        /// <param name="expiryThresholdDays">만료 임박 임계값 (일)</param>
        /// <returns>만료 임박 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetDomainsWithExpiringSslAsync(int expiryThresholdDays = 30)
        {
            var thresholdDate = DateTime.UtcNow.AddDays(expiryThresholdDays);
            
            return await _dbSet
                .Include(d => d.Organization)
                .Where(d => d.SSLEnabled && 
                           d.CertificateExpiry.HasValue && 
                           d.CertificateExpiry <= thresholdDate && 
                           d.IsActive && 
                           !d.IsDeleted)
                .OrderBy(d => d.CertificateExpiry)
                .ToListAsync();
        }

        /// <summary>
        /// 과도한 검증 시도가 있는 도메인 조회
        /// </summary>
        /// <param name="maxAttempts">최대 허용 시도 횟수</param>
        /// <returns>과도한 시도가 있는 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetDomainsWithExcessiveVerificationAttemptsAsync(int maxAttempts = 5)
        {
            return await _dbSet
                .Include(d => d.Organization)
                .Where(d => d.VerificationAttemptCount > maxAttempts && 
                           !d.IsVerified && 
                           d.IsActive && 
                           !d.IsDeleted)
                .OrderByDescending(d => d.VerificationAttemptCount)
                .ToListAsync();
        }

        /// <summary>
        /// 검증 대기 중인 도메인 조회
        /// </summary>
        /// <param name="maxAgeHours">최대 대기 시간 (시간)</param>
        /// <returns>검증 대기 중인 도메인 목록</returns>
        public async Task<IEnumerable<OrganizationDomain>> GetPendingVerificationDomainsAsync(int maxAgeHours = 24)
        {
            var cutoffDate = DateTime.UtcNow.AddHours(-maxAgeHours);
            
            return await _dbSet
                .Include(d => d.Organization)
                .Where(d => !d.IsVerified && 
                           d.IsActive && 
                           d.CreatedAt >= cutoffDate && 
                           !d.IsDeleted)
                .OrderBy(d => d.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 도메인을 검증됨으로 표시
        /// </summary>
        /// <param name="domainId">도메인 ID</param>
        /// <param name="verifiedByConnectedId">검증한 사용자의 ConnectedId</param>
        /// <param name="verifiedAt">검증 시간 (null이면 현재 시간 사용)</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> MarkDomainAsVerifiedAsync(
            Guid domainId, 
            Guid verifiedByConnectedId, 
            DateTime? verifiedAt = null)
        {
            var domain = await _dbSet.FirstOrDefaultAsync(d => d.Id == domainId && !d.IsDeleted);
            if (domain == null)
                return false;

            domain.IsVerified = true;
            domain.VerifiedAt = verifiedAt ?? DateTime.UtcNow;
            domain.VerifiedByConnectedId = verifiedByConnectedId;

            try
            {
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// SSL 인증서 정보 업데이트
        /// </summary>
        /// <param name="domainId">도메인 ID</param>
        /// <param name="certificateExpiry">인증서 만료 날짜</param>
        /// <param name="sslEnabled">SSL 활성화 여부</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> UpdateSslCertificateAsync(
            Guid domainId, 
            DateTime certificateExpiry, 
            bool sslEnabled = true)
        {
            var domain = await _dbSet.FirstOrDefaultAsync(d => d.Id == domainId && !d.IsDeleted);
            if (domain == null)
                return false;

            domain.SSLEnabled = sslEnabled;
            domain.CertificateExpiry = certificateExpiry;

            try
            {
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 도메인 활성화 상태 업데이트
        /// </summary>
        /// <param name="domainId">도메인 ID</param>
        /// <param name="isActive">활성화 여부</param>
        /// <param name="updatedByConnectedId">업데이트한 사용자의 ConnectedId</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> UpdateDomainStatusAsync(
            Guid domainId, 
            bool isActive, 
            Guid updatedByConnectedId)
        {
            var domain = await _dbSet.FirstOrDefaultAsync(d => d.Id == domainId && !d.IsDeleted);
            if (domain == null)
                return false;

            domain.IsActive = isActive;
            domain.UpdatedAt = DateTime.UtcNow;
            domain.UpdatedByConnectedId = updatedByConnectedId;

            try
            {
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 만료된 검증 토큰 정리
        /// </summary>
        /// <param name="olderThanDays">며칠 이전의 토큰을 정리할지</param>
        /// <returns>정리된 토큰 개수</returns>
        public async Task<int> CleanupExpiredVerificationTokensAsync(int olderThanDays = 7)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            
            var expiredTokenDomains = await _dbSet
                .Where(d => !string.IsNullOrEmpty(d.VerificationToken) && 
                           d.CreatedAt < cutoffDate && 
                           !d.IsVerified &&
                           !d.IsDeleted)
                .ToListAsync();

            foreach (var domain in expiredTokenDomains)
            {
                domain.VerificationToken = null;
            }

            try
            {
                await _context.SaveChangesAsync();
                return expiredTokenDomains.Count;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 비활성 도메인 아카이브
        /// </summary>
        /// <param name="inactiveDays">며칠 동안 비활성 상태인 도메인을 아카이브할지</param>
        /// <returns>아카이브된 도메인 개수</returns>
        public async Task<int> ArchiveInactiveDomainsAsync(int inactiveDays = 90)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            
            var inactiveDomains = await _dbSet
                .Where(d => (!d.IsVerified || !d.IsActive) && 
                           d.CreatedAt < cutoffDate &&
                           !d.IsDeleted)
                .ToListAsync();

            foreach (var domain in inactiveDomains)
            {
                domain.IsActive = false;
                domain.UpdatedAt = DateTime.UtcNow;
            }

            try
            {
                await _context.SaveChangesAsync();
                return inactiveDomains.Count;
            }
            catch
            {
                return 0;
            }
        }

        #endregion
    }
}