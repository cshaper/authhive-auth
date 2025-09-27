using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    public class OrganizationDomainRepository : BaseRepository<OrganizationDomain>, IOrganizationDomainRepository
    {
        // [수정] 자식 클래스에서 직접 사용할 Logger 필드 추가
        private readonly ILogger<OrganizationDomainRepository> _logger;

        // [수정] 생성자 로직 변경
        public OrganizationDomainRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache cache,
            ILogger<OrganizationDomainRepository> logger) 
            : base(context, organizationContext, cache) // <-- 부모에게는 필요한 3개만 전달
        {
            // 자식 클래스에서 사용할 Logger는 여기서 직접 할당
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 도메인 조회

        public async Task<OrganizationDomain?> GetByDomainAsync(string domain)
        {
            var lowerCaseDomain = domain.ToLowerInvariant();
            return await _dbSet.AsNoTracking().FirstOrDefaultAsync(d => d.Domain == lowerCaseDomain);
        }

        public async Task<bool> IsDomainExistsAsync(string domain)
        {
            var lowerCaseDomain = domain.ToLowerInvariant();
            return await _dbSet.AnyAsync(d => d.Domain == lowerCaseDomain);
        }

        public async Task<OrganizationDomain?> GetByVerificationTokenAsync(string verificationToken)
        {
            return await _dbSet.AsNoTracking().FirstOrDefaultAsync(d => d.VerificationToken == verificationToken);
        }

        #endregion

        #region 도메인 상태별 조회

        public async Task<IEnumerable<OrganizationDomain>> GetVerifiedDomainsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId).Where(d => d.IsVerified).AsNoTracking().ToListAsync();
        }

        public async Task<IEnumerable<OrganizationDomain>> GetActiveDomainsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId).Where(d => d.IsActive).AsNoTracking().ToListAsync();
        }

        public async Task<OrganizationDomain?> GetPrimaryDomainAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(d => d.DomainType == DomainType.Primary && d.IsActive);
        }

        public async Task<IEnumerable<OrganizationDomain>> GetByTypeAsync(Guid organizationId, DomainType domainType)
        {
            return await QueryForOrganization(organizationId).Where(d => d.DomainType == domainType).AsNoTracking().ToListAsync();
        }

        public override async Task<IEnumerable<OrganizationDomain>> GetByOrganizationIdAsync(Guid organizationId)
        {
            // 부모의 GetByOrganizationIdAsync가 virtual로 선언되어 있다고 가정하고 override
            return await QueryForOrganization(organizationId).AsNoTracking().ToListAsync();
        }

        #endregion

        #region SSL 관련

        public async Task<IEnumerable<OrganizationDomain>> GetSslEnabledDomainsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId).Where(d => d.SSLEnabled).AsNoTracking().ToListAsync();
        }

        public async Task<IEnumerable<OrganizationDomain>> GetExpiringCertificatesAsync(int daysBeforeExpiry = 30)
        {
            var expiryDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);
            return await _dbSet
                .Where(d => d.SSLEnabled && d.CertificateExpiry.HasValue && d.CertificateExpiry.Value <= expiryDate)
                .AsNoTracking()
                .ToListAsync();
        }

        public async Task<bool> UpdateSslCertificateAsync(Guid domainId, DateTime certificateExpiry, bool sslEnabled = true)
        {
            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.CertificateExpiry, certificateExpiry)
                    .SetProperty(d => d.SSLEnabled, sslEnabled)) > 0;
        }

        #endregion

        #region 도메인 검증 관리

        public async Task<bool> IncrementVerificationAttemptAsync(Guid domainId)
        {
            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.VerificationAttemptCount, d => d.VerificationAttemptCount + 1)
                    .SetProperty(d => d.LastVerificationAttempt, DateTime.UtcNow)) > 0;
        }

        public async Task<bool> MarkDomainAsVerifiedAsync(Guid domainId, Guid verifiedByConnectedId, DateTime? verifiedAt = null)
        {
            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsVerified, true)
                    .SetProperty(d => d.VerifiedAt, verifiedAt ?? DateTime.UtcNow)
                    .SetProperty(d => d.VerifiedByConnectedId, verifiedByConnectedId)
                    .SetProperty(d => d.VerificationToken, (string?)null)) > 0;
        }
        
        public async Task<IEnumerable<OrganizationDomain>> GetPendingVerificationDomainsAsync(int maxAgeHours = 24)
        {
            var cutoffDate = DateTime.UtcNow.AddHours(-maxAgeHours);
            return await _dbSet
                .Where(d => !d.IsVerified && d.CreatedAt >= cutoffDate)
                .AsNoTracking()
                .ToListAsync();
        }

        public async Task<IEnumerable<OrganizationDomain>> GetDomainsWithExcessiveVerificationAttemptsAsync(int maxAttempts = 5)
        {
            return await _dbSet
                .Where(d => !d.IsVerified && d.VerificationAttemptCount >= maxAttempts)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 도메인 상태 관리

        public async Task<bool> UpdateDomainStatusAsync(Guid domainId, bool isActive, Guid updatedByConnectedId)
        {
            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsActive, isActive)) > 0;
        }

        #endregion

        #region 유지보수 및 정리 (배치 작업용)

        public async Task<int> CleanupExpiredVerificationTokensAsync(int olderThanDays = 7)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            return await _dbSet
                .Where(d => !d.IsVerified && d.CreatedAt < cutoffDate)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.VerificationToken, (string?)null));
        }

        public async Task<int> ArchiveInactiveDomainsAsync(int inactiveDays = 90)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            // UpdatedAt이 AuditableEntity에 의해 자동 관리된다고 가정
            return await _dbSet
                .Where(d => d.IsActive && d.UpdatedAt < cutoffDate)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsActive, false));
        }

        #endregion
    }
}