using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 도메인 Repository 구현체.
    /// 사용: 데이터 접근 계층(DAL)으로서, 조직의 도메인과 관련된 모든 데이터베이스 작업을 처리합니다.
    /// </summary>
    public class OrganizationDomainRepository : BaseRepository<OrganizationDomain>, IOrganizationDomainRepository
    {
        private readonly ILogger<OrganizationDomainRepository> _logger;

        /// <summary>
        /// 생성자: 필요한 서비스(DbContext, CacheService, Logger)를 주입받습니다.
        /// 사용: 의존성 주입(DI) 컨테이너가 이 클래스의 인스턴스를 생성할 때 호출됩니다.
        /// </summary>
        public OrganizationDomainRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<OrganizationDomainRepository> logger) 
            : base(context, cacheService) // 현대화된 BaseRepository 생성자 호출
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티가 조직 범위에 속하는지 여부를 결정합니다.
        /// 사용: BaseRepository의 QueryForOrganization 헬퍼 메서드에서 조직 ID 필터링 여부를 판단하는 데 사용됩니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 도메인 조회

        /// <summary>
        /// 도메인 이름(문자열)으로 도메인 정보를 조회합니다. 캐시를 우선 확인합니다.
        /// 사용: 사용자가 이메일/도메인으로 로그인 시 소속 조직을 찾거나, 새 도메인 등록 시 전역 중복을 확인할 때 호출됩니다.
        /// </summary>
        public async Task<OrganizationDomain?> GetByDomainAsync(string domain, CancellationToken cancellationToken = default)
        {
            var lowerCaseDomain = domain.ToLowerInvariant();
            string cacheKey = $"Domain:{lowerCaseDomain}";

            if (_cacheService != null)
            {
                var cachedDomain = await _cacheService.GetAsync<OrganizationDomain>(cacheKey, cancellationToken);
                if (cachedDomain != null) return cachedDomain;
            }

            var domainFromDb = await _dbSet.AsNoTracking().FirstOrDefaultAsync(d => d.Domain == lowerCaseDomain, cancellationToken);

            if (domainFromDb != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, domainFromDb, TimeSpan.FromHours(1), cancellationToken);
            }

            return domainFromDb;
        }

        /// <summary>
        /// 특정 도메인 이름이 시스템에 이미 존재하는지 빠르게 확인합니다.
        /// 사용: 도메인 등록 UI에서 사용자가 도메인 이름을 입력할 때 실시간으로 중복 여부를 알려주는 기능에 사용됩니다.
        /// </summary>
        public async Task<bool> IsDomainExistsAsync(string domain, CancellationToken cancellationToken = default)
        {
            var lowerCaseDomain = domain.ToLowerInvariant();
            return await _dbSet.AnyAsync(d => d.Domain == lowerCaseDomain, cancellationToken);
        }

        /// <summary>
        /// 도메인 소유권 검증에 사용되는 고유 토큰으로 도메인 정보를 조회합니다.
        /// 사용: 사용자가 DNS TXT 레코드를 설정한 후 '검증' 버튼을 클릭했을 때, 시스템이 해당 토큰을 가진 도메인을 찾아 검증을 시도하는 과정에서 호출됩니다.
        /// </summary>
        public async Task<OrganizationDomain?> GetByVerificationTokenAsync(string verificationToken, CancellationToken cancellationToken = default)
        {
            return await _dbSet.AsNoTracking().FirstOrDefaultAsync(d => d.VerificationToken == verificationToken, cancellationToken);
        }

        #endregion

        #region 도메인 상태별 조회

        /// <summary>
        /// 특정 조직에 속한 '검증된(Verified)' 상태의 모든 도메인을 조회합니다.
        /// 사용: 조직 관리 대시보드에서 검증이 완료된 도메인 목록을 보여주거나, 이메일 발송 시 사용 가능한 발신 도메인 목록을 가져올 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetVerifiedDomainsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).Where(d => d.IsVerified).AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직에 속한 '활성(Active)' 상태의 모든 도메인을 조회합니다.
        /// 사용: 사용자가 로그인하거나, 애플리케이션에서 사용할 수 있는 실제 운영 도메인 목록을 표시할 때 호출됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetActiveDomainsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).Where(d => d.IsActive).AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직의 '기본(Primary)' 도메인을 조회합니다. 캐시를 우선 확인합니다.
        /// 사용: 조직의 대표 이메일 주소를 생성하거나, 알림 등에서 기본적으로 사용할 발신 도메인을 결정할 때 사용됩니다.
        /// </summary>
        public async Task<OrganizationDomain?> GetPrimaryDomainAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"PrimaryDomain:{organizationId}";

            if (_cacheService != null)
            {
                var cachedDomain = await _cacheService.GetAsync<OrganizationDomain>(cacheKey, cancellationToken);
                if (cachedDomain != null) return cachedDomain;
            }

            var primaryDomain = await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(d => d.DomainType == DomainType.Primary && d.IsActive, cancellationToken);

            if (primaryDomain != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, primaryDomain, TimeSpan.FromHours(1), cancellationToken);
            }

            return primaryDomain;
        }

        /// <summary>
        /// 특정 조직의 특정 타입(Primary, Secondary 등)에 해당하는 도메인 목록을 조회합니다.
        /// 사용: 도메인 관리 페이지에서 타입별로 도메인을 필터링하여 보여줄 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetByTypeAsync(Guid organizationId, DomainType domainType, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).Where(d => d.DomainType == domainType).AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직에 속한 모든 도메인(삭제된 것 제외)을 조회합니다.
        /// 사용: 조직의 전체 도메인 목록을 표시하는 관리 페이지에서 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).AsNoTracking().ToListAsync(cancellationToken);
        }

        #endregion

        #region SSL 관련

        /// <summary>
        /// 특정 조직의 도메인 중 SSL이 활성화된 도메인 목록을 조회합니다.
        /// 사용: SSL 인증서 관리 대시보드에서 HTTPS가 적용된 도메인 목록을 보여줄 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetSslEnabledDomainsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).Where(d => d.SSLEnabled).AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 전체 조직을 대상으로 SSL 인증서 만료가 임박한 도메인 목록을 조회합니다.
        /// 사용: 자동화된 배치(Batch) 작업에서 주기적으로 실행되어, 만료 예정인 인증서를 감지하고 관리자에게 갱신 알림을 보내는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetExpiringCertificatesAsync(int daysBeforeExpiry = 30, CancellationToken cancellationToken = default)
        {
            var expiryDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);
            return await _dbSet
                .Where(d => d.SSLEnabled && d.CertificateExpiry.HasValue && d.CertificateExpiry.Value <= expiryDate)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 도메인의 SSL 인증서 정보를 업데이트합니다. (만료일, 활성화 상태)
        /// 사용: Let's Encrypt와 같은 자동 갱신 시스템 또는 관리자가 수동으로 인증서를 업데이트한 후 DB 정보를 동기화할 때 호출됩니다.
        /// </summary>
        public async Task<bool> UpdateSslCertificateAsync(Guid domainId, DateTime certificateExpiry, bool sslEnabled = true, CancellationToken cancellationToken = default)
        {
            var domain = await GetByIdAsync(domainId, cancellationToken);
            if (domain != null) await InvalidateDomainCacheAsync(domain, cancellationToken);

            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.CertificateExpiry, certificateExpiry.ToUniversalTime())
                    .SetProperty(d => d.SSLEnabled, sslEnabled),
                    cancellationToken) > 0;
        }

        #endregion

        #region 도메인 검증 관리

        /// <summary>
        /// 특정 도메인의 소유권 검증 시도 횟수를 1 증가시키고, 마지막 시도 시간을 기록합니다.
        /// 사용: 사용자가 도메인 검증을 시도할 때마다 호출되어, 과도한 시도를 막는 로직(Rate Limiting)의 기반 데이터로 사용됩니다.
        /// </summary>
        public async Task<bool> IncrementVerificationAttemptAsync(Guid domainId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.VerificationAttemptCount, d => d.VerificationAttemptCount + 1)
                    .SetProperty(d => d.LastVerificationAttempt, DateTime.UtcNow),
                    cancellationToken) > 0;
        }

        /// <summary>
        /// 특정 도메인을 '검증 완료' 상태로 변경하고 관련 정보를 기록합니다. 검증 토큰은 초기화됩니다.
        /// 사용: DNS TXT 레코드 확인 또는 이메일 링크 클릭 등 도메인 소유권 검증 절차가 성공적으로 완료되었을 때 호출됩니다.
        /// </summary>
        public async Task<bool> MarkDomainAsVerifiedAsync(Guid domainId, Guid verifiedByConnectedId, DateTime? verifiedAt = null, CancellationToken cancellationToken = default)
        {
            var domain = await GetByIdAsync(domainId, cancellationToken);
            if (domain != null) await InvalidateDomainCacheAsync(domain, cancellationToken);

            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsVerified, true)
                    .SetProperty(d => d.VerifiedAt, verifiedAt ?? DateTime.UtcNow)
                    .SetProperty(d => d.VerifiedByConnectedId, verifiedByConnectedId)
                    .SetProperty(d => d.VerificationToken, (string?)null), // 검증 후 토큰 제거
                    cancellationToken) > 0;
        }

        /// <summary>
        /// 생성된 지 일정 시간(기본 24시간)이 지났지만 아직 검증되지 않은 도메인 목록을 조회합니다.
        /// 사용: 관리자 대시보드에서 검증이 지연되고 있는 도메인을 확인하거나, 사용자에게 검증을 독려하는 알림을 보내는 배치 작업에 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetPendingVerificationDomainsAsync(int maxAgeHours = 24, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddHours(-maxAgeHours);
            return await _dbSet
                .Where(d => !d.IsVerified && d.CreatedAt >= cutoffDate)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 설정된 횟수(기본 5회) 이상 검증을 시도했지만 아직 성공하지 못한 도메인 목록을 조회합니다.
        /// 사용: 보안 모니터링 시스템에서 비정상적인 도메인 검증 시도(예: 자동화된 공격)를 탐지하는 데 사용될 수 있습니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDomain>> GetDomainsWithExcessiveVerificationAttemptsAsync(int maxAttempts = 5, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(d => !d.IsVerified && d.VerificationAttemptCount >= maxAttempts)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 도메인 상태 관리

        /// <summary>
        /// 특정 도메인의 활성화(IsActive) 상태를 변경합니다.
        /// 사용: 관리자가 특정 도메인을 통한 서비스 접근을 일시적으로 차단하거나 다시 허용할 때 사용됩니다.
        /// </summary>
        public async Task<bool> UpdateDomainStatusAsync(Guid domainId, bool isActive, Guid updatedByConnectedId, CancellationToken cancellationToken = default)
        {
            var domain = await GetByIdAsync(domainId, cancellationToken);
            if (domain != null) await InvalidateDomainCacheAsync(domain, cancellationToken);

            return await _dbSet
                .Where(d => d.Id == domainId)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsActive, isActive)
                    // UpdatedAt, UpdatedBy 등은 AuditableEntityInterceptor가 처리한다고 가정
                    , cancellationToken) > 0;
        }

        #endregion

        #region 유지보수 및 정리 (배치 작업용)

        /// <summary>
        /// 생성된 지 오래되었지만(기본 7일) 검증되지 않은 도메인들의 검증 토큰을 제거(null 처리)합니다.
        /// 사용: 보안 강화를 위해 주기적인 배치 작업으로 실행되어, 만료된 토큰이 외부에 노출되어 악용될 가능성을 줄입니다.
        /// </summary>
        public async Task<int> CleanupExpiredVerificationTokensAsync(int olderThanDays = 7, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            return await _dbSet
                .Where(d => !d.IsVerified && d.CreatedAt < cutoffDate && d.VerificationToken != null)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.VerificationToken, (string?)null),
                    cancellationToken);
        }

        /// <summary>
        /// 오랫동안(기본 90일) 업데이트되지 않은 활성 도메인을 비활성 상태로 변경합니다. (아카이빙 개념)
        /// 사용: 월간 배치 작업 등에서 실행되어, 더 이상 사용되지 않는 것으로 추정되는 도메인을 정리하고 시스템을 깔끔하게 유지하는 데 사용됩니다.
        /// </summary>
        public async Task<int> ArchiveInactiveDomainsAsync(int inactiveDays = 90, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            // UpdatedAt이 AuditableEntity에 의해 자동 관리된다고 가정
            return await _dbSet
                .Where(d => d.IsActive && d.UpdatedAt < cutoffDate)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(d => d.IsActive, false),
                    cancellationToken);
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 특정 도메인과 관련된 캐시 항목들(도메인 이름 기반, 조직의 기본 도메인)을 무효화합니다.
        /// 사용: 도메인 정보가 변경될 때마다 호출되어 캐시된 낡은 데이터가 사용되는 것을 방지합니다.
        /// </summary>
        private async Task InvalidateDomainCacheAsync(OrganizationDomain domain, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;

            var tasks = new List<Task>();
            tasks.Add(_cacheService.RemoveAsync($"Domain:{domain.Domain.ToLowerInvariant()}", cancellationToken));
            
            // 만약 이 도메인이 Primary 도메인이었다면, 조직의 Primary 도메인 캐시도 무효화해야 함
            if (domain.DomainType == DomainType.Primary)
            {
                tasks.Add(_cacheService.RemoveAsync($"PrimaryDomain:{domain.OrganizationId}", cancellationToken));
            }
            
            try
            {
                await Task.WhenAll(tasks);
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for domain {DomainId}", domain.Id);
                // 캐시 삭제 실패는 전체 로직을 중단시키지 않음
            }
        }

        #endregion
    }
}
