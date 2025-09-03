using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 도메인 Repository 구현체 - AuthHive v15
    /// 도메인 소유권 검증, SSL 관리, DNS 설정 등 도메인 관련 모든 데이터 접근을 담당합니다.
    /// </summary>
    public class OrganizationDomainRepository : BaseRepository<OrganizationDomain>, IOrganizationDomainRepository
    {
        public OrganizationDomainRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache) { }

        #region IOrganizationDomainRepository 구현

/// <summary>
       /// 도메인 이름으로 도메인 조회
       /// 사용 시점: 신규 도메인 추가 시 중복 체크, 로그인 시 도메인 기반 조직 식별
       /// </summary>
       public async Task<OrganizationDomain?> GetByDomainAsync(string domain)
       {
           return await _dbSet
               .Include(d => d.Organization)
               .Include(d => d.VerifiedBy)
               .FirstOrDefaultAsync(d => d.Domain == domain && !d.IsDeleted);
       }

       /// <summary>
       /// 도메인 존재 여부 확인
       /// 사용 시점: 빠른 중복 체크가 필요할 때 (UI 실시간 검증 등)
       /// </summary>
       public async Task<bool> IsDomainExistsAsync(string domain)
       {
           return await _dbSet
               .AnyAsync(d => d.Domain == domain && !d.IsDeleted);
       }

       /// <summary>
       /// 검증 토큰으로 도메인 조회
       /// 사용 시점: DNS/TXT 레코드 검증 프로세스, 이메일 검증 링크 처리
       /// </summary>
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
       /// 사용 시점: 검증 실패 시 호출, 브루트포스 공격 방지용 카운터
       /// </summary>
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
               InvalidateCache(domainId); // 캐시 무효화
               return true;
           }
           catch
           {
               return false;
           }
       }

       #endregion

       #region 도메인 타입 및 상태별 조회 (BaseRepository 활용)

       /// <summary>
       /// 검증된 도메인 조회
       /// 사용 시점: 도메인 관리 대시보드, 이메일 발송 가능 도메인 목록 조회
       /// </summary>
       public async Task<IEnumerable<OrganizationDomain>> GetVerifiedDomainsAsync(Guid organizationId)
       {
           return await FindByOrganizationAsync(
               organizationId,
               d => d.IsVerified
           );
       }

       /// <summary>
       /// 활성 도메인 조회
       /// 사용 시점: 현재 사용 가능한 도메인 목록 표시
       /// </summary>
       public async Task<IEnumerable<OrganizationDomain>> GetActiveDomainsAsync(Guid organizationId)
       {
           return await FindByOrganizationAsync(
               organizationId,
               d => d.IsActive
           );
       }

       /// <summary>
       /// 기본(Primary) 도메인 조회
       /// 사용 시점: 기본 이메일 도메인 설정, 메인 웹사이트 URL 결정
       /// </summary>
       public async Task<OrganizationDomain?> GetPrimaryDomainAsync(Guid organizationId)
       {
           var domains = await FindByOrganizationAsync(
               organizationId,
               d => d.DomainType == DomainType.Primary && 
                    d.IsActive && 
                    d.IsVerified
           );
           
           return domains.FirstOrDefault();
       }

       /// <summary>
       /// 도메인 타입별 조회
       /// 사용 시점: Primary/Secondary/Alias 등 타입별 도메인 관리
       /// </summary>
       public async Task<IEnumerable<OrganizationDomain>> GetByTypeAsync(Guid organizationId, DomainType domainType)
       {
           return await FindByOrganizationAsync(
               organizationId,
               d => d.DomainType == domainType
           );
       }

       /// <summary>
       /// SSL이 활성화된 도메인 조회
       /// 사용 시점: SSL 인증서 관리 대시보드
       /// </summary>
       public async Task<IEnumerable<OrganizationDomain>> GetSslEnabledDomainsAsync(Guid organizationId)
       {
           return await FindByOrganizationAsync(
               organizationId,
               d => d.SSLEnabled && d.IsActive
           );
       }

       #endregion

       #region SSL 및 검증 관리 메서드

       /// <summary>
       /// 만료 임박 SSL 인증서 도메인 조회 (전체 조직 대상)
       /// 사용 시점: 배치 작업으로 인증서 갱신 알림 발송
       /// </summary>
       public async Task<IEnumerable<OrganizationDomain>> GetExpiringCertificatesAsync(int daysBeforeExpiry = 30)
       {
           var expiryThreshold = DateTime.UtcNow.AddDays(daysBeforeExpiry);
           
           // 전체 조직을 대상으로 하므로 _dbSet 직접 사용
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
       /// 도메인을 검증됨으로 표시
       /// 사용 시점: DNS/TXT 레코드 검증 성공, 이메일 검증 완료
       /// </summary>
       public async Task<bool> MarkDomainAsVerifiedAsync(
           Guid domainId, 
           Guid verifiedByConnectedId, 
           DateTime? verifiedAt = null)
       {
           var domain = await GetByIdAsync(domainId);
           if (domain == null)
               return false;

           domain.IsVerified = true;
           domain.VerifiedAt = verifiedAt ?? DateTime.UtcNow;
           domain.VerifiedByConnectedId = verifiedByConnectedId;
           domain.VerificationToken = null; // 검증 완료 후 토큰 제거

           await UpdateAsync(domain);
           
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
       /// 사용 시점: Let's Encrypt 갱신, 수동 인증서 업로드
       /// </summary>
       public async Task<bool> UpdateSslCertificateAsync(
           Guid domainId, 
           DateTime certificateExpiry, 
           bool sslEnabled = true)
       {
           var domain = await GetByIdAsync(domainId);
           if (domain == null)
               return false;

           domain.SSLEnabled = sslEnabled;
           domain.CertificateExpiry = certificateExpiry;
           domain.UpdatedAt = DateTime.UtcNow;

           await UpdateAsync(domain);
           
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
       /// 사용 시점: 도메인 임시 비활성화, 재활성화
       /// </summary>
       public async Task<bool> UpdateDomainStatusAsync(
           Guid domainId, 
           bool isActive, 
           Guid updatedByConnectedId)
       {
           var domain = await GetByIdAsync(domainId);
           if (domain == null)
               return false;

           domain.IsActive = isActive;
           domain.UpdatedAt = DateTime.UtcNow;
           domain.UpdatedByConnectedId = updatedByConnectedId;

           await UpdateAsync(domain);
           
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

       #region 정리 및 유지보수 메서드 (배치 작업용)

       /// <summary>
       /// 검증 대기 중인 도메인 조회
       /// 사용 시점: 관리자 대시보드, 검증 재시도 배치 작업
       /// </summary>
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
       /// 과도한 검증 시도가 있는 도메인 조회
       /// 사용 시점: 보안 모니터링, 의심스러운 활동 탐지
       /// </summary>
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
       /// 만료된 검증 토큰 정리
       /// 사용 시점: 일일 배치 작업 (보안 강화)
       /// </summary>
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
               domain.UpdatedAt = DateTime.UtcNow;
               InvalidateCache(domain.Id);
           }

           await _context.SaveChangesAsync();
           return expiredTokenDomains.Count;
       }

       /// <summary>
       /// 비활성 도메인 아카이브
       /// 사용 시점: 월간 정리 배치 작업
       /// </summary>
       public async Task<int> ArchiveInactiveDomainsAsync(int inactiveDays = 90)
       {
           var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
           
           var inactiveDomains = await _dbSet
               .Where(d => (!d.IsVerified || !d.IsActive) && 
                          d.CreatedAt < cutoffDate &&
                          !d.IsDeleted)
               .ToListAsync();

           var timestamp = DateTime.UtcNow;
           foreach (var domain in inactiveDomains)
           {
               domain.IsActive = false;
               domain.UpdatedAt = timestamp;
               InvalidateCache(domain.Id);
           }

           await _context.SaveChangesAsync();
           return inactiveDomains.Count;
       }

       #endregion
   }
}