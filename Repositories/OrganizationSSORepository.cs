using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using System.Text.Json;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 SSO 설정 Repository 구현체 - AuthHive v15.5
    /// SSO 설정 관리, 검증, 우선순위 처리 등 SSO 관련 모든 데이터 접근을 담당합니다.
    /// </summary>
    public class OrganizationSSORepository : BaseRepository<OrganizationSSO>, IOrganizationSSORepository
    {
        public OrganizationSSORepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region SSO 고유 조회

        /// <summary>
        /// 조직의 기본 SSO 설정 조회
        /// </summary>
        public async Task<OrganizationSSO?> GetDefaultByOrganizationAsync(Guid organizationId)
        {
            var cacheKey = $"OrgSSO:Default:{organizationId}";
            if (_cache?.TryGetValue(cacheKey, out OrganizationSSO? cached) == true)
            {
                return cached;
            }

            var result = await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .FirstOrDefaultAsync(s => s.IsDefault && s.IsActive);

            if (result != null && _cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        /// <summary>
        /// SSO 타입별 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetByTypeAsync(
            Guid organizationId,
            OSType ssoType,
            bool includeInactive = false)
        {
            var query = QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.SSOType == ssoType);

            if (!includeInactive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 제공자별 조회 (Enum 버전)
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetByProviderAsync(
            Guid organizationId,
            SSOProvider provider)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.ProviderName == provider && s.IsActive)
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 제공자별 조회 (String 버전) - IOrganizationSSORepository 인터페이스 구현
        /// WHO: 인증 서비스, SSO 관리자
        /// WHEN: 특정 Provider의 SSO 설정 필요 시
        /// WHERE: Admin Dashboard, 인증 플로우
        /// WHAT: Provider명으로 SSO 검색
        /// WHY: Provider별 설정 관리 및 라우팅
        /// HOW: ProviderName enum 매칭
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetByProviderAsync(
            Guid organizationId,
            string provider,
            bool includeInactive = false)
        {
            // String을 SSOProvider enum으로 변환
            if (!Enum.TryParse<SSOProvider>(provider, true, out var ssoProvider))
            {
                return new List<OrganizationSSO>();
            }

            var query = QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Where(s => s.ProviderName == ssoProvider);

            if (!includeInactive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 도메인 기반 SSO 조회
        /// WHO: 인증 라우터, Proxy 서비스
        /// WHEN: 사용자가 도메인으로 접근 시
        /// WHERE: AuthHive.Proxy 도메인 라우팅
        /// WHAT: 도메인과 매칭되는 SSO 검색
        /// WHY: 도메인별 자동 SSO 선택
        /// HOW: Configuration JSON에서 도메인 검색
        /// </summary>
        public async Task<OrganizationSSO?> GetByDomainAsync(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return null;

            var normalizedDomain = domain.Trim().ToLower();

            // Configuration 필드에 도메인 정보가 포함되어 있다고 가정
            var ssos = await _dbSet
                .Include(s => s.Organization)
                .Where(s => s.IsActive && !s.IsDeleted)
                .AsNoTracking()
                .ToListAsync();

            // 메모리에서 Configuration JSON 파싱하여 도메인 매칭
            foreach (var sso in ssos)
            {
                if (string.IsNullOrWhiteSpace(sso.Configuration))
                    continue;

                try
                {
                    var config = JsonDocument.Parse(sso.Configuration);
                    if (config.RootElement.TryGetProperty("allowedDomains", out var domainsElement))
                    {
                        if (domainsElement.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var domainElement in domainsElement.EnumerateArray())
                            {
                                if (domainElement.GetString()?.ToLower() == normalizedDomain)
                                {
                                    config.Dispose();
                                    return sso;
                                }
                            }
                        }
                    }
                    config.Dispose();
                }
                catch
                {
                    continue;
                }
            }

            return null;
        }

        #endregion

        #region 활성 상태 관리

        /// <summary>
        /// 활성 SSO 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetActiveByOrganizationAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.IsActive)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.CreatedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 우선순위 순으로 정렬된 SSO 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetByPriorityAsync(
            Guid organizationId,
            bool onlyActive = true)
        {
            var query = QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .AsQueryable();

            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query
                .OrderBy(s => s.Priority)
                .ThenByDescending(s => s.IsDefault)
                .ThenBy(s => s.CreatedAt)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region 검증 및 테스트

        /// <summary>
        /// 테스트가 필요한 SSO 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetRequiringTestAsync(int daysSinceLastTest = 30)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysSinceLastTest);

            return await _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive &&
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || s.LastTestedAt < cutoffDate))
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
                .ThenBy(s => s.OrganizationId)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 테스트 실패한 SSO 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetFailedTestsAsync(Guid? organizationId = null)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-60);

            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive &&
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || s.LastTestedAt < cutoffDate));

            if (organizationId.HasValue)
            {
                query = query.Where(s => s.OrganizationId == organizationId.Value);
            }

            return await query
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// SSO 설정 유효성 검증
        /// WHO: SSO 설정 저장 프로세스
        /// WHEN: Create/Update 전 검증
        /// WHERE: Service 계층
        /// WHAT: 메타데이터, 필수 필드 검증
        /// WHY: 잘못된 설정으로 인한 인증 실패 방지
        /// HOW: 비즈니스 규칙 적용
        /// </summary>
        public async Task<bool> ValidateConfigurationAsync(OrganizationSSO sso)
        {
            if (sso == null) return false;

            if (sso.OrganizationId == Guid.Empty) return false;

            // 중복 검증 (같은 조직에 동일한 Provider+DisplayName)
            var existing = await _dbSet
                .Where(s => s.OrganizationId == sso.OrganizationId &&
                           s.ProviderName == sso.ProviderName &&
                           s.DisplayName == sso.DisplayName &&
                           s.Id != sso.Id &&
                           !s.IsDeleted)
                .AnyAsync();

            if (existing) return false;

            // Configuration JSON 검증
            if (!string.IsNullOrWhiteSpace(sso.Configuration))
            {
                try
                {
                    var jsonDoc = JsonDocument.Parse(sso.Configuration);
                    jsonDoc.Dispose();
                }
                catch
                {
                    return false;
                }
            }

            return true;
        }

        #endregion

        #region 기본 설정 관리

        /// <summary>
        /// 조직의 다른 SSO를 기본이 아닌 것으로 설정
        /// </summary>
        public async Task<int> UnsetDefaultExceptAsync(Guid organizationId, Guid excludeSsoId)
        {
            if (_cache != null)
            {
                _cache.Remove($"OrgSSO:Default:{organizationId}");
            }

            var ssoToUpdate = await _dbSet
                .Where(s => s.OrganizationId == organizationId &&
                           s.Id != excludeSsoId &&
                           s.IsDefault &&
                           !s.IsDeleted)
                .ToListAsync();

            if (ssoToUpdate.Count == 0)
            {
                return 0;
            }

            foreach (var sso in ssoToUpdate)
            {
                sso.IsDefault = false;
                sso.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            return ssoToUpdate.Count;
        }

        #endregion

        #region Cache Management

        /// <summary>
        /// 캐시에서 SSO 설정 조회
        /// WHO: 고빈도 인증 요청
        /// WHEN: 매 로그인 시도
        /// WHERE: AuthHive.Auth 인증 플로우
        /// WHAT: Redis 캐시된 SSO 설정
        /// WHY: DB 부하 감소, 응답 속도 향상
        /// HOW: Redis GET with TTL management
        /// </summary>
        public async Task<OrganizationSSO?> GetFromCacheAsync(Guid ssoId)
        {
            if (_cache == null) return null;

            var cacheKey = $"OrgSSO:{ssoId}";
            if (_cache.TryGetValue(cacheKey, out OrganizationSSO? cached))
            {
                return cached;
            }

            var sso = await GetByIdAsync(ssoId);
            if (sso != null)
            {
                _cache.Set(cacheKey, sso, TimeSpan.FromMinutes(10));
            }

            return sso;
        }

        /// <summary>
        /// 조직의 SSO 캐시 무효화
        /// WHO: SSO 설정 변경 프로세스
        /// WHEN: SSO Create/Update/Delete
        /// WHERE: OrganizationSSOService
        /// WHAT: Redis 캐시 엔트리 삭제
        /// WHY: 캐시 일관성 보장
        /// HOW: Redis DEL pattern matching
        /// </summary>
        public async Task InvalidateCacheAsync(Guid organizationId)
        {
            if (_cache == null) return;

            _cache.Remove($"OrgSSO:Default:{organizationId}");
            _cache.Remove($"OrgSSO:List:{organizationId}");
            _cache.Remove($"OrgSSO:Active:{organizationId}");

            var ssos = await QueryForOrganization(organizationId).ToListAsync();
            foreach (var sso in ssos)
            {
                _cache.Remove($"OrgSSO:{sso.Id}");
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// SSO 설정을 캐시에 저장
        /// WHO: SSO 조회 후 자동
        /// WHEN: Cache miss 후 DB 조회 시
        /// WHERE: Repository 조회 메서드
        /// WHAT: SSO 객체 직렬화 후 저장
        /// WHY: 후속 요청 성능 향상
        /// HOW: Redis SET with 1시간 TTL
        /// </summary>
        public async Task SetCacheAsync(OrganizationSSO sso, TimeSpan? expiry = null)
        {
            if (_cache == null || sso == null) return;

            var cacheKey = $"OrgSSO:{sso.Id}";
            var cacheExpiry = expiry ?? TimeSpan.FromMinutes(10);
            _cache.Set(cacheKey, sso, cacheExpiry);

            await Task.CompletedTask;
        }

        #endregion

        #region Audit and Compliance

        /// <summary>
        /// SSO 변경 이력 조회
        /// WHO: 보안 감사자, Compliance 팀
        /// WHEN: 보안 감사, 인시던트 조사
        /// WHERE: Audit Dashboard
        /// WHAT: SSO 설정 변경 로그
        /// WHY: 규정 준수, 변경 추적
        /// HOW: AuditLog 테이블 JOIN
        /// </summary>
        public async Task<IEnumerable<SSOAuditLog>> GetAuditLogsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            // TODO: 실제 AuditLog 테이블과 JOIN 구현
            return await Task.FromResult(new List<SSOAuditLog>());
        }

        /// <summary>
        /// SSO 사용 통계 조회
        /// WHO: 조직 관리자, 분석팀
        /// WHEN: 월간 리포트
        /// WHERE: Analytics Dashboard
        /// WHAT: 로그인 통계, 성공률
        /// WHY: SSO 효율성 분석
        /// HOW: SessionActivityLog 집계
        /// </summary>
        public async Task<SSOUsageStatistics> GetUsageStatisticsAsync(
            Guid ssoId,
            DateTime startDate,
            DateTime endDate)
        {
            // TODO: 실제 로그 테이블에서 집계
            return await Task.FromResult(new SSOUsageStatistics
            {
                TotalLogins = 0,
                SuccessfulLogins = 0,
                FailedLogins = 0,
                UniqueUsers = 0,
                LastUsedAt = DateTime.UtcNow
            });
        }

        #endregion

        #region Statistics


        /// <summary>
        /// SSO 타입별 사용 통계
        /// </summary>
        public async Task<Dictionary<OSType, int>> GetTypeStatisticsAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.SSOType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Type, s => s.Count);
        }

        /// <summary>
        /// Provider별 사용 통계 - IOrganizationSSORepository 인터페이스 구현
        /// WHO: 플랫폼 관리자
        /// WHEN: 통계 리포트 생성
        /// WHERE: Analytics Dashboard
        /// WHAT: Provider별 SSO 사용 현황
        /// WHY: 플랫폼 사용 패턴 분석
        /// HOW: GROUP BY ProviderName
        /// </summary>
        public async Task<Dictionary<string, int>> GetProviderStatisticsAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.ProviderName)
                .Select(g => new
                {
                    Provider = g.Key.ToString(),
                    Count = g.Count()
                })
                .ToListAsync();

            return statistics.ToDictionary(
                s => s.Provider ?? "Unknown",
                s => s.Count);
        }

        /// <summary>
        /// 제공자별 사용 통계 (Enum 버전) - 내부 사용
        /// </summary>
        public async Task<Dictionary<SSOProvider, int>> GetProviderStatisticsEnumAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.ProviderName)
                .Select(g => new { Provider = g.Key, Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Provider, s => s.Count);
        }

        /// <summary>
        /// Provider별 사용 통계 (String 버전) - 메서드 오버로드 제거
        /// </summary>
        public async Task<Dictionary<string, int>> GetProviderStatisticsStringAsync()
        {
            var statistics = await _dbSet
                .Where(s => s.IsActive && !s.IsDeleted)
                .GroupBy(s => s.ProviderName)
                .Select(g => new { Provider = g.Key.ToString(), Count = g.Count() })
                .ToListAsync();

            return statistics.ToDictionary(s => s.Provider, s => s.Count);
        }

        /// <summary>
        /// SSO 장애율 통계
        /// WHO: SRE 팀, 모니터링 시스템
        /// WHEN: SLA 리포트, 장애 분석
        /// WHERE: Monitoring Dashboard
        /// WHAT: Provider별 실패율
        /// WHY: SLA 관리, 안정성 개선
        /// HOW: FailureCount / TotalAttempts
        /// </summary>
        public async Task<Dictionary<string, double>> GetFailureRateStatisticsAsync(
            DateTime startDate,
            DateTime endDate)
        {
            // TODO: 실제 로그 테이블에서 집계
            return await Task.FromResult(new Dictionary<string, double>());
        }

        /// <summary>
        /// 조직별 SSO 통계
        /// WHO: 플랫폼 관리자
        /// WHEN: 전체 플랫폼 분석
        /// WHERE: Platform Analytics
        /// WHAT: 조직당 SSO 개수, 활성화 비율
        /// WHY: 플랫폼 사용 패턴 파악
        /// HOW: GROUP BY OrganizationId
        /// </summary>
        public async Task<Dictionary<Guid, SSOOrganizationStats>> GetOrganizationStatisticsAsync()
        {
            var statistics = await _dbSet
                .Where(s => !s.IsDeleted)
                .GroupBy(s => s.OrganizationId)
                .Select(g => new SSOOrganizationStats
                {
                    OrganizationId = g.Key,
                    TotalSSOCount = g.Count(),
                    ActiveSSOCount = g.Count(s => s.IsActive),
                    HasFailedSSO = g.Any(s => s.LastTestedAt != null && s.LastTestedAt < DateTime.UtcNow.AddDays(-60))
                })
                .ToListAsync();

            return statistics.ToDictionary(s => s.OrganizationId, s => s);
        }

        #endregion

        #region Bulk Operations

        /// <summary>
        /// 여러 조직의 SSO 설정 일괄 조회
        /// WHO: 플랫폼 관리자, 마이그레이션 도구
        /// WHEN: 대량 데이터 처리
        /// WHERE: Admin Tools
        /// WHAT: 복수 조직의 SSO 설정
        /// WHY: 일괄 처리 효율성
        /// HOW: WHERE OrganizationId IN
        /// </summary>
        public async Task<Dictionary<Guid, IEnumerable<OrganizationSSO>>> GetByOrganizationsAsync(
            IEnumerable<Guid> organizationIds)
        {
            var orgIdsList = organizationIds.ToList();
            var ssos = await _dbSet
                .Where(s => orgIdsList.Contains(s.OrganizationId) && !s.IsDeleted)
                .Include(s => s.Organization)
                .AsNoTracking()
                .ToListAsync();

            return ssos.GroupBy(s => s.OrganizationId)
                       .ToDictionary(g => g.Key, g => g.AsEnumerable());
        }

        /// <summary>
        /// 만료 예정 인증서를 가진 SSO 조회
        /// WHO: 보안 팀, Alert 시스템
        /// WHEN: 일일 체크
        /// WHERE: Certificate Management
        /// WHAT: 30일 내 만료 인증서
        /// WHY: 인증서 만료 사전 방지
        /// HOW: Configuration JSON 파싱 및 만료일 체크
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> GetExpiringCertificatesAsync(int daysBeforeExpiry = 30)
        {
            // TODO: Configuration JSON에서 인증서 정보 파싱하여 만료일 체크
            var cutoffDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);

            return await _dbSet
                .Where(s => s.IsActive &&
                           !s.IsDeleted &&
                           s.Configuration != null)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion

        #region Additional Utility Methods

        /// <summary>
        /// SSO 테스트 상태 업데이트
        /// </summary>
        public async Task<bool> UpdateTestStatusAsync(
            Guid ssoId,
            Guid testedByConnectedId,
            DateTime? testedAt = null)
        {
            var sso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted);
            if (sso == null)
                return false;

            sso.LastTestedAt = testedAt ?? DateTime.UtcNow;
            sso.LastTestedByConnectedId = testedByConnectedId;
            sso.UpdatedAt = DateTime.UtcNow;
            sso.UpdatedByConnectedId = testedByConnectedId;

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
        /// 기본 SSO 설정 변경
        /// </summary>
        public async Task<bool> SetAsDefaultAsync(Guid ssoId, Guid updatedByConnectedId)
        {
            var newDefaultSso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted);
            if (newDefaultSso == null)
                return false;

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                await UnsetDefaultExceptAsync(newDefaultSso.OrganizationId, ssoId);

                newDefaultSso.IsDefault = true;
                newDefaultSso.UpdatedAt = DateTime.UtcNow;
                newDefaultSso.UpdatedByConnectedId = updatedByConnectedId;

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                if (_cache != null)
                {
                    var cacheKey = $"OrgSSO:Default:{newDefaultSso.OrganizationId}";
                    _cache.Set(cacheKey, newDefaultSso, TimeSpan.FromMinutes(10));
                }

                return true;
            }
            catch
            {
                await transaction.RollbackAsync();
                return false;
            }
        }

        /// <summary>
        /// 조직의 SSO 설정 개수 조회
        /// </summary>
        public async Task<int> GetCountByOrganizationAsync(Guid organizationId, bool onlyActive = true)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId && !s.IsDeleted);

            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 표시 이름으로 SSO 검색
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> SearchByDisplayNameAsync(
            Guid organizationId,
            string displayName)
        {
            if (string.IsNullOrWhiteSpace(displayName))
            {
                return await GetActiveByOrganizationAsync(organizationId);
            }

            var searchTerm = displayName.Trim().ToLower();

            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.IsActive &&
                           s.DisplayName != null &&
                           s.DisplayName.ToLower().Contains(searchTerm))
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync();
        }

        #endregion
    }
}