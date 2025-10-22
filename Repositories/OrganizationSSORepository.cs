using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using static AuthHive.Core.Enums.Auth.SessionEnums;
using System.Text.Json;
// DTO 참조 제거
// using AuthHive.Core.Models.Organization.Responses;
// IOrganizationContext 참조 제거
// using AuthHive.Core.Interfaces.Organization.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 SSO 설정 Repository 구현체 - AuthHive v16
    /// [FIXED] BaseRepository 상속 및 ICacheService 사용, 비즈니스 로직 제거
    /// </summary>
    public class OrganizationSSORepository : BaseRepository<OrganizationSSO>, IOrganizationSSORepository
    {
        public OrganizationSSORepository(
            AuthDbContext context,
            ICacheService? cacheService = null) // IOrganizationContext 제거, IMemoryCache -> ICacheService
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
        }

        protected override bool IsOrganizationScopedEntity() => true; // SSO 설정은 조직 범위

        #region SSO 고유 조회

        public async Task<OrganizationSSO?> GetDefaultByOrganizationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"OrgSSO:Default:{organizationId}";
            if (_cacheService != null) // _cache -> _cacheService
            {
                // TryGetValue -> GetAsync
                var cached = await _cacheService.GetAsync<OrganizationSSO>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var result = await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .FirstOrDefaultAsync(s => s.IsDefault && s.IsActive, cancellationToken); // CancellationToken 추가

            if (result != null && _cacheService != null) // _cache -> _cacheService
            {
                // Set -> SetAsync
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(10), cancellationToken);
            }

            return result;
        }

        public async Task<IEnumerable<OrganizationSSO>> GetByTypeAsync(
            Guid organizationId,
            OSType ssoType,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
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
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        // Enum 버전
        public async Task<IEnumerable<OrganizationSSO>> GetByProviderAsync(
            Guid organizationId,
            SSOProvider provider,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.ProviderName == provider && s.IsActive)
                .OrderBy(s => s.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        // String 버전
        public async Task<IEnumerable<OrganizationSSO>> GetByProviderAsync(
            Guid organizationId,
            string provider,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            if (!Enum.TryParse<SSOProvider>(provider, true, out var ssoProvider))
            {
                return Enumerable.Empty<OrganizationSSO>();
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
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        public async Task<OrganizationSSO?> GetByDomainAsync(
            string domain,
            CancellationToken cancellationToken = default)
        {
            // TODO: JSON 파싱 및 검색 로직은 서비스 계층으로 이동하는 것을 권장합니다.
            if (string.IsNullOrWhiteSpace(domain))
                return null;

            var normalizedDomain = domain.Trim().ToLower();

            var ssos = await _dbSet
                .Include(s => s.Organization)
                .Where(s => s.IsActive && !s.IsDeleted)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 추가

            foreach (var sso in ssos)
            {
                if (string.IsNullOrWhiteSpace(sso.Configuration))
                    continue;

                try
                {
                    using var config = JsonDocument.Parse(sso.Configuration); // using 추가
                    if (config.RootElement.TryGetProperty("allowedDomains", out var domainsElement) &&
                        domainsElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var domainElement in domainsElement.EnumerateArray())
                        {
                            if (domainElement.GetString()?.ToLower() == normalizedDomain)
                            {
                                return sso;
                            }
                        }
                    }
                }
                catch { continue; } // JSON 파싱 실패 시 무시
            }
            return null;
        }

        #endregion

        #region 활성 상태 관리

        public async Task<IEnumerable<OrganizationSSO>> GetActiveByOrganizationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(s => s.Organization)
                .Include(s => s.DefaultRole)
                .Where(s => s.IsActive)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        public async Task<IEnumerable<OrganizationSSO>> GetByPriorityAsync(
              Guid organizationId,
              bool onlyActive = true,
              CancellationToken cancellationToken = default)
        {
            // [FIXED] var 대신 명시적 타입 IQueryable<OrganizationSSO> 사용
            IQueryable<OrganizationSSO> query = QueryForOrganization(organizationId)
            .Include(s => s.Organization)
            .Include(s => s.DefaultRole);

            if (onlyActive)
            {
                // 이제 IQueryable<OrganizationSSO> 타입에 할당하므로 문제 없음
                query = query.Where(s => s.IsActive);
            }

            return await query
              .OrderBy(s => s.Priority)
              .ThenByDescending(s => s.IsDefault)
              .ThenBy(s => s.CreatedAt)
              .AsNoTracking()
              .ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 및 테스트 상태 조회

        public async Task<IEnumerable<OrganizationSSO>> GetRequiringTestAsync(
            int daysSinceLastTest = 30,
            CancellationToken cancellationToken = default)
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
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        public async Task<IEnumerable<OrganizationSSO>> GetFailedTestsAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // TODO: '실패' 상태를 어떻게 저장하는지에 따라 구현 변경 필요 (예: 별도 필드 또는 로그 테이블)
            // 현재는 단순히 오래된 테스트 기록을 가져옵니다.
            var cutoffDate = DateTime.UtcNow.AddDays(-60);

            var query = _dbSet
                .Include(s => s.Organization)
                .Include(s => s.LastTestedBy)
                .Where(s => s.IsActive &&
                           !s.IsDeleted &&
                           (s.LastTestedAt == null || s.LastTestedAt < cutoffDate)); // 실패 상태 필터링 필요

            if (organizationId.HasValue)
            {
                query = query.Where(s => s.OrganizationId == organizationId.Value);
            }

            return await query
                .OrderBy(s => s.LastTestedAt ?? DateTime.MinValue)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        #endregion

        #region Bulk Operations (조회)

        public async Task<Dictionary<Guid, IEnumerable<OrganizationSSO>>> GetByOrganizationsAsync(
            IEnumerable<Guid> organizationIds,
            CancellationToken cancellationToken = default)
        {
            var orgIdsList = organizationIds.ToList();
            if (!orgIdsList.Any())
            {
                return new Dictionary<Guid, IEnumerable<OrganizationSSO>>();
            }

            var ssos = await _dbSet
                .Where(s => orgIdsList.Contains(s.OrganizationId) && !s.IsDeleted)
                .Include(s => s.Organization)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CancellationToken 추가

            return ssos.GroupBy(s => s.OrganizationId)
                       .ToDictionary(g => g.Key, g => g.AsEnumerable());
        }

        #endregion

        #region Additional Utility Methods

        public async Task<bool> UpdateTestStatusAsync(
            Guid ssoId,
            Guid testedByConnectedId,
            DateTime? testedAt = null,
            CancellationToken cancellationToken = default)
        {
            var sso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted, cancellationToken); // CT 추가
            if (sso == null)
                return false;

            sso.LastTestedAt = testedAt ?? DateTime.UtcNow;
            sso.LastTestedByConnectedId = testedByConnectedId;
            sso.UpdatedAt = DateTime.UtcNow;
            sso.UpdatedByConnectedId = testedByConnectedId;

            try
            {
                // UpdateAsync 사용 (BaseRepository)
                await UpdateAsync(sso, cancellationToken);
                // SaveChanges는 UnitOfWork에서 처리
                return true;
            }
            catch
            {
                // TODO: Log exception
                return false;
            }
        }

        public async Task<bool> SetAsDefaultAsync(
            Guid ssoId,
            Guid updatedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var newDefaultSso = await _dbSet.FirstOrDefaultAsync(s => s.Id == ssoId && !s.IsDeleted, cancellationToken); // CT 추가
            if (newDefaultSso == null)
                return false;

            // TODO: 트랜잭션 관리는 서비스 계층 또는 UnitOfWork에서 처리하는 것이 더 좋습니다.
            using var transaction = await _context.Database.BeginTransactionAsync(cancellationToken); // CT 추가
            try
            {
                // 다른 SSO 설정을 non-default로 변경 (ExecuteUpdateAsync 사용)
                await _dbSet
                    .Where(s => s.OrganizationId == newDefaultSso.OrganizationId &&
                                s.Id != ssoId &&
                                s.IsDefault &&
                                !s.IsDeleted)
                    .ExecuteUpdateAsync(updates => updates
                        .SetProperty(s => s.IsDefault, false)
                        .SetProperty(s => s.UpdatedAt, DateTime.UtcNow)
                        .SetProperty(s => s.UpdatedByConnectedId, updatedByConnectedId),
                        cancellationToken); // CT 추가

                // 선택된 SSO를 default로 설정
                newDefaultSso.IsDefault = true;
                newDefaultSso.UpdatedAt = DateTime.UtcNow;
                newDefaultSso.UpdatedByConnectedId = updatedByConnectedId;
                _dbSet.Update(newDefaultSso); // 상태 변경

                await _context.SaveChangesAsync(cancellationToken); // 변경 사항 저장 (UnitOfWork에서 할 수도 있음)
                await transaction.CommitAsync(cancellationToken); // CT 추가

                // 캐시 무효화 또는 업데이트
                if (_cacheService != null)
                {
                    var cacheKey = $"OrgSSO:Default:{newDefaultSso.OrganizationId}";
                    // 이전 기본값 캐시 제거
                    await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                    // 필요 시 새 기본값 캐시 설정 (GetDefaultByOrganizationAsync가 처리하도록 둘 수도 있음)
                    // await _cacheService.SetAsync(cacheKey, newDefaultSso, TimeSpan.FromMinutes(10), cancellationToken);
                }

                return true;
            }
            catch
            {
                await transaction.RollbackAsync(cancellationToken); // CT 추가
                // TODO: Log exception
                return false;
            }
        }

        /// <summary>
        /// 조직의 SSO 설정 개수 조회
        /// </summary>
        public async Task<int> GetCountByOrganizationAsync(
            Guid organizationId,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId && !s.IsDeleted);

            if (onlyActive)
            {
                query = query.Where(s => s.IsActive);
            }

            return await query.CountAsync(cancellationToken); // CancellationToken 추가
        }

        /// <summary>
        /// 표시 이름으로 SSO 검색
        /// </summary>
        public async Task<IEnumerable<OrganizationSSO>> SearchByDisplayNameAsync(
            Guid organizationId,
            string displayName,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(displayName))
            {
                return await GetActiveByOrganizationAsync(organizationId, cancellationToken); // CT 추가
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
                .ToListAsync(cancellationToken); // CancellationToken 추가
        }

        #endregion

        // [FIXED] 비즈니스 로직 및 서비스 계층 책임 메서드 구현 제거:
        // - ValidateConfigurationAsync
        // - UnsetDefaultExceptAsync (SetAsDefaultAsync 내부 로직으로 일부 이동)
        // - GetFromCacheAsync, InvalidateCacheAsync, SetCacheAsync (내부 캐시 처리 로직으로 변경)
        // - GetAuditLogsAsync
        // - GetUsageStatisticsAsync
        // - GetProviderStatisticsAsync (String, Enum, StringAsync 버전 모두)
        // - GetFailureRateStatisticsAsync
        // - GetOrganizationStatisticsAsync
        // - GetExpiringCertificatesAsync
    }
}