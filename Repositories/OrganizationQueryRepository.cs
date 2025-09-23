using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Organization 조회 전용 Repository 구현체 - CQRS Query Side
    /// AuthHive v15
    /// </summary>
    public class OrganizationQueryRepository : BaseRepository<OrganizationEntity>, IOrganizationQueryRepository
    {
        private const string CACHE_KEY_PREFIX = "org_query_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public OrganizationQueryRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region 상태별 조회

        /// <summary>
        /// 특정 상태의 조직들 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetByStatusAsync(
            OrganizationStatus status,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}status_{status}";
            
            if (_cache != null && _cache.TryGetValue<IEnumerable<OrganizationEntity>>(cacheKey, out var cached))
            {
                return cached!;
            }

            var organizations = await Query()
                .Where(o => o.Status == status)
                .Include(o => o.ParentOrganization)
                .Include(o => o.ChildOrganizations)
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);

            if (_cache != null && organizations.Any())
            {
                _cache.Set(cacheKey, organizations, _cacheExpiration);
            }

            return organizations;
        }

        /// <summary>
        /// 활성 조직들 조회 (선택적 제한)
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetActiveOrganizationsAsync(
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}active_{limit ?? 0}";
            
            if (_cache != null && _cache.TryGetValue<IEnumerable<OrganizationEntity>>(cacheKey, out var cached))
            {
                return cached!;
            }

            IQueryable<OrganizationEntity> query = Query()
                .Where(o => o.Status == OrganizationStatus.Active)
                .Include(o => o.ParentOrganization)
                .OrderByDescending(o => o.CreatedAt);

            if (limit.HasValue && limit.Value > 0)
            {
                query = query.Take(limit.Value);
            }

            var organizations = await query.ToListAsync(cancellationToken);

            if (_cache != null && organizations.Any())
            {
                _cache.Set(cacheKey, organizations, _cacheExpiration);
            }

            return organizations;
        }

        #endregion

        #region 검색

        /// <summary>
        /// 조직 검색 (페이징 포함)
        /// </summary>
        public async Task<PagedResult<OrganizationEntity>> SearchAsync(
            string? searchTerm,
            OrganizationStatus? status,
            OrganizationType? type,
            int pageNumber,
            int pageSize,
            CancellationToken cancellationToken = default)
        {
            // 기본 쿼리 생성
            IQueryable<OrganizationEntity> query = Query();

            // Include 관계 데이터
            query = query
                .Include(o => o.ParentOrganization)
                .Include(o => o.ChildOrganizations)
                .Include(o => o.Domains);

            // 검색어 필터링
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var lowerSearchTerm = searchTerm.ToLower();
                query = query.Where(o => 
                    o.Name.ToLower().Contains(lowerSearchTerm) ||
                    (o.Slug != null && o.Slug.ToLower().Contains(lowerSearchTerm)) ||
                    (o.Description != null && o.Description.ToLower().Contains(lowerSearchTerm)) ||
                    (o.OrganizationKey != null && o.OrganizationKey.ToLower().Contains(lowerSearchTerm)) ||
                    (o.Website != null && o.Website.ToLower().Contains(lowerSearchTerm)) ||
                    (o.Industry != null && o.Industry.ToLower().Contains(lowerSearchTerm))
                );
            }

            // 상태 필터링
            if (status.HasValue)
            {
                query = query.Where(o => o.Status == status.Value);
            }

            // 타입 필터링
            if (type.HasValue)
            {
                query = query.Where(o => o.Type == type.Value);
            }

            // 전체 개수 계산
            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬 및 페이징
            var items = await query
                .OrderBy(o => o.Name)
                .ThenByDescending(o => o.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<OrganizationEntity>(items, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 계층 구조 조회

        /// <summary>
        /// 부모 조직 ID로 자식 조직들 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetChildOrganizationsAsync(
            Guid parentId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.ParentOrganizationId == parentId)
                .Include(o => o.ChildOrganizations)
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 전체 조직 계층 구조 조회 (재귀적)
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetOrganizationHierarchyAsync(
            Guid? rootOrganizationId = null,
            CancellationToken cancellationToken = default)
        {
            if (rootOrganizationId.HasValue)
            {
                // 특정 조직부터 시작
                var rootOrg = await GetByIdAsync(rootOrganizationId.Value);
                if (rootOrg == null)
                    return Enumerable.Empty<OrganizationEntity>();

                return await GetHierarchyRecursive(rootOrganizationId.Value, cancellationToken);
            }
            else
            {
                // 최상위 조직들 찾기 (부모가 없는 조직들)
                var topOrganizations = await Query()
                    .Where(o => o.ParentOrganizationId == null)
                    .Include(o => o.ChildOrganizations)
                    .ToListAsync(cancellationToken);

                var result = new List<OrganizationEntity>();
                foreach (var org in topOrganizations)
                {
                    result.Add(org);
                    result.AddRange(await GetHierarchyRecursive(org.Id, cancellationToken));
                }

                return result;
            }
        }

        /// <summary>
        /// 재귀적으로 계층 구조 조회
        /// </summary>
        private async Task<IEnumerable<OrganizationEntity>> GetHierarchyRecursive(
            Guid organizationId,
            CancellationToken cancellationToken,
            HashSet<Guid>? visited = null)
        {
            visited ??= new HashSet<Guid>();

            // 순환 참조 방지
            if (!visited.Add(organizationId))
                return Enumerable.Empty<OrganizationEntity>();

            var childOrganizations = await GetChildOrganizationsAsync(organizationId, cancellationToken);
            var result = new List<OrganizationEntity>(childOrganizations);

            foreach (var child in childOrganizations)
            {
                result.AddRange(await GetHierarchyRecursive(child.Id, cancellationToken, visited));
            }

            return result;
        }

        #endregion

        #region 고급 검색 및 필터링

        /// <summary>
        /// 복합 조건으로 조직 검색
        /// </summary>
        public async Task<PagedResult<OrganizationEntity>> AdvancedSearchAsync(
            Expression<Func<OrganizationEntity, bool>> criteria,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            IQueryable<OrganizationEntity> query = Query();
            query = query
                .Include(o => o.ParentOrganization)
                .Include(o => o.ChildOrganizations)
                .Where(criteria);

            var totalCount = await query.CountAsync(cancellationToken);

            var items = await query
                .OrderBy(o => o.Name)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<OrganizationEntity>(items, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 타입별 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetByTypeAsync(
            OrganizationType type,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.Type == type)
                .Include(o => o.ParentOrganization)
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 계층 구조 타입별 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetByHierarchyTypeAsync(
            OrganizationHierarchyType hierarchyType,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.HierarchyType == hierarchyType)
                .Include(o => o.ParentOrganization)
                .Include(o => o.ChildOrganizations)
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 조직 상태별 통계
        /// </summary>
        public async Task<Dictionary<OrganizationStatus, int>> GetStatusStatisticsAsync(
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .GroupBy(o => o.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 조직 타입별 통계
        /// </summary>
        public async Task<Dictionary<OrganizationType, int>> GetTypeStatisticsAsync(
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .GroupBy(o => o.Type)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 날짜별 생성 통계
        /// </summary>
        public async Task<Dictionary<DateTime, int>> GetCreationStatisticsAsync(
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.CreatedAt >= startDate && o.CreatedAt <= endDate)
                .GroupBy(o => o.CreatedAt.Date)
                .Select(g => new { Date = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Date, x => x.Count, cancellationToken);
        }

        #endregion

        #region 도메인 관련

        /// <summary>
        /// 도메인으로 조직 검색
        /// </summary>
        public async Task<OrganizationEntity?> GetByDomainAsync(
            string domain,
            CancellationToken cancellationToken = default)
        {
            var lowerDomain = domain.ToLower();
            
            return await Query()
                .Include(o => o.Domains)
                .Where(o => o.Domains.Any(d => 
                    d.Domain.ToLower() == lowerDomain && 
                    d.IsVerified))
                .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Slug으로 조직 검색
        /// </summary>
        public async Task<OrganizationEntity?> GetBySlugAsync(
            string slug,
            CancellationToken cancellationToken = default)
        {
            var lowerSlug = slug.ToLower();
            
            return await Query()
                .Include(o => o.ParentOrganization)
                .Include(o => o.ChildOrganizations)
                .FirstOrDefaultAsync(o => o.Slug != null && o.Slug.ToLower() == lowerSlug, cancellationToken);
        }

        #endregion

        #region 최근 활동

        /// <summary>
        /// 최근 생성된 조직들
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetRecentlyCreatedAsync(
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .OrderByDescending(o => o.CreatedAt)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 최근 업데이트된 조직들
        /// </summary>
        public async Task<IEnumerable<OrganizationEntity>> GetRecentlyUpdatedAsync(
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.UpdatedAt != null)
                .OrderByDescending(o => o.UpdatedAt)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region IReadRepository 구현

        /// <summary>
        /// 표현식 조건으로 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(Expression<Func<OrganizationEntity, bool>> predicate)
        {
            return await Query().AnyAsync(predicate);
        }

        /// <summary>
        /// 페이징된 결과 조회
        /// </summary>
        public async Task<PagedResult<OrganizationEntity>> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<OrganizationEntity, bool>>? predicate = null,
            Func<IQueryable<OrganizationEntity>, IOrderedQueryable<OrganizationEntity>>? orderBy = null)
        {
            IQueryable<OrganizationEntity> query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = orderBy(query);
            }
            else
            {
                query = query.OrderBy(o => o.Name);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new PagedResult<OrganizationEntity>(items, totalCount, pageNumber, pageSize);
        }

        #endregion
    }
}