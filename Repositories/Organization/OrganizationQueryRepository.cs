// 파일: AuthHive.Auth.Repositories/OrganizationQueryRepository.cs (최종)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;

namespace AuthHive.Auth.Repositories
{
    // ... (클래스 정의 및 필드 유지) ...
    public class OrganizationQueryRepository : BaseRepository<OrganizationEntity>, IOrganizationQueryRepository
    {
        private const string CACHE_KEY_PREFIX = "org_query_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public OrganizationQueryRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
        }

        protected override bool IsOrganizationBaseEntity() => false;

        #region IOrganizationQueryRepository 구현 (특화된 쿼리)

        // ... (SearchAsync, GetUserOrganizationsAsync, GetAccessibleOrganizationsAsync, GetCountByStatusAsync 메서드 구현 유지) ...

        public async Task<PagedResult<OrganizationEntity>> SearchAsync(
            string? searchTerm,
            OrganizationStatus? status,
            OrganizationType? type,
            int pageNumber,
            int pageSize,
            CancellationToken cancellationToken = default)
        {
            var query = Query().AsNoTracking();

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                 var lowerSearchTerm = searchTerm.ToLower();
                 query = query.Where(o => o.Name.ToLower().Contains(lowerSearchTerm) || 
                                          (o.Slug != null && o.Slug.ToLower().Contains(lowerSearchTerm)));
            }

            if (status.HasValue) query = query.Where(o => o.Status == status.Value);
            if (type.HasValue) query = query.Where(o => o.Type == type.Value);
            
            var totalCount = await query.CountAsync(cancellationToken);

            var items = await query
                .OrderBy(o => o.Name)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);
            
            return new PagedResult<OrganizationEntity>(items, totalCount, pageNumber, pageSize);
        }
        
        public async Task<IEnumerable<OrganizationEntity>> GetUserOrganizationsAsync(
            Guid userId,
            bool activeOnly = true,
            bool includeInherited = false,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                .Where(o => o.Memberships!.Any(m => 
                    m.Member != null && 
                    m.Member.UserId == userId && 
                    (!activeOnly || m.Status == OrganizationMembershipStatus.Active)))
                .Where(o => !o.IsDeleted);

            return await query
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationEntity>> GetAccessibleOrganizationsAsync(
            Guid connectedId,
            IEnumerable<OrganizationMembershipStatus> allowedStatuses,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                .Where(o => o.Memberships!.Any(m =>
                    m.ConnectedId == connectedId &&
                    allowedStatuses.Contains(m.Status)))
                .Where(o => !o.IsDeleted);

            return await query
                .OrderBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<int> GetCountByStatusAsync(CancellationToken cancellationToken = default)
        {
            return await CountAsync(cancellationToken: cancellationToken);
        }

        #endregion

        #region IReadRepository<Organization> 구현 (CS0535 해결)

        public async Task<IEnumerable<OrganizationEntity>> GetByStatusAsync(
            OrganizationStatus status,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}status_{status}";
            
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<OrganizationEntity>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var organizations = await Query()
                .Where(o => o.Status == status)
                .OrderBy(o => o.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (_cacheService != null && organizations.Any())
            {
                await _cacheService.SetAsync(cacheKey, organizations, _cacheExpiration, cancellationToken);
            }

            return organizations;
        }

        public async Task<IEnumerable<OrganizationEntity>> GetActiveOrganizationsAsync(
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}active_{limit ?? 0}";
            
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<OrganizationEntity>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            IQueryable<OrganizationEntity> query = Query()
                .Where(o => o.Status == OrganizationStatus.Active)
                .OrderByDescending(o => o.CreatedAt);

            if (limit.HasValue && limit.Value > 0)
            {
                query = query.Take(limit.Value);
            }

            var organizations = await query.AsNoTracking().ToListAsync(cancellationToken);

            if (_cacheService != null && organizations.Any())
            {
                await _cacheService.SetAsync(cacheKey, organizations, _cacheExpiration, cancellationToken);
            }

            return organizations;
        }

        public Task<bool> ExistsAsync(
            Expression<Func<OrganizationEntity, bool>> predicate, 
            CancellationToken cancellationToken = default)
        {
            return AnyAsync(predicate, cancellationToken);
        }

        /// <summary>
        /// 페이징된 결과 조회 (IReadRepository 시그니처 충족)
        /// </summary>
        public async Task<PagedResult<OrganizationEntity>> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<OrganizationEntity, bool>>? predicate = null,
            Func<IQueryable<OrganizationEntity>, IOrderedQueryable<OrganizationEntity>>? orderBy = null,
            CancellationToken cancellationToken = default)
        {
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000; 

            IQueryable<OrganizationEntity> query = Query().AsNoTracking();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            // 쿼리 실행 전에 카운트를 먼저 가져옵니다.
            var totalCount = await query.CountAsync(cancellationToken);

            if (orderBy != null)
            {
                query = orderBy(query);
            }
            else
            {
                // 기본 정렬: Name
                query = query.OrderBy(o => o.Name);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<OrganizationEntity>(items, totalCount, pageNumber, pageSize);
        }

        #endregion
    }
}