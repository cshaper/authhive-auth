using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Business.Marketplace.Core;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Marketplace.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Service;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Business.AddonEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 마켓플레이스의 모든 상품(Product) 데이터에 접근하기 위한 리포지토리 구현체입니다.
    /// 애드온, API, 번들 등 모든 거래 가능한 상품을 통합 관리합니다.
    /// </summary>
    public class ProductRepository : BaseRepository<Product>, IProductRepository
    {
        public ProductRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ICacheService cacheService)
            : base(context, organizationContext, cacheService)
        {
            // BaseRepository 생성자가 모든 초기화를 처리합니다.
        }

        #region 기본 조회 (캐시 적용)

        /// <summary>
        /// 상품의 고유 키(ProductKey)로 상품 정보를 조회합니다. (Cache-Aside 패턴 적용)
        /// 이 메서드는 가장 빈번하게 사용되는 조회 중 하나입니다.
        /// </summary>
        public async Task<Product?> GetByProductKeyAsync(string productKey, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null)
            {
                return await _dbSet.AsNoTracking().FirstOrDefaultAsync(p => p.ProductKey == productKey, cancellationToken);
            }

            string cacheKey = $"product_by_key:{productKey}";

            var cachedProduct = await _cacheService.GetAsync<Product>(cacheKey);
            if (cachedProduct != null)
            {
                return cachedProduct;
            }

            var productFromDb = await _dbSet.AsNoTracking().FirstOrDefaultAsync(p => p.ProductKey == productKey, cancellationToken);

            if (productFromDb != null)
            {
                await _cacheService.SetAsync(cacheKey, productFromDb);
            }

            return productFromDb;
        }

        #endregion

        #region 재정의된 CUD (추가 캐시 무효화)

        /// <summary>
        /// Product 엔티티를 수정할 때, 기본 ID 캐시 외에 ProductKey 캐시도 함께 무효화합니다.
        /// </summary>
        public override async Task UpdateAsync(Product entity)
        {
            // 1. BaseRepository의 기본 Update 로직을 호출하여 ID 기반 캐시를 무효화합니다.
            await base.UpdateAsync(entity);

            // 2. 이 리포지토리의 고유 조회 키인 ProductKey에 대한 캐시도 추가로 무효화합니다.
            if (_cacheService != null)
            {
                string cacheKey = $"product_by_key:{entity.ProductKey}";
                await _cacheService.RemoveAsync(cacheKey);
            }
        }

        // SAAS-NOTE: AddAsync, DeleteAsync 등 다른 CUD 메서드들도 필요에 따라
        // ProductKey 캐시 무효화 로직을 추가하기 위해 위와 같이 override 할 수 있습니다.

        #endregion

        #region IProductRepository 구현

        public async Task<IEnumerable<Product>> GetByTypeAsync(ProductType productType, ProductStatus? status = null, int? limit = null, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                              .Where(p => p.ProductType == productType);

            if (status.HasValue)
            {
                query = query.Where(p => p.Status == status.Value);
            }
            
            query = query.OrderBy(p => p.DisplayOrder).ThenBy(p => p.Name);

            if (limit.HasValue)
            {
                query = query.Take(limit.Value);
            }

            return await query.ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Product>> GetByProviderIdAsync(Guid providerId, ProductType? productType = null, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                              .Where(p => p.ProviderId == providerId);

            if (productType.HasValue)
            {
                query = query.Where(p => p.ProductType == productType.Value);
            }

            if (status.HasValue)
            {
                query = query.Where(p => p.Status == status.Value);
            }

            return await query.OrderBy(p => p.Name).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Product>> GetByCategoryIdAsync(Guid categoryId, bool includeSubcategories = false, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
            // SAAS-NOTE: 'includeSubcategories' 로직은 계층 구조 쿼리를 필요로 하므로 복잡합니다.
            // 이 기능은 성능을 고려하여 Service 계층에서 여러 쿼리를 조합하거나,
            // 데이터베이스의 재귀 쿼리(CTE) 기능을 사용하여 구현하는 것이 더 적합할 수 있습니다.
            // 여기서는 기본 기능만 구현합니다.
            var query = _dbSet.AsNoTracking()
                              .Where(p => p.CategoryId == categoryId);

            if (status.HasValue)
            {
                query = query.Where(p => p.Status == status.Value);
            }

            return await query.ToListAsync(cancellationToken);
        }

        // SAAS-NOTE: 상태, 가격, 통계 등 나머지 복잡한 조회 및 업데이트 메서드들은
        // 대부분 여러 테이블을 조인하거나, 통계를 계산하거나, 복잡한 비즈니스 규칙을 포함합니다.
        // 이러한 로직들은 순수한 데이터 접근을 넘어 서비스 계층의 역할에 해당하므로,
        // 이 리포지토리에서는 가장 기본적인 구현만 제공하거나 Service에서 처리하도록 위임합니다.
        // 아래는 간단한 구현 예시입니다.

        public Task<bool> UpdateStatusAsync(Guid productId, ProductStatus newStatus, string? reason = null, CancellationToken cancellationToken = default)
        {
            // SAAS-NOTE: 상태 변경은 단순한 업데이트가 아니라 상태 전이 규칙(State Transition Rule) 검증과
            // 감사 로그(Audit Log), 이벤트 발행(EventBus)이 필요한 복잡한 트랜잭션입니다.
            // 따라서 이 로직의 완전한 구현은 'MarketplaceService'에서 UnitOfWork를 사용하여 처리해야 합니다.
            // Repository는 단순히 데이터를 찾아주는 역할만 수행합니다.
            throw new NotImplementedException("This logic should be implemented in the Service layer.");
        }

        public Task<IEnumerable<Product>> SearchAsync(string? searchTerm = null, ProductType? productType = null, ProductStatus? status = null, AddonSalesType? salesType = null, decimal? minPrice = null, decimal? maxPrice = null, int skip = 0, int take = 20, CancellationToken cancellationToken = default)
        {
            // SAAS-NOTE: 검색 기능, 특히 Full-Text Search나 다중 필터링은 성능 최적화가 중요하며
            // Elasticsearch와 같은 별도의 검색 엔진과 연동될 수 있습니다.
            // 이 로직은 'SearchService' 또는 'MarketplaceService'에서 담당하는 것이 좋습니다.
            throw new NotImplementedException("Search logic should be implemented in a dedicated Service layer.");
        }

        public Task<Dictionary<ProductType, int>> GetCountByTypeAsync(Guid? providerId = null, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
             var query = _dbSet.AsQueryable();

             if(providerId.HasValue)
             {
                 query = query.Where(p => p.ProviderId == providerId.Value);
             }

             if(status.HasValue)
             {
                 query = query.Where(p => p.Status == status.Value);
             }

             return query.GroupBy(p => p.ProductType)
                         .Select(g => new { ProductType = g.Key, Count = g.Count() })
                         .ToDictionaryAsync(x => x.ProductType, x => x.Count, cancellationToken);
        }

        #endregion
    }
}
