using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Business.Marketplace.Core;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Marketplace.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
// using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationContext 제거
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging; // ILogger 추가
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 마켓플레이스의 모든 상품(Product) 데이터에 접근하기 위한 리포지토리 구현체입니다. - AuthHive v16
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용, 서비스 로직 제거
    /// </summary>
    public class ProductRepository : BaseRepository<Product>, IProductRepository
    {
        private readonly ILogger<ProductRepository> _logger; // 로거 추가

        public ProductRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ICacheService? cacheService, // ICacheService? 사용
            ILogger<ProductRepository> logger) // 로거 주입
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. Product 정의는 전역적이므로 조직 범위 아님 (false).
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => false;

        #region 기본 조회 (캐시 적용, CancellationToken 추가)

        /// <summary>
        /// 상품의 고유 키(ProductKey)로 상품 정보를 조회합니다. (Cache-Aside 패턴 적용)
        /// </summary>
        public async Task<Product?> GetByProductKeyAsync(string productKey, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(productKey)) return null;

            string cacheKey = GetCacheKey($"ProductKey:{productKey.ToLowerInvariant()}"); // BaseRepository GetCacheKey 사용

            if (_cacheService != null)
            {
                var cachedProduct = await _cacheService.GetAsync<Product>(cacheKey, cancellationToken); // CT 전달
                if (cachedProduct != null) return cachedProduct;
            }

            // Query() 사용 (IsDeleted=false 포함)
            var productFromDb = await Query()
                .Include(p => p.Provider) // 필요 시 Provider 정보 포함
                .Include(p => p.Category) // 필요 시 Category 정보 포함
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.ProductKey == productKey, cancellationToken); // CT 전달

            if (productFromDb != null && _cacheService != null)
            {
                // 상품 정보는 자주 바뀌지 않으므로 비교적 긴 TTL 설정 (예: 1시간)
                await _cacheService.SetAsync(cacheKey, productFromDb, TimeSpan.FromHours(1), cancellationToken); // CT 전달
            }

            return productFromDb;
        }

        #endregion

        #region 재정의된 CUD (추가 캐시 무효화, CancellationToken 추가)

        public override async Task<Product> AddAsync(Product entity, CancellationToken cancellationToken = default)
        {
            var result = await base.AddAsync(entity, cancellationToken);
            // ProductKey 캐시가 있다면 무효화 (GetByProductKeyAsync 캐시)
            await InvalidateProductKeyCacheAsync(result.ProductKey, cancellationToken);
            return result;
        }

        /// <summary>
        /// Product 엔티티를 수정할 때, 기본 ID 캐시 외에 ProductKey 캐시도 함께 무효화합니다.
        /// </summary>
        public override async Task UpdateAsync(Product entity, CancellationToken cancellationToken = default)
        {
            // 변경 전 ProductKey 조회 (키 값이 변경될 수 있으므로)
            // AsNoTracking 사용하여 불필요한 추적 방지
            var originalKey = await Query()
                .Where(p => p.Id == entity.Id)
                .Select(p => p.ProductKey)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);

            await base.UpdateAsync(entity, cancellationToken); // ID 기반 캐시 무효화 포함

            // ProductKey 캐시 무효화 (이전 키 + 현재 키 모두)
            if (!string.IsNullOrEmpty(originalKey))
            {
                await InvalidateProductKeyCacheAsync(originalKey, cancellationToken);
            }
            if (originalKey != entity.ProductKey && !string.IsNullOrEmpty(entity.ProductKey))
            {
                await InvalidateProductKeyCacheAsync(entity.ProductKey, cancellationToken);
            }
        }

        public override async Task DeleteAsync(Product entity, CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(entity, cancellationToken); // ID 기반 캐시 무효화 포함
            // ProductKey 캐시 무효화
            await InvalidateProductKeyCacheAsync(entity.ProductKey, cancellationToken);
        }

        public override async Task DeleteRangeAsync(IEnumerable<Product> entities, CancellationToken cancellationToken = default)
        {
             var entityList = entities?.ToList();
             if (entityList == null || !entityList.Any()) return;

            await base.DeleteRangeAsync(entityList, cancellationToken); // ID 기반 캐시 무효화 포함
            // 각 엔티티의 ProductKey 캐시 무효화
            foreach (var entity in entityList)
            {
                 await InvalidateProductKeyCacheAsync(entity.ProductKey, cancellationToken);
            }
        }

        // ProductKey 캐시 무효화 헬퍼
        private async Task InvalidateProductKeyCacheAsync(string? productKey, CancellationToken cancellationToken)
        {
            if (_cacheService != null && !string.IsNullOrWhiteSpace(productKey))
            {
                string cacheKey = GetCacheKey($"ProductKey:{productKey.ToLowerInvariant()}");
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                 _logger.LogDebug("Invalidated ProductKey cache for key: {ProductKey}", productKey);
            }
        }

        #endregion

        #region IProductRepository 구현 (CancellationToken 추가)

        public async Task<IEnumerable<Product>> GetByTypeAsync(
            ProductType productType, ProductStatus? status = null, int? limit = null, CancellationToken cancellationToken = default)
        {
            var query = Query() // Query() 사용
                .Where(p => p.ProductType == productType);

            if (status.HasValue) query = query.Where(p => p.Status == status.Value);

            query = query.OrderBy(p => p.DisplayOrder).ThenBy(p => p.Name);

            if (limit.HasValue) query = query.Take(limit.Value);

            return await query.AsNoTracking().ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<Product>> GetByProviderIdAsync(
            Guid providerId, ProductType? productType = null, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
            var query = Query() // Query() 사용
                .Where(p => p.ProviderId == providerId);

            if (productType.HasValue) query = query.Where(p => p.ProductType == productType.Value);
            if (status.HasValue) query = query.Where(p => p.Status == status.Value);

            return await query
                .Include(p => p.Category) // 필요 시 카테고리 정보 포함
                .OrderBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<IEnumerable<Product>> GetByCategoryIdAsync(
            Guid categoryId, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
            // includeSubcategories 로직은 서비스 계층 책임
            var query = Query() // Query() 사용
                .Where(p => p.CategoryId == categoryId);

            if (status.HasValue) query = query.Where(p => p.Status == status.Value);

            return await query
                .Include(p => p.Provider) // 필요 시 제공자 정보 포함
                .OrderBy(p => p.DisplayOrder).ThenBy(p => p.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // CT 추가
        }

        public async Task<Dictionary<ProductType, int>> GetCountByTypeAsync(
            Guid? providerId = null, ProductStatus? status = null, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetGroupCountAsync 활용
            Expression<Func<Product, bool>>? predicate = null;
            if (providerId.HasValue || status.HasValue)
            {
                predicate = p => (!providerId.HasValue || p.ProviderId == providerId.Value) &&
                                  (!status.HasValue || p.Status == status.Value);
            }

            return await GetGroupCountAsync(p => p.ProductType, predicate, cancellationToken); // CT 추가
        }

        #endregion

        // [FIXED] 서비스 계층 책임 메서드 구현 제거됨
        // - UpdateStatusAsync 구현 제거
        // - SearchAsync 구현 제거
    }
}