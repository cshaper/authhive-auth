using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Auth.Data.Context;

namespace AuthHive.Auth.Repositories.Base
{
    /// <summary>
    /// BaseRepository 최종본 - AuthHive v16 아키텍처 원칙이 완벽하게 적용되었습니다.
    /// 이 클래스는 데이터 접근의 공통 로직(CRUD, 기본 쿼리, 캐싱)만을 책임지며,
    /// '명시적 지시' 원칙에 따라 어떤 암묵적인 컨텍스트(IOrganizationContext)에도 의존하지 않습니다.
    /// 모든 하위 리포지토리는 이 클래스를 상속받아 공통 기능을 재사용하고, 자신만의 고유한 쿼리만 추가하면 됩니다.
    /// </summary>
    public abstract class BaseRepository<TEntity> : IRepository<TEntity> where TEntity : BaseEntity
    {
        // 데이터베이스와 직접 통신하는 DbContext입니다. Unit of Work 패턴의 일부로 관리됩니다.
        protected readonly AuthDbContext _context;
        // 특정 엔티티 타입(예: User, Product)의 데이터베이스 테이블(Set)에 대한 접근을 제공합니다.
        protected readonly DbSet<TEntity> _dbSet;
        // 분산 캐시(Redis 등)와 인-메모리 캐시를 모두 지원하는 하이브리드 캐시 서비스입니다.
        // null일 수 있으며, 이 경우 캐싱 로직은 건너뜁니다.
        protected readonly ICacheService? _cacheService;

        /// <summary>
        /// [최종 수정] 생성자에서 IOrganizationContext를 완전히 제거하고,
        /// AuthDbContext와 ICacheService만 명시적으로 주입받습니다.
        /// 이를 통해 리포지토리는 외부 컨텍스트에 대한 의존성을 완전히 제거하고 테스트 용이성을 확보합니다.
        /// </summary>
        protected BaseRepository(AuthDbContext context, ICacheService? cacheService = null)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _dbSet = context.Set<TEntity>();
            _cacheService = cacheService;
        }

        #region Cache Key Generation
        /// <summary>
        /// 전역 엔티티(예: User)를 위한 캐시 키를 생성합니다. (예: "User:a1b2c3d4...")
        /// 이 키는 조직 ID를 포함하지 않아 모든 테넌트에서 공유될 수 있는 데이터에 사용됩니다.
        /// </summary>
        /// <param name="id">엔티티의 고유 ID</param>
        protected virtual string GetCacheKey(Guid id) => $"{typeof(TEntity).Name}:{id}";

        /// <summary>
        /// 조직 범위 엔티티(예: Product)를 위한 캐시 키를 생성합니다. (예: "Product:org_guid:product_guid")
        /// 조직 ID를 키에 포함하여 테넌트 간 데이터가 절대 섞이지 않도록 보장합니다.
        /// </summary>
        /// <param name="id">엔티티의 고유 ID</param>
        /// <param name="organizationId">엔티티가 속한 조직의 ID</param>
        protected virtual string GetCacheKey(Guid id, Guid organizationId) => $"{typeof(TEntity).Name}:{organizationId}:{id}";
        #endregion

        #region Core Query Methods
        /// <summary>
        /// 삭제되지 않은 모든 엔티티에 대한 기본 IQueryable 진입점입니다.
        /// 모든 조회 쿼리는 _dbSet을 직접 사용하는 대신, 이 메서드를 통해 시작해야 합니다.
        /// 이를 통해 '삭제된 데이터는 조회하지 않는다'는 시스템의 핵심 규칙을 중앙에서 강제합니다.
        /// </summary>
        public virtual IQueryable<TEntity> Query() => _dbSet.Where(e => !e.IsDeleted);

        /// <summary>
        /// 특정 조직 ID로 필터링된 IQueryable을 반환하는 헬퍼 메서드입니다.
        /// 조직 범위 엔티티를 조회할 때 코드 중복을 줄여줍니다.
        /// </summary>
        /// <param name="organizationId">필터링할 명시적인 조직 ID</param>
        protected virtual IQueryable<TEntity> QueryForOrganization(Guid organizationId)
        {
            var query = Query();
            if (IsOrganizationScopedEntity())
            {
                // EF.Property를 사용하여 TEntity가 OrganizationId 속성을 직접 노출하지 않더라도
                // 데이터베이스의 'OrganizationId' 컬럼을 기준으로 동적으로 쿼리합니다.
                query = query.Where(e => EF.Property<Guid>(e, "OrganizationId") == organizationId);
            }
            return query;
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티가 조직 범위인지 여부를 결정합니다.
        /// 자식 리포지토리는 이 메서드를 반드시 재정의(override)하여 자신의 엔티티 특성을 명시해야 합니다.
        /// 예: UserRepository -> false, ProductRepository -> true
        /// </summary>
        protected abstract bool IsOrganizationScopedEntity();
        #endregion

        #region 조회 작업 (IRepository 구현)
        public virtual async Task<TEntity?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var cacheKey = GetCacheKey(id);
            if (_cacheService != null)
            {
                var cachedEntity = await _cacheService.GetAsync<TEntity>(cacheKey, cancellationToken);
                if (cachedEntity != null) return cachedEntity;
            }

            var entityFromDb = await _dbSet.FindAsync(new object[] { id }, cancellationToken);

            if (entityFromDb != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, entityFromDb, TimeSpan.FromMinutes(15), cancellationToken);
            }
            return entityFromDb;
        }

        public virtual async Task<IEnumerable<TEntity>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return await Query().AsNoTracking().ToListAsync(cancellationToken);
        }

        public virtual async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await Query().Where(predicate).AsNoTracking().ToListAsync(cancellationToken);
        }

        public virtual async Task<TEntity?> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await Query().AsNoTracking().FirstOrDefaultAsync(predicate, cancellationToken);
        }

        public virtual async Task<int> CountAsync(Expression<Func<TEntity, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            var query = Query();
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync(cancellationToken);
        }

        public virtual async Task<bool> AnyAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(predicate, cancellationToken);
        }
        
        public virtual async Task<bool> ExistsAsync(Guid id, CancellationToken cancellationToken = default)
        {
            // GetByIdAsync를 호출하여 캐시 로직을 재활용하고 DB 부하를 줄입니다.
            var entity = await GetByIdAsync(id, cancellationToken);
            return entity != null;
        }
        
        public virtual async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedAsync(int pageNumber, int pageSize, Expression<Func<TEntity, bool>>? predicate = null, Expression<Func<TEntity, object>>? orderBy = null, bool isDescending = false, CancellationToken cancellationToken = default)
        {
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000; // 과도한 데이터 조회를 막는 안전장치(DOS 방지)

            var query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            if (orderBy != null)
            {
                query = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
            }
            else
            {
                // [수정] 모든 BaseEntity가 반드시 가지고 있는 'Id'를 기본 정렬 기준으로 사용합니다.
                // 'CreatedAt'과 같은 특정 속성에 의존하지 않아 모든 엔티티에 대해 안전하게 동작합니다.
                query = query.OrderByDescending(e => e.Id);
            }

            var items = await query
                .AsNoTracking()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }
        #endregion

        #region CUD 작업 (IRepository 구현)
        public virtual async Task<TEntity> AddAsync(TEntity entity, CancellationToken cancellationToken = default)
        {
            await _dbSet.AddAsync(entity, cancellationToken);
            return entity; // 인터페이스 계약에 맞춰 추가된 엔티티를 반환합니다.
        }

        public virtual Task AddRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default)
        {
            return _dbSet.AddRangeAsync(entities, cancellationToken);
        }

        public virtual Task UpdateAsync(TEntity entity, CancellationToken cancellationToken = default)
        {
            // 엔티티의 상태를 '수정됨'으로 표시합니다. 실제 DB 저장은 UnitOfWork에서 처리합니다.
            _dbSet.Update(entity);
            // 데이터 변경 후에는 반드시 관련 캐시를 제거하여 데이터 정합성을 유지합니다.
            // 참고: 조직 범위 엔티티의 경우, 자식 리포지토리에서 이 메서드를 override하여
            // InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken)를 호출해야 합니다.
            return InvalidateCacheAsync(entity.Id, cancellationToken);
        }

        public virtual Task UpdateRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default)
        {
            _dbSet.UpdateRange(entities);
            var tasks = entities.Select(e => InvalidateCacheAsync(e.Id, cancellationToken));
            return Task.WhenAll(tasks);
        }

        public virtual async Task DeleteAsync(TEntity entity, CancellationToken cancellationToken = default)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            _dbSet.Update(entity);
            await InvalidateCacheAsync(entity.Id, cancellationToken);
        }

        public virtual async Task SoftDeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var entity = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (entity != null)
            {
                await DeleteAsync(entity, cancellationToken);
            }
        }
        
        public virtual async Task DeleteRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default)
        {
            var timestamp = DateTime.UtcNow;
            var tasks = new List<Task>();
            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = timestamp;
                tasks.Add(InvalidateCacheAsync(entity.Id, cancellationToken));
            }
            _dbSet.UpdateRange(entities);
            await Task.WhenAll(tasks);
        }
        #endregion

        #region 통계 작업 (IRepository 구현)
        public virtual async Task<Dictionary<TKey, int>> GetGroupCountAsync<TKey>(Expression<Func<TEntity, TKey>> keySelector, Expression<Func<TEntity, bool>>? predicate = null, CancellationToken cancellationToken = default) where TKey : notnull
        {
            var query = Query();
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query
                .GroupBy(keySelector)
                .Select(g => new { Key = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Key, x => x.Count, cancellationToken);
        }

        public virtual async Task<Dictionary<DateTime, int>> GetDailyCountAsync(Expression<Func<TEntity, DateTime>> dateSelector, DateTime startDate, DateTime endDate, Expression<Func<TEntity, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            var query = Query();
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            var datePropertyName = dateSelector.GetPropertyName();
            return await query
                .Where(e => EF.Property<DateTime>(e, datePropertyName) >= startDate.Date && EF.Property<DateTime>(e, datePropertyName) < endDate.Date.AddDays(1))
                .GroupBy(e => EF.Property<DateTime>(e, datePropertyName).Date)
                .Select(g => new { Date = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Date, x => x.Count, cancellationToken);
        }
        #endregion

        #region Cache Invalidation
        protected virtual Task InvalidateCacheAsync(Guid id, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return Task.CompletedTask;
            var cacheKey = GetCacheKey(id);
            return _cacheService.RemoveAsync(cacheKey, cancellationToken);
        }

        protected virtual Task InvalidateCacheAsync(Guid id, Guid organizationId, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return Task.CompletedTask;
            var cacheKey = GetCacheKey(id, organizationId);
            return _cacheService.RemoveAsync(cacheKey, cancellationToken);
        }
        #endregion
    }

    /// <summary>
    /// 통계 쿼리에서 람다 표현식의 속성 이름을 문자열로 안전하게 가져오기 위한 확장 메서드입니다.
    /// </summary>
    public static class ExpressionExtensions
    {
        public static string GetPropertyName<T, TProperty>(this Expression<Func<T, TProperty>> expression)
        {
            if (expression.Body is MemberExpression memberExpression)
            {
                return memberExpression.Member.Name;
            }
            // Convert(x.Enum)과 같은 경우를 처리
            if (expression.Body is UnaryExpression unaryExpression && unaryExpression.Operand is MemberExpression operand)
            {
                return operand.Member.Name;
            }
            throw new ArgumentException("Expression must be a member expression");
        }
    }
}