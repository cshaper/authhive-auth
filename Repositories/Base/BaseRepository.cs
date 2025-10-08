using AuthHive.Core.Entities.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Repositories.Base
{
    /// <summary>
    /// AI 친화적인 BaseRepository - 기능 풍부하지만 사용하기 쉬운 구조
    /// 캐시, 통계, 페이징 등 자주 필요한 기능들을 모두 포함
    /// v15.5: 멀티 조직 환경 완전 지원
    /// 
    /// 이 BaseRepository를 상속받는 모든 자식 Repository는 아래 규칙을 반드시 준수해야 합니다.
    /// 1. 'override'는 신중하게 사용:
    ///    부모(BaseRepository)의 기능을 완전히 무시하고 새로 작성해야 하는 경우가 아니라면 사용하지 마십시오.
    ///    기능을 '확장'할 때만 사용하고, 반드시 `base.MethodName()`을 호출하여 부모의 핵심 로직을 활용해야 합니다.
    ///    예시: `public override async Task<T> AddAsync(T entity) { entity.Something = "special"; return await base.AddAsync(entity); }`
    /// 2. 'new' 키워드는 절대 사용 금지:
    ///    메서드를 숨기는 `new` 키워드는 아키텍처를 혼란스럽게 만들므로 절대 사용해서는 안 됩니다.
    /// 3. 고유 기능은 새로운 메서드로 구현:
    ///    특정 Repository에만 필요한 기능은 `override`를 고려하기보다, `GetByEmailAsync`처럼 새로운 이름의 메서드를 만드는 것이 좋습니다.
    /// </summary>
    public abstract class BaseRepository<TEntity> : IRepository<TEntity> where TEntity : BaseEntity
    {
        protected readonly AuthDbContext _context;
        protected readonly DbSet<TEntity> _dbSet;
        protected readonly ICacheService? _cacheService;
        protected readonly IOrganizationContext _organizationContext;

        private readonly TimeSpan _defaultCacheTtl = TimeSpan.FromMinutes(15);

        protected BaseRepository(AuthDbContext context, IOrganizationContext organizationContext, ICacheService? cacheService = null)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
            _dbSet = context.Set<TEntity>();
            _cacheService = cacheService;
        }

        #region 기본 CRUD (자동 캐시 포함)

        /// <summary>
        /// 기본 쿼리 - 소프트 삭제 필터링 및 조직 필터링 자동 적용
        /// </summary>
        public virtual IQueryable<TEntity> Query()
        {
            var query = _dbSet.Where(e => !e.IsDeleted);

            // 조직 스코프 엔티티라면 자동 필터링
            if (IsOrganizationScopedEntity())
            {
                var orgId = _organizationContext.CurrentOrganizationId;
                if (orgId == null)
                {
                    throw new InvalidOperationException(
                        $"Cannot query organization-scoped entity {typeof(TEntity).Name} without organization context.");
                }

                query = query.Where(e => EF.Property<Guid>(e, "OrganizationId") == orgId.Value);
            }

            return query;
        }

        /// <summary>
        /// 특정 조직의 데이터를 명시적으로 조회 (관리자 전용)
        /// </summary>
        protected virtual IQueryable<TEntity> QueryForOrganization(Guid organizationId)
        {
            var query = _dbSet.Where(e => !e.IsDeleted);

            if (IsOrganizationScopedEntity())
            {
                query = query.Where(e => EF.Property<Guid>(e, "OrganizationId") == organizationId);
            }

            return query;
        }

        /// <summary>
        /// 엔티티가 조직 스코프인지 확인
        /// </summary>
        protected virtual bool IsOrganizationScopedEntity()
        {
            return typeof(OrganizationScopedEntity).IsAssignableFrom(typeof(TEntity));
        }

        /// <summary>
        /// ID로 조회 - 캐시 자동 적용 (ICacheService 사용)
        /// </summary>
        public virtual async Task<TEntity?> GetByIdAsync(Guid id)
        {
            if (_cacheService == null)
            {
                // 캐시가 없으면 DB에서 바로 조회하여 반환
                return await Query().AsNoTracking().FirstOrDefaultAsync(e => e.Id == id);
            }

            string cacheKey = GetCacheKey("GetById", id);

            // 1. 캐시에서 조회 (ICacheService.GetAsync는 TEntity?를 반환)
            var entity = await _cacheService.GetAsync<TEntity>(cacheKey);

            if (entity != null)
            {
                return entity;
            }

            // 2. DB에서 조회
            entity = await Query().AsNoTracking().FirstOrDefaultAsync(e => e.Id == id);

            // 3. DB 결과가 null이 아닐 경우 캐시에 저장 (ICacheService.SetAsync는 TEntity를 요구함)
            if (entity != null)
            {
                await _cacheService.SetAsync(cacheKey, entity, _defaultCacheTtl);
            }

            return entity;
        }

        public virtual async Task<IEnumerable<TEntity>> GetAllAsync()
        {
            return await Query().AsNoTracking().ToListAsync();
        }

        public virtual async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await Query().Where(predicate).AsNoTracking().ToListAsync();
        }

        public virtual async Task<TEntity?> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await Query().AsNoTracking().FirstOrDefaultAsync(predicate);
        }

        public virtual async Task<int> CountAsync(Expression<Func<TEntity, bool>>? predicate = null)
        {
            var query = Query();
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync();
        }

        public virtual async Task<bool> AnyAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await Query().AnyAsync(predicate);
        }

        /// <summary>
        /// ID로 엔티티의 존재 여부를 확인합니다. - 캐시 자동 적용
        /// </summary>
// BaseRepository.cs 내 ExistsAsync 메서드

        /// <summary>
        /// ID로 엔티티의 존재 여부를 확인합니다. - 캐시 자동 적용 (ICacheService 사용)
        /// Note: GetByIdAsync를 호출하여 캐시 로직을 재활용합니다.
        /// </summary>
        public virtual async Task<bool> ExistsAsync(Guid id)
        {
            // 1. GetByIdAsync를 호출하여 캐시/DB에서 엔티티를 조회합니다.
            //    (GetByIdAsync 내부에서 이미 ICacheService의 GetOrSet 로직이 처리됨)
            var entity = await GetByIdAsync(id);

            return entity != null;
        }


        #endregion

        #region 페이징 (성능 최적화 포함)

        /// <summary>
        /// 페이징 조회 - DOS 방지 및 성능 최적화 자동 적용
        /// </summary>
        public virtual async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<TEntity, bool>>? predicate = null,
            Expression<Func<TEntity, object>>? orderBy = null,
            bool isDescending = false)
        {
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000; // DOS 방지

            var query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending
                    ? query.OrderByDescending(orderBy)
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(e => e.Id);
            }

            var items = await query
                .AsNoTracking()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        #endregion

        #region CUD 작업 (캐시 무효화 자동 처리)

        public virtual async Task<TEntity> AddAsync(TEntity entity)
        {
            await InvalidateCacheAsync(entity.Id);
            await _dbSet.AddAsync(entity);
            return entity;
        }

        public virtual async Task AddRangeAsync(IEnumerable<TEntity> entities)
        {
            var entityList = entities.ToList();
            foreach (var entity in entityList)
            {
                await InvalidateCacheAsync(entity.Id);
            }
            await _dbSet.AddRangeAsync(entityList);
        }

        // BaseRepository.cs 내 UpdateAsync 메서드 수정

        public virtual async Task UpdateAsync(TEntity entity)
        {
            // ⭐️ 수정됨: ICacheService를 사용하므로 비동기 메서드를 await하여 호출
            await InvalidateCacheAsync(entity.Id);

            _context.Entry(entity).State = EntityState.Modified;

            // 이 메서드가 IUnitOfWork.SaveChangesAsync() 호출 전에 실행되므로,
            // 변경 상태 설정 후 Task.CompletedTask를 반환하는 기존 패턴을 유지하되 async를 사용해야 함.
            await Task.CompletedTask;
        }

        public virtual async Task UpdateRangeAsync(IEnumerable<TEntity> entities)
        {
            // CUD 작업은 캐시 무효화를 위해 비동기로 처리되어야 합니다.
            foreach (var entity in entities)
            {
                // ⭐️ ICacheService의 비동기 메서드를 await하여 호출
                await InvalidateCacheAsync(entity.Id);
            }

            _dbSet.UpdateRange(entities);

            // 이 메서드는 SaveChangesAsync()를 호출하지 않으므로 Task.CompletedTask를 await합니다.
            await Task.CompletedTask;
        }

        public virtual async Task DeleteAsync(TEntity entity)
        {
            // ⭐️ 수정됨: ICacheService를 사용하므로 비동기 메서드를 await하여 호출
            await InvalidateCacheAsync(entity.Id);

            // Soft Delete 로직
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            _dbSet.Update(entity);

            // SaveChangesAsync는 상위 레이어(IUnitOfWork)에서 호출되므로,
            // 이 메서드 자체는 상태 변경 후 완료된 Task를 반환합니다.
            await Task.CompletedTask;
        }

        /// <summary>
        /// ID로 엔티티를 Soft Delete 처리합니다. - 캐시 무효화 자동 처리
        /// </summary>
        // BaseRepository.cs 내 SoftDeleteAsync 메서드

        public virtual async Task SoftDeleteAsync(Guid id)
        {
            // ⭐️ 수정됨: ICacheService를 사용하므로 비동기 메서드를 await하여 호출
            await InvalidateCacheAsync(id);

            var entity = await Query().FirstOrDefaultAsync(e => e.Id == id);

            if (entity != null)
            {
                // Soft Delete 로직
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;
                _dbSet.Update(entity);
                // Note: SaveChangesAsync는 상위 레이어(UnitOfWork)에서 호출됨
            }
        }
        public virtual async Task DeleteRangeAsync(IEnumerable<TEntity> entities)
        {
            var timestamp = DateTime.UtcNow;

            // ⭐️ CUD 작업이므로 async로 선언하고 비동기 호출을 처리해야 함
            foreach (var entity in entities)
            {
                // ❌ InvalidateCache(entity.Id); 
                await InvalidateCacheAsync(entity.Id); // ⭐️ ICacheService를 사용하도록 수정

                // Soft Delete 로직
                entity.IsDeleted = true;
                entity.DeletedAt = timestamp;
            }

            _dbSet.UpdateRange(entities);

            // 이 메서드가 SaveChangesAsync()를 직접 호출하지 않으므로,
            // Task.CompletedTask를 await하여 Task<T> 시그니처를 충족시킵니다.
            await Task.CompletedTask;
        }

        #endregion

        #region 통계 및 분석 (자주 사용되는 것들)

        /// <summary>
        /// 그룹별 개수 통계 - 대시보드 등에서 자주 사용
        /// </summary>
        public virtual async Task<Dictionary<TKey, int>> GetGroupCountAsync<TKey>(
            Expression<Func<TEntity, TKey>> keySelector,
            Expression<Func<TEntity, bool>>? predicate = null)
            where TKey : notnull
        {
            var query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query
                .GroupBy(keySelector)
                .Select(g => new { Key = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Key, x => x.Count);
        }

        /// <summary>
        /// 날짜별 통계 - 차트 등에서 자주 사용
        /// </summary>
        public virtual async Task<Dictionary<DateTime, int>> GetDailyCountAsync(
            Expression<Func<TEntity, DateTime>> dateSelector,
            DateTime startDate,
            DateTime endDate,
            Expression<Func<TEntity, bool>>? predicate = null)
        {
            var query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query
                .Where(e => EF.Property<DateTime>(e, dateSelector.GetPropertyName()) >= startDate &&
                           EF.Property<DateTime>(e, dateSelector.GetPropertyName()) <= endDate)
                .GroupBy(e => EF.Property<DateTime>(e, dateSelector.GetPropertyName()).Date)
                .Select(g => new { Date = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Date, x => x.Count);
        }

        #endregion

        #region 조직별 전용 메서드 (OrganizationScopedRepository 통합)

        /// <summary>
        /// 특정 조직의 엔티티 조회 (관리자 전용)
        /// </summary>
        public virtual async Task<IEnumerable<TEntity>> GetByOrganizationIdAsync(Guid organizationId)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            return await QueryForOrganization(organizationId).AsNoTracking().ToListAsync();
        }

        /// <summary>
        /// ID와 조직 ID로 엔티티 조회
        /// </summary>
        public virtual async Task<TEntity?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(e => e.Id == id);
        }

        /// <summary>
        /// 특정 조직에서 조건에 맞는 엔티티 검색
        /// </summary>
        public virtual async Task<IEnumerable<TEntity>> FindByOrganizationAsync(
            Guid organizationId,
            Expression<Func<TEntity, bool>> predicate)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            return await QueryForOrganization(organizationId)
                .Where(predicate)
                .AsNoTracking()
                .ToListAsync();
        }

        /// <summary>
        /// 조직별 페이징 조회
        /// </summary>
        public virtual async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber,
            int pageSize,
            Expression<Func<TEntity, bool>>? additionalPredicate = null,
            Expression<Func<TEntity, object>>? orderBy = null,
            bool isDescending = false)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            // DOS 방지
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 10;
            if (pageSize > 1000) pageSize = 1000;

            var query = QueryForOrganization(organizationId);

            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending
                    ? query.OrderByDescending(orderBy)
                    : query.OrderBy(orderBy);
            }

            var items = await query
                .AsNoTracking()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        /// <summary>
        /// 조직 내 엔티티 존재 확인
        /// </summary>
        public virtual async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
        {
            if (!IsOrganizationScopedEntity())
            {
                return await ExistsAsync(id); // 일반 존재 확인으로 폴백
            }

            return await QueryForOrganization(organizationId).AnyAsync(e => e.Id == id);
        }

        /// <summary>
        /// 조직별 개수 세기
        /// </summary>
        public virtual async Task<int> CountByOrganizationAsync(
            Guid organizationId,
            Expression<Func<TEntity, bool>>? predicate = null)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            var query = QueryForOrganization(organizationId);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 조직의 모든 엔티티 삭제 (관리자 전용)
        /// </summary>
        public virtual async Task DeleteAllByOrganizationAsync(Guid organizationId)
        {
            if (!IsOrganizationScopedEntity())
            {
                throw new InvalidOperationException($"Entity {typeof(TEntity).Name} is not organization-scoped.");
            }

            var entities = await GetByOrganizationIdAsync(organizationId);

            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;
            }

            _dbSet.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        #endregion

        #region 헬퍼 메서드

        /// <summary>
        /// 캐시 키 생성 - 조직 컨텍스트 반영
        /// </summary>
        private string GetCacheKey(string operation, params object[] parameters)
        {
            var orgId = _organizationContext.CurrentOrganizationId?.ToString() ?? "Global";
            var paramStr = string.Join(":", parameters);
            return $"{typeof(TEntity).Name}:{operation}:{orgId}:{paramStr}";
        }

        /// 캐시 무효화 - 조직별 분리 및 ICacheService 사용
        /// CUD 작업 후 캐시 일관성을 유지하기 위해 사용됩니다.
        /// </summary>
        protected virtual async Task InvalidateCacheAsync(Guid entityId)
        {
            // ⭐️ ICacheService 필드명은 _cacheService로 가정 (BaseRepository 생성자에서 변경됨)
            if (_cacheService == null) return;

            string cacheKey = GetCacheKey("GetById", entityId);

            // ⭐️ ICacheService의 비동기 RemoveAsync 메서드 호출
            await _cacheService.RemoveAsync(cacheKey);
        }

        #endregion
    }
}

// Expression 확장 메서드 (통계 쿼리용)
public static class ExpressionExtensions
{
    public static string GetPropertyName<T, TProperty>(this Expression<Func<T, TProperty>> expression)
    {
        if (expression.Body is MemberExpression memberExpression)
        {
            return memberExpression.Member.Name;
        }
        throw new ArgumentException("Expression must be a member expression");
    }
}