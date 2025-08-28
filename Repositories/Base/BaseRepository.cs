using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Entities.Base;
using AuthHive.Auth.Data.Context;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories.Base
{
    /// <summary>
    /// 제네릭 Repository 기본 구현 - AuthHive v15
    /// 모든 Repository의 기본 클래스로 공통 CRUD 작업을 제공합니다.
    /// </summary>
    /// <typeparam name="TEntity">BaseEntity를 상속받는 엔티티 타입</typeparam>
    public class BaseRepository<TEntity> : IRepository<TEntity> where TEntity : BaseEntity
    {
        protected readonly AuthDbContext _context;
        protected readonly DbSet<TEntity> _dbSet;

        public BaseRepository(AuthDbContext context)
        {
            _context = context;
            _dbSet = context.Set<TEntity>();
        }

        #region 조회 작업

        /// <summary>
        /// ID로 엔티티 조회
        /// </summary>
        /// <param name="id">엔티티 ID</param>
        /// <returns>엔티티 또는 null</returns>
        public async Task<TEntity?> GetByIdAsync(Guid id)
        {
            return await _dbSet.FindAsync(id);
        }

        /// <summary>
        /// 모든 엔티티 조회 (삭제되지 않은 것만)
        /// </summary>
        /// <returns>엔티티 목록</returns>
        public async Task<IEnumerable<TEntity>> GetAllAsync()
        {
            return await _dbSet.Where(e => !e.IsDeleted).ToListAsync();
        }

        /// <summary>
        /// 조건에 맞는 엔티티 조회
        /// </summary>
        /// <param name="predicate">검색 조건</param>
        /// <returns>조건에 맞는 엔티티 목록</returns>
        public async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await _dbSet.Where(e => !e.IsDeleted).Where(predicate).ToListAsync();
        }

        /// <summary>
        /// 조건에 맞는 첫 번째 엔티티 조회
        /// </summary>
        /// <param name="predicate">검색 조건</param>
        /// <returns>첫 번째 엔티티 또는 null</returns>
        public async Task<TEntity?> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await _dbSet.Where(e => !e.IsDeleted).Where(predicate).FirstOrDefaultAsync();
        }

        /// <summary>
        /// 조건에 맞는 엔티티 존재 여부 확인
        /// </summary>
        /// <param name="predicate">검색 조건</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> AnyAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await _dbSet.Where(e => !e.IsDeleted).AnyAsync(predicate);
        }

        /// <summary>
        /// 페이징된 데이터 조회
        /// </summary>
        /// <param name="pageNumber">페이지 번호 (1부터 시작)</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="predicate">검색 조건</param>
        /// <param name="orderBy">정렬 기준</param>
        /// <param name="isDescending">내림차순 여부</param>
        /// <returns>페이징된 데이터와 전체 개수</returns>
        public async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<TEntity, bool>>? predicate = null,
            Expression<Func<TEntity, object>>? orderBy = null,
            bool isDescending = false)
        {
            IQueryable<TEntity> query = _dbSet.Where(e => !e.IsDeleted);

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

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        #endregion

        #region CUD 작업

        /// <summary>
        /// 새 엔티티 추가
        /// </summary>
        /// <param name="entity">추가할 엔티티</param>
        /// <returns>추가된 엔티티</returns>
        public async Task<TEntity> AddAsync(TEntity entity)
        {
            if (entity.Id == Guid.Empty)
            {
                entity.Id = Guid.NewGuid();
            }

            await _dbSet.AddAsync(entity);
            await _context.SaveChangesAsync();

            return entity;
        }

        /// <summary>
        /// 여러 엔티티 일괄 추가
        /// </summary>
        /// <param name="entities">추가할 엔티티 목록</param>
        public async Task AddRangeAsync(IEnumerable<TEntity> entities)
        {
            var entityList = entities.ToList();

            foreach (var entity in entityList)
            {
                if (entity.Id == Guid.Empty)
                {
                    entity.Id = Guid.NewGuid();
                }
            }

            await _dbSet.AddRangeAsync(entityList);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 엔티티 업데이트
        /// </summary>
        /// <param name="entity">업데이트할 엔티티</param>
        public async Task UpdateAsync(TEntity entity)
        {
            _dbSet.Update(entity);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 여러 엔티티 일괄 업데이트
        /// </summary>
        /// <param name="entities">업데이트할 엔티티 목록</param>
        public async Task UpdateRangeAsync(IEnumerable<TEntity> entities)
        {
            _dbSet.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// ID로 엔티티 삭제 (Soft Delete)
        /// </summary>
        /// <param name="id">삭제할 엔티티 ID</param>
        public async Task DeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
            {
                await DeleteAsync(entity);
            }
        }

        /// <summary>
        /// 엔티티 삭제 (Soft Delete)
        /// </summary>
        /// <param name="entity">삭제할 엔티티</param>
        public async Task DeleteAsync(TEntity entity)
        {
            // Soft delete
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;

            _dbSet.Update(entity);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 여러 엔티티 일괄 삭제 (Soft Delete)
        /// </summary>
        /// <param name="entities">삭제할 엔티티 목록</param>
        public async Task DeleteRangeAsync(IEnumerable<TEntity> entities)
        {
            var timestamp = DateTime.UtcNow;
            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = timestamp;
            }

            _dbSet.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// ID로 엔티티 Soft Delete
        /// </summary>
        /// <param name="id">삭제할 엔티티 ID</param>
        public async Task SoftDeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;

                _dbSet.Update(entity);
                await _context.SaveChangesAsync();
            }
        }

        #endregion

        #region 유틸리티

        /// <summary>
        /// ID로 엔티티 존재 여부 확인
        /// </summary>
        /// <param name="id">엔티티 ID</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> ExistsAsync(Guid id)
        {
            return await _dbSet.AnyAsync(e => e.Id == id && !e.IsDeleted);
        }

        /// <summary>
        /// 조건으로 엔티티 존재 여부 확인
        /// </summary>
        /// <param name="filter">검색 조건</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> filter)
        {
            return await _dbSet.Where(e => !e.IsDeleted).AnyAsync(filter);
        }

        /// <summary>
        /// 조건에 맞는 엔티티 개수 조회
        /// </summary>
        /// <param name="filter">검색 조건 (선택적)</param>
        /// <returns>엔티티 개수</returns>
        public async Task<int> CountAsync(Expression<Func<TEntity, bool>>? filter = null)
        {
            IQueryable<TEntity> query = _dbSet.Where(e => !e.IsDeleted);

            if (filter != null)
            {
                query = query.Where(filter);
            }

            return await query.CountAsync();
        }

        #endregion

        #region Protected Methods

        /// <summary>
        /// 쿼리 가능한 컬렉션 반환 (짧은 이름)
        /// </summary>
        /// <returns>삭제되지 않은 엔티티의 IQueryable</returns>
        protected IQueryable<TEntity> Query()
        {
            return _dbSet.Where(e => !e.IsDeleted);
        }

        /// <summary>
        /// 쿼리 가능한 컬렉션 반환
        /// </summary>
        /// <returns>삭제되지 않은 엔티티의 IQueryable</returns>
        protected IQueryable<TEntity> GetQueryable()
        {
            return _dbSet.Where(e => !e.IsDeleted);
        }

        /// <summary>
        /// 변경사항 저장
        /// </summary>
        protected async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }

        #endregion
    }
}