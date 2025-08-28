// Path: AuthHive.Auth/Repositories/Base/OrganizationScopedRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Entities.Base;
using AuthHive.Auth.Data.Context;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories.Base
{
    /// <summary>
    /// 조직 스코프 Repository 기본 구현
    /// </summary>
    public class OrganizationScopedRepository<TEntity> : BaseRepository<TEntity>, IOrganizationScopedRepository<TEntity> 
        where TEntity : OrganizationScopedEntity
    {
        public OrganizationScopedRepository(AuthDbContext context) : base(context) { }

        public async Task<IEnumerable<TEntity>> GetByOrganizationIdAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(e => e.OrganizationId == organizationId && !e.IsDeleted)
                .ToListAsync();
        }

        public async Task<TEntity?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _dbSet
                .FirstOrDefaultAsync(e => e.Id == id && e.OrganizationId == organizationId && !e.IsDeleted);
        }

        public async Task<IEnumerable<TEntity>> FindByOrganizationAsync(
            Guid organizationId, 
            Expression<Func<TEntity, bool>> predicate)
        {
            return await _dbSet
                .Where(e => e.OrganizationId == organizationId && !e.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber,
            int pageSize,
            Expression<Func<TEntity, bool>>? additionalPredicate = null,
            Expression<Func<TEntity, object>>? orderBy = null,
            bool isDescending = false)
        {
            var query = _dbSet.Where(e => e.OrganizationId == organizationId && !e.IsDeleted);

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
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _dbSet.AnyAsync(e => 
                e.Id == id && 
                e.OrganizationId == organizationId && 
                !e.IsDeleted);
        }

        public async Task<int> CountByOrganizationAsync(
            Guid organizationId, 
            Expression<Func<TEntity, bool>>? predicate = null)
        {
            var query = _dbSet.Where(e => e.OrganizationId == organizationId && !e.IsDeleted);
            
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            
            return await query.CountAsync();
        }

        public async Task DeleteAllByOrganizationAsync(Guid organizationId)
        {
            var entities = await GetByOrganizationIdAsync(organizationId);
            
            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;
            }
            
            _dbSet.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }
    }
}