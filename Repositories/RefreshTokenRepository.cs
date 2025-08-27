using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace AuthHive.Auth.Repositories
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<RefreshTokenRepository> _logger;

        public RefreshTokenRepository(AuthDbContext context, ILogger<RefreshTokenRepository> logger)
        {
            _context = context;
            _logger = logger;
        }

        // IRefreshTokenRepository 특정 메서드
        public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash)
        {
            return await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash && !rt.IsDeleted);
        }

        public async Task<RefreshToken?> GetByTokenValueAsync(string tokenValue)
        {
            return await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.TokenValue == tokenValue && !rt.IsDeleted);
        }

        public async Task<int> RevokeAllForUserAsync(Guid userId)
        {
            return await _context.RefreshTokens
                .Where(rt => rt.ConnectedId == userId && !rt.IsRevoked)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, DateTime.UtcNow)
                    .SetProperty(rt => rt.RevokedReason, "User requested revocation"));
        }

        public async Task<int> RevokeAllForSessionAsync(Guid sessionId)
        {
            return await _context.RefreshTokens
                .Where(rt => rt.SessionId == sessionId && !rt.IsRevoked)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, DateTime.UtcNow)
                    .SetProperty(rt => rt.RevokedReason, "Session terminated"));
        }

        public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(Guid userId)
        {
            return await _context.RefreshTokens
                .Where(rt => rt.ConnectedId == userId && rt.IsActive && !rt.IsRevoked && !rt.IsDeleted)
                .ToListAsync();
        }

        // IRepository<RefreshToken> 기본 구현
        public async Task<RefreshToken?> GetByIdAsync(Guid id)
        {
            return await _context.RefreshTokens.FindAsync(id);
        }

        public async Task<IEnumerable<RefreshToken>> GetAllAsync()
        {
            return await _context.RefreshTokens
                .Where(e => !e.IsDeleted)
                .ToListAsync();
        }

        public async Task<IEnumerable<RefreshToken>> FindAsync(Expression<Func<RefreshToken, bool>> predicate)
        {
            return await _context.RefreshTokens
                .Where(e => !e.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<RefreshToken?> FirstOrDefaultAsync(Expression<Func<RefreshToken, bool>> predicate)
        {
            return await _context.RefreshTokens
                .Where(e => !e.IsDeleted)
                .FirstOrDefaultAsync(predicate);
        }

        public async Task<bool> AnyAsync(Expression<Func<RefreshToken, bool>> predicate)
        {
            return await _context.RefreshTokens
                .Where(e => !e.IsDeleted)
                .AnyAsync(predicate);
        }

        public async Task<int> CountAsync(Expression<Func<RefreshToken, bool>>? predicate = null)
        {
            var query = _context.RefreshTokens.Where(e => !e.IsDeleted);
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync();
        }

        public async Task<(IEnumerable<RefreshToken> Items, int TotalCount)> GetPagedAsync(
            int pageNumber, int pageSize, 
            Expression<Func<RefreshToken, bool>>? predicate = null,
            Expression<Func<RefreshToken, object>>? orderBy = null, 
            bool isDescending = false)
        {
            var query = _context.RefreshTokens.Where(e => !e.IsDeleted);
            
            if (predicate != null)
                query = query.Where(predicate);
            
            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending 
                    ? query.OrderByDescending(orderBy) 
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(e => e.IssuedAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<RefreshToken> AddAsync(RefreshToken entity)
        {
            await _context.RefreshTokens.AddAsync(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task AddRangeAsync(IEnumerable<RefreshToken> entities)
        {
            await _context.RefreshTokens.AddRangeAsync(entities);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(RefreshToken entity)
        {
            _context.Entry(entity).State = EntityState.Modified;
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRangeAsync(IEnumerable<RefreshToken> entities)
        {
            _context.RefreshTokens.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
            {
                await DeleteAsync(entity);
            }
        }

        public async Task DeleteAsync(RefreshToken entity)
        {
            _context.RefreshTokens.Remove(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteRangeAsync(IEnumerable<RefreshToken> entities)
        {
            _context.RefreshTokens.RemoveRange(entities);
            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;
                await UpdateAsync(entity);
            }
        }

        public async Task<bool> ExistsAsync(Guid id)
        {
            return await _context.RefreshTokens
                .AnyAsync(e => e.Id == id && !e.IsDeleted);
        }

        public async Task<bool> ExistsAsync(Expression<Func<RefreshToken, bool>> predicate)
        {
            return await _context.RefreshTokens
                .Where(e => !e.IsDeleted)
                .AnyAsync(predicate);
        }
    }
}