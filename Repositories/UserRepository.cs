using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(AuthDbContext context, ILogger<UserRepository> logger)
        {
            _context = context;
            _logger = logger;
        }

        #region IUserRepository Specific Implementations

        public async Task<User?> GetByEmailAsync(string email, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.AsQueryable();
            if (!includeDeleted) query = query.Where(u => !u.IsDeleted);
            var emailLower = email?.ToLower();
            return await query.FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == emailLower, cancellationToken);
        }

        public async Task<User?> GetByUsernameAsync(string username, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.AsQueryable();
            if (!includeDeleted) query = query.Where(u => !u.IsDeleted);
            var usernameLower = username?.ToLower();
            return await query.FirstOrDefaultAsync(u => u.Username != null && u.Username.ToLower() == usernameLower, cancellationToken);
        }

        public async Task<User?> GetByExternalIdAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await _context.Users.FirstOrDefaultAsync(u => !u.IsDeleted && u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId, cancellationToken);
        }

        public async Task<User?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await _context.ConnectedIds.Where(c => c.Id == connectedId && c.User != null && !c.User.IsDeleted).Select(c => c.User).FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<PagedResult<User>> SearchAsync(SearchUserRequest request, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.Where(u => !u.IsDeleted);
            if (request.Status.HasValue) query = query.Where(u => u.Status == request.Status.Value);

            if (!string.IsNullOrWhiteSpace(request.SearchKeyword))
            {
                var searchTermLower = request.SearchKeyword.ToLower();
                query = query.Where(u => (u.Email != null && u.Email.ToLower().Contains(searchTermLower)) || (u.Username != null && u.Username.ToLower().Contains(searchTermLower)));
            }
            
            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query.OrderByDescending(u => u.CreatedAt).Skip((request.PageNumber - 1) * request.PageSize).Take(request.PageSize).ToListAsync(cancellationToken);
            return new PagedResult<User> { Items = items, TotalCount = totalCount, PageNumber = request.PageNumber, PageSize = request.PageSize };
        }

        public async Task<PagedResult<User>> GetByOrganizationAsync(Guid organizationId, UserStatus? status = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            var userQuery = _context.ConnectedIds.Where(c => c.OrganizationId == organizationId && c.User != null && !c.User.IsDeleted).Select(c => c.User).Distinct();
            if (status.HasValue) userQuery = userQuery.Where(u => u.Status == status.Value);
            var totalCount = await userQuery.CountAsync(cancellationToken);
            var items = await userQuery.OrderBy(u => u.Username).Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
            return new PagedResult<User> { Items = items, TotalCount = totalCount, PageNumber = pageNumber, PageSize = pageSize };
        }

        public async Task<IEnumerable<User>> GetRecentUsersAsync(int count = 10, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => !u.IsDeleted).OrderByDescending(u => u.CreatedAt).Take(count).ToListAsync(cancellationToken);
        }

        public async Task<bool> IsEmailExistsAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.AsQueryable();
            if (excludeUserId.HasValue) query = query.Where(u => u.Id != excludeUserId.Value);
            var emailLower = email?.ToLower();
            return await query.AnyAsync(u => u.Email != null && u.Email.ToLower() == emailLower, cancellationToken);
        }

        public async Task<bool> IsUsernameExistsAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.AsQueryable();
            if (excludeUserId.HasValue) query = query.Where(u => u.Id != excludeUserId.Value);
            var usernameLower = username?.ToLower();
            return await query.AnyAsync(u => u.Username != null && u.Username.ToLower() == usernameLower, cancellationToken);
        }

        public async Task<bool> IsExternalIdExistsAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await _context.Users.AnyAsync(u => u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId, cancellationToken);
        }

        public async Task<User?> FindByPasswordResetTokenAsync(string hashedToken)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.PasswordResetToken == hashedToken && !u.IsDeleted);
        }

        public async Task<bool> UpdateStatusAsync(Guid id, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.Status, status), cancellationToken) > 0;
        }

        public async Task<bool> UpdateEmailVerifiedAsync(Guid id, bool verified, DateTime? verifiedAt = null, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsEmailVerified, u => verified).SetProperty(u => u.EmailVerifiedAt, u => verified ? (verifiedAt ?? DateTime.UtcNow) : null), cancellationToken) > 0;
        }

        public async Task<bool> UpdateTwoFactorEnabledAsync(Guid id, bool enabled, string? twoFactorMethod = null, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsTwoFactorEnabled, u => enabled).SetProperty(u => u.TwoFactorMethod, u => enabled ? twoFactorMethod : null), cancellationToken) > 0;
        }

        public async Task<bool> UpdateLastLoginAsync(Guid id, DateTime loginTime, string? ipAddress = null, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.LastLoginAt, u => loginTime).SetProperty(u => u.LastLoginIp, u => ipAddress), cancellationToken) > 0;
        }

        public async Task<IEnumerable<Guid>> GetConnectedIdsAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var query = _context.ConnectedIds.Where(c => c.UserId == userId);
            return await query.Select(c => c.Id).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Guid>> GetOrganizationIdsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return await _context.ConnectedIds.Where(c => c.UserId == userId).Select(c => c.OrganizationId).Distinct().ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<User>> GetInactiveUsersAsync(int inactiveDays, int limit = 100, CancellationToken cancellationToken = default)
        {
            var threshold = DateTime.UtcNow.AddDays(-inactiveDays);
            return await _context.Users.Where(u => u.LastLoginAt < threshold && u.Status == UserStatus.Active).OrderBy(u => u.LastLoginAt).Take(limit).ToListAsync(cancellationToken);
        }

        public async Task<int> BulkUpdateStatusAsync(IEnumerable<Guid> userIds, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            return await _context.Users.Where(u => userIds.Contains(u.Id)).ExecuteUpdateAsync(s => s.SetProperty(u => u.Status, status), cancellationToken);
        }

        public async Task<int> GetUserCountAsync(UserStatus? status = null, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var query = _context.Users.Where(u => !u.IsDeleted);
            if (status.HasValue) query = query.Where(u => u.Status == status.Value);
            if (organizationId.HasValue) query = query.Where(u => u.ConnectedIds.Any(c => c.OrganizationId == organizationId.Value));
            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region Base IRepository<T> Implementations
        
        public async Task<User?> GetByIdAsync(Guid id)
        {
            return await _context.Users.FindAsync(id);
        }

        public async Task<IEnumerable<User>> GetAllAsync()
        {
            return await _context.Users.Where(e => !e.IsDeleted).ToListAsync();
        }

        public async Task<IEnumerable<User>> FindAsync(Expression<Func<User, bool>> predicate)
        {
            return await _context.Users.Where(e => !e.IsDeleted).Where(predicate).ToListAsync();
        }

        public async Task<User?> FirstOrDefaultAsync(Expression<Func<User, bool>> predicate)
        {
            return await _context.Users.Where(e => !e.IsDeleted).FirstOrDefaultAsync(predicate);
        }

        public async Task<bool> AnyAsync(Expression<Func<User, bool>> predicate)
        {
            return await _context.Users.Where(e => !e.IsDeleted).AnyAsync(predicate);
        }

        public async Task<int> CountAsync(Expression<Func<User, bool>>? predicate = null)
        {
            var query = _context.Users.Where(e => !e.IsDeleted);
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync();
        }

        public async Task<(IEnumerable<User> Items, int TotalCount)> GetPagedAsync(int pageNumber, int pageSize, Expression<Func<User, bool>>? predicate = null, Expression<Func<User, object>>? orderBy = null, bool isDescending = false)
        {
            var query = _context.Users.Where(e => !e.IsDeleted);
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            
            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(e => e.Id);
            }

            var items = await query.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();
            return (items, totalCount);
        }

        public async Task<User> AddAsync(User entity)
        {
            await _context.Users.AddAsync(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task AddRangeAsync(IEnumerable<User> entities)
        {
            await _context.Users.AddRangeAsync(entities);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(User entity)
        {
            _context.Entry(entity).State = EntityState.Modified;
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRangeAsync(IEnumerable<User> entities)
        {
            _context.Users.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
            {
                _context.Users.Remove(entity);
                await _context.SaveChangesAsync();
            }
        }

        public async Task DeleteAsync(User entity)
        {
            _context.Users.Remove(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteRangeAsync(IEnumerable<User> entities)
        {
            _context.Users.RemoveRange(entities);
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
            return await _context.Users.AnyAsync(e => e.Id == id && !e.IsDeleted);
        }

        public async Task<bool> ExistsAsync(Expression<Func<User, bool>> predicate)
        {
            return await _context.Users.Where(e => !e.IsDeleted).AnyAsync(predicate);
        }

        #endregion
    }
}