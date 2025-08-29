// Path: AuthHive.Auth/Repositories/UserRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Entities.Auth;

namespace AuthHive.Auth.Repositories
{
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        // 부모 클래스에서 이미 _context와 _dbSet이 정의되어 있으므로 제거
        // private readonly AuthDbContext _context; // 제거

        public UserRepository(AuthDbContext context) : base(context)
        {
            // base 생성자가 _context와 _dbSet을 초기화함
        }

        #region IUserRepository 구현

        public async Task<User?> GetByEmailAsync(string email, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            var query = includeDeleted ? _dbSet : _dbSet.Where(u => !u.IsDeleted);
            return await query.FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
        }
        public async Task<User?> GetByIdWithProfileAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Include(u => u.UserProfile) // UserProfile을 함께 로드(JOIN)하도록 지정
                .FirstOrDefaultAsync(u => u.Id == userId && !u.IsDeleted, cancellationToken);
        }
        public async Task<User?> GetByUsernameAsync(string username, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            var query = includeDeleted ? _dbSet : _dbSet.Where(u => !u.IsDeleted);
            return await query.FirstOrDefaultAsync(u => u.Username == username, cancellationToken);
        }

        public async Task<User?> GetByExternalIdAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(u => !u.IsDeleted && u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<User?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Include(u => u.ConnectedIds)
                .Where(u => !u.IsDeleted && u.ConnectedIds.Any(c => c.Id == connectedId))
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<PagedResult<User>> SearchAsync(SearchUserRequest request, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(u => !u.IsDeleted);

            // 검색 조건 적용
            if (!string.IsNullOrWhiteSpace(request.SearchKeyword))
            {
                query = query.Where(u =>
                    u.Username != null && u.Username.Contains(request.SearchKeyword) ||
                    u.Email != null && u.Email.Contains(request.SearchKeyword) ||
                    u.DisplayName != null && u.DisplayName.Contains(request.SearchKeyword));
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<User>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = request.PageNumber,
                PageSize = request.PageSize
            };
        }

        public async Task<PagedResult<User>> GetByOrganizationAsync(
            Guid organizationId,
            UserStatus? status = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet
                .Include(u => u.ConnectedIds)
                .Where(u => !u.IsDeleted && u.OrganizationId == organizationId);

            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<User>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize
            };
        }

        public async Task<IEnumerable<User>> GetRecentUsersAsync(int count = 10, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(u => !u.IsDeleted)
                .OrderByDescending(u => u.CreatedAt)
                .Take(count)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> IsEmailExistsAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(u => !u.IsDeleted && u.Email == email);

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsUsernameExistsAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(u => !u.IsDeleted && u.Username == username);

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsExternalIdExistsAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(u => !u.IsDeleted && u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId)
                .AnyAsync(cancellationToken);
        }

        public async Task<bool> UpdateStatusAsync(Guid id, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.Status = status;
            user.UpdatedByConnectedId = updatedByConnectedId;
            user.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(user);
            return true;
        }

        public async Task<bool> UpdateEmailVerifiedAsync(Guid id, bool verified, DateTime? verifiedAt = null, CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.IsEmailVerified = verified;
            user.EmailVerifiedAt = verifiedAt ?? DateTime.UtcNow;

            await UpdateAsync(user);
            return true;
        }

        public async Task<bool> UpdateTwoFactorEnabledAsync(Guid id, bool enabled, string? twoFactorMethod = null, CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.IsTwoFactorEnabled = enabled;
            user.TwoFactorMethod = twoFactorMethod;

            await UpdateAsync(user);
            return true;
        }

        public async Task<bool> UpdateLastLoginAsync(Guid id, DateTime loginTime, string? ipAddress = null, CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.LastLoginAt = loginTime;
            if (ipAddress != null)
            {
                user.LastLoginIp = ipAddress;
            }

            await UpdateAsync(user);
            return true;
        }

        public async Task<IEnumerable<Guid>> GetConnectedIdsAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var query = _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId);

            if (activeOnly)
            {
                query = query.Where(c => !c.IsDeleted);
            }

            return await query.Select(c => c.Id).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Guid>> GetOrganizationIdsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return await _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .Select(c => c.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        // FindByUsernameOrEmailAsync - Guid? 반환
        public async Task<Guid?> FindByUsernameOrEmailAsync(string identifier)
        {
            var user = await _dbSet
                .Where(u => (u.Username == identifier || u.Email == identifier) && !u.IsDeleted)
                .FirstOrDefaultAsync();

            return user?.Id;
        }

        // FindByPasswordResetTokenAsync
        public async Task<User?> FindByPasswordResetTokenAsync(string hashedToken)
        {
            return await _dbSet
                .Where(u => u.PasswordResetToken == hashedToken && !u.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<User>> GetInactiveUsersAsync(int inactiveDays, int limit = 100, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await _dbSet
                .Where(u => !u.IsDeleted && (u.LastLoginAt == null || u.LastLoginAt < cutoffDate))
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        public async Task<int> BulkUpdateStatusAsync(IEnumerable<Guid> userIds, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            var users = await _dbSet
                .Where(u => userIds.Contains(u.Id) && !u.IsDeleted)
                .ToListAsync(cancellationToken);

            foreach (var user in users)
            {
                user.Status = status;
                user.UpdatedByConnectedId = updatedByConnectedId;
                user.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync(cancellationToken);
            return users.Count;
        }

        public async Task<int> GetUserCountAsync(UserStatus? status = null, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(u => !u.IsDeleted);

            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            if (organizationId.HasValue)
            {
                query = query.Where(u => u.OrganizationId == organizationId.Value);
            }

            return await query.CountAsync(cancellationToken);
        }

        #endregion
    }
}