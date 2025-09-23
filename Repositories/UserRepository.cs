// Path: AuthHive.Auth/Repositories/UserRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// User Repository 구현 - AuthHive v15.5
    /// </summary>
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        /// <summary>
        /// 생성자
        /// </summary>
        public UserRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        #region Override 메서드

        /// <summary>
        /// User는 조직 스코프가 아님
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return false;
        }

        #endregion

        #region IUserRepository 구현

        /// <summary>
        /// ID로 사용자를 조회하되, UserProfile 정보도 함께 가져옵니다.
        /// </summary>
        public async Task<User?> GetByIdWithProfileAsync(
            Guid userId, 
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"User:GetByIdWithProfile:{userId}";
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out User? cachedUser))
            {
                return cachedUser;
            }

            var user = await Query()
                .Include(u => u.UserProfile)
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

            if (user != null && _cache != null)
            {
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set(cacheKey, user, cacheOptions);
            }

            return user;
        }

        /// <summary>
        /// 이메일로 사용자 조회
        /// </summary>
        public async Task<User?> GetByEmailAsync(
            string email, 
            bool includeDeleted = false, 
            CancellationToken cancellationToken = default)
        {
            var query = includeDeleted ? _dbSet : Query();
            return await query
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
        }

        /// <summary>
        /// 사용자명으로 사용자 조회
        /// </summary>
        public async Task<User?> GetByUsernameAsync(
            string username, 
            bool includeDeleted = false, 
            CancellationToken cancellationToken = default)
        {
            var query = includeDeleted ? _dbSet : Query();
            return await query
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Username == username, cancellationToken);
        }

        /// <summary>
        /// 외부 시스템 ID로 사용자 조회
        /// </summary>
        public async Task<User?> GetByExternalIdAsync(
            string externalSystemType, 
            string externalUserId, 
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(u => 
                    u.ExternalSystemType == externalSystemType && 
                    u.ExternalUserId == externalUserId, 
                    cancellationToken);
        }

        /// <summary>
        /// ConnectedId로 사용자 조회
        /// </summary>
        public async Task<User?> GetByConnectedIdAsync(
            Guid connectedId, 
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(u => u.ConnectedIds)
                .AsNoTracking()
                .FirstOrDefaultAsync(u => 
                    u.ConnectedIds.Any(c => c.Id == connectedId), 
                    cancellationToken);
        }

        /// <summary>
        /// 사용자 검색 (페이징 포함)
        /// </summary>
        public async Task<PagedResult<User>> SearchAsync(
            SearchUserRequest request, 
            CancellationToken cancellationToken = default)
        {
            // dynamic을 사용하여 BaseSearchRequest 속성 접근
            dynamic req = request;
            
            // 페이징 값 가져오기 및 유효성 검증
            int pageNumber = (int)(req.PageNumber ?? 1);
            int pageSize = (int)(req.PageSize ?? 20);
            string? searchTerm = (string?)req.SearchTerm;
            string? sortBy = (string?)req.SortBy;
            bool sortDescending = (bool)(req.SortDescending ?? true);
            
            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var query = Query();

            // 검색어 필터
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var term = searchTerm.ToLower();
                query = query.Where(u =>
                    (u.Username != null && u.Username.ToLower().Contains(term)) ||
                    (u.Email != null && u.Email.ToLower().Contains(term)) ||
                    (u.DisplayName != null && u.DisplayName.ToLower().Contains(term)));
            }

            // 상태 필터
            if (request.Status.HasValue)
            {
                query = query.Where(u => u.Status == request.Status.Value);
            }

            // 이메일 인증 필터
            if (request.EmailVerified.HasValue)
            {
                query = query.Where(u => u.IsEmailVerified == request.EmailVerified.Value);
            }

            // 2FA 필터
            if (request.IsTwoFactorEnabled.HasValue)
            {
                query = query.Where(u => u.IsTwoFactorEnabled == request.IsTwoFactorEnabled.Value);
            }

            // 외부 시스템 타입 필터
            if (!string.IsNullOrWhiteSpace(request.ExternalSystemType))
            {
                query = query.Where(u => u.ExternalSystemType == request.ExternalSystemType);
            }

            // 마지막 로그인 날짜 필터
            if (request.LastLoginAfter.HasValue)
            {
                query = query.Where(u => u.LastLoginAt != null && u.LastLoginAt >= request.LastLoginAfter.Value);
            }
            if (request.LastLoginBefore.HasValue)
            {
                query = query.Where(u => u.LastLoginAt != null && u.LastLoginAt <= request.LastLoginBefore.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬
            query = sortBy?.ToLower() switch
            {
                "email" => sortDescending ? 
                    query.OrderByDescending(u => u.Email) : 
                    query.OrderBy(u => u.Email),
                "username" => sortDescending ? 
                    query.OrderByDescending(u => u.Username) : 
                    query.OrderBy(u => u.Username),
                "createdat" => sortDescending ? 
                    query.OrderByDescending(u => u.CreatedAt) : 
                    query.OrderBy(u => u.CreatedAt),
                "lastlogin" => sortDescending ? 
                    query.OrderByDescending(u => u.LastLoginAt) : 
                    query.OrderBy(u => u.LastLoginAt),
                "displayname" => sortDescending ? 
                    query.OrderByDescending(u => u.DisplayName) : 
                    query.OrderBy(u => u.DisplayName),
                "status" => sortDescending ?
                    query.OrderByDescending(u => u.Status) :
                    query.OrderBy(u => u.Status),
                _ => sortDescending ?
                    query.OrderByDescending(u => u.CreatedAt) :
                    query.OrderBy(u => u.CreatedAt)
            };

            // 페이징
            var items = await query
                .AsNoTracking()
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

        /// <summary>
        /// 조직의 사용자 목록 조회
        /// </summary>
        public async Task<PagedResult<User>> GetByOrganizationAsync(
            Guid organizationId,
            UserStatus? status = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Include(u => u.ConnectedIds)
                .Where(u => u.OrganizationId == organizationId);

            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            
            var items = await query
                .OrderByDescending(u => u.CreatedAt)
                .AsNoTracking()
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

        /// <summary>
        /// 최근 가입한 사용자 조회
        /// </summary>
        public async Task<IEnumerable<User>> GetRecentUsersAsync(
            int count = 10, 
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .OrderByDescending(u => u.CreatedAt)
                .Take(count)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 메서드

        /// <summary>
        /// 이메일 중복 확인
        /// </summary>
        public async Task<bool> IsEmailExistsAsync(
            string email, 
            Guid? excludeUserId = null, 
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(u => u.Email == email);

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        /// <summary>
        /// 사용자명 중복 확인
        /// </summary>
        public async Task<bool> IsUsernameExistsAsync(
            string username, 
            Guid? excludeUserId = null, 
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(u => u.Username == username);

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        /// <summary>
        /// 외부 시스템 ID 중복 확인
        /// </summary>
        public async Task<bool> IsExternalIdExistsAsync(
            string externalSystemType, 
            string externalUserId, 
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .AnyAsync(u => 
                    u.ExternalSystemType == externalSystemType && 
                    u.ExternalUserId == externalUserId, 
                    cancellationToken);
        }

        #endregion

        #region 상태 관리

        /// <summary>
        /// 사용자 상태 변경
        /// </summary>
        public async Task<bool> UpdateStatusAsync(
            Guid id, 
            UserStatus status, 
            Guid? updatedByConnectedId = null, 
            CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.Status = status;
            user.UpdatedByConnectedId = updatedByConnectedId;
            user.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(user);
            await _context.SaveChangesAsync(cancellationToken);
            
            return true;
        }

        /// <summary>
        /// 이메일 인증 상태 업데이트
        /// </summary>
        public async Task<bool> UpdateEmailVerifiedAsync(
            Guid id, 
            bool verified, 
            DateTime? verifiedAt = null, 
            CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.IsEmailVerified = verified;
            user.EmailVerifiedAt = verifiedAt ?? DateTime.UtcNow;

            await UpdateAsync(user);
            await _context.SaveChangesAsync(cancellationToken);
            
            return true;
        }

        /// <summary>
        /// 2단계 인증 상태 업데이트
        /// </summary>
        public async Task<bool> UpdateTwoFactorEnabledAsync(
            Guid id, 
            bool enabled, 
            string? twoFactorMethod = null, 
            CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.IsTwoFactorEnabled = enabled;
            user.TwoFactorMethod = twoFactorMethod;

            await UpdateAsync(user);
            await _context.SaveChangesAsync(cancellationToken);
            
            return true;
        }

        /// <summary>
        /// 마지막 로그인 시간 업데이트
        /// </summary>
        public async Task<bool> UpdateLastLoginAsync(
            Guid id, 
            DateTime loginTime, 
            string? ipAddress = null, 
            CancellationToken cancellationToken = default)
        {
            var user = await GetByIdAsync(id);
            if (user == null) return false;

            user.LastLoginAt = loginTime;
            if (ipAddress != null)
            {
                user.LastLoginIp = ipAddress;
            }

            await UpdateAsync(user);
            await _context.SaveChangesAsync(cancellationToken);
            
            return true;
        }

        #endregion

        #region 관련 엔티티

        /// <summary>
        /// 사용자의 ConnectedId 목록 조회
        /// </summary>
        public async Task<IEnumerable<Guid>> GetConnectedIdsAsync(
            Guid userId, 
            bool activeOnly = true, 
            CancellationToken cancellationToken = default)
        {
            var query = _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId);

            if (activeOnly)
            {
                query = query.Where(c => !c.IsDeleted);
            }

            return await query
                .Select(c => c.Id)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 사용자의 조직 ID 목록 조회
        /// </summary>
        public async Task<IEnumerable<Guid>> GetOrganizationIdsAsync(
            Guid userId, 
            CancellationToken cancellationToken = default)
        {
            return await _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId && !c.IsDeleted)
                .Select(c => c.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 비밀번호 관련

        /// <summary>
        /// 사용자명 또는 이메일로 사용자 ID 조회
        /// </summary>
        public async Task<Guid?> FindByUsernameOrEmailAsync(string identifier)
        {
            var user = await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(u => 
                    u.Username == identifier || 
                    u.Email == identifier);

            return user?.Id;
        }

        /// <summary>
        /// 비밀번호 재설정 토큰으로 사용자 조회
        /// </summary>
        public async Task<User?> FindByPasswordResetTokenAsync(string hashedToken)
        {
            return await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.PasswordResetToken == hashedToken);
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 비활성 사용자 조회
        /// </summary>
        public async Task<IEnumerable<User>> GetInactiveUsersAsync(
            int inactiveDays, 
            int limit = 100, 
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await Query()
                .Where(u => u.LastLoginAt == null || u.LastLoginAt < cutoffDate)
                .OrderBy(u => u.LastLoginAt ?? u.CreatedAt)
                .Take(limit)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 여러 사용자 상태 일괄 변경
        /// </summary>
        public async Task<int> BulkUpdateStatusAsync(
            IEnumerable<Guid> userIds, 
            UserStatus status, 
            Guid? updatedByConnectedId = null, 
            CancellationToken cancellationToken = default)
        {
            var userIdList = userIds.ToList();
            var users = await Query()
                .Where(u => userIdList.Contains(u.Id))
                .ToListAsync(cancellationToken);

            if (!users.Any()) return 0;

            var timestamp = DateTime.UtcNow;
            foreach (var user in users)
            {
                user.Status = status;
                user.UpdatedByConnectedId = updatedByConnectedId;
                user.UpdatedAt = timestamp;
                
                InvalidateCache(user.Id);
            }

            _dbSet.UpdateRange(users);
            await _context.SaveChangesAsync(cancellationToken);
            
            return users.Count;
        }

        #endregion

        #region 집계

        /// <summary>
        /// 사용자 수 집계
        /// </summary>
        public async Task<int> GetUserCountAsync(
            UserStatus? status = null, 
            Guid? organizationId = null, 
            CancellationToken cancellationToken = default)
        {
            var query = Query();

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