// Path: AuthHive.Auth/Repositories/UserRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Memory; // ❌ IMemoryCache 제거됨
using Microsoft.Extensions.Logging;
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
using AuthHive.Core.Interfaces.Infra.Cache; // ⭐️ ICacheService 사용을 위해 추가

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// User Repository 구현 - AuthHive v15.5 (ICacheService 적용 완료)
    /// User 엔티티는 조직 스코프가 아니므로, RLS 필터링을 우회합니다.
    /// </summary>
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        // UserRepository는 BaseRepository의 필드를 직접 사용하지 않고 DI된 로거만 유지합니다.
        private readonly ILogger<UserRepository> _logger;

        /// <summary>
        /// 생성자 (IMemoryCache 대신 ICacheService를 받음)
        /// </summary>
        public UserRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserRepository> logger, // 로거 추가
            ICacheService? cacheService = null) // ⭐️ ICacheService로 변경
            : base(context, organizationContext, cacheService) // BaseRepository에 전달
        {
            _logger = logger;
        }

        #region Override 메서드

        /// <summary>
        /// User 엔티티는 조직 스코프가 아니므로, BaseRepository의 조직 필터링을 우회합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return false;
        }

        #endregion

        #region IUserRepository 구현 (조회 및 상태 관리)

        /// <summary>
        /// ID로 사용자를 조회하되, UserProfile 정보도 함께 가져옵니다. (ICacheService 적용)
        /// </summary>
        public async Task<User?> GetByIdWithProfileAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            // 1. 캐시 키 정의
            string cacheKey = $"User:GetByIdWithProfile:{userId}";

            // 2. ICacheService에서 조회 시도 (null 검사 및 안전한 할당)
            User? user = null; // 조회 결과를 저장할 변수 초기화

            // ⭐️ _cacheService가 null인지 먼저 확인합니다.
            if (_cacheService != null)
            {
                // ICacheService의 GetAsync<T>를 호출하여 캐시에서 User를 조회합니다.
                user = await _cacheService.GetAsync<User>(cacheKey);
            }

            if (user != null)
            {
                return user;
            }

            // 3. DB 조회 (Include를 사용)
            // Query()는 BaseRepository의 RLS(조직 필터링)를 우회하여 전역 User 테이블을 조회함.
            user = await Query()
                .Include(u => u.UserProfile)
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

            // 4. 캐시 저장 (ICacheService.SetAsync 사용)
            // User 엔티티가 null이 아닐 때만 저장합니다.
            if (user != null && _cacheService != null)
            {
                // Note: TTL 15분은 BaseRepository의 기본 TTL을 따릅니다.
                await _cacheService.SetAsync(cacheKey, user, TimeSpan.FromMinutes(15));
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
        /// ConnectedId는 User에 대한 관계를 가지고 있으므로 Include 사용
        /// </summary>
        public async Task<User?> GetByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()는 User 엔티티에 대한 RLS 필터링을 하지 않으므로 안전합니다.
            return await Query()
                .Include(u => u.ConnectedIds)
                .AsNoTracking()
                .FirstOrDefaultAsync(u =>
                    u.ConnectedIds.Any(c => c.Id == connectedId),
                    cancellationToken);
        }

        /// <summary>
        /// 사용자 검색 (페이징 포함)
        /// BaseRepository의 GetPagedAsync를 직접 활용하는 것이 이상적이나, 복잡한 동적 필터링 로직을 유지
        /// </summary>
        public async Task<PagedResult<User>> SearchAsync(
            SearchUserRequest request,
            CancellationToken cancellationToken = default)
        {
            // BaseSearchRequest 속성 접근을 위한 dynamic은 유지 (기존 코드의 패턴)
            dynamic req = request;

            int pageNumber = (int)(req.PageNumber ?? 1);
            int pageSize = (int)(req.PageSize ?? 20);
            string? searchTerm = (string?)req.SearchTerm;
            string? sortBy = (string?)req.SortBy;
            bool sortDescending = (bool)(req.SortDescending ?? true);

            if (pageNumber < 1) pageNumber = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100; // DOS 방지: 최대 100개로 제한 유지

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
            if (request.Status.HasValue) query = query.Where(u => u.Status == request.Status.Value);
            // 이메일 인증 필터
            if (request.EmailVerified.HasValue) query = query.Where(u => u.IsEmailVerified == request.EmailVerified.Value);
            // 2FA 필터
            if (request.IsTwoFactorEnabled.HasValue) query = query.Where(u => u.IsTwoFactorEnabled == request.IsTwoFactorEnabled.Value);
            // 외부 시스템 타입 필터
            if (!string.IsNullOrWhiteSpace(request.ExternalSystemType)) query = query.Where(u => u.ExternalSystemType == request.ExternalSystemType);
            // 마지막 로그인 날짜 필터
            if (request.LastLoginAfter.HasValue) query = query.Where(u => u.LastLoginAt != null && u.LastLoginAt >= request.LastLoginAfter.Value);
            if (request.LastLoginBefore.HasValue) query = query.Where(u => u.LastLoginAt != null && u.LastLoginAt <= request.LastLoginBefore.Value);

            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬
            query = sortBy?.ToLower() switch
            {
                "email" => sortDescending ? query.OrderByDescending(u => u.Email) : query.OrderBy(u => u.Email),
                "username" => sortDescending ? query.OrderByDescending(u => u.Username) : query.OrderBy(u => u.Username),
                "createdat" => sortDescending ? query.OrderByDescending(u => u.CreatedAt) : query.OrderBy(u => u.CreatedAt),
                "lastlogin" => sortDescending ? query.OrderByDescending(u => u.LastLoginAt) : query.OrderBy(u => u.LastLoginAt),
                "displayname" => sortDescending ? query.OrderByDescending(u => u.DisplayName) : query.OrderBy(u => u.DisplayName),
                "status" => sortDescending ? query.OrderByDescending(u => u.Status) : query.OrderBy(u => u.Status),
                _ => sortDescending ? query.OrderByDescending(u => u.CreatedAt) : query.OrderBy(u => u.CreatedAt)
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
        /// NOTE: User 엔티티에 OrganizationId가 있으므로 직접 쿼리 가능함.
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
                .Where(u => u.OrganizationId == organizationId); // ⭐️ User 엔티티의 OrganizationId 필터링

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

            await UpdateAsync(user); // 캐시 무효화 포함
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
        /// 사용자의 ConnectedId 목록 조회 (ID만)
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

                // ⭐️ 캐시 무효화 (await 필요)
                await InvalidateCacheAsync(user.Id);
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

        // ⭐️ BaseRepository의 IMemoryCache -> ICacheService 리팩토링으로 인해 
        // IMemoryCache 필드 및 MemoryCacheEntryOptions는 BaseRepository에서 제거되었습니다. 
        // UserRepository는 BaseRepository를 상속받아 ICacheService를 간접적으로 사용합니다.
    }
}