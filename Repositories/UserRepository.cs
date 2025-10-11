using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth; // ConnectedId 엔티티 사용을 위해 필수
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// User Repository 구현 - AuthHive v16 (아키텍처 원칙 적용 최종본)
    /// IUserRepository 인터페이스의 모든 요구사항을 완벽하게 구현합니다.
    /// </summary>
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(
            AuthDbContext context,
            ILogger<UserRepository> logger,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger;
        }

        #region Override Methods
        /// <summary>
        /// User 엔티티는 '전역(Global)' 개념이므로 특정 조직에 '직접' 종속되지 않습니다.
        /// User와 Organization의 관계는 'ConnectedId'라는 중간 엔티티를 통해 N:M으로 맺어집니다.
        /// 따라서 BaseRepository의 자동 조직 필터링 로직을 우회하도록 false를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;
        #endregion

        #region IUserRepository Implementations


        public async Task<User?> GetByIdWithProfileAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // GetByIdAsync를 재사용하여 캐싱 이점을 활용합니다.
            var user = await GetByIdAsync(userId, cancellationToken);
            if (user != null)
            {
                // UserProfile을 명시적으로 로드합니다.
                await _context.Entry(user).Reference(u => u.UserProfile).LoadAsync(cancellationToken);
            }
            return user;
        }

        public async Task<User?> GetByEmailAsync(string email, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email)) return null;
            var query = includeDeleted ? _context.Set<User>().IgnoreQueryFilters() : Query();
            return await query.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
        }

        public async Task<User?> GetByUsernameAsync(string username, bool includeDeleted = false, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username)) return null;
            var query = includeDeleted ? _context.Set<User>().IgnoreQueryFilters() : Query();
            return await query.AsNoTracking().FirstOrDefaultAsync(u => u.Username == username, cancellationToken);
        }

        public async Task<User?> GetByExternalIdAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId, cancellationToken);
        }
        /// <summary>
        /// [신규 구현] IUserRepository 인터페이스에 정의된 계약을 이행합니다.
        /// AuthHive 개념에 따라 'ConnectedId' 테이블을 조회하여
        /// 특정 조직에 속한 '활성 멤버십'의 수를 계산합니다.
        /// </summary>
        /// <param name="organizationId">사용자 수를 계산할 조직의 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>해당 조직의 활성 사용자 수</returns>
        public async Task<int> CountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // User 테이블을 직접 세는 것이 아니라,
            // User와 Organization의 관계를 맺어주는 'ConnectedId'(사원증)의 개수를 셉니다.
            // 이렇게 함으로써 한 명의 User가 여러 조직에 속한 N:M 관계를 정확하게 처리할 수 있습니다.
            return await _context.Set<ConnectedId>()
                .CountAsync(c => c.OrganizationId == organizationId && c.Status == ConnectedIdStatus.Active, cancellationToken);
        }
        /// <summary>
        /// ConnectedId를 통해 연결된 전역 사용자(User) 엔티티를 조회합니다.
        /// ConnectedId -> User 탐색 속성을 사용합니다.
        /// </summary>
        public async Task<User?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // _context.Set<ConnectedId>()를 사용하여 ConnectedId 테이블에 접근합니다.
            // EF Core 쿼리에서 Nullable 탐색 속성을 사용할 때 AsNoTracking()과 관련된 CS8634 오류를 해결하기 위해
            // .Select(c => c.User!)를 사용하여 null-check를 강제합니다. (User는 Nullable이 아니라고 가정)
            return await _context.Set<ConnectedId>()
                .Where(c => c.Id == connectedId)
                .Select(c => c.User!) // ✅ [CS8634 해결] Null Forgiveness Operator(!)를 사용하여 AsNoTracking()이 Non-nullable 타입을 받도록 합니다.
                .AsNoTracking()
                // .Where(u => u != null) 로직은 Select(c => c.User!)로 대체되었습니다.
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<PagedResult<User>> SearchAsync(SearchUserRequest request, CancellationToken cancellationToken = default)
        {
            var query = Query();

            if (!string.IsNullOrWhiteSpace(request.SearchTerm))
            {
                var term = request.SearchTerm.ToLower();
                query = query.Where(u =>
                    (u.Username != null && u.Username.ToLower().Contains(term)) ||
                    (u.Email != null && u.Email.ToLower().Contains(term)) ||
                    (u.DisplayName != null && u.DisplayName.ToLower().Contains(term)));
            }
            if (request.Status.HasValue)
            {
                query = query.Where(u => u.Status == request.Status.Value);
            }
            // ... 기타 필터링 조건 ...

            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query
                .OrderByDescending(u => u.CreatedAt)
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return new PagedResult<User>(items, totalCount, request.PageNumber, request.PageSize);
        }
        /// <summary>
        /// [최종 구현] IUserRepository 인터페이스에 정의된 계약을 이행합니다.
        /// AuthHive 개념에 따라 'ConnectedId'를 통해 특정 조직의 사용자 목록을 페이징하여 조회하고,
        /// (Items, TotalCount) 튜플 형태로 결과를 반환합니다.
        /// </summary>
        /// <param name="organizationId">조회할 조직의 ID</param>
        /// <param name="pageNumber">페이지 번호</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 목록과 전체 개수를 포함하는 튜플</returns>
        public async Task<(IEnumerable<User> Items, int TotalCount)> GetPagedByOrganizationAsync(Guid organizationId, int pageNumber, int pageSize, CancellationToken cancellationToken = default)
        {
            // 1. 'ConnectedId' 테이블에서 시작하여 특정 조직의 멤버십을 찾고, 연결된 User가 null이 아닌 경우만 필터링합니다.
            //    이 단계에서 'c.User.IsDeleted'에 안전하게 접근할 수 있습니다. (CS8602 해결)
            var query = _context.Set<ConnectedId>()
                .Where(c => c.OrganizationId == organizationId && c.User != null && !c.User.IsDeleted)
                // 2. [핵심 최종 해결책] Select 구문 안에서 Null-Forigiving 연산자(!)를 사용하여
                //    IQueryable<User?>가 아닌 IQueryable<User> 타입을 반환하도록 컴파일러에게 명확히 지시합니다.
                //    이것이 이전에 다른 메서드에서 성공했던 패턴입니다.
                .Select(c => c.User!);

            // 3. 필터링된 최종 결과의 전체 개수를 먼저 계산합니다.
            var totalCount = await query.CountAsync(cancellationToken);

            // 4. 정렬, 페이징을 적용하여 실제 데이터를 가져옵니다.
            //    이제 query는 IQueryable<User> 타입이므로, AsNoTracking()에서 CS8634 오류가 발생하지 않습니다.
            var items = await query
                .OrderByDescending(u => u.CreatedAt) // 최신 가입자 순으로 정렬
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            // 5. 인터페이스가 요구하는 (Items, TotalCount) 튜플 형태로 결과를 반환합니다.
            return (items, totalCount);
        }


        /// <summary>
        /// [최종 수정] IUserRepository 인터페이스의 시그니처와 반환 타입을 완벽하게 준수하는 구현입니다.
        /// </summary>
        public async Task<PagedResult<User>> GetByOrganizationAsync(
            Guid organizationId,
            UserStatus? status = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // 1. [쿼리 구성] ConnectedId를 통해 User에 접근하며, Null 및 삭제된 유저를 필터링합니다.
            var query = _context.Set<ConnectedId>()
                .Where(c => c.OrganizationId == organizationId)

                // 1-1. [Null 안전성 확보] User 탐색 속성이 null이 아닌 경우만 필터링합니다 (CS8602 해결).
                // ConnectedId는 존재하지만 User가 삭제되어 연결이 끊긴 경우를 방지합니다.
                .Where(c => c.User != null)

                // 1-2. User 엔티티를 선택하고, 삭제된 유저를 필터링합니다.
                // Select(c => c.User!)를 사용하여 EF Core가 User를 Non-nullable로 처리하도록 유도합니다.
                // 이 시점의 IQueryable<User>는 Non-nullable 타입이 되어 CS8634 오류를 해결합니다.
                .Select(c => c.User!)
                .Where(u => !u.IsDeleted);

            // 2. [상태 필터링] 요청된 사용자 상태(Active, Suspended 등)에 따라 필터링을 적용합니다.
            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            // 3. [페이징 계산] 전체 개수를 조회합니다. (DB I/O)
            var totalCount = await query.CountAsync(cancellationToken);

            // 4. [데이터 조회] 페이징 및 정렬된 데이터를 조회합니다. (DB I/O)
            var items = await query
                .OrderByDescending(u => u.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken); // ✅ CancellationToken 전달

            // 5. [결과 반환] PagedResult 타입 캐스팅 및 생성
            // ToListAsync() 결과는 List<User> (User는 Non-nullable 클래스)이므로, 
            // PagedResult<User> 생성자에 안전하게 전달됩니다 (CS8620 해결).
            return new PagedResult<User>(items, totalCount, pageNumber, pageSize);
        }
        // AuthHive.Auth/Repositories/UserRepository.cs (가정)

        public async Task<bool> IsUserInOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            // _context.Set<ConnectedId>()를 사용하여 User와 Organization 관계를 조회합니다.
            return await _context.Set<ConnectedId>()
                .AsNoTracking()
                // 해당 User가 해당 Organization에 대해 활성화된 ConnectedId를 가지고 있는지 확인
                .AnyAsync(c => c.UserId == userId &&
                               c.OrganizationId == organizationId &&
                               c.Status == ConnectedIdStatus.Active, // 활성 멤버십만 카운트
                         cancellationToken);
        }
        public async Task<IEnumerable<User>> GetRecentUsersAsync(int count = 10, CancellationToken cancellationToken = default)
        {
            return await Query().OrderByDescending(u => u.CreatedAt).Take(count).AsNoTracking().ToListAsync(cancellationToken);
        }

        public async Task<bool> IsEmailExistsAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(u => u.Email == email);
            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsUsernameExistsAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(u => u.Username == username);
            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsExternalIdExistsAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(u => u.ExternalSystemType == externalSystemType && u.ExternalUserId == externalUserId, cancellationToken);
        }

        public async Task<bool> UpdateStatusAsync(Guid id, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null) return false;
            user.Status = status;
            await UpdateAsync(user, cancellationToken);
            // 실제 저장은 UnitOfWork.SaveChangesAsync()에서 처리됩니다.
            return true;
        }

        public async Task<bool> UpdateEmailVerifiedAsync(Guid id, bool verified, DateTime? verifiedAt = null, CancellationToken cancellationToken = default)
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null) return false;
            user.IsEmailVerified = verified;
            user.EmailVerifiedAt = verified ? (verifiedAt ?? DateTime.UtcNow) : null;
            await UpdateAsync(user, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateTwoFactorEnabledAsync(Guid id, bool enabled, string? twoFactorMethod = null, CancellationToken cancellationToken = default)
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null) return false;
            user.IsTwoFactorEnabled = enabled;
            user.TwoFactorMethod = enabled ? twoFactorMethod : null;
            await UpdateAsync(user, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateLastLoginAsync(Guid id, DateTime loginTime, string? ipAddress = null, CancellationToken cancellationToken = default)
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null) return false;
            user.LastLoginAt = loginTime;
            if (ipAddress != null) user.LastLoginIp = ipAddress;
            await UpdateAsync(user, cancellationToken);
            return true;
        }

        public async Task<IEnumerable<Guid>> GetConnectedIdsAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var query = _context.Set<ConnectedId>().Where(c => c.UserId == userId);
            if (activeOnly) query = query.Where(c => !c.IsDeleted);
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

        public async Task<User?> FindByPasswordResetTokenAsync(string hashedToken)
        {
            return await Query().FirstOrDefaultAsync(u => u.PasswordResetToken == hashedToken);
        }

        public async Task<Guid?> FindByUsernameOrEmailAsync(string identifier)
        {
            var user = await Query().AsNoTracking().FirstOrDefaultAsync(u => u.Username == identifier || u.Email == identifier);
            return user?.Id;
        }

        public async Task<IEnumerable<User>> GetInactiveUsersAsync(int inactiveDays, int limit = 100, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            return await Query()
                .Where(u => u.LastLoginAt == null || u.LastLoginAt < cutoffDate)
                .OrderBy(u => u.CreatedAt)
                .Take(limit)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public async Task<int> BulkUpdateStatusAsync(IEnumerable<Guid> userIds, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            var userList = userIds.ToList();
            var usersToUpdate = await _dbSet.Where(u => userList.Contains(u.Id)).ToListAsync(cancellationToken);
            foreach (var user in usersToUpdate)
            {
                user.Status = status;
            }
            await UpdateRangeAsync(usersToUpdate, cancellationToken);
            return usersToUpdate.Count;
        }

        // AuthHive.Auth/Repositories/UserRepository.cs

        public async Task<int> GetUserCountAsync(UserStatus? status = null, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            if (organizationId.HasValue)
            {
                // 1. [ConnectedId 쿼리 시작] 특정 조직에 속한 ConnectedId를 조회합니다.
                var query = _context.Set<ConnectedId>()
                    .Where(c => c.OrganizationId == organizationId.Value)

                    // 2. [CS8602 해결] c.User가 null이 아닌 경우만 필터링합니다. (Nullity Check)
                    .Where(c => c.User != null)

                    // 3. User 엔티티를 선택합니다. 이 시점에서 c.User는 Non-nullable입니다.
                    // Select(c => c.User!)를 사용하여 User를 Non-nullable 타입으로 명확히 지정합니다.
                    .Select(c => c.User!)

                    // 4. 삭제된 유저를 필터링합니다. (안전하게 c.User.IsDeleted에 접근)
                    .Where(u => !u.IsDeleted);

                // 5. 상태 필터링 (선택적)
                if (status.HasValue)
                {
                    query = query.Where(u => u.Status == status.Value);
                }

                // 6. 카운트 반환
                return await query.CountAsync(cancellationToken);
            }

            // 조직 ID가 없는 경우: 전역 사용자(Global User) 수를 계산합니다.
            return await CountAsync(u => !status.HasValue || u.Status == status.Value, cancellationToken);
        }

        #endregion
    }
}