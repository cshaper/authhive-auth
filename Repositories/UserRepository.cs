using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.User.Repository; // 인터페이스 네임스페이스
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 사용
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User; // User 엔티티
using AuthHive.Core.Entities.Auth; // ConnectedId 엔티티 사용
using AuthHive.Core.Models.Common; // PagedResult
using AuthHive.Core.Models.User.Requests; // SearchUserRequest
using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums; // ConnectedIdStatus

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자(User) 저장소 구현 - AuthHive v16.1
    /// 
    /// 역할: AuthHive 시스템의 '전역 사용자' 계정 정보를 관리합니다.
    ///       User 엔티티는 특정 조직에 직접 속하지 않으며, 조직과의 관계는 ConnectedId를 통해 맺어집니다.
    ///       
    /// [v16.1 변경 사항]
    /// 1. (아키텍처) IsOrganizationScopedEntity() => false 확인
    /// 2. (캐싱) 생성자에서 ICacheService를 BaseRepository로 전달하도록 버그 수정
    /// 3. (UoW) 서비스 책임인 BulkUpdateStatusAsync 제거, SaveChangesAsync 없음 확인
    /// 4. (최적화) 읽기 전용 쿼리에 AsNoTracking() 적용
    /// 5. (안정성) 모든 비동기 메서드에 CancellationToken 적용 및 전달
    /// 6. (인터페이스 일치) IUserRepository 최신 정의에 맞춰 메서드 시그니처 및 로직 수정
    /// 7. (가독성) 상세 한글 주석 추가
    /// </summary>
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        private readonly ILogger<UserRepository> _logger;

        /// <summary>
        /// 생성자: v16.1 원칙에 따라 ICacheService를 BaseRepository로 전달합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="logger">로깅 서비스</param>
        /// <param name="cacheService">캐시 서비스 (BaseRepository로 전달됨)</param>
        public UserRepository(
            AuthDbContext context,
            ILogger<UserRepository> logger,
            ICacheService? cacheService = null)
            : base(context, cacheService) // ⭐️ [v16.1 수정] cacheService 전달
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region Override Methods
        /// <summary>
        /// User 엔티티는 전역이므로 조직 범위가 아닙니다. 'false'를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;
        #endregion

        #region IUserRepository Implementations (기본 조회)

        /// <summary>
        /// 사용자 ID로 사용자를 조회하고, UserProfile 정보도 함께 로드합니다. (Eager Loading)
        /// </summary>
        /// <param name="userId">조회할 사용자 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (UserProfile 포함, 없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 사용자 상세 정보 페이지처럼 프로필 정보가 함께 필요한 경우 사용합니다.
        /// 주의: BaseRepository의 GetByIdAsync는 User 엔티티만 캐시하므로, Profile 로드는 DB 접근이 발생할 수 있습니다.
        /// </remarks>
        public async Task<User?> GetByIdWithProfileAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetByIdAsync는 캐시를 먼저 확인합니다.
            var user = await GetByIdAsync(userId, cancellationToken);
            if (user != null)
            {
                // UserProfile을 명시적으로 로드 (필요 시 DB 접근 발생)
                // AsNoTracking은 GetByIdAsync에서 이미 처리되었을 수 있으므로 생략 (수정 가능성 있음)
                await _context.Entry(user).Reference(u => u.UserProfile).LoadAsync(cancellationToken);
            }
            return user;
        }

        /// <summary>
        /// 이메일 주소로 사용자를 조회합니다 (대소문자 구분 없음 - DB collation 따름).
        /// </summary>
        /// <param name="email">조회할 이메일 주소</param>
        /// <param name="includeDeleted">삭제된 사용자 포함 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 로그인 시 사용자 식별, 회원가입 시 이메일 중복 확인 등에 사용됩니다.
        /// </remarks>
        public async Task<User?> FindByEmailAsync(string email, bool includeDeleted = false, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            if (string.IsNullOrWhiteSpace(email)) return null;

            // includeDeleted 플래그에 따라 기본 Query() 또는 필터 무시 쿼리 사용
            var query = includeDeleted ? _dbSet.IgnoreQueryFilters() : Query();

            // 이메일 비교는 DB 설정(collation)에 따라 대소문자 구분 여부가 결정됩니다.
            // 명시적으로 구분 없음을 원하면 .ToLowerInvariant() 등을 사용할 수 있으나 성능 저하 가능성 있음.
            return await query
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
        }

        /// <summary>
        /// 사용자명으로 사용자를 조회합니다 (대소문자 구분 정책은 DB 설정 따름).
        /// </summary>
        /// <param name="username">조회할 사용자명</param>
        /// <param name="includeDeleted">삭제된 사용자 포함 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 사용자명 기반 로그인, 프로필 페이지 접근 등에 사용될 수 있습니다.
        /// </remarks>
        public async Task<User?> FindByUsernameAsync(string username, bool includeDeleted = false, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            if (string.IsNullOrWhiteSpace(username)) return null;
            var query = includeDeleted ? _dbSet.IgnoreQueryFilters() : Query();
            return await query
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(u => u.Username == username, cancellationToken);
        }

        /// <summary>
        /// 외부 인증 시스템 정보(제공자 및 사용자 ID)로 사용자를 조회합니다.
        /// </summary>
        /// <param name="provider">외부 인증 시스템 식별자 (예: "Google", "Kakao")</param>
        /// <param name="externalUserId">해당 시스템에서의 사용자 고유 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 소셜 로그인 콜백 처리 시, 외부 ID를 통해 기존 AuthHive 사용자와 매핑합니다.
        /// </remarks>
        public async Task<User?> FindByExternalIdAsync(string provider, string externalUserId, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터명 provider로 통일
        {
            // [v16.1] Query() 사용 및 파라미터명 일치
            return await Query()
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(u => u.ExternalSystemType == provider && u.ExternalUserId == externalUserId, cancellationToken);
        }

        /// <summary>
        /// ConnectedId를 통해 연결된 전역 사용자(User) 엔티티를 조회합니다.
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 조직 멤버 정보에서 해당 멤버의 전역 사용자 계정 정보를 가져올 때 사용합니다.
        /// </remarks>
        public async Task<User?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // ConnectedId 테이블에서 User 네비게이션 속성을 통해 조회
            // [v16.1] Where 절 추가하여 Nullability 경고 해결 및 AsNoTracking 추가
            return await _context.Set<ConnectedId>()
                .Where(c => c.Id == connectedId && !c.IsDeleted && c.User != null) // User null 체크 추가
                .Select(c => c.User!) // null 아님 보장
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// 비밀번호 재설정 토큰의 해시값으로 사용자를 조회합니다.
        /// </summary>
        /// <param name="hashedToken">해시된 비밀번호 재설정 토큰</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 엔티티 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 사용자가 비밀번호 재설정 링크를 클릭했을 때, 토큰 유효성을 검증하기 위해 해당 토큰을 가진 사용자를 찾습니다.
        /// 주의: 토큰 만료 시간 검증 등은 서비스 레이어에서 별도로 처리해야 합니다.
        /// </remarks>
        public async Task<User?> FindByPasswordResetTokenAsync(string hashedToken, CancellationToken cancellationToken = default) // [v16.1] CancellationToken 추가
        {
            // [v16.1] Query() 사용 및 AsNoTracking 추가
            return await Query()
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(u => u.PasswordResetToken == hashedToken, cancellationToken);
        }

        /// <summary>
        /// 사용자명 또는 이메일 주소로 사용자 ID(Guid)를 조회합니다.
        /// </summary>
        public async Task<Guid?> FindIdByUsernameOrEmailAsync(string identifier, CancellationToken cancellationToken = default)
        {
            // [v16.2 수정] AsNoTracking() 제거 (CS0452 해결)
            return await Query()
                .Where(u => u.Username == identifier || u.Email == identifier)
                .Select(u => (Guid?)u.Id)
                // .AsNoTracking() // Guid?는 AsNoTracking 사용 불가
                .FirstOrDefaultAsync(cancellationToken);
        }
        #endregion

        #region IUserRepository Implementations (목록 조회 및 검색)

        /// <summary>
        /// 다양한 조건(검색어, 상태 등)으로 사용자를 검색하고 페이징된 결과를 반환합니다.
        /// </summary>
        /// <param name="request">검색 조건 DTO</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 사용자 목록</returns>
        /// <remarks>
        /// 사용 예시: 관리자 페이지에서 사용자 관리 기능을 구현할 때 사용합니다.
        /// </remarks>
        public async Task<PagedResult<User>> SearchUsersAsync(SearchUserRequest request, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var query = Query(); // IsDeleted=false 필터 자동 적용

            // 검색어 필터 (Username, Email, DisplayName)
            if (!string.IsNullOrWhiteSpace(request.SearchTerm))
            {
                var term = request.SearchTerm.ToLowerInvariant();
                query = query.Where(u =>
                    (u.Username != null && u.Username.ToLowerInvariant().Contains(term)) ||
                    (u.Email != null && u.Email.ToLowerInvariant().Contains(term)) || // Email은 Null 불가 가정
                    (u.DisplayName != null && u.DisplayName.ToLowerInvariant().Contains(term)));
            }

            // 상태 필터
            if (request.Status.HasValue)
            {
                query = query.Where(u => u.Status == request.Status.Value);
            }

            // 이메일 인증 여부 필터
            if (request.EmailVerified.HasValue)
            {
                query = query.Where(u => u.IsEmailVerified == request.EmailVerified.Value);
            }

            // 2단계 인증 활성화 여부 필터
            if (request.IsTwoFactorEnabled.HasValue)
            {
                query = query.Where(u => u.IsTwoFactorEnabled == request.IsTwoFactorEnabled.Value);
            }

            // [v16.1] 조직 필터링 (SearchUserRequest에 OrganizationId가 있다면)
            if (request.OrganizationId.HasValue)
            {
                var userIdsInOrg = _context.ConnectedIds
                   .Where(c => c.OrganizationId == request.OrganizationId.Value && !c.IsDeleted)
                   .Select(c => c.UserId).Distinct();
                query = query.Where(u => userIdsInOrg.Contains(u.Id));
            }


            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬 적용 (예: 생성일 내림차순)
            // TODO: request DTO에 SortBy, SortDescending 추가하고 동적 정렬 구현 필요
            var sortedQuery = query.OrderByDescending(u => u.CreatedAt);

            // [v16.1] AsNoTracking 추가
            var items = await sortedQuery
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            // [v16.1] PagedResult 생성자 사용
            return new PagedResult<User>(items, totalCount, request.PageNumber, request.PageSize);
        }

        /// <summary>
        /// 특정 조직에 속한 사용자 목록을 페이징하여 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="status">(선택) 필터링할 사용자 상태</param>
        /// <param name="pageNumber">페이지 번호</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="sortBy">(선택) 정렬 필드</param>
        /// <param name="sortDescending">(선택) 정렬 방향</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 사용자 목록</returns>
        /// <remarks>
        /// 사용 예시: 조직 관리 페이지에서 해당 조직의 멤버 목록을 조회할 때 사용합니다.
        /// </remarks>
        public async Task<PagedResult<User>> GetUsersByOrganizationAsync( // [v16.1] 이름 변경
            Guid organizationId, UserStatus? status = null, int pageNumber = 1, int pageSize = 50,
            string? sortBy = null, bool sortDescending = false, CancellationToken cancellationToken = default)
        {
            // ConnectedId 테이블에서 시작하여 User 정보 조회 (Null 및 삭제 필터링 포함)
            var query = _context.Set<ConnectedId>()
                .Where(c => c.OrganizationId == organizationId && c.User != null && !c.User.IsDeleted)
                .Select(c => c.User!); // User 선택 (null 아님 보장)

            // 상태 필터 적용
            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬 적용 (예시: sortBy 파라미터 활용 - 실제 구현 필요)
            var sortedQuery = query; // TODO: sortBy, sortDescending 기반 동적 정렬 로직 추가
            if (string.IsNullOrEmpty(sortBy)) // 기본 정렬
            {
                sortedQuery = sortDescending ? query.OrderByDescending(u => u.CreatedAt) : query.OrderBy(u => u.CreatedAt);
            }
            else
            {
                // 동적 정렬 구현 (예: ApplySorting 헬퍼 메서드 사용)
            }

            // [v16.1] AsNoTracking 추가
            var items = await sortedQuery
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            // [v16.1] PagedResult 생성자 사용
            return new PagedResult<User>(items, totalCount, pageNumber, pageSize);
        }

        // [v16.1] 제거: GetPagedByOrganizationAsync (튜플 반환 버전) - 인터페이스와 불일치

        /// <summary>
        /// 최근에 가입한 사용자 목록을 조회합니다.
        /// </summary>
        /// <param name="count">조회할 사용자 수</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>최근 가입 사용자 목록</returns>
        /// <remarks>
        /// 사용 예시: 관리자 대시보드에 최근 가입자 현황을 보여줄 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<User>> GetRecentUsersAsync(int count = 10, CancellationToken cancellationToken = default) // [v16.1] CancellationToken 추가
        {
            return await Query()
                .OrderByDescending(u => u.CreatedAt) // 생성일 내림차순
                .Take(count)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken); // [v16.1] CancellationToken 전달
        }

        /// <summary>
        /// 지정된 기간 동안 활동(마지막 로그인 기준)이 없는 비활성 사용자 목록을 조회합니다.
        /// </summary>
        /// <param name="inactiveDays">비활성으로 간주할 기간(일 수)</param>
        /// <param name="limit">최대 조회 개수</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>비활성 사용자 목록</returns>
        /// <remarks>
        /// 사용 예시: 장기 미사용 계정을 정리하거나, 비활성 사용자에게 복귀 유도 메일을 보낼 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<User>> GetInactiveUsersAsync(int inactiveDays, int limit = 100, CancellationToken cancellationToken = default) // [v16.1] CancellationToken 추가
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            return await Query()
                // 마지막 로그인이 없거나(null) 기준일 이전인 경우
                .Where(u => u.LastLoginAt == null || u.LastLoginAt < cutoffDate)
                .OrderBy(u => u.CreatedAt) // 오래된 사용자 순 정렬
                .Take(limit)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken); // [v16.1] CancellationToken 전달
        }

        #endregion

        #region IUserRepository Implementations (검증)

        /// <summary>
        /// 해당 이메일 주소를 가진 (삭제되지 않은) 사용자가 존재하는지 확인합니다.
        /// </summary>
        /// <param name="email">확인할 이메일 주소</param>
        /// <param name="excludeUserId">(선택) 검사에서 제외할 사용자 ID (예: 본인 정보 수정 시)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> CheckEmailExistsAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var query = Query().Where(u => u.Email == email);
            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        /// <summary>
        /// 해당 사용자명을 가진 (삭제되지 않은) 사용자가 존재하는지 확인합니다.
        /// </summary>
        /// <param name="username">확인할 사용자명</param>
        /// <param name="excludeUserId">(선택) 검사에서 제외할 사용자 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> CheckUsernameExistsAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            // 사용자명은 Nullable일 수 있으므로 null 체크 필요
            if (string.IsNullOrWhiteSpace(username)) return false;
            var query = Query().Where(u => u.Username == username);
            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        /// <summary>
        /// 해당 외부 인증 시스템 ID를 가진 (삭제되지 않은) 사용자가 존재하는지 확인합니다.
        /// </summary>
        /// <param name="provider">외부 인증 시스템 식별자</param>
        /// <param name="externalUserId">해당 시스템에서의 사용자 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> CheckExternalIdExistsAsync(string provider, string externalUserId, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터명 provider
        {
            // [v16.1] 파라미터명 provider 사용
            return await Query().AnyAsync(u => u.ExternalSystemType == provider && u.ExternalUserId == externalUserId, cancellationToken);
        }

        /// <summary>
        /// 특정 사용자가 주어진 조직의 (활성) 멤버인지 확인합니다.
        /// </summary>
        /// <param name="userId">확인할 사용자 ID</param>
        /// <param name="organizationId">확인할 조직 ID</param>
        /// <param name="activeMemberOnly">활성 멤버(ConnectedIdStatus.Active)만 확인할지 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>멤버 여부</returns>
        public async Task<bool> IsUserMemberOfOrganizationAsync(Guid userId, Guid organizationId, bool activeMemberOnly = true, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터 추가
        {
            // ConnectedId 테이블에서 관계 확인
            var query = _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId && c.OrganizationId == organizationId && !c.IsDeleted);

            // 활성 멤버만 확인하는 경우 Status 조건 추가
            if (activeMemberOnly)
            {
                query = query.Where(c => c.Status == ConnectedIdStatus.Active);
            }

            // AsNoTracking은 AnyAsync에 필요 없음
            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region IUserRepository Implementations (상태 관리 - UoW 적용)

        // --- 참고 ---
        // 아래 Update 메서드들은 특정 필드만 업데이트하지만, EF Core의 기본 동작은
        // 전체 엔티티를 'Modified'로 표시합니다. 성능이 매우 중요하다면
        // ExecuteUpdateAsync (EF Core 7+) 같은 벌크 업데이트 기능을 고려할 수 있으나,
        // 여기서는 표준적인 UpdateAsync + UnitOfWork 패턴을 따릅니다.

        /// <summary>
        /// 사용자의 상태(Status) 필드만 업데이트합니다. (서비스 레이어 구현 권장)
        /// </summary>
        /// <param name="id">사용자 ID</param>
        /// <param name="status">새로운 상태</param>
        /// <param name="updatedByConnectedId">(선택) 작업을 수행한 ConnectedId (감사 추적용)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> UpdateUserStatusAsync(Guid id, UserStatus status, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터 추가
        {
            // 업데이트 대상 엔티티 로드 (AsNoTracking 없음 - 추적 필요)
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null || user.IsDeleted) return false; // 삭제된 사용자는 업데이트 불가

            user.Status = status;
            // UpdatedAt, UpdatedBy 등은 BaseRepository.UpdateAsync 또는 SaveChangesAsync에서 처리됨

            // [v16.1] BaseRepository의 UpdateAsync 호출 (SaveChangesAsync 없음)
            await UpdateAsync(user, cancellationToken);
            // 실제 저장은 UnitOfWork.SaveChangesAsync()에서 처리됩니다.
            return true;
        }

        /// <summary>
        /// 사용자의 이메일 인증 관련 필드만 업데이트합니다. (서비스 레이어 구현 권장)
        /// </summary>
        public async Task<bool> UpdateUserEmailVerificationAsync(Guid id, bool isVerified, DateTime? verifiedAt = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null || user.IsDeleted) return false;

            user.IsEmailVerified = isVerified;
            // 인증된 경우, 현재 시간 또는 제공된 시간 사용. 인증 해제 시 null 설정.
            user.EmailVerifiedAt = isVerified ? (verifiedAt ?? DateTime.UtcNow) : null;

            await UpdateAsync(user, cancellationToken);
            return true;
        }

        /// <summary>
        /// 사용자의 2단계 인증 관련 필드만 업데이트합니다. (서비스 레이어 구현 권장)
        /// </summary>
        public async Task<bool> UpdateUserTwoFactorAsync(Guid id, bool isEnabled, string? twoFactorMethod = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null || user.IsDeleted) return false;

            user.IsTwoFactorEnabled = isEnabled;
            // 활성화될 때만 메서드 설정, 비활성화 시 null 설정
            user.TwoFactorMethod = isEnabled ? twoFactorMethod : null;

            await UpdateAsync(user, cancellationToken);
            return true;
        }

        /// <summary>
        /// 사용자의 마지막 로그인 관련 필드만 업데이트합니다. (서비스 레이어 구현 권장)
        /// </summary>
        public async Task<bool> UpdateUserLastLoginAsync(Guid id, DateTime loginTime, string? ipAddress = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var user = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (user == null || user.IsDeleted) return false;

            user.LastLoginAt = loginTime;
            if (ipAddress != null) user.LastLoginIp = ipAddress; // IP 주소는 제공될 때만 업데이트

            await UpdateAsync(user, cancellationToken);
            return true;
        }

        #endregion

        #region IUserRepository Implementations (관련 엔티티 ID 조회 - AsNoTracking 적용)

        /// <summary>
        /// 특정 사용자에게 연결된 모든 (활성 또는 전체) ConnectedId 목록을 조회합니다.
        /// </summary>
        /// <param name="userId">사용자 ID</param>
        /// <param name="activeOnly">활성(삭제되지 않은) ConnectedId만 조회할지 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>ConnectedId 목록</returns>
        public async Task<IEnumerable<Guid>> GetConnectedIdsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            var query = _context.Set<ConnectedId>().Where(c => c.UserId == userId);

            // activeOnly 플래그에 따라 IsDeleted 필터 적용
            if (activeOnly)
            {
                query = query.Where(c => !c.IsDeleted); // BaseEntity의 IsDeleted 사용
            }

            // [v16.1] AsNoTracking 추가 (Select 후에는 불필요)
            return await query
                .Select(c => c.Id) // Id만 선택
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자가 속한 모든 조직의 ID 목록을 조회합니다.
        /// </summary>
        /// <param name="userId">사용자 ID</param>
        /// <param name="activeMembershipOnly">활성 멤버십(ConnectedIdStatus.Active) 기준 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조직 ID 목록</returns>
        public async Task<IEnumerable<Guid>> GetOrganizationIdsForUserAsync(Guid userId, bool activeMembershipOnly = true, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터 추가
        {
            var query = _context.Set<ConnectedId>()
                .Where(c => c.UserId == userId && !c.IsDeleted); // 기본적으로 삭제되지 않은 연결만 고려

            // 활성 멤버십만 필터링하는 경우 Status 조건 추가
            if (activeMembershipOnly)
            {
                query = query.Where(c => c.Status == ConnectedIdStatus.Active);
            }

            // [v16.1] AsNoTracking 추가 (Select 후에는 불필요)
            return await query
                .Select(c => c.OrganizationId) // OrganizationId 선택
                .Distinct() // 한 사용자가 같은 조직에 여러 ConnectedId 가질 수 있으므로 중복 제거
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region IUserRepository Implementations (집계 및 통계)

        /// <summary>
        /// 조건(상태, 조직)에 맞는 사용자 수를 집계합니다.
        /// </summary>
        /// <param name="status">(선택) 필터링할 사용자 상태</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한 (ConnectedId 조인)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 사용자 수</returns>
        public async Task<int> CountUsersAsync(UserStatus? status = null, Guid? organizationId = null, CancellationToken cancellationToken = default) // [v16.1] 이름 변경
        {
            // 조직 ID가 주어진 경우, ConnectedId를 통해 간접적으로 카운트
            if (organizationId.HasValue)
            {
                var query = _context.Set<ConnectedId>()
                    .Where(c => c.OrganizationId == organizationId.Value && c.User != null && !c.User.IsDeleted) // 조직 및 User 유효성 필터
                    .Select(c => c.User!); // User 선택

                // 상태 필터 적용
                if (status.HasValue)
                {
                    query = query.Where(u => u.Status == status.Value);
                }

                // 고유 사용자 수 계산 (한 사용자가 조직에 여러 역할로 존재 가능하므로 Distinct)
                return await query.Select(u => u.Id).Distinct().CountAsync(cancellationToken);
            }
            else // 조직 ID가 없는 경우, 전역 사용자 카운트
            {
                // [v16.1] BaseRepository의 CountAsync 활용
                return await CountAsync(u => !status.HasValue || u.Status == status.Value, cancellationToken);
            }
        }

        /// <summary>
        /// 특정 조직에 속한 (활성 또는 전체) 사용자 수를 계산합니다.
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="activeOnly">활성 멤버(ConnectedIdStatus.Active)만 계산할지 여부</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조직 내 사용자 수</returns>
        public async Task<int> CountUsersInOrganizationAsync(Guid organizationId, bool activeOnly = true, CancellationToken cancellationToken = default) // [v16.1] 이름 변경, 파라미터 추가
        {
            // ConnectedId 테이블에서 조직 멤버십 카운트
            var query = _context.Set<ConnectedId>()
                .Where(c => c.OrganizationId == organizationId && !c.IsDeleted); // 기본적으로 삭제 안된 연결

            // 활성 멤버만 계산하는 경우 Status 조건 추가
            if (activeOnly)
            {
                query = query.Where(c => c.Status == ConnectedIdStatus.Active);
            }

            // 고유 사용자(UserId) 수 계산
            return await query.Select(c => c.UserId).Distinct().CountAsync(cancellationToken);
        }

        #endregion

        // [v16.1] 제거: BulkUpdateStatusAsync - 서비스 레이어 책임
        // public async Task<int> BulkUpdateStatusAsync(...) { ... }

    }
}