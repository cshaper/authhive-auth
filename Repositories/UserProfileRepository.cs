using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository; // 인터페이스 네임스페이스
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums; // UserLanguage, UserMetadataMode 사용
// using AuthHive.Core.Interfaces.Organization.Service; // [v16.1] 제거: IOrganizationContext 의존성 제거
using AuthHive.Core.Interfaces.Infra.Cache; // [v16.1] ICacheService 사용

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 프로필 저장소 구현 - AuthHive v16.1
    /// 
    /// 역할: 사용자의 기본 프로필 정보(전화번호, 프로필 사진, 언어/지역 설정, 개인정보 등)를 관리합니다.
    ///       User 엔티티와 1:1 관계이며, 조직 범위 엔티티가 아닙니다.
    ///       
    /// [v16.1 변경 사항]
    /// 1. (아키텍처) IsOrganizationBaseEntity() => false 로 변경 및 관련 쿼리 로직 수정
    /// 2. (아키텍처) IOrganizationContext 의존성 제거
    /// 3. (캐싱) BaseRepository의 _cacheService 사용하도록 캐시 로직 통합 (생성자 버그 수정 포함)
    /// 4. (UoW) SaveChangesAsync() 호출 없음 확인
    /// 5. (최적화) 읽기 전용 쿼리에 AsNoTracking() 적용
    /// 6. (안정성) 모든 비동기 메서드에 CancellationToken 적용 및 전달
    /// 7. (가독성) 상세 한글 주석 추가
    /// </summary>
    public class UserProfileRepository : BaseRepository<UserProfile>, IUserProfileRepository
    {
        private readonly ILogger<UserProfileRepository> _logger;
        // [v16.1] 제거: _cacheService 필드 (BaseRepository의 protected _cacheService 사용)

        /// <summary>
        /// 생성자: v16.1 원칙에 따라 IOrganizationContext를 제거하고, ICacheService는 BaseRepository로 전달합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="logger">로깅 서비스</param>
        /// <param name="cacheService">캐시 서비스 (BaseRepository로 전달됨)</param>
        public UserProfileRepository(
            AuthDbContext context,
            ILogger<UserProfileRepository> logger, // [v16.1] IOrganizationContext 제거
            ICacheService? cacheService = null)
            : base(context, cacheService) 
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [v16.1] BaseRepository의 추상 메서드를 구현합니다.
        /// UserProfile은 User(글로벌 엔티티)와 직접 연결되므로 조직 범위 엔티티가 아닙니다.
        /// 따라서 'false'를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => false;

        #region 기본 조회 (캐시 및 AsNoTracking 적용)

        /// <summary>
        /// ConnectedId를 사용하여 사용자의 프로필을 조회합니다.
        /// 캐시를 먼저 확인하고, 없으면 DB에서 조회 후 캐시에 저장합니다.
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 고유 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 프로필 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 사용자 정보 팝업 등에서 특정 사용자의 상세 프로필을 표시할 때 사용합니다.
        /// </remarks>
        public async Task<UserProfile?> GetByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = GetConnectedIdCacheKey(connectedId);
            UserProfile? profile;

            // 1. 캐시 조회 시도 (BaseRepository의 _cacheService 사용)
            if (_cacheService != null)
            {
                profile = await _cacheService.GetAsync<UserProfile>(cacheKey, cancellationToken);
                if (profile != null)
                {
                    _logger.LogDebug("[캐시 히트] ConnectedId: {ConnectedId}의 UserProfile.", connectedId);
                    return profile;
                }
                 _logger.LogDebug("[캐시 미스] ConnectedId: {ConnectedId}의 UserProfile. DB 조회 시작.", connectedId);
            }

            // 2. DB 조회 (ConnectedId -> User -> UserProfile)
            //    [v16.1] Where 절 추가하여 Nullability 경고 해결 및 AsNoTracking 추가
            profile = await _context.ConnectedIds
                .Where(c => c.Id == connectedId && !c.IsDeleted && c.User != null && c.User.UserProfile != null) 
                .Select(c => c.User!.UserProfile!) // null 아님 보장
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(cancellationToken);

            // 3. 캐시 저장 (DB 결과가 있고 캐시 서비스 사용 가능 시)
            if (profile != null && _cacheService != null)
            {
                // [v16.1] SetAsync에 CancellationToken 전달
                await _cacheService.SetAsync(cacheKey, profile, TimeSpan.FromMinutes(15), cancellationToken); // 예: 15분 캐시
            }

            return profile;
        }

        /// <summary>
        /// 여러 ConnectedId에 해당하는 프로필 목록을 한 번의 DB 쿼리로 조회합니다. (N+1 문제 방지)
        /// </summary>
        /// <param name="connectedIds">조회할 ConnectedId 목록</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조회된 프로필 목록</returns>
        /// <remarks>
        /// 사용 예시: 조직 멤버 목록 화면에서 각 멤버의 프로필 사진과 이름을 함께 표시할 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<UserProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds,
            CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any())
            {
                return Enumerable.Empty<UserProfile>();
            }

            // [v16.1] AsNoTracking 추가
            var profiles = await _context.ConnectedIds
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                .Where(c => c.User != null && c.User.UserProfile != null) 
                .Select(c => c.User!.UserProfile!) 
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
            return profiles;
        }

        /// <summary>
        /// 특정 조직에 속한 모든 사용자의 프로필을 페이징하여 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="pageNumber">페이지 번호 (1부터 시작)</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 프로필 결과</returns>
        /// <remarks>
        /// 사용 예시: 조직 관리자가 조직 멤버 관리 페이지에서 멤버 목록을 조회할 때 사용합니다.
        /// [v16.1] UserProfile은 조직 범위가 아니므로, ConnectedId를 통해 간접 조회합니다.
        /// </remarks>
        public async Task<PagedResult<UserProfile>> GetByOrganizationAsync(
            Guid organizationId,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: QueryForOrganization 대신 ConnectedId를 통해 간접 쿼리
            var query = _context.ConnectedIds
                 .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)
                 .Where(c => c.User != null && c.User.UserProfile != null)
                 .Select(c => c.User!.UserProfile!); // UserProfile 선택

            var totalCount = await query.CountAsync(cancellationToken);

            // [v16.1] AsNoTracking 추가
            var profiles = await query
                .OrderByDescending(p => p.CreatedAt) // 기본 정렬 (생성일 내림차순)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// ConnectedId를 통해 사용자의 프로필이 존재하는지 확인합니다. (캐시 우선 확인)
        /// </summary>
        /// <param name="connectedId">확인할 사용자의 ConnectedId</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>프로필 존재 여부</returns>
        /// <remarks>
        /// 사용 예시: 사용자 초대 수락 시, 이미 프로필이 생성되었는지 확인할 때 사용합니다.
        /// </remarks>
        public async Task<bool> ExistsByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            // GetByConnectedIdAsync는 내부적으로 캐시를 확인하므로 효율적입니다.
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            return profile != null;
        }
        #endregion

        #region 언어 및 지역 설정 (AsNoTracking 적용)

        /// <summary>
        /// 특정 선호 언어를 설정한 사용자 프로필 목록을 페이징하여 조회합니다.
        /// </summary>
        /// <param name="language">조회할 언어 (Enum)</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="pageNumber">페이지 번호</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 프로필 결과</returns>
        /// <remarks>
        /// 사용 예시: 특정 언어 사용자 그룹에게 타겟 공지사항을 발송하기 위해 대상 목록을 조회합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<PagedResult<UserProfile>> GetByLanguageAsync(
            UserLanguage language,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var languageCode = language.ToString().ToLowerInvariant(); // Enum을 소문자 문자열로 변환

            // [v16.1] 수정: Query() 사용 (IsDeleted=false 필터)
            IQueryable<UserProfile> query = Query()
                .Include(p => p.User) // User 정보 포함 (정렬 등 사용)
                .Where(p => p.PreferredLanguage == languageCode);

            // [v16.1] 수정: 조직 필터 적용 (헬퍼 메서드 사용)
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            // [v16.1] AsNoTracking 추가
            var profiles = await query
                .OrderBy(p => p.User.DisplayName ?? p.User.Email) // 이름 또는 이메일로 정렬
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 특정 타임존을 설정한 사용자 프로필 목록을 페이징하여 조회합니다.
        /// </summary>
        /// <param name="timeZone">조회할 타임존 문자열 (예: "Asia/Seoul")</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="pageNumber">페이지 번호</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 프로필 결과</returns>
        /// <remarks>
        /// 사용 예시: 특정 시간대에 맞는 예약 알림 등을 보내기 위해 해당 지역 사용자 목록을 조회합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<PagedResult<UserProfile>> GetByTimeZoneAsync(
            string timeZone,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query()
                .Include(p => p.User)
                .Where(p => p.TimeZone == timeZone);

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            // [v16.1] AsNoTracking 추가
            var profiles = await query
                .OrderBy(p => p.User.DisplayName ?? p.User.Email)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 메타데이터 및 개인정보 관리 (AsNoTracking 적용)

        /// <summary>
        /// 메타데이터 입력 상태(최소/전체)에 따라 프로필 목록을 조회합니다.
        /// </summary>
        /// <param name="mode">조회할 모드 (Minimal: 필수 외 정보 없음, Full: 추가 정보 있음)</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 프로필 목록</returns>
        /// <remarks>
        /// 사용 예시: 프로필 정보 입력률이 낮은 사용자 그룹을 찾아 정보 입력을 독려하는 캠페인을 진행합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<IEnumerable<UserProfile>> GetByMetadataModeAsync(
            UserMetadataMode mode,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query().Include(p => p.User);

            // 메타데이터 모드 필터 적용 (헬퍼 사용)
            query = ApplyMetadataModeFilter(query, mode);

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            // [v16.1] AsNoTracking 추가
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 전화번호로 사용자의 프로필을 조회합니다. (고유값 가정)
        /// </summary>
        /// <param name="phoneNumber">조회할 전화번호</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 프로필 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: SMS 인증 등 전화번호 기반 사용자 식별 시 프로필 정보를 함께 가져옵니다.
        /// 주의: 전화번호 형식 정규화(Normalization)는 서비스 레이어에서 처리해야 합니다.
        /// </remarks>
        public async Task<UserProfile?> GetByPhoneNumberAsync(
            string phoneNumber,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber)) return null;

            // [v16.1] BaseRepository의 FirstOrDefaultAsync 사용 및 AsNoTracking 추가
            return await FirstOrDefaultAsync(p => p.PhoneNumber == phoneNumber, cancellationToken);
        }

        /// <summary>
        /// 이메일 주소로 사용자의 프로필을 조회합니다. (고유값 가정)
        /// </summary>
        /// <param name="email">조회할 이메일 주소</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>사용자 프로필 (없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 로그인 또는 비밀번호 찾기 시 이메일로 사용자 정보를 조회합니다.
        /// </remarks>
        public async Task<UserProfile?> GetByEmailAsync(
            string email,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email)) return null;

            // User 테이블에서 이메일로 조회 후 UserProfile을 가져옴
            // [v16.1] AsNoTracking 추가
            var user = await _context.Users
                .AsNoTracking() // 읽기 전용
                .Include(u => u.UserProfile) // 프로필 정보 포함
                .FirstOrDefaultAsync(u => u.Email == email && !u.IsDeleted, cancellationToken);

            return user?.UserProfile;
        }

        #endregion

        #region 프로필 완성도 및 상태 (AsNoTracking 적용)

        /// <summary>
        /// 프로필 완성도 점수 범위에 해당하는 사용자 프로필 목록을 페이징하여 조회합니다.
        /// </summary>
        /// <param name="minCompleteness">최소 완성도 (0-100)</param>
        /// <param name="maxCompleteness">최대 완성도 (0-100)</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="pageNumber">페이지 번호</param>
        /// <param name="pageSize">페이지 크기</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 프로필 결과</returns>
        /// <remarks>
        /// 사용 예시: 완성도가 높은 사용자 그룹에게 특정 혜택을 제공하거나, 낮은 사용자에게 정보 입력을 유도합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<PagedResult<UserProfile>> GetByCompletenessRangeAsync(
            int minCompleteness,
            int maxCompleteness,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query()
                .Include(p => p.User)
                .Where(p => p.CompletionPercentage >= minCompleteness &&
                              p.CompletionPercentage <= maxCompleteness);

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            // [v16.1] AsNoTracking 추가
            var profiles = await query
                .OrderBy(p => p.CompletionPercentage) // 완성도 오름차순 정렬
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 프로필 이미지가 설정되지 않은 사용자 프로필 목록을 조회합니다.
        /// </summary>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="limit">최대 조회 개수</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>프로필 이미지가 없는 프로필 목록</returns>
        /// <remarks>
        /// 사용 예시: 프로필 사진 등록률을 높이기 위해 이미지가 없는 사용자 목록을 추출합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<IEnumerable<UserProfile>> GetProfilesWithoutImageAsync(
            Guid? organizationId = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query()
                .Include(p => p.User)
                .Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            // [v16.1] AsNoTracking 추가
            return await query
                .Take(limit) // 최대 개수 제한
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 시점 이후에 업데이트된 프로필 목록을 조회합니다.
        /// </summary>
        /// <param name="since">기준 시점 (UTC)</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="limit">최대 조회 개수</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>최근 업데이트된 프로필 목록</returns>
        /// <remarks>
        /// 사용 예시: 외부 시스템과 사용자 프로필 정보를 동기화할 때, 변경된 데이터만 선별하여 가져옵니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<IEnumerable<UserProfile>> GetRecentlyUpdatedAsync(
            DateTime since,
            Guid? organizationId = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query()
                .Include(p => p.User)
                .Where(p => p.UpdatedAt.HasValue && p.UpdatedAt >= since);

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            // [v16.1] AsNoTracking 추가
            return await query
                .OrderByDescending(p => p.UpdatedAt) // 최근 업데이트 순 정렬
                .Take(limit)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 프로필 관리 (UoW 적용)

        /// <summary>
        /// 사용자 프로필을 생성하거나 업데이트합니다(Upsert). UserId 기준입니다.
        /// </summary>
        /// <param name="profile">생성 또는 업데이트할 프로필 엔티티</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>생성되거나 업데이트된 프로필 엔티티</returns>
        /// <remarks>
        /// 사용 예시: 사용자가 회원가입 직후 프로필 정보를 입력하거나, 기존 정보를 수정할 때 호출됩니다.
        /// 주의: 이 메서드는 캐시를 무효화하지 않습니다. 호출하는 서비스 레이어에서 관련 ConnectedId를 조회하여 캐시를 무효화해야 합니다.
        /// </remarks>
        public async Task<UserProfile> UpsertAsync(
            UserProfile profile,
            CancellationToken cancellationToken = default)
        {
            // UserId로 기존 프로필 조회 (AsNoTracking 생략 - 업데이트 대상 추적)
            var existing = await FirstOrDefaultAsync(p => p.UserId == profile.UserId, cancellationToken);

            if (existing == null) // 생성
            {
                profile.CompletionPercentage = profile.CalculateCompletionPercentage(); // 완성도 계산
                // [v16.1] BaseRepository의 AddAsync 사용 (SaveChangesAsync 없음)
                return await AddAsync(profile, cancellationToken);
            }
            else // 업데이트
            {
                UpdateProfileFromSource(existing, profile); // 기존 엔티티에 변경사항 적용 (헬퍼)
                existing.UpdateProfile(); // 완성도 재계산 (엔티티 내부 메서드 호출)
                // [v16.1] BaseRepository의 UpdateAsync 사용 (SaveChangesAsync 없음)
                await UpdateAsync(existing, cancellationToken); 
                return existing;
            }
        }

        /// <summary>
        /// 사용자의 프로필 완성도 점수를 직접 업데이트합니다. (주의해서 사용)
        /// </summary>
        /// <param name="connectedId">대상 사용자의 ConnectedId</param>
        /// <param name="completeness">새로운 완성도 점수 (0-100)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>업데이트 성공 여부</returns>
        /// <remarks>
        /// 사용 예시: 관리 도구 등에서 특정 조건 만족 시 프로필 완성도를 보정해주는 등의 특수 케이스에 사용될 수 있습니다.
        /// 일반적으로 완성도는 `UpsertAsync`에서 자동 계산됩니다.
        /// </remarks>
        public async Task<bool> UpdateCompletenessAsync(
            Guid connectedId,
            int completeness,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: 업데이트 위해 추적 상태로 로드 (AsNoTracking 없음)
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.CompletionPercentage = Math.Clamp(completeness, 0, 100); // 0~100 범위 보장
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile, cancellationToken); // [v16.1] BaseRepository의 UpdateAsync
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken); // [v16.1] 캐시 무효화 (Async)

            return true;
        }

        /// <summary>
        /// 사용자의 프로필 메타데이터(JSON)를 업데이트합니다.
        /// </summary>
        /// <param name="connectedId">대상 사용자의 ConnectedId</param>
        /// <param name="metadata">업데이트할 메타데이터 Dictionary</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>업데이트 성공 여부</returns>
        /// <remarks>
        /// 사용 예시: 사용자가 UI 테마, 선호 레이아웃 등 개인화 설정을 저장할 때 사용됩니다.
        /// </remarks>
        public async Task<bool> UpdateMetadataAsync(
          Guid connectedId,
          Dictionary<string, object> metadata,
          CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: 업데이트 위해 추적 상태로 로드
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.ProfileMetadata = JsonSerializer.Serialize(metadata);
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile, cancellationToken); // [v16.1] BaseRepository의 UpdateAsync
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken); // [v16.1] 캐시 무효화 (Async)

            return true;
        }

        #endregion

        #region 검색 및 필터링 (AsNoTracking 적용)

        /// <summary>
        /// 다양한 조건으로 사용자 프로필을 검색하고 페이징하여 반환합니다.
        /// </summary>
        /// <param name="request">검색 조건 DTO</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>페이징된 검색 결과</returns>
        /// <remarks>
        /// 사용 예시: 관리자 페이지에서 사용자 목록을 다양한 조건(이름, 이메일, 조직, 상태 등)으로 검색합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<PagedResult<UserProfile>> SearchAsync(
            SearchUserProfileRequest request,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            IQueryable<UserProfile> query = Query().Include(p => p.User); // User 정보는 항상 필요

            // 검색어 필터 (DisplayName, Email, PhoneNumber, Bio, Location)
            if (!string.IsNullOrWhiteSpace(request.SearchTerm))
            {
                // 대소문자 구분 없이 검색 (ToLowerInvariant 사용 권장)
                string term = request.SearchTerm.ToLowerInvariant(); 
                query = query.Where(p =>
                    (p.User.DisplayName != null && p.User.DisplayName.ToLowerInvariant().Contains(term)) ||
                    p.User.Email.ToLowerInvariant().Contains(term) || // Email은 Null 불가 가정
                    (p.PhoneNumber != null && p.PhoneNumber.Contains(term)) || // 전화번호 형식 고려 필요
                    (p.Bio != null && p.Bio.ToLowerInvariant().Contains(term)) ||
                    (p.Location != null && p.Location.ToLowerInvariant().Contains(term)));
            }

            // [v16.1] 수정: 조직 필터 적용 (헬퍼 사용)
            if (request.OrganizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, request.OrganizationId.Value);
            }
            
            // ConnectedId 필터 (특정 사용자의 프로필 검색)
            if (request.ConnectedId.HasValue)
            {
                 var userId = await _context.ConnectedIds
                     .Where(c => c.Id == request.ConnectedId.Value && !c.IsDeleted)
                     .Select(c => c.UserId).FirstOrDefaultAsync(cancellationToken);
                 if(userId != default) { query = query.Where(p => p.UserId == userId); }
                 else { return PagedResult<UserProfile>.Empty(request.PageNumber, request.PageSize); } // [v16.1] Empty 사용
            }


            // 타임존 필터
            if (!string.IsNullOrWhiteSpace(request.TimeZone))
            {
                query = query.Where(p => p.TimeZone == request.TimeZone);
            }

            // 메타데이터 모드 필터 (헬퍼 사용)
            if (request.MetadataMode.HasValue)
            {
                query = ApplyMetadataModeFilter(query, request.MetadataMode.Value);
            }

            // 완성도 범위 필터
            if (request.MinCompleteness.HasValue)
                query = query.Where(p => p.CompletionPercentage >= request.MinCompleteness.Value);
            if (request.MaxCompleteness.HasValue)
                query = query.Where(p => p.CompletionPercentage <= request.MaxCompleteness.Value);

            // 프로필 이미지 필터
            if (request.HasProfileImage.HasValue)
            {
                query = request.HasProfileImage.Value
                    ? query.Where(p => !string.IsNullOrEmpty(p.ProfileImageUrl))
                    : query.Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));
            }

            // 업데이트 날짜 필터
            if (request.UpdatedAfter.HasValue)
                query = query.Where(p => p.UpdatedAt.HasValue && p.UpdatedAt >= request.UpdatedAfter.Value);
            if (request.UpdatedBefore.HasValue)
                query = query.Where(p => p.UpdatedAt.HasValue && p.UpdatedAt <= request.UpdatedBefore.Value);

            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬 적용 (헬퍼 사용)
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);

            // [v16.1] AsNoTracking 추가
            var profiles = await sortedQuery
                .AsNoTracking() // 읽기 전용
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, request.PageNumber, request.PageSize);
        }

        #endregion

        #region 집계

        /// <summary>
        /// 조건에 맞는 사용자 프로필 수를 계산합니다.
        /// </summary>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한</param>
        /// <param name="hasProfileImage">(선택) 프로필 이미지 유무로 필터링</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 프로필 수</returns>
        /// <remarks>
        /// 사용 예시: 대시보드에서 조직 내 총 사용자 수 또는 프로필 사진 등록률 등을 계산합니다.
        /// [v16.1] 조직 필터링 로직 수정
        /// </remarks>
        public async Task<int> GetProfileCountAsync(
            Guid? organizationId = null,
            bool? hasProfileImage = null,
            CancellationToken cancellationToken = default)
        {
            // [v16.1] 수정: Query() 사용
            var query = Query();

            // [v16.1] 수정: 조직 필터 적용
            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            // 프로필 이미지 필터
            if (hasProfileImage.HasValue)
            {
                query = hasProfileImage.Value
                    ? query.Where(p => !string.IsNullOrEmpty(p.ProfileImageUrl))
                    : query.Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));
            }

            // CountAsync는 AsNoTracking 불필요
            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// UserProfile 조회/업데이트 시 ConnectedId 기반 캐시 키를 생성합니다.
        /// UserProfile은 UserId와 1:1이지만, ConnectedId로 조회하는 경우가 많으므로 별도 키 정의.
        /// </summary>
        private string GetConnectedIdCacheKey(Guid connectedId)
        {
            // 형식: "UserProfile:ConnectedId:{GUID}"
            return $"{typeof(UserProfile).Name}:ConnectedId:{connectedId}";
        }

        /// <summary>
        /// ConnectedId 기반 캐시를 무효화합니다. (비동기)
        /// </summary>
        /// <param name="connectedId">무효화할 대상의 ConnectedId</param>
        /// <param name="cancellationToken">취소 토큰</param>
        protected virtual async Task InvalidateConnectedIdCacheAsync(Guid connectedId, CancellationToken cancellationToken = default) // [v16.1] CancellationToken 추가
        {
            // [v16.1] BaseRepository의 protected _cacheService 사용
            if (_cacheService == null) return;
            string cacheKey = GetConnectedIdCacheKey(connectedId);
            // [v16.1] RemoveAsync에 CancellationToken 전달
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
        }
        
        /// <summary>
        /// [v16.1] 업데이트를 위해 엔티티를 추적 상태로 로드하는 헬퍼 메서드
        /// GetByConnectedIdAsync는 AsNoTracking이므로, 업데이트 시에는 이 메서드 사용
        /// </summary>
        private async Task<UserProfile?> GetProfileForUpdateByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken)
        {
             // AsNoTracking() 없이 DB에서 직접 조회하여 변경 추적 활성화
             return await _context.ConnectedIds
                 .Where(c => c.Id == connectedId && !c.IsDeleted && c.User != null && c.User.UserProfile != null) 
                 .Select(c => c.User!.UserProfile!) 
                 .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// [v16.1] UserProfile 쿼리에 조직 필터를 적용하는 헬퍼 메서드
        /// UserProfile은 UserId를 기준으로 하므로, ConnectedId 테이블을 조인하여 필터링합니다.
        /// </summary>
        /// <param name="query">필터를 적용할 IQueryable<UserProfile></param>
        /// <param name="organizationId">필터링할 조직 ID</param>
        /// <returns>조직 필터가 적용된 IQueryable<UserProfile></returns>
        private IQueryable<UserProfile> ApplyOrganizationFilter(
            IQueryable<UserProfile> query,
            Guid organizationId)
        {
            // UserProfile의 UserId가 해당 OrganizationId를 가진 ConnectedId와 연결되어 있는지 확인
            return query.Where(p => _context.ConnectedIds
                .Any(c => c.UserId == p.UserId &&
                          c.OrganizationId == organizationId &&
                          !c.IsDeleted)); // 활성 ConnectedId만 고려
        }

        /// <summary>
        /// 메타데이터 모드(Minimal/Full)에 따라 쿼리 필터를 적용하는 헬퍼 메서드
        /// </summary>
        private IQueryable<UserProfile> ApplyMetadataModeFilter(
            IQueryable<UserProfile> query,
            UserMetadataMode mode)
        {
            return mode switch
            {
                // Minimal: Bio와 Location이 모두 비어있는 경우
                UserMetadataMode.Minimal => query.Where(p =>
                    string.IsNullOrEmpty(p.Bio) && string.IsNullOrEmpty(p.Location)),
                // Full: Bio 또는 Location 중 하나라도 값이 있는 경우
                UserMetadataMode.Full => query.Where(p =>
                    !string.IsNullOrEmpty(p.Bio) || !string.IsNullOrEmpty(p.Location)),
                // All (기본값): 필터링 없음
                _ => query
            };
        }

        /// <summary>
        /// 기존 프로필 엔티티(existing)를 원본 프로필(source) 데이터로 업데이트 (내부 사용)
        /// </summary>
        private void UpdateProfileFromSource(UserProfile existing, UserProfile source)
        {
            // User 엔티티와 직접 관련된 필드(UserId, User)는 변경하지 않음
            existing.PhoneNumber = source.PhoneNumber;
            existing.PhoneVerified = source.PhoneVerified;
            existing.ProfileImageUrl = source.ProfileImageUrl;
            existing.TimeZone = source.TimeZone;
            existing.PreferredLanguage = source.PreferredLanguage;
            existing.PreferredCurrency = source.PreferredCurrency;
            existing.Bio = source.Bio;
            existing.WebsiteUrl = source.WebsiteUrl;
            existing.Location = source.Location;
            existing.DateOfBirth = source.DateOfBirth;
            existing.Gender = source.Gender;
            existing.ProfileMetadata = source.ProfileMetadata;
            existing.IsPublic = source.IsPublic;
            existing.EmailNotificationsEnabled = source.EmailNotificationsEnabled;
            existing.SmsNotificationsEnabled = source.SmsNotificationsEnabled;
            // CompletionPercentage는 UpdateProfile()에서 재계산됨
            // CreatedAt, CreatedBy 등은 생성 시에만 설정되므로 업데이트하지 않음
            // UpdatedAt, UpdatedBy 등은 SaveChangesAsync() 또는 UpdateAsync에서 자동 처리됨
        }

        /// <summary>
        /// 쿼리에 동적 정렬 적용 (내부 사용)
        /// </summary>
        private IOrderedQueryable<UserProfile> ApplySorting(
            IQueryable<UserProfile> query, string? sortBy, bool descending)
        {
             // 기본 정렬: 생성일 내림차순
            Expression<Func<UserProfile, object?>> keySelector = p => p.CreatedAt; 
            
            switch (sortBy?.ToLowerInvariant()) // [v16.1] InvariantCulture 사용
            {
                case "displayname":
                    keySelector = p => p.User.DisplayName ?? p.User.Email; // User 정보 필요
                    break;
                case "email":
                    keySelector = p => p.User.Email; // User 정보 필요
                    break;
                case "completeness":
                    keySelector = p => p.CompletionPercentage;
                    break;
                case "lastupdated":
                    // UpdatedAt이 null일 수 있으므로 CreatedAt으로 대체
                    keySelector = p => p.UpdatedAt ?? p.CreatedAt; 
                    break;
                 // 기본 정렬은 CreatedAt
            }
            
            // [v16.1] OrderBy/OrderByDescending 분리 명확화
            return descending 
                ? query.OrderByDescending(keySelector) 
                : query.OrderBy(keySelector);
        }

        #endregion
    }
}