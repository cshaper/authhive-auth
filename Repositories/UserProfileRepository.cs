using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 프로필 저장소 구현 - AuthHive v15
    /// BaseRepository를 활용하여 최적화된 구조
    /// SystemAuditableEntity 기반 (조직 독립적)
    /// </summary>
    public class UserProfileRepository : BaseRepository<UserProfile>, IUserProfileRepository
    {
        private readonly ILogger<UserProfileRepository> _logger;

        public UserProfileRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserProfileRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>ConnectedId로 프로필 조회 (캐시 활용)</summary>
        public async Task<UserProfile?> GetByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인
            if (_cache != null)
            {
                string cacheKey = GetConnectedIdCacheKey(connectedId);
                if (_cache.TryGetValue(cacheKey, out UserProfile? cachedProfile))
                {
                    return cachedProfile;
                }
            }

            // ConnectedId -> User -> UserProfile 경로로 조회
            var connectedIdEntity = await _context.ConnectedIds
                .Include(c => c.User)
                .ThenInclude(u => u!.UserProfile)
                .FirstOrDefaultAsync(c => c.Id == connectedId && !c.IsDeleted, cancellationToken);

            var profile = connectedIdEntity?.User?.UserProfile;

            // 캐시 저장
            if (profile != null && _cache != null)
            {
                string cacheKey = GetConnectedIdCacheKey(connectedId);
                _cache.Set(cacheKey, profile, GetCacheOptions());
            }

            return profile;
        }

        /// <summary>여러 ConnectedId의 프로필 일괄 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds,
            CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any())
            {
                return Enumerable.Empty<UserProfile>();
            }

            var profiles = await _context.ConnectedIds
                // 1. 요청된 ID와 삭제되지 않은 항목을 먼저 필터링합니다.
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                // 2. User 또는 UserProfile이 없는 데이터를 DB 조회 단계에서 제외합니다.
                .Where(c => c.User != null && c.User.UserProfile != null)
                // 3. UserProfile을 선택합니다.
                .Select(c => c.User!.UserProfile!)
                .ToListAsync(cancellationToken);
            return profiles;
        }

        /// <summary>조직별 프로필 조회</summary>
        public async Task<PagedResult<UserProfile>> GetByOrganizationAsync(
            Guid organizationId,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // UserProfile을 직접 조회하는 쿼리 정의
            var query = _context.ConnectedIds
                // 1. 기본적인 조건으로 필터링
                .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)

                // 2. 'User'와 'UserProfile'이 모두 존재하는 데이터만 안전하게 필터링
                .Where(c => c.User != null && c.User.UserProfile != null)

                // 3. '!' 연산자로 컴파일러에게 null이 아님을 명확히 알려주고 UserProfile 선택
                .Select(c => c.User!.UserProfile!);

            // 페이징 처리를 위한 나머지 로직은 동일
            var totalCount = await query.CountAsync(cancellationToken);

            var profiles = await query
                .OrderByDescending(p => p.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>프로필 존재 여부 확인</summary>
        public async Task<bool> ExistsByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인
            if (_cache != null)
            {
                string cacheKey = GetConnectedIdCacheKey(connectedId);
                if (_cache.TryGetValue(cacheKey, out _))
                {
                    return true;
                }
            }

            return await _context.ConnectedIds
                .Where(c => c.Id == connectedId && !c.IsDeleted)
                .AnyAsync(c => c.User != null && c.User.UserProfile != null, cancellationToken);
        }

        #endregion

        #region 언어 및 지역 설정

        /// <summary>언어별 사용자 프로필 조회</summary>
        public async Task<PagedResult<UserProfile>> GetByLanguageAsync(
            UserLanguage language,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var languageCode = language.ToString().ToLower();
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted && p.PreferredLanguage == languageCode);

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .OrderBy(p => p.User.DisplayName ?? p.User.Email)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>타임존별 사용자 프로필 조회</summary>
        public async Task<PagedResult<UserProfile>> GetByTimeZoneAsync(
            string timeZone,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted && p.TimeZone == timeZone);

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .OrderBy(p => p.User.DisplayName ?? p.User.Email)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 메타데이터 및 개인정보 관리

        /// <summary>메타데이터 모드별 프로필 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetByMetadataModeAsync(
            UserMetadataMode mode,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted);

            query = mode switch
            {
                UserMetadataMode.Minimal => query.Where(p => string.IsNullOrEmpty(p.Bio) && string.IsNullOrEmpty(p.Location)),
                UserMetadataMode.Full => query.Where(p => !string.IsNullOrEmpty(p.Bio) || !string.IsNullOrEmpty(p.Location)),
                _ => query
            };

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>전화번호로 프로필 조회</summary>
        public async Task<UserProfile?> GetByPhoneNumberAsync(
            string phoneNumber,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber)) return null;

            return await FirstOrDefaultAsync(p => p.PhoneNumber == phoneNumber);
        }

        /// <summary>이메일로 프로필 조회</summary>
        public async Task<UserProfile?> GetByEmailAsync(
            string email,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email)) return null;

            var user = await _context.Users
                .Include(u => u.UserProfile)
                .FirstOrDefaultAsync(u => u.Email == email && !u.IsDeleted, cancellationToken);

            return user?.UserProfile;
        }

        #endregion

        #region 프로필 완성도 및 상태

        /// <summary>프로필 완성도 범위별 조회</summary>
        public async Task<PagedResult<UserProfile>> GetByCompletenessRangeAsync(
            int minCompleteness,
            int maxCompleteness,
            Guid? organizationId = null,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted &&
                           p.CompletionPercentage >= minCompleteness &&
                           p.CompletionPercentage <= maxCompleteness);

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .OrderBy(p => p.CompletionPercentage)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>프로필 이미지가 없는 사용자 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetProfilesWithoutImageAsync(
            Guid? organizationId = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted && string.IsNullOrEmpty(p.ProfileImageUrl));

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            return await query
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        /// <summary>최근 업데이트된 프로필 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetRecentlyUpdatedAsync(
            DateTime since,
            Guid? organizationId = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted && p.UpdatedAt.HasValue && p.UpdatedAt >= since);

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            return await query
                .OrderByDescending(p => p.UpdatedAt)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 프로필 관리

        /// <summary>프로필 생성 또는 업데이트 (Upsert)</summary>
        public async Task<UserProfile> UpsertAsync(
            UserProfile profile,
            CancellationToken cancellationToken = default)
        {
            var existing = await FirstOrDefaultAsync(p => p.UserId == profile.UserId);

            if (existing == null)
            {
                profile.CompletionPercentage = profile.CalculateCompletionPercentage();
                return await AddAsync(profile);
            }
            else
            {
                UpdateProfileFromSource(existing, profile);
                existing.UpdateProfile(); // 완성도 재계산
                await UpdateAsync(existing);
                return existing;
            }
        }

        /// <summary>프로필 완성도 업데이트</summary>
        public async Task<bool> UpdateCompletenessAsync(
            Guid connectedId,
            int completeness,
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.CompletionPercentage = Math.Max(0, Math.Min(100, completeness));
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);

            return true;
        }

        /// <summary>프로필 메타데이터 업데이트</summary>
        public async Task<bool> UpdateMetadataAsync(
            Guid connectedId,
            Dictionary<string, object> metadata,
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.ProfileMetadata = JsonSerializer.Serialize(metadata);
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);

            return true;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>프로필 검색</summary>
        public async Task<PagedResult<UserProfile>> SearchAsync(
            SearchUserProfileRequest request,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = _context.UserProfiles
                .Include(p => p.User)
                .Where(p => !p.IsDeleted);

            // 검색어 필터
            if (!string.IsNullOrWhiteSpace(request.SearchTerm))
            {
                query = query.Where(p =>
                    (p.User.DisplayName != null && p.User.DisplayName.Contains(request.SearchTerm)) ||
                    p.User.Email.Contains(request.SearchTerm) ||
                    (p.PhoneNumber != null && p.PhoneNumber.Contains(request.SearchTerm)) ||
                    (p.Bio != null && p.Bio.Contains(request.SearchTerm)) ||
                    (p.Location != null && p.Location.Contains(request.SearchTerm)));
            }

            // ConnectedId 필터
            if (request.ConnectedId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.Id == request.ConnectedId.Value &&
                              c.UserId == p.UserId &&
                              !c.IsDeleted));
            }

            // 조직 필터
            if (request.OrganizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, request.OrganizationId.Value);
            }

            // 타임존 필터
            if (!string.IsNullOrWhiteSpace(request.TimeZone))
            {
                query = query.Where(p => p.TimeZone == request.TimeZone);
            }

            // 메타데이터 모드 필터
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

            // 정렬 및 페이징
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await sortedQuery
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(
                profiles, totalCount, request.PageNumber, request.PageSize);
        }

        #endregion

        #region 집계

        /// <summary>프로필 수 집계</summary>
        public async Task<int> GetProfileCountAsync(
            Guid? organizationId = null,
            bool? hasProfileImage = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query();

            if (organizationId.HasValue)
            {
                query = ApplyOrganizationFilter(query, organizationId.Value);
            }

            if (hasProfileImage.HasValue)
            {
                query = hasProfileImage.Value
                    ? query.Where(p => !string.IsNullOrEmpty(p.ProfileImageUrl))
                    : query.Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));
            }

            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>ConnectedId용 캐시 키 생성</summary>
        private string GetConnectedIdCacheKey(Guid connectedId)
        {
            return $"UserProfile:ConnectedId:{connectedId}";
        }

        /// <summary>ConnectedId 캐시 무효화</summary>
        private void InvalidateConnectedIdCache(Guid connectedId)
        {
            _cache?.Remove(GetConnectedIdCacheKey(connectedId));
        }

        /// <summary>캐시 옵션 가져오기</summary>
        private MemoryCacheEntryOptions GetCacheOptions()
        {
            return new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
                SlidingExpiration = TimeSpan.FromMinutes(5),
                Priority = CacheItemPriority.Normal
            };
        }

        /// <summary>조직 필터 적용</summary>
        private IQueryable<UserProfile> ApplyOrganizationFilter(
            IQueryable<UserProfile> query,
            Guid organizationId)
        {
            return query.Where(p => _context.ConnectedIds
                .Any(c => c.UserId == p.UserId &&
                          c.OrganizationId == organizationId &&
                          !c.IsDeleted));
        }

        /// <summary>메타데이터 모드 필터 적용</summary>
        private IQueryable<UserProfile> ApplyMetadataModeFilter(
            IQueryable<UserProfile> query,
            UserMetadataMode mode)
        {
            return mode switch
            {
                UserMetadataMode.Minimal => query.Where(p =>
                    string.IsNullOrEmpty(p.Bio) && string.IsNullOrEmpty(p.Location)),
                UserMetadataMode.Full => query.Where(p =>
                    !string.IsNullOrEmpty(p.Bio) || !string.IsNullOrEmpty(p.Location)),
                _ => query
            };
        }

        /// <summary>기존 프로필을 새 데이터로 업데이트</summary>
        private void UpdateProfileFromSource(UserProfile existing, UserProfile source)
        {
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
        }

        /// <summary>정렬 적용</summary>
        private IOrderedQueryable<UserProfile> ApplySorting(
            IQueryable<UserProfile> query,
            string? sortBy,
            bool descending)
        {
            return sortBy?.ToLower() switch
            {
                "displayname" => descending
                    ? query.OrderByDescending(p => p.User.DisplayName ?? p.User.Email)
                    : query.OrderBy(p => p.User.DisplayName ?? p.User.Email),
                "email" => descending
                    ? query.OrderByDescending(p => p.User.Email)
                    : query.OrderBy(p => p.User.Email),
                "completeness" => descending
                    ? query.OrderByDescending(p => p.CompletionPercentage)
                    : query.OrderBy(p => p.CompletionPercentage),
                "lastupdated" => descending
                    ? query.OrderByDescending(p => p.UpdatedAt ?? p.CreatedAt)
                    : query.OrderBy(p => p.UpdatedAt ?? p.CreatedAt),
                _ => descending
                    ? query.OrderByDescending(p => p.CreatedAt)
                    : query.OrderBy(p => p.CreatedAt)
            };
        }

        #endregion
    }
}