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
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 프로필 저장소 구현 - AuthHive v15
    /// SystemAuditableEntity 기반 (조직 독립적)
    /// </summary>
    public class UserProfileRepository : BaseRepository<UserProfile>, IUserProfileRepository
    {
        private readonly ILogger<UserProfileRepository> _logger;

        public UserProfileRepository(
            AuthDbContext context,
            ILogger<UserProfileRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>ConnectedId로 프로필 조회 (User와 함께 로드)</summary>
        public async Task<UserProfile?> GetByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // ConnectedId -> User -> UserProfile 경로로 조회
            var connectedId_entity = await _context.ConnectedIds
                .Include(c => c.User)
                .ThenInclude(u => u.UserProfile)
                .FirstOrDefaultAsync(c => c.Id == connectedId && !c.IsDeleted, cancellationToken);

            return connectedId_entity?.User?.UserProfile;
        }

        /// <summary>여러 ConnectedId의 프로필 일괄 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetByConnectedIdsAsync(IEnumerable<Guid> connectedIds, CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any()) return new List<UserProfile>();

            var profiles = await _context.ConnectedIds
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                .Include(c => c.User)
                .ThenInclude(u => u.UserProfile)
                .Select(c => c.User.UserProfile)
                .Where(p => p != null)
                .ToListAsync(cancellationToken);

            return profiles!;
        }

        /// <summary>조직별 프로필 조회 (ConnectedId를 통한 간접 조회)</summary>
        public async Task<PagedResult<UserProfile>> GetByOrganizationAsync(
            Guid organizationId, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            var query = _context.ConnectedIds
                .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)
                .Include(c => c.User)
                .ThenInclude(u => u.UserProfile)
                .Where(c => c.User.UserProfile != null)
                .Select(c => c.User.UserProfile!);

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .OrderByDescending(p => p.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>프로필 존재 여부 확인</summary>
        public async Task<bool> ExistsByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await _context.ConnectedIds
                .Where(c => c.Id == connectedId && !c.IsDeleted)
                .AnyAsync(c => c.User.UserProfile != null, cancellationToken);
        }

        #endregion

        #region 언어 및 지역 설정

        /// <summary>언어별 사용자 프로필 조회 (기본 구현 - enum 대신 문자열 사용)</summary>
        public async Task<PagedResult<UserProfile>> GetByLanguageAsync(
            UserLanguage language, Guid? organizationId = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            var languageCode = language.ToString().ToLower(); // enum을 문자열로 변환
            
            IQueryable<UserProfile> query = Query().Where(p => p.PreferredLanguage == languageCode);

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .Include(p => p.User)
                .OrderBy(p => p.User.DisplayName ?? p.User.Email)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>타임존별 사용자 프로필 조회</summary>
        public async Task<PagedResult<UserProfile>> GetByTimeZoneAsync(
            string timeZone, Guid? organizationId = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query().Where(p => p.TimeZone == timeZone);

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .Include(p => p.User)
                .OrderBy(p => p.User.DisplayName ?? p.User.Email)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 메타데이터 및 개인정보 관리

        /// <summary>메타데이터 모드별 프로필 조회 (기본 구현)</summary>
        public async Task<IEnumerable<UserProfile>> GetByMetadataModeAsync(
            UserMetadataMode mode, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            // 기본 구현 - 실제로는 User 엔티티에 MetadataMode 필드가 있어야 함
            IQueryable<UserProfile> query = Query().Include(p => p.User);

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            // 메타데이터 모드에 따른 필터링 로직은 비즈니스 요구사항에 따라 구현
            switch (mode)
            {
                case UserMetadataMode.Minimal:
                    query = query.Where(p => string.IsNullOrEmpty(p.Bio) && string.IsNullOrEmpty(p.Location));
                    break;
                case UserMetadataMode.Full:
                    query = query.Where(p => !string.IsNullOrEmpty(p.Bio) || !string.IsNullOrEmpty(p.Location));
                    break;
                default:
                    break;
            }

            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>전화번호로 프로필 조회</summary>
        public async Task<UserProfile?> GetByPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber)) return null;

            return await Query()
                .Include(p => p.User)
                .FirstOrDefaultAsync(p => p.PhoneNumber == phoneNumber, cancellationToken);
        }

        /// <summary>이메일로 프로필 조회 (User 테이블에서 이메일 조회)</summary>
        public async Task<UserProfile?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
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
            int minCompleteness, int maxCompleteness, Guid? organizationId = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query().Where(p => p.CompletionPercentage >= minCompleteness && p.CompletionPercentage <= maxCompleteness);

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .Include(p => p.User)
                .OrderBy(p => p.CompletionPercentage)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, pageNumber, pageSize);
        }

        /// <summary>프로필 이미지가 없는 사용자 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetProfilesWithoutImageAsync(
            Guid? organizationId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query().Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            return await query
                .Include(p => p.User)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        /// <summary>최근 업데이트된 프로필 조회</summary>
        public async Task<IEnumerable<UserProfile>> GetRecentlyUpdatedAsync(
            DateTime since, Guid? organizationId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query().Where(p => p.UpdatedAt.HasValue && p.UpdatedAt >= since);

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
            }

            return await query
                .Include(p => p.User)
                .OrderByDescending(p => p.UpdatedAt)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 프로필 관리

        /// <summary>프로필 생성 또는 업데이트 (Upsert)</summary>
        public async Task<UserProfile> UpsertAsync(UserProfile profile, CancellationToken cancellationToken = default)
        {
            var existing = await Query().FirstOrDefaultAsync(p => p.UserId == profile.UserId, cancellationToken);
            
            if (existing == null)
            {
                profile.CompletionPercentage = profile.CalculateCompletionPercentage();
                return await AddAsync(profile);
            }
            else
            {
                // 기존 프로필 업데이트
                existing.PhoneNumber = profile.PhoneNumber;
                existing.PhoneVerified = profile.PhoneVerified;
                existing.ProfileImageUrl = profile.ProfileImageUrl;
                existing.TimeZone = profile.TimeZone;
                existing.PreferredLanguage = profile.PreferredLanguage;
                existing.PreferredCurrency = profile.PreferredCurrency;
                existing.Bio = profile.Bio;
                existing.WebsiteUrl = profile.WebsiteUrl;
                existing.Location = profile.Location;
                existing.DateOfBirth = profile.DateOfBirth;
                existing.Gender = profile.Gender;
                existing.ProfileMetadata = profile.ProfileMetadata;
                existing.IsPublic = profile.IsPublic;
                existing.EmailNotificationsEnabled = profile.EmailNotificationsEnabled;
                existing.SmsNotificationsEnabled = profile.SmsNotificationsEnabled;
                
                existing.UpdateProfile(); // 완성도 재계산
                
                await UpdateAsync(existing);
                return existing;
            }
        }

        /// <summary>프로필 완성도 업데이트</summary>
        public async Task<bool> UpdateCompletenessAsync(Guid connectedId, int completeness, CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.CompletionPercentage = Math.Max(0, Math.Min(100, completeness));
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile);
            
            return true;
        }

        /// <summary>프로필 메타데이터 업데이트</summary>
        public async Task<bool> UpdateMetadataAsync(Guid connectedId, Dictionary<string, object> metadata, CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.ProfileMetadata = JsonSerializer.Serialize(metadata);
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile);
            
            return true;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>프로필 검색 (개선된 구현)</summary>
        public async Task<PagedResult<UserProfile>> SearchAsync(SearchUserProfileRequest request, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query().Include(p => p.User);

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
                    .Any(c => c.Id == request.ConnectedId.Value && c.UserId == p.UserId && !c.IsDeleted));
            }

            // 조직 필터
            if (request.OrganizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == request.OrganizationId.Value && !c.IsDeleted));
            }

            // 타임존 필터
            if (!string.IsNullOrWhiteSpace(request.TimeZone))
            {
                query = query.Where(p => p.TimeZone == request.TimeZone);
            }

            // 메타데이터 모드 필터
            if (request.MetadataMode.HasValue)
            {
                switch (request.MetadataMode.Value)
                {
                    case UserMetadataMode.Minimal:
                        query = query.Where(p => string.IsNullOrEmpty(p.Bio) && string.IsNullOrEmpty(p.Location));
                        break;
                    case UserMetadataMode.Full:
                        query = query.Where(p => !string.IsNullOrEmpty(p.Bio) || !string.IsNullOrEmpty(p.Location));
                        break;
                }
            }

            // 완성도 범위 필터
            if (request.MinCompleteness.HasValue)
            {
                query = query.Where(p => p.CompletionPercentage >= request.MinCompleteness.Value);
            }
            if (request.MaxCompleteness.HasValue)
            {
                query = query.Where(p => p.CompletionPercentage <= request.MaxCompleteness.Value);
            }

            // 프로필 이미지 필터
            if (request.HasProfileImage.HasValue)
            {
                query = request.HasProfileImage.Value 
                    ? query.Where(p => !string.IsNullOrEmpty(p.ProfileImageUrl))
                    : query.Where(p => string.IsNullOrEmpty(p.ProfileImageUrl));
            }

            // 업데이트 날짜 범위 필터
            if (request.UpdatedAfter.HasValue)
            {
                query = query.Where(p => p.UpdatedAt.HasValue && p.UpdatedAt >= request.UpdatedAfter.Value);
            }
            if (request.UpdatedBefore.HasValue)
            {
                query = query.Where(p => p.UpdatedAt.HasValue && p.UpdatedAt <= request.UpdatedBefore.Value);
            }

            // 정렬
            query = ApplySorting(query, request.SortBy, request.SortDescending);

            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await query
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserProfile>.Create(profiles, totalCount, request.PageNumber, request.PageSize);
        }

        /// <summary>정렬 적용</summary>
        private IQueryable<UserProfile> ApplySorting(IQueryable<UserProfile> query, string? sortBy, bool descending)
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

        #region 집계

        /// <summary>프로필 수 집계</summary>
        public async Task<int> GetProfileCountAsync(
            Guid? organizationId = null, bool? hasProfileImage = null, CancellationToken cancellationToken = default)
        {
            IQueryable<UserProfile> query = Query();

            if (organizationId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && c.OrganizationId == organizationId.Value && !c.IsDeleted));
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

        /// <summary>기본 쿼리 (소프트 삭제된 항목 제외)</summary>
        private new IQueryable<UserProfile> Query()
        {
            return _context.UserProfiles.Where(p => !p.IsDeleted);
        }

        #endregion
    }
}