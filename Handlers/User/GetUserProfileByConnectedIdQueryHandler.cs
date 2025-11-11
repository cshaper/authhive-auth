// [AuthHive.Auth] GetUserProfileByConnectedIdQueryHandler.cs
// v17 CQRS "본보기": 'GetUserProfileByConnectedIdQuery'를 처리하여 'UserDetailResponse'를 조회합니다.
// [v17 철학] L1(IMemoryCache)를 제거하고, L2(ICacheService - Redis) 캐시만 사용하도록 단순화합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra.Cache; // [v17] Redis 캐시 서비스 주입
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Caching.Memory; // [v17 수정] L1 로컬 캐시 제거
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Common; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "ConnectedId로 프로필 조회" 유스케이스 핸들러 (SOP 1-Read-I)
    /// v17 철학에 따라 ICacheService(Redis)만 사용하도록 단순화됨.
    /// </summary>
    public class GetUserProfileByConnectedIdQueryHandler : IRequestHandler<GetUserProfileByConnectedIdQuery, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _profileRepository;
        private readonly ICacheService _cacheService; // [v17 수정] Redis (L2)만 사용
        private readonly ILogger<GetUserProfileByConnectedIdQueryHandler> _logger;
        
        private const string CACHE_KEY_CONNECTED_PREFIX = "user:profile:connected:";
        private const int CACHE_EXPIRATION_MINUTES = 15;

        public GetUserProfileByConnectedIdQueryHandler(
            IUserRepository userRepository,
            IUserProfileRepository profileRepository,
            ICacheService cacheService, // [v17 수정]
            ILogger<GetUserProfileByConnectedIdQueryHandler> logger)
        {
            _userRepository = userRepository;
            _profileRepository = profileRepository;
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetUserProfileByConnectedIdQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserProfileByConnectedIdQuery for {ConnectedId}", query.ConnectedId);

            var cacheKey = $"{CACHE_KEY_CONNECTED_PREFIX}{query.ConnectedId}";

            // 1. [v17 수정] L1(로컬) 캐시 조회 로직 "제거"
            
            // 2. 분산 캐시(Redis) 조회
            var cachedProfile = await _cacheService.GetAsync<UserDetailResponse>(cacheKey, cancellationToken);
            if (cachedProfile != null)
            {
                _logger.LogDebug("Profile retrieved from distributed cache (Redis) for ConnectedId {ConnectedId}", query.ConnectedId);
                return cachedProfile;
            }

            // 3. DB 조회 (Cache Miss)
            var profile = await _profileRepository.GetByConnectedIdAsync(query.ConnectedId, cancellationToken);
            if (profile == null)
            {
                throw new KeyNotFoundException($"Profile not found for ConnectedId: {query.ConnectedId}");
            }

            var user = await _userRepository.GetByIdAsync(profile.UserId, cancellationToken);
             if (user == null)
            {
                throw new KeyNotFoundException($"User (UserId: {profile.UserId}) not found for ConnectedId: {query.ConnectedId}");
            }

            // 4. 응답 DTO 매핑
            var responseDto = MapToDto(profile, user);

            // 5. 캐시 저장 (Redis에만)
            await _cacheService.SetAsync(cacheKey, responseDto, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

            return responseDto;
        }
        
        // [v17 수정] 불필요한 L1(로컬) 캐시 헬퍼 메서드 제거

        // --- v17 표준 MapToDto ---
        private UserDetailResponse MapToDto(UserProfile profile, UserEntity user)
        {
            return new UserDetailResponse
            {
                Id = user.Id,
                Status = user.Status,
                Email = user.Email,
                Username = user.Username,
                DisplayName = user.DisplayName,
                EmailVerified = user.IsEmailVerified,
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                LastLoginAt = user.LastLoginAt,
                CreatedAt = user.CreatedAt,
                ExternalUserId = user.ExternalUserId,
                ExternalSystemType = user.ExternalSystemType,
                UpdatedAt = user.UpdatedAt,
                CreatedByConnectedId = user.CreatedByConnectedId,
                UpdatedByConnectedId = user.UpdatedByConnectedId,
                Profile = new UserProfileInfo
                {
                     UserId = profile.UserId,
                     PhoneNumber = profile.PhoneNumber,
                     PhoneVerified = profile.PhoneVerified,
                     ProfileImageUrl = profile.ProfileImageUrl,
                     TimeZone = profile.TimeZone,
                     PreferredLanguage = profile.PreferredLanguage,
                     PreferredCurrency = profile.PreferredCurrency,
                     Bio = profile.Bio,
                     WebsiteUrl = profile.WebsiteUrl,
                     Location = profile.Location,
                     DateOfBirth = profile.DateOfBirth,
                     Gender = profile.Gender,
                     CompletionPercentage = profile.CompletionPercentage,
                     IsPublic = profile.IsPublic,
                     LastProfileUpdateAt = profile.LastProfileUpdateAt
                },
                Organizations = new (), 
                ActiveSessionCount = 0,
                TotalConnectedIdCount = 0 
            };
        }
    }
}