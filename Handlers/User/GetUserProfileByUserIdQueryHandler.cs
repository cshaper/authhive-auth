// [AuthHive.Auth] GetUserProfileByUserIdQueryHandler.cs
// v17 CQRS "본보기": 'GetUserProfileByUserIdQuery'를 처리합니다.
// v16 UserProfileService.GetByUserIdAsync의 '조직 보안 검사' 및 '캐싱' 로직을 이관합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Auth.Service; // [v16 의존성] IConnectedIdService
using AuthHive.Core.Interfaces.Infra.Cache; // [v17] Redis 캐시
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Common; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "조직 컨텍스트 내 UserId로 프로필 조회" 유스케이스 핸들러 (SOP 1-Read-P)
    /// v16의 이중 캐시(L1 제거) 및 조직 멤버십 검사 로직을 포함합니다.
    /// </summary>
    public class GetUserProfileByUserIdQueryHandler : IRequestHandler<GetUserProfileByUserIdQuery, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _profileRepository;
        private readonly ICacheService _cacheService; // [v17] Redis (L2)
        private readonly IConnectedIdService _connectedIdService; // [v16 로직] 멤버십 검사
        private readonly ILogger<GetUserProfileByUserIdQueryHandler> _logger;
        
        // [v16 캐시 키] UserProfileService 참조
        private const string CACHE_KEY_PREFIX = "user:profile:";
        private const int CACHE_EXPIRATION_MINUTES = 15;

        public GetUserProfileByUserIdQueryHandler(
            IUserRepository userRepository,
            IUserProfileRepository profileRepository,
            ICacheService cacheService,
            IConnectedIdService connectedIdService, // [v16 의존성]
            ILogger<GetUserProfileByUserIdQueryHandler> logger)
        {
            _userRepository = userRepository;
            _profileRepository = profileRepository;
            _cacheService = cacheService;
            _connectedIdService = connectedIdService;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetUserProfileByUserIdQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserProfileByUserIdQuery for {TargetUserId} in Org {OrganizationId}", 
                query.TargetUserId, query.RequestingOrganizationId);

            var cacheKey = $"{CACHE_KEY_PREFIX}{query.TargetUserId}"; // v16 키 형식

            // 1. 분산 캐시(Redis) 조회 (v16 로직 이관)
            var cachedProfile = await _cacheService.GetAsync<UserDetailResponse>(cacheKey, cancellationToken);
            if (cachedProfile != null)
            {
                _logger.LogDebug("Profile retrieved from distributed cache (Redis) for User {UserId}", query.TargetUserId);
                return cachedProfile;
            }

            // 2. [v16 보안 로직] 조직 멤버십 검사
            var isMemberResult = await _connectedIdService.IsMemberOfOrganizationAsync(
                query.TargetUserId, 
                query.RequestingOrganizationId, 
                cancellationToken);
            
            if (!isMemberResult.IsSuccess || isMemberResult.Data == false)
            {
                _logger.LogWarning("Forbidden access attempt: Org {OrgId} tried to access user {UserId} (not a member).", 
                    query.RequestingOrganizationId, query.TargetUserId);
                // [v17 수정] ServiceResult.Forbidden 대신 예외 사용
                throw new KeyNotFoundException($"User profile not found in this organization context: {query.TargetUserId}");
            }
            
            // 3. DB 조회 (Cache Miss & 멤버십 통과)
            var user = await _userRepository.GetByIdAsync(query.TargetUserId, cancellationToken);
            if (user == null)
            {
                throw new KeyNotFoundException($"User not found: {query.TargetUserId}");
            }
            
            var profile = await _profileRepository.GetByIdAsync(query.TargetUserId, cancellationToken);
            // profile은 null일 수 있음 (프로필 미생성)

            // 4. 응답 DTO 매핑
            var responseDto = MapToDto(profile, user);

            // 5. 캐시 저장 (Redis에만)
            await _cacheService.SetAsync(cacheKey, responseDto, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

            return responseDto;
        }

        /// <summary>
        /// 엔티티(User, UserProfile)를 v17 응답 DTO (UserDetailResponse)로 매핑
        /// </summary>
        private UserDetailResponse MapToDto(UserProfile? profile, UserEntity user)
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
                Profile = profile == null ? null : new UserProfileInfo
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