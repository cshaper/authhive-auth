using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Repositories.Profile;
using AuthHive.Core.Interfaces.User.Repositories.Security;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository; // 🚨 공식 인터페이스 참조
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries.Profile;
using AuthHive.Core.Models.User.Responses.Profile;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using System;
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User.Profile
{
    // 🚨 임시 로컬 인터페이스 정의 삭제됨

    /// <summary>
    /// [v18] "ConnectedId로 프로필 조회" 유스케이스 핸들러 (SOP 1-Read-I)
    /// </summary>
    public class GetUserProfileByConnectedIdQueryHandler : IRequestHandler<GetUserProfileByConnectedIdQuery, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUserSocialAccountRepository _socialRepository; // 외부 연동 정보용
        private readonly IOrganizationMembershipRepository _membershipRepository; // [New] ConnectedId 매핑용
        private readonly ICacheService _cacheService;
        private readonly ILogger<GetUserProfileByConnectedIdQueryHandler> _logger;
        
        private const string CACHE_KEY_CONNECTED_PREFIX = "user:profile:connected:";
        private const int CACHE_EXPIRATION_MINUTES = 15;

        public GetUserProfileByConnectedIdQueryHandler(
            IUserRepository userRepository,
            IUserProfileRepository profileRepository,
            IUserSocialAccountRepository socialRepository,
            IOrganizationMembershipRepository membershipRepository,
            ICacheService cacheService,
            ILogger<GetUserProfileByConnectedIdQueryHandler> logger)
        {
            _userRepository = userRepository;
            _profileRepository = profileRepository;
            _socialRepository = socialRepository;
            _membershipRepository = membershipRepository; 
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetUserProfileByConnectedIdQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserProfileByConnectedIdQuery for {ConnectedId}", query.ConnectedId);

            var cacheKey = $"{CACHE_KEY_CONNECTED_PREFIX}{query.ConnectedId}";

            // 1. 분산 캐시(Redis) 조회
            var cachedProfile = await _cacheService.GetAsync<UserDetailResponse>(cacheKey, cancellationToken);
            if (cachedProfile != null)
            {
                return cachedProfile;
            }

            // 2. DB 조회 (Cache Miss) - ConnectedId로 UserId 조회 (공식 인터페이스 메서드)
            var connectedIdEntity = await _membershipRepository.GetByIdAsync(query.ConnectedId, cancellationToken);
            
            if (connectedIdEntity == null)
            {
                throw new KeyNotFoundException($"Membership (ConnectedId: {query.ConnectedId}) not found.");
            }
            
            // ConnectedId Entity에서 UserId 추출
            var userId = connectedIdEntity.UserId;

            // 3. User 및 UserProfile 조회 
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            var profile = await _profileRepository.GetByUserIdAsync(userId, cancellationToken);
            var socialAccounts = await _socialRepository.GetByUserIdAsync(userId, cancellationToken);

            if (user == null)
            {
                throw new KeyNotFoundException($"User (UserId: {userId}) not found.");
            }
            
            // 4. 응답 DTO 매핑
            var responseDto = MapToDto(profile, user, socialAccounts);

            // 5. 캐시 저장
            await _cacheService.SetAsync(cacheKey, responseDto, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

            return responseDto;
        }
        
        private UserDetailResponse MapToDto(
            UserProfile? profile, 
            UserEntity user, 
            IEnumerable<UserSocialAccount> socialAccounts)
        {
            var primarySocial = socialAccounts.FirstOrDefault();
            
            return new UserDetailResponse
            {
                // User & Base Info
                Id = user.Id,
                Status = user.Status,
                Email = user.Email,
                Username = user.Username,
                IsEmailVerified = user.IsEmailVerified,
                PhoneNumber = user.PhoneNumber, 
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                LastLoginAt = user.LastLoginAt,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt,

                // Mapping
                ExternalUserId = primarySocial?.ProviderId, 
                ExternalSystemType = primarySocial?.Provider.ToString(),
                
                Profile = profile == null ? null : new UserProfileInfo
                {
                     UserId = profile.UserId,
                     ProfileImageUrl = profile.ProfileImageUrl,
                     TimeZone = profile.TimeZone,
                     PreferredLanguage = profile.PreferredLanguage,
                     PreferredCurrency = profile.PreferredCurrency,
                     Bio = profile.Bio,
                     WebsiteUrl = profile.WebsiteUrl,
                     Location = profile.Location,
                     DateOfBirth = profile.DateOfBirth,
                     Gender = profile.Gender,
                     IsPublic = profile.IsPublic,
                     LastProfileUpdateAt = profile.LastProfileUpdateAt,
                     CompletionPercentage = CalculateCompletionPercentage(profile)
                },
                Organizations = new List<UserOrganizationInfo>(), 
                ActiveSessionCount = 0,
                TotalConnectedIdCount = 0 
            };
        }
        
        private int CalculateCompletionPercentage(UserProfile profile)
        {
            int score = 0;
            if (!string.IsNullOrEmpty(profile.Bio)) score += 20;
            if (!string.IsNullOrEmpty(profile.Location)) score += 20;
            if (!string.IsNullOrEmpty(profile.ProfileImageUrl)) score += 20;
            return score;
        }
    }
}