// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.User.Repositories.Profile;
// using AuthHive.Core.Interfaces.User.Repositories.Security;
// using AuthHive.Core.Interfaces.Infra.Cache;
// using AuthHive.Core.Interfaces.Organization.Repository; // 🚨 필수: 공식 인터페이스 using
// using AuthHive.Core.Models.User.Common;
// using AuthHive.Core.Models.User.Queries.Profile;
// using AuthHive.Core.Models.User.Responses.Profile;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System.Collections.Generic;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using UserEntity = AuthHive.Core.Entities.User.User;
// using System;
// using AuthHive.Core.Exceptions;
// using AuthHive.Core.Entities.Auth.ConnectedId; 

// namespace AuthHive.Auth.Handlers.User.Profile; 

// // 🚨 로컬 인터페이스 정의를 제거하세요. (이 코드는 여기에 있으면 안 됩니다.)
// // public interface IOrganizationMembershipRepository { ... }

// public class GetUserProfileByUserIdQueryHandler : IRequestHandler<GetUserProfileByUserIdQuery, UserDetailResponse>
// {
//     private readonly IUserRepository _userRepository;
//     private readonly IUserProfileRepository _profileRepository;
//     private readonly IUserSocialAccountRepository _socialRepository;
//     private readonly IOrganizationMembershipRepository _membershipRepository; // 이제 Core 인터페이스를 참조합니다.
//     private readonly ICacheService _cacheService;
//     private readonly ILogger<GetUserProfileByUserIdQueryHandler> _logger;

//     private const string CACHE_KEY_PREFIX = "user:profile:";
//     private const int CACHE_EXPIRATION_MINUTES = 15;

//     public GetUserProfileByUserIdQueryHandler(
//         IUserRepository userRepository,
//         IUserProfileRepository profileRepository,
//         IUserSocialAccountRepository socialRepository,
//         IOrganizationMembershipRepository membershipRepository,
//         ICacheService cacheService,
//         ILogger<GetUserProfileByUserIdQueryHandler> logger)
//     {
//         _userRepository = userRepository;
//         _profileRepository = profileRepository;
//         _socialRepository = socialRepository;
//         _membershipRepository = membershipRepository;
//         _cacheService = cacheService;
//         _logger = logger;
//     }

//     public async Task<UserDetailResponse> Handle(GetUserProfileByUserIdQuery query, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling GetUserProfileByUserIdQuery for {TargetUserId} in Org {OrganizationId}", 
//             query.TargetUserId, query.RequestingOrganizationId);

//         var cacheKey = $"{CACHE_KEY_PREFIX}{query.TargetUserId}";

//         // 1. 캐시 조회 (생략)
//         var cachedProfile = await _cacheService.GetAsync<UserDetailResponse>(cacheKey, cancellationToken);
//         if (cachedProfile != null) return cachedProfile;
        
//         // 2. [Security Check] ConnectedId 조회 및 멤버십 검사
//         // [Fix CS1061] IOrganizationMembershipRepository의 공식 메서드 사용
//         var connectedId = await _membershipRepository.GetByUserAndOrganizationAsync( 
//             query.TargetUserId, 
//             query.RequestingOrganizationId, 
//             cancellationToken);

//         if (connectedId == null)
//         {
//             throw new KeyNotFoundException($"User profile not found in organization context: {query.TargetUserId}");
//         }
        
//         // 3. DB 조회
//         var user = await _userRepository.GetByIdAsync(query.TargetUserId, cancellationToken);
//         var profile = await _profileRepository.GetByUserIdAsync(query.TargetUserId, cancellationToken);
//         var socialAccounts = await _socialRepository.GetByUserIdAsync(query.TargetUserId, cancellationToken);

//         if (user == null)
//         {
//             throw new KeyNotFoundException($"Orphaned ConnectedId found for User: {query.TargetUserId}");
//         }
        
//         // 4. 응답 DTO 매핑
//         var responseDto = MapToDto(profile, user, socialAccounts);

//         // 5. 캐시 저장
//         await _cacheService.SetAsync(cacheKey, responseDto, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

//         return responseDto;
//     }

//     private UserDetailResponse MapToDto(
//         UserProfile? profile, 
//         UserEntity user, 
//         IEnumerable<UserSocialAccount> socialAccounts)
//     {
//         var primarySocial = socialAccounts.FirstOrDefault();

//         return new UserDetailResponse
//         {
//             // --- User & Base Info ---
//             Id = user.Id,
//             Status = user.Status,
//             Email = user.Email,
//             // ... (나머지 속성 매핑) ...
            
//             // Profile 매핑은 생략
//             Profile = profile == null ? null : new UserProfileInfo { UserId = profile.UserId, /* ... */ },
            
//             Organizations = new List<UserOrganizationInfo>(), 
//             ActiveSessionCount = 0,
//             TotalConnectedIdCount = 0 
//         };
//     }

//     private int CalculateCompletionPercentage(UserProfile profile)
//     {
//         int score = 0;
//         if (!string.IsNullOrEmpty(profile.Bio)) score += 20;
//         if (!string.IsNullOrEmpty(profile.Location)) score += 20;
//         if (!string.IsNullOrEmpty(profile.ProfileImageUrl)) score += 20;
//         return score;
//     }
// }