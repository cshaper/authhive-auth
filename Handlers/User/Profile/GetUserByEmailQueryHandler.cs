// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.User.Repositories.Profile;
// using AuthHive.Core.Interfaces.User.Repositories.Security; 
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

// namespace AuthHive.Auth.Handlers.User.Profile;

// public class GetUserByEmailQueryHandler : IRequestHandler<GetUserByEmailQuery, UserDetailResponse>
// {
//     private readonly IUserRepository _userRepository;
//     private readonly IUserProfileRepository _profileRepository;
//     private readonly IUserSocialAccountRepository _socialRepository;
//     private readonly ILogger<GetUserByEmailQueryHandler> _logger;

//     public GetUserByEmailQueryHandler(
//         IUserRepository userRepository,
//         IUserProfileRepository profileRepository,
//         IUserSocialAccountRepository socialRepository,
//         ILogger<GetUserByEmailQueryHandler> logger)
//     {
//         _userRepository = userRepository;
//         _profileRepository = profileRepository;
//         _socialRepository = socialRepository;
//         _logger = logger;
//     }

//     public async Task<UserDetailResponse> Handle(GetUserByEmailQuery query, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling GetUserByEmailQuery for {Email}", query.Email);

//         // 1. User Entity 조회
//         // [근본 해결] Interface에 정의된 표준 메서드 'GetByEmailAsync'를 사용합니다.
//         var user = await _userRepository.GetByEmailAsync(query.Email, cancellationToken);
        
//         if (user == null)
//         {
//             throw new KeyNotFoundException($"User not found with email: {query.Email}");
//         }

//         // 2. Profile 조회
//         var profile = await _profileRepository.GetByIdAsync(user.Id, cancellationToken);

//         // 3. Social Account 조회 (ExternalUserId 등 확인용)
//         var socialAccounts = await _socialRepository.GetByUserIdAsync(user.Id, cancellationToken);

//         // 4. DTO 매핑
//         return MapToDto(profile, user, socialAccounts);
//     }

//     private UserDetailResponse MapToDto(
//         UserProfile? profile, 
//         UserEntity user, 
//         IEnumerable<UserSocialAccount> socialAccounts)
//     {
//         // 대표 소셜 계정 추출
//         var primarySocial = socialAccounts.FirstOrDefault();

//         return new UserDetailResponse
//         {
//             // --- User 기본 정보 ---
//             Id = user.Id,
//             Status = user.Status,
//             Email = user.Email,
//             Username = user.Username,
//             IsEmailVerified = user.IsEmailVerified,
//             PhoneNumber = user.PhoneNumber, // User 엔티티에서 가져옴
//             IsTwoFactorEnabled = user.IsTwoFactorEnabled,
//             LastLoginAt = user.LastLoginAt,
//             CreatedAt = user.CreatedAt,
//             UpdatedAt = user.UpdatedAt,

//             // --- 외부 연동 정보 (소셜 테이블에서 가져옴) ---
//             ExternalUserId = primarySocial?.ProviderId,
//             ExternalSystemType = primarySocial?.Provider.ToString(),
            
//             // --- Profile 정보 ---
//             Profile = profile == null ? null : new UserProfileInfo
//             {
//                  UserId = profile.UserId,
//                  ProfileImageUrl = profile.ProfileImageUrl,
//                  TimeZone = profile.TimeZone,
//                  PreferredLanguage = profile.PreferredLanguage,
//                  PreferredCurrency = profile.PreferredCurrency,
//                  Bio = profile.Bio,
//                  WebsiteUrl = profile.WebsiteUrl,
//                  Location = profile.Location,
                 
//                  // [v18 Entity 수정 반영]
//                  DateOfBirth = profile.DateOfBirth,
//                  Gender = profile.Gender,
//                  IsPublic = profile.IsPublic,
//                  LastProfileUpdateAt = profile.LastProfileUpdateAt,
                 
//                  // 계산 로직 (간소화)
//                  CompletionPercentage = CalculateCompletionPercentage(profile)
//             },
            
//             Organizations = new List<UserOrganizationInfo>(), // 빈 리스트 초기화
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