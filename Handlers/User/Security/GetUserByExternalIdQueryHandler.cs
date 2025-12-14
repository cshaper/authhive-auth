// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.User.Repositories.Profile;
// using AuthHive.Core.Interfaces.User.Repositories.Security; // [Fix] I/F for Social Accounts
// using AuthHive.Core.Models.User.Common;
// using AuthHive.Core.Models.User.Queries.Security;
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

// namespace AuthHive.Auth.Handlers.User.Security; // Correct Namespace (Security)

// /// <summary>
// /// [v18] "외부 ID로 사용자 조회" 유스케이스 핸들러 (JIT Provisioning의 Get 단계)
// /// </summary>
// public class GetUserByExternalIdQueryHandler : IRequestHandler<GetUserByExternalIdQuery, UserDetailResponse>
// {
//     private readonly IUserRepository _userRepository;
//     private readonly IUserProfileRepository _profileRepository;
//     private readonly IUserSocialAccountRepository _socialRepository; // [New]
//     private readonly ILogger<GetUserByExternalIdQueryHandler> _logger;

//     public GetUserByExternalIdQueryHandler(
//         IUserRepository userRepository,
//         IUserProfileRepository profileRepository,
//         IUserSocialAccountRepository socialRepository,
//         ILogger<GetUserByExternalIdQueryHandler> logger)
//     {
//         _userRepository = userRepository;
//         _profileRepository = profileRepository;
//         _socialRepository = socialRepository;
//         _logger = logger;
//     }

//     public async Task<UserDetailResponse> Handle(GetUserByExternalIdQuery query, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling GetUserByExternalIdQuery for {ExternalSystemType}:{ExternalUserId}", 
//             query.ExternalSystemType, query.ExternalUserId);

//         // 1. [Fix] UserSocialAccount 리포지토리를 통해 소셜 계정 조회
//         // 이 조회는 User ID를 얻기 위한 핵심 단계입니다.
//         var socialAccount = await _socialRepository.GetByProviderKeyAsync(
//             (AuthHive.Core.Enums.Auth.SocialProvider)Enum.Parse(typeof(AuthHive.Core.Enums.Auth.SocialProvider), query.ExternalSystemType),
//             query.ExternalUserId,
//             cancellationToken);

//         if (socialAccount == null)
//         {
//             // [JIT의 Get 단계] 사용자를 못 찾으면 KeyNotFoundException을 던져 Orchestrator(GetOrCreate...)가 Catch하고 Create를 실행하도록 유도합니다.
//             throw new KeyNotFoundException($"User not found with ExternalId: {query.ExternalSystemType}:{query.ExternalUserId}");
//         }

//         // 2. User 엔티티 조회 (Social Account에서 UserId 획득)
//         var user = await _userRepository.GetByIdAsync(socialAccount.UserId, cancellationToken);
        
//         // 3. UserProfile 엔티티 조회 (null 허용)
//         var profile = await _profileRepository.GetByUserIdAsync(user!.Id, cancellationToken);
        
//         // 4. 응답 DTO 반환
//         // FindByExternalIdAsync 대신 GetByProviderKeyAsync를 사용하여 소셜 계정 엔티티를 찾았으므로
//         // 매핑 시 해당 엔티티를 활용하여 ExternalUserId 등을 채워야 합니다.
//         var socialAccounts = new List<UserSocialAccount> { socialAccount }; // 단일 계정 리스트로 변환
//         return MapToDto(profile, user!, socialAccounts); 
//     }

//     /// <summary>
//     /// 엔티티(User, UserProfile)를 v18 응답 DTO (UserDetailResponse)로 매핑
//     /// </summary>
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
//             Username = user.Username,
//             IsEmailVerified = user.IsEmailVerified,
//             PhoneNumber = user.PhoneNumber, 
//             IsTwoFactorEnabled = user.IsTwoFactorEnabled,
//             CreatedAt = user.CreatedAt,
//             UpdatedAt = user.UpdatedAt,

//             // --- External Info (from SocialAccount) ---
//             ExternalUserId = primarySocial?.ProviderId,
//             ExternalSystemType = primarySocial?.Provider.ToString(),
            
//             // --- Profile Info (Fixes Property Mismatches) ---
//             Profile = profile == null ? null : new UserProfileInfo
//             {
//                  UserId = profile.UserId,
//                  ProfileImageUrl = profile.ProfileImageUrl,
//                  TimeZone = profile.TimeZone,
//                  Bio = profile.Bio,
//                  WebsiteUrl = profile.WebsiteUrl,
//                  Location = profile.Location,
//                  DateOfBirth = profile.DateOfBirth,
//                  Gender = profile.Gender,
//                  IsPublic = profile.IsPublic,
//                  LastProfileUpdateAt = profile.LastProfileUpdateAt,
                 
//                  CompletionPercentage = 0 // 계산 로직 제거, 0으로 설정
//             },
            
//             Organizations = new List<UserOrganizationInfo>(), 
//             ActiveSessionCount = 0,
//             TotalConnectedIdCount = 0 
//         };
//     }
// }