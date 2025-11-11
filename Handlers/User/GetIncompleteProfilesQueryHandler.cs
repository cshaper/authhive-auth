// [AuthHive.Auth] GetIncompleteProfilesQueryHandler.cs
// v17 CQRS "본보기": 'GetIncompleteProfilesQuery'를 처리하여 미완성 프로필 목록을 조회합니다.
// v16 UserProfileService.GetIncompleteProfilesAsync (전역) 로직을 이관합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq; // .Select()
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "미완성 프로필 조회" 유스케이스 핸들러 (SOP 1-Read-K)
    /// </summary>
    public class GetIncompleteProfilesQueryHandler : IRequestHandler<GetIncompleteProfilesQuery, IReadOnlyList<UserDetailResponse>>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<GetIncompleteProfilesQueryHandler> _logger;

        public GetIncompleteProfilesQueryHandler(
            IUserProfileRepository profileRepository,
            IUserRepository userRepository,
            ILogger<GetIncompleteProfilesQueryHandler> logger)
        {
            _profileRepository = profileRepository;
            _userRepository = userRepository;
            _logger = logger;
        }

        public async Task<IReadOnlyList<UserDetailResponse>> Handle(GetIncompleteProfilesQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation(
                "Handling GetIncompleteProfilesQuery (Global): Threshold < {Threshold}, Limit {Limit}",
                query.MaxCompletenessThreshold, query.Limit);

            // 1. DB 조회 (v16 로직 이관)
            var profiles = await _profileRepository.FindAsync(
                p => p.CompletionPercentage < query.MaxCompletenessThreshold,
                cancellationToken);

            // [v16 로직] .Take(limit) 적용
            var limitedProfiles = profiles.Take(query.Limit).ToList();

            var result = new List<UserDetailResponse>();

            // 2. 응답 DTO 매핑
            // [v17 정합성] N+1 쿼리 문제가 있으나, 우선 v16 로직을 그대로 이관
            foreach (var profile in limitedProfiles)
            {
                var user = await _userRepository.GetByIdAsync(profile.UserId, cancellationToken);
                if (user != null)
                {
                    result.Add(MapToDto(profile, user));
                }
                else
                {
                    _logger.LogWarning("Orphaned profile found (ProfileId: {ProfileId}) for missing User (UserId: {UserId})",
                        profile.Id, profile.UserId);
                }
            }

            return result;
        }

        /// <summary>
        /// 엔티티(User, UserProfile)를 v17 응답 DTO (UserDetailResponse)로 매핑
        /// </summary>
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