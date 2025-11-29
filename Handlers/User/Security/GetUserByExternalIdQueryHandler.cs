// [AuthHive.Auth] GetUserByExternalIdQueryHandler.cs
// v17 CQRS "본보기": 'GetUserByExternalIdQuery'를 처리하여 사용자를 외부 ID(소셜)로 조회합니다.
// v16 UserService의 '조직 검사' 로직을 v17 철학에 따라 의도적으로 제거합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "외부 ID로 사용자 조회" 유스케이스 핸들러 (SOP 1-Read-M)
    /// </summary>
    public class GetUserByExternalIdQueryHandler : IRequestHandler<GetUserByExternalIdQuery, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _profileRepository;
        private readonly ILogger<GetUserByExternalIdQueryHandler> _logger;

        public GetUserByExternalIdQueryHandler(
            IUserRepository userRepository,
            IUserProfileRepository profileRepository,
            ILogger<GetUserByExternalIdQueryHandler> logger)
        {
            _userRepository = userRepository;
            _profileRepository = profileRepository;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetUserByExternalIdQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserByExternalIdQuery for {ExternalSystemType}:{ExternalUserId}", 
                query.ExternalSystemType, query.ExternalUserId);

            // 1. User 엔티티 조회 (v16 로직)
            // [v17 로직 수정] v16 IUserRepository의 FindByExternalIdAsync 사용
            var user = await _userRepository.FindByExternalIdAsync(query.ExternalSystemType, query.ExternalUserId, cancellationToken);
            if (user == null)
            {
                throw new KeyNotFoundException($"User not found with ExternalId: {query.ExternalSystemType}:{query.ExternalUserId}");
            }

            // 2. UserProfile 엔티티 조회 (null 허용)
            var profile = await _profileRepository.GetByIdAsync(user.Id, cancellationToken);

            // 3. v17 철학 적용
            // [v17 수정] v16 UserService의 '조직 검사' 로직(IsUserInOrganizationAsync)을
            // v17 철학(User는 전역 엔티티)에 따라 의도적으로 "제거"함.

            // 4. 응답 DTO 반환
            return MapToDto(profile, user);
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