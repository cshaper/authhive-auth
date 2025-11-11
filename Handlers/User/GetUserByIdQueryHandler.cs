// [AuthHive.Auth] GetUserByIdQueryHandler.cs
// v17 CQRS "본보기": 플랫폼 전역 'User'를 ID로 조회하는 'GetUserByIdQuery'를 처리합니다.
// v16의 UserService.GetByIdAsync 로직 중, v17 철학에 맞지 않는
// '조직(Organization) 소속 검사' 로직을 의도적으로 제거합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
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
    /// [v17] "ID로 사용자 조회" 유스케이스 핸들러 (SOP 1-Read-D)
    /// </summary>
    public class GetUserByIdQueryHandler : IRequestHandler<GetUserByIdQuery, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _profileRepository;
        private readonly ILogger<GetUserByIdQueryHandler> _logger;

        public GetUserByIdQueryHandler(
            IUserRepository userRepository,
            IUserProfileRepository profileRepository,
            ILogger<GetUserByIdQueryHandler> logger)
        {
            _userRepository = userRepository;
            _profileRepository = profileRepository;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetUserByIdQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserByIdQuery for User {UserId}", query.UserId);

            // 1. User 엔티티 조회 (v16 로직)
            var user = await _userRepository.GetByIdAsync(query.UserId, cancellationToken);
            if (user == null)
            {
                // [v17 수정] ServiceResult.Failure 대신 표준 예외 사용
                throw new KeyNotFoundException($"User not found: {query.UserId}");
            }

            // 2. UserProfile 엔티티 조회 (v17 응답 DTO 구성을 위해)
            // UserProfile은 1:1 관계이며, 아직 생성되지 않았을 수 있음 (null 허용)
            var profile = await _profileRepository.GetByIdAsync(query.UserId, cancellationToken);

            // 3. v17 철학 적용
            // [v17 수정] v16 UserService의 '조직 검사' 로직(IsUserInOrganizationAsync)을
            // v17 철학(User는 전역 엔티티)에 따라 의도적으로 "제거"함.

            // 4. 응답 DTO 반환
            // (Create/Update 핸들러에서 사용한 MapToDto 헬퍼 사용)
            return MapToDto(profile, user);
        }

        /// <summary>
        /// 엔티티(User, UserProfile)를 v17 응답 DTO (UserDetailResponse)로 매핑
        /// </summary>
        private UserDetailResponse MapToDto(UserProfile? profile, UserEntity user)
        {
            return new UserDetailResponse
            {
                // BaseDto (required)
                Id = user.Id,

                // UserResponse
                Status = user.Status,
                Email = user.Email,
                Username = user.Username,
                DisplayName = user.DisplayName,
                EmailVerified = user.IsEmailVerified,
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                LastLoginAt = user.LastLoginAt,
                CreatedAt = user.CreatedAt,

                // UserDetailResponse
                ExternalUserId = user.ExternalUserId,
                ExternalSystemType = user.ExternalSystemType,
                UpdatedAt = user.UpdatedAt,
                CreatedByConnectedId = user.CreatedByConnectedId,
                UpdatedByConnectedId = user.UpdatedByConnectedId,
                
                // Profile 정보 (Profile이 null일 수 있음)
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
                
                // 이 쿼리는 조직/세션 정보를 조회할 책임이 없음
                Organizations = new (), 
                ActiveSessionCount = 0,
                TotalConnectedIdCount = 0 
            };
        }
    }
}