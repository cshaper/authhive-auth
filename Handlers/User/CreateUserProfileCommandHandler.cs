// [AuthHive.Auth] CreateUserProfileCommandHandler.cs
// v17 CQRS "본보기": 'User'에 대한 'Profile'을 생성하는 'CreateUserProfileCommand'를 처리합니다.
// 이 핸들러는 UserProfileService.CreateAsync의 로직을 이관받아 수행합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Profile; // UserProfileCreatedEvent
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Common; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 프로필 생성" 유스케이스 핸들러 (SOP 1-Write-B)
    /// </summary>
    public class CreateUserProfileCommandHandler : IRequestHandler<CreateUserProfileCommand, UserDetailResponse>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUserRepository _userRepository; // User 정보 조회를 위해 추가
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<CreateUserProfileCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public CreateUserProfileCommandHandler(
            IUserProfileRepository profileRepository,
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<CreateUserProfileCommandHandler> logger,
            IUserValidator userValidator)
        {
            _profileRepository = profileRepository;
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<UserDetailResponse> Handle(CreateUserProfileCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling CreateUserProfileCommand for User {UserId}", command.UserId);

            // 1. 유효성 검사 (Validator로 책임 이관)
            // (v16 UserProfileService.CreateAsync 로직 이관 완료)
            var validationResult = await _userValidator.ValidateProfileCreationAsync(command);
            if (!validationResult.IsSuccess)
            {
                throw new ValidationException(validationResult.ErrorMessage ?? "Profile creation validation failed.");
            }
            
            // 2. 엔티티 매핑 (v16 UserProfileService.CreateAsync 로직 이관)
            var newProfile = new UserProfile
            {
                UserId = command.UserId, // [정합성] PK를 Command의 UserId(AggregateId)로 설정
                Id = Guid.NewGuid(), // [v16 로직] UserProfile 엔티티는 별도의 Id를 가짐
                
                PhoneNumber = command.PhoneNumber,
                TimeZone = command.TimeZone ?? "UTC", // v16 기본값
                PreferredLanguage = command.Language.ToString() ?? "en", // v16 기본값
                PreferredCurrency = command.PreferredCurrency ?? "USD", // v16 기본값
                ProfileImageUrl = command.ProfileImageUrl,
                Bio = command.Bio,
                WebsiteUrl = command.WebsiteUrl,
                Location = command.Location,
                DateOfBirth = command.DateOfBirth,
                Gender = command.Gender,
                ProfileMetadata = command.Metadata,
                IsPublic = command.IsPublic ?? false, // v16 기본값
                EmailNotificationsEnabled = command.EmailNotificationsEnabled ?? true, // v16 기본값
                SmsNotificationsEnabled = command.SmsNotificationsEnabled ?? false, // v16 기본값
                
                // CreatedByConnectedId 등 감사 속성은 SystemGlobalBaseEntity가 자동 처리 (가정)
            };
            
            // 3. 엔티티 도메인 메서드 호출
            newProfile.UpdateProfile(); // CompletionPercentage 및 LastProfileUpdateAt 계산

            // 4. 데이터베이스 저장
            await _profileRepository.AddAsync(newProfile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Profile created for user {UserId} (ProfileId: {ProfileId})", newProfile.UserId, newProfile.Id);

            // 5. 이벤트 발행 (v17 본보기: 캐시/감사/이메일 로직 제외)
            var profileCreatedEvent = new UserProfileCreatedEvent(
                userId: newProfile.UserId,
                profileId: newProfile.Id,
                createdByConnectedId: command.TriggeredBy ?? command.UserId, // 요청자 또는 본인
                completionPercentage: newProfile.CompletionPercentage,
                phoneNumber: newProfile.PhoneNumber,
                timeZone: newProfile.TimeZone,
                preferredLanguage: newProfile.PreferredLanguage,
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                source: "UserProfileHandler" // v17 표준
            );
            await _mediator.Publish(profileCreatedEvent, cancellationToken);

            // 6. 응답 DTO 반환 (UserDetailResponse)
            var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (user == null)
            {
                 // 방금 User가 있다고 검증했으므로, 이 예외는 이론상 발생하면 안 됨
                 throw new KeyNotFoundException($"User not found after profile creation: {command.UserId}");
            }
            return MapToDto(newProfile, user); // 헬퍼 메서드 재사용
        }

        /// <summary>
        /// v16 UserProfileService.MapToDto 로직을 핸들러로 이관 (응답 DTO 생성)
        /// UserDetailResponse는 UserResponse를 상속하므로 모든 필드를 채웁니다.
        /// </summary>
        private UserDetailResponse MapToDto(UserProfile profile, UserEntity user)
        {
            return new UserDetailResponse
            {
                // BaseDto (required)
                Id = user.Id, // [정합성] 응답 DTO의 Id는 User.Id

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
                CreatedByConnectedId = user.CreatedByConnectedId, // User 엔티티의 감사 속성
                UpdatedByConnectedId = user.UpdatedByConnectedId, // User 엔티티의 감사 속성
                
                // Profile 정보 (v4.4 수정사항 적용)
                Profile = new UserProfileInfo
                {
                     UserId = profile.UserId, // [CS0117 해결]
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