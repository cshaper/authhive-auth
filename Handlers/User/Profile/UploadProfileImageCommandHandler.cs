// [AuthHive.Auth] UploadProfileImageCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile'의 프로필 이미지를 업로드하는 'UploadProfileImageCommand'를 처리합니다.
// v16의 stub 로직을 대체하며, IStorageService(GCS) 전문가에게 업로드를 위임합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.Infra.Storage; // [v17] GCS 서비스 주입
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Profile; // ProfileImageUploadedEvent
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.IO; // MemoryStream
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Common;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "프로필 이미지 업로드" 유스케이스 핸들러 (SOP 1-Write-G)
    /// 'Create'와 유사하게, 서버 생성 값(URL)이 포함된 DTO를 반환합니다.
    /// </summary>
    public class UploadProfileImageCommandHandler : IRequestHandler<UploadProfileImageCommand, UserDetailResponse>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUserRepository _userRepository;
        private readonly IStorageService _storageService; // [v17] GCS 전문가
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<UploadProfileImageCommandHandler> _logger;
        // [v17 수정] v16 Validator는 이 유스케이스에 대한 로직이 없었으므로 제외

        public UploadProfileImageCommandHandler(
            IUserProfileRepository profileRepository,
            IUserRepository userRepository,
            IStorageService storageService, // [v17] GCS 전문가 주입
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<UploadProfileImageCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _userRepository = userRepository;
            _storageService = storageService;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(UploadProfileImageCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling UploadProfileImageCommand for User {UserId}, FileName: {FileName}", command.UserId, command.FileName);

            // 1. 엔티티 조회 (v16 UserProfileService.UploadProfileImageAsync 로직)
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                // [정합성] 프로필이 없으면 이미지를 업로드할 수 없음
                throw new KeyNotFoundException($"Profile not found for user: {command.UserId}. Cannot upload image.");
            }
            
            var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (user == null)
            {
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }

            var oldImageUrl = profile.ProfileImageUrl; // 이벤트 발행을 위해 이전 URL 저장

            // 2. GCS에 파일 업로드 (전문가 위임)
            string newImageUrl;
            // GCS에 저장할 경로 생성 (예: "profiles/USER_ID/avatar_TIMESTAMP.png")
            string fileExtension = Path.GetExtension(command.FileName);
            string objectName = $"profiles/{command.UserId}/avatar_{DateTime.UtcNow.Ticks}{fileExtension}";

            try
            {
                // Command의 byte[]를 Stream으로 변환
                await using (var fileStream = new MemoryStream(command.ImageData))
                {
                    newImageUrl = await _storageService.UploadAsync(
                        fileStream,
                        objectName,
                        command.ContentType,
                        cancellationToken
                    );
                }
                _logger.LogInformation("Image uploaded to GCS for User {UserId}. New URL: {NewUrl}", command.UserId, newImageUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to upload image to GCS for User {UserId}", command.UserId);
                throw new InvalidOperationException("Failed to upload profile image.", ex);
            }

            // 3. 엔티티 도메인 메서드 호출 및 저장
            profile.UpdateProfileImage(newImageUrl); // 엔티티 내부의 URL, UploadedAt, CompletionPercentage 업데이트
            
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 4. 이벤트 발행
            var imageUploadedEvent = new ProfileImageUploadedEvent(
                userId: profile.UserId,
                uploadedByConnectedId: command.TriggeredBy ?? command.UserId,
                newImageUrl: newImageUrl,
                imageSize: command.ImageData.Length,
                contentType: command.ContentType,
                oldImageUrl: oldImageUrl,
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                ipAddress: command.IpAddress, // BaseCommand에서 상속 (가정)
                source: "UserProfileHandler", // v17 표준
                userAgent: null // (추후 Controller에서 command에 주입 가능)
            );
            await _mediator.Publish(imageUploadedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (서버 생성 URL 포함)
            return MapToDto(profile, user);
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
                UpdatedAt = user.UpdatedAt, // 방금 업데이트되었으므로 최신 값
                CreatedByConnectedId = user.CreatedByConnectedId,
                UpdatedByConnectedId = user.UpdatedByConnectedId,
                Profile = new UserProfileInfo
                {
                     UserId = profile.UserId,
                     PhoneNumber = profile.PhoneNumber,
                     PhoneVerified = profile.PhoneVerified,
                     ProfileImageUrl = profile.ProfileImageUrl, // [v17] 방금 업로드된 새 URL
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