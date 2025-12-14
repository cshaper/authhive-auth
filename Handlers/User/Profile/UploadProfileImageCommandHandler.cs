// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.User.Repositories.Profile;
// using AuthHive.Core.Interfaces.User.Repositories.Security;
// using AuthHive.Core.Interfaces.Infra.Storage;
// using AuthHive.Core.Models.User.Events.Profile;
// using AuthHive.Core.Models.User.Responses.Profile;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.IO;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using AuthHive.Core.Models.User.Commands.Profile;
// using AuthHive.Core.Exceptions;
// using UserEntity = AuthHive.Core.Entities.User.User;
// using AuthHive.Core.Models.User.Common;
// using System.Collections.Generic;
// using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// namespace AuthHive.Auth.Handlers.User.Profile;

// /// <summary>
// /// [v18] "프로필 이미지 업로드" 유스케이스 핸들러 (SOP 1-Write-G)
// /// </summary>
// public class UploadProfileImageCommandHandler : IRequestHandler<UploadProfileImageCommand, UserProfileResponse>
// {
//     private readonly IUserProfileRepository _profileRepository;
//     private readonly IUserRepository _userRepository;
//     private readonly IStorageService _storageService;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IMediator _mediator;
//     private readonly ILogger<UploadProfileImageCommandHandler> _logger;
//     private readonly IDateTimeProvider _timeProvider;
//     // NOTE: IUserSocialAccountRepository는 DTO가 UserProfileResponse로 간소화되어 필요성이 낮아짐

//     public UploadProfileImageCommandHandler(
//         IUserProfileRepository profileRepository,
//         IUserRepository userRepository,
//         IStorageService storageService,
//         IUnitOfWork unitOfWork,
//         IMediator mediator,
//         IDateTimeProvider timeProvider,
//         ILogger<UploadProfileImageCommandHandler> logger)
//     {
//         _profileRepository = profileRepository;
//         _userRepository = userRepository;
//         _storageService = storageService;
//         _unitOfWork = unitOfWork;
//         _mediator = mediator;
//         _timeProvider = timeProvider;
//         _logger = logger;
//     }

//     public async Task<UserProfileResponse> Handle(UploadProfileImageCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling UploadProfileImageCommand for User {UserId}, FileName: {FileName}", command.UserId, command.FileName);

//         // 1. 엔티티 조회 (User Entity는 존재 여부만 체크)
//         var profile = await _profileRepository.GetByUserIdAsync(command.UserId, cancellationToken);
//         if (profile == null)
//         {
//             throw new KeyNotFoundException($"Profile not found for user: {command.UserId}. Cannot upload image.");
//         }

//         // User Entity는 ID 검증용으로만 사용 (필수)
//         var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
//         if (user == null)
//         {
//             throw new KeyNotFoundException($"User not found: {command.UserId}");
//         }

//         var oldImageUrl = profile.ProfileImageUrl;

//         // 2. GCS에 파일 업로드
//         string newImageUrl;
//         string fileExtension = Path.GetExtension(command.FileName);
//         string objectName = $"profiles/{command.UserId}/avatar_{_timeProvider.UtcNow.Ticks}{fileExtension}";

//         try
//         {
//             await using (var fileStream = new MemoryStream(command.FileContent))
//             {
//                 newImageUrl = await _storageService.UploadAsync(
//                     fileStream,
//                     objectName,
//                     command.ContentType,
//                     cancellationToken
//                 );
//             }
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Failed to upload image to GCS for User {UserId}", command.UserId);
//             throw new InvalidOperationException("Failed to upload profile image.", ex);
//         }

//         // 3. 엔티티 도메인 메서드 호출 및 저장
//         profile.UpdateProfileImage(newImageUrl);

//         await _profileRepository.UpdateAsync(profile, cancellationToken);
//         await _unitOfWork.SaveChangesAsync(cancellationToken);
//         // 4. 이벤트 발행 (Audit, Cache Invalidation)
//         var imageUploadedEvent = new ProfileImageUploadedEvent
//         {
//             AggregateId = command.UserId,
//             OccurredOn = _timeProvider.UtcNow,
//             // TriggeredBy, OrganizationId, CorrelationId는 Command에 추가되었다고 가정
//             TriggeredBy = command.TriggeredBy,
//             OrganizationId = command.OrganizationId,
//             CorrelationId = command.CorrelationId?.ToString(),

//             UserId = profile.UserId,
//             UploadedByConnectedId = command.TriggeredBy, // TriggeredBy 사용
//             NewImageUrl = newImageUrl,
//             ImageSize = command.FileContent.Length,
//             ContentType = command.ContentType,
//             OldImageUrl = oldImageUrl,
//             UploadedAt = _timeProvider.UtcNow
//         };

//         await _mediator.Publish(imageUploadedEvent, cancellationToken);

//         _logger.LogInformation("Profile image updated in DB and event published. UserId: {UserId}", command.UserId);

//         // 5. 응답 DTO 반환 (UserProfileResponse는 프로필 정보만 포함)
//         return MapToProfileResponse(profile);
//     }

//     // --- DTO 매핑 헬퍼 ---
//     private UserProfileResponse MapToProfileResponse(UserProfile profile)
//     {
//         // UserProfile 엔티티의 정보만 UserProfileResponse DTO로 변환
//         return new UserProfileResponse
//         {
//             UserId = profile.UserId,
//             Bio = profile.Bio,
//             Location = profile.Location,
//             ProfileImageUrl = profile.ProfileImageUrl,
//             PreferredLanguage = profile.PreferredLanguage,
//             TimeZone = profile.TimeZone,
//             WebsiteUrl = profile.WebsiteUrl,
//             // CompletionPercentage는 엔티티 속성이 아니므로 계산 필요 (또는 0으로 처리)
//             CompletionPercentage = CalculateCompletionPercentage(profile),
//             UpdatedAt = profile.UpdatedAt
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