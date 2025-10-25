// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/UpdateProfileImageUrlHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ProfileImageUploadedEvent를 처리하는 핸들러입니다.
// 목적: UserProfile 엔티티에 새 프로필 이미지 URL을 업데이트합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Profile; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserProfileRepository (가정)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Profile
{
    /// <summary>
    /// <see cref="ProfileImageUploadedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// </summary>
    public class UpdateProfileImageUrlHandler
        : IDomainEventHandler<ProfileImageUploadedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserProfileRepository _userProfileRepository;
        private readonly ILogger<UpdateProfileImageUrlHandler> _logger;

        public UpdateProfileImageUrlHandler(
            IUserProfileRepository userProfileRepository,
            ILogger<UpdateProfileImageUrlHandler> logger)
        {
            this._userProfileRepository = userProfileRepository ?? throw new ArgumentNullException(nameof(userProfileRepository));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 이미지 업로드 이벤트를 처리하여 UserProfile의 URL을 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(ProfileImageUploadedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    // (수정) @event.ProfileImageUrl 대신 @event.NewImageUrl 사용
                    "Starting profile image URL update for UserId: {UserId}. New URL: {Url}",
                    @event.UserId, @event.NewImageUrl);

                // 1. 상태 업데이트 로직 호출
                // (IUserProfileRepository는 UserId를 PK로 사용한다고 가정하고 호출합니다.)
                var updateResult = await _userProfileRepository.UpdateImageUrlAsync(
                    @event.UserId, // UserId를 기준으로 업데이트
                    @event.NewImageUrl, // NewImageUrl 사용
                    @event.UploadedByConnectedId, // 업데이트 수행 ConnectedId
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (updateResult) // UpdateImageUrlAsync가 bool을 반환한다고 가정
                {
                     _logger.LogInformation(
                        "UserProfile image URL successfully updated. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to update UserProfile image URL. (UserId: {UserId})",
                        @event.UserId);
                    throw new InvalidOperationException($"Failed to update profile image URL for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Profile image URL update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating UserProfile image URL. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
