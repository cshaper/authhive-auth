// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/UpdateProfileImageDeletionHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ProfileImageDeletedEvent를 처리하는 핸들러입니다.
// 목적: UserProfile 엔티티의 이미지 URL 필드를 null로 초기화합니다.
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
    /// <see cref="ProfileImageDeletedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// </summary>
    public class UpdateProfileImageDeletionHandler
        : IDomainEventHandler<ProfileImageDeletedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserProfileRepository _userProfileRepository;
        private readonly ILogger<UpdateProfileImageDeletionHandler> _logger;

        public UpdateProfileImageDeletionHandler(
            IUserProfileRepository userProfileRepository,
            ILogger<UpdateProfileImageDeletionHandler> logger)
        {
            this._userProfileRepository = userProfileRepository ?? throw new ArgumentNullException(nameof(userProfileRepository));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 이미지 삭제 이벤트를 처리하여 UserProfile의 URL을 초기화합니다.
        /// </summary>
        public async Task HandleAsync(ProfileImageDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Starting profile image URL deletion for UserId: {UserId} (Reason: {Reason})",
                    @event.UserId, @event.DeletionReason);

                // 1. 상태 업데이트 로직 호출
                // (가정) IUserProfileRepository에 이미지 URL을 null로 설정하는 메서드가 존재합니다.
                var updateResult = await _userProfileRepository.ClearImageUrlAsync(
                    @event.UserId, 
                    @event.DeletedByConnectedId, // 삭제를 수행한 ConnectedId
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (updateResult)
                {
                     _logger.LogInformation(
                        "UserProfile image URL successfully cleared. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to clear UserProfile image URL. (UserId: {UserId})",
                        @event.UserId);
                    throw new InvalidOperationException($"Failed to clear profile image URL for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Profile image URL deletion cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error clearing UserProfile image URL. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
