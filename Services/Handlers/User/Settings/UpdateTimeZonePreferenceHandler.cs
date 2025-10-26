// File: AuthHive.Auth/Services/Handlers/User/Settings/UpdateTimeZonePreferenceHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// TimeZoneChangedEvent 발생 시 사용자 시간대 설정을 업데이트합니다.
// (예: 캐시 무효화 또는 DB 직접 업데이트)
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService (예시)
// using AuthHive.Core.Interfaces.User.Repository; // 필요 시 IUserProfileRepository 등 주입
using AuthHive.Core.Models.User.Events.Settings; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Settings
{
    /// <summary>
    /// (한글 주석) 사용자 시간대 설정 변경 시 관련 캐시 또는 데이터를 업데이트하는 핸들러입니다.
    /// </summary>
    public class UpdateTimeZonePreferenceHandler :
        IDomainEventHandler<TimeZoneChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService; // 캐시 업데이트 예시
        // private readonly IUserProfileRepository _profileRepository; // DB 업데이트 예시
        private readonly ILogger<UpdateTimeZonePreferenceHandler> _logger;
        private const string CACHE_KEY_PREFIX = "profile"; // 시간대는 보통 프로필의 일부

        // --- IDomainEventHandler 구현 ---
        public int Priority => 50;
        public bool IsEnabled => true;

        public UpdateTimeZonePreferenceHandler(
            ICacheService cacheService,
            // IUserProfileRepository profileRepository,
            ILogger<UpdateTimeZonePreferenceHandler> logger)
        {
            _cacheService = cacheService;
            // _profileRepository = profileRepository;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 시간대 변경 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(TimeZoneChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Updating time zone preference cache/data for User {UserId}. New TimeZone: {NewTimeZone}",
                    @event.UserId, @event.NewTimeZone);

                // (한글 주석) 방법 1: 관련 캐시 무효화 (예: 사용자 프로필 캐시)
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogDebug("Invalidated profile cache for User {UserId} due to time zone change.", @event.UserId);

                // (한글 주석) 방법 2: 캐시에 새 시간대 직접 업데이트 (캐시 구조가 허용한다면)
                // var profileData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken);
                // if (profileData != null)
                // {
                //     profileData["timezone"] = @event.NewTimeZone;
                //     await _cacheService.SetAsync(cacheKey, profileData, TimeSpan.FromMinutes(30), cancellationToken);
                // }

                // (한글 주석) 방법 3: Repository를 통해 DB에 직접 반영 (UserProfileService가 이미 처리했을 수 있음)
                // await _profileRepository.UpdateTimeZoneAsync(@event.UserId, @event.NewTimeZone, cancellationToken);

            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to process TimeZoneChangedEvent for User {UserId}, Event: {EventId}",
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("UpdateTimeZonePreferenceHandler initialized.");
             return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
             // (가정) _profileRepository는 직접 헬스 체크 불필요
        }
        #endregion
    }
}