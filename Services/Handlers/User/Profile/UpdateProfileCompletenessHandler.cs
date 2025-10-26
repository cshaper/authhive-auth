// File: AuthHive.Auth/Services/Handlers/User/Profile/UpdateProfileCompletenessHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// ProfileCompletenessChangedEvent 발생 시 관련 데이터를 업데이트합니다.
// (예: 캐시 업데이트, 통계 업데이트 등)
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.User.Events.Profile; // The Event (가상 정의 사용)
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Profile
{
    /// <summary>
    /// (한글 주석) 프로필 완성도 변경 시 캐시 또는 관련 데이터를 업데이트하는 핸들러입니다.
    /// </summary>
    public class UpdateProfileCompletenessHandler :
        IDomainEventHandler<ProfileCompletenessChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<UpdateProfileCompletenessHandler> _logger;
        private const string CACHE_KEY_PREFIX = "profile";

        // --- IDomainEventHandler 구현 ---
        public int Priority => 50; // 비교적 낮은 우선순위
        public bool IsEnabled => true;

        public UpdateProfileCompletenessHandler(
            ICacheService cacheService,
            ILogger<UpdateProfileCompletenessHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 프로필 완성도 변경 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(ProfileCompletenessChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Updating profile completeness cache for User {UserId}. New: {NewPercentage}%",
                    @event.UserId, @event.NewPercentage);

                // (한글 주석) 예시: 완성도 정보를 캐시에 직접 저장 (이벤트에 정보가 있다면)
                if (@event.CurrentCompletenessInfo != null)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}:completeness:{@event.UserId:N}";
                    // (한글 주석) ProfileCompletenessInfo는 class이므로 SetAsync 사용 가능
                    await _cacheService.SetAsync(cacheKey, @event.CurrentCompletenessInfo, TimeSpan.FromHours(1), cancellationToken);
                }
                else
                {
                    // (한글 주석) 또는, 관련 캐시(예: 전체 프로필 캐시)를 무효화하여 다음 요청 시 다시 계산하도록 유도
                    var profileCacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                    await _cacheService.RemoveAsync(profileCacheKey, cancellationToken);
                    _logger.LogDebug("Invalidated profile cache for User {UserId} due to completeness change.", @event.UserId);
                }

                // (한글 주석) 추가 로직:
                // - 사용자 통계 업데이트 (예: 완성도 100% 달성 사용자 수 증가)
                // - 특정 완성도 도달 시 알림 발송 (IEventBus 사용)
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update profile completeness for User {UserId}, Event: {EventId}",
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("UpdateProfileCompletenessHandler initialized.");
             return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}