// File: AuthHive.Auth/Services/Handlers/User/Settings/UpdateNotificationSettingsHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// NotificationSettingsChangedEvent 발생 시 사용자 설정을 업데이트합니다.
// (예: 캐시 무효화 또는 DB 직접 업데이트)
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService (예시)
// using AuthHive.Core.Interfaces.User.Repository; // 필요 시 IUserNotificationSettingRepository 주입
using AuthHive.Core.Models.User.Events.Settings; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json; // JSON 처리
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Settings
{
    /// <summary>
    /// (한글 주석) 사용자 알림 설정 변경 시 관련 캐시 또는 데이터를 업데이트하는 핸들러입니다.
    /// </summary>
    public class UpdateNotificationSettingsHandler :
        IDomainEventHandler<NotificationSettingsChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService; // 캐시 업데이트 예시
        // private readonly IUserNotificationSettingRepository _settingRepository; // DB 업데이트 예시
        private readonly ILogger<UpdateNotificationSettingsHandler> _logger;
        private const string CACHE_KEY_PREFIX = "settings";

        // --- IDomainEventHandler 구현 ---
        public int Priority => 50;
        public bool IsEnabled => true;

        public UpdateNotificationSettingsHandler(
            ICacheService cacheService,
            // IUserNotificationSettingRepository settingRepository,
            ILogger<UpdateNotificationSettingsHandler> logger)
        {
            _cacheService = cacheService;
            // _settingRepository = settingRepository;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 알림 설정 변경 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(NotificationSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Updating notification settings cache/data for User {UserId}. Changed categories: {Categories}",
                    @event.UserId, string.Join(", ", @event.ChangedCategories));

                // (한글 주석) 방법 1: 관련 캐시 무효화 (가장 간단)
                var cacheKey = $"{CACHE_KEY_PREFIX}:notification:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogDebug("Invalidated notification settings cache for User {UserId}.", @event.UserId);

                // (한글 주석) 방법 2: 캐시에 새 설정 직접 업데이트 (이벤트에 새 설정 JSON이 있으므로 가능)
                // try
                // {
                //     // (가정) 캐시에는 Dictionary<string, bool> 형태로 저장한다고 가정
                //     var newSettingsDict = JsonSerializer.Deserialize<Dictionary<string, bool>>(@event.NewSettings);
                //     if (newSettingsDict != null)
                //     {
                //          await _cacheService.SetAsync(cacheKey, newSettingsDict, TimeSpan.FromDays(1), cancellationToken);
                //     }
                // }
                // catch (JsonException jsonEx)
                // {
                //      _logger.LogWarning(jsonEx, "Failed to deserialize NewSettings JSON for User {UserId}", @event.UserId);
                //      // JSON 파싱 실패 시 캐시 삭제로 fallback
                //      await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                // }


                // (한글 주석) 방법 3: Repository를 통해 DB에 직접 반영 (필요 시)
                // await _settingRepository.UpdateSettingsAsync(@event.UserId, @event.NewSettings, cancellationToken);

            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to process NotificationSettingsChangedEvent for User {UserId}, Event: {EventId}",
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("UpdateNotificationSettingsHandler initialized.");
             return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (가정) _cacheService는 IHealthCheckable 구현
             return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
             // (가정) _settingRepository는 직접 헬스 체크 불필요 (UoW 통해 관리)
        }
        #endregion
    }
}