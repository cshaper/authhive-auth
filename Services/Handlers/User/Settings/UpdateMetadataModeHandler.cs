// File: AuthHive.Auth/Services/Handlers/User/Settings/UpdateMetadataModeHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// MetadataModeChangedEvent 발생 시 관련 캐시 무효화 등 후속 처리를 수행합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.User.Events.Settings; // The Event (가상 정의 사용)
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Settings
{
    /// <summary>
    /// (한글 주석) 사용자 메타데이터 모드 변경 시 관련 캐시를 무효화하는 핸들러입니다.
    /// </summary>
    public class UpdateMetadataModeHandler :
        IDomainEventHandler<MetadataModeChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<UpdateMetadataModeHandler> _logger;
        // (한글 주석) 메타데이터 모드가 프로필 정보에 영향을 준다면 관련 캐시 키 사용
        private const string PROFILE_CACHE_PREFIX = "profile";
        // (한글 주석) 또는 별도의 설정 캐시 키 사용
        // private const string SETTINGS_CACHE_PREFIX = "settings";

        // --- IDomainEventHandler 구현 ---
        public int Priority => 50;
        public bool IsEnabled => true;

        public UpdateMetadataModeHandler(
            ICacheService cacheService,
            ILogger<UpdateMetadataModeHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 메타데이터 모드 변경 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(MetadataModeChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing MetadataModeChanged event for User {UserId}. Mode: {OldMode} -> {NewMode}",
                    @event.UserId, @event.OldMode, @event.NewMode);

                // (한글 주석) 메타데이터 모드 변경은 사용자 프로필 표시 방식 등에 영향을 줄 수 있으므로,
                // 관련 캐시(예: 사용자 프로필 캐시)를 무효화하는 것이 일반적입니다.
                var cacheKey = $"{PROFILE_CACHE_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogDebug("Invalidated profile cache for User {UserId} due to metadata mode change.", @event.UserId);

                // (한글 주석) 추가 로직:
                // - 만약 모드 변경에 따라 DB 데이터를 즉시 업데이트해야 한다면 Repository 호출
                // - 특정 모드 활성화/비활성화 시 다른 시스템에 알림 (IEventBus 사용)

            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to process MetadataModeChangedEvent for User {UserId}, Event: {EventId}",
                    @event.UserId, @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("UpdateMetadataModeHandler initialized.");
             return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}