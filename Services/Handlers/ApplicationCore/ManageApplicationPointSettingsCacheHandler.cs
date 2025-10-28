// File: AuthHive.Auth/Services/Handlers/ApplicationCore/ManageApplicationPointSettingsCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationPointSettingsChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // Dictionary
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 포인트 설정 변경 시, 관련 캐시를 업데이트합니다.
    /// (ApplicationEventHandler의 UpdatePointSettingsCacheAsync 로직 분리)
    /// </summary>
    public class ManageApplicationPointSettingsCacheHandler :
        IDomainEventHandler<ApplicationPointSettingsChangedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageApplicationPointSettingsCacheHandler> _logger;

        // 캐시 키 (기존 핸들러 참조)
        private const string POINT_SETTINGS_CACHE_KEY_FORMAT = "app:{0}:points:settings";
        private static readonly TimeSpan PointSettingsCacheTTL = TimeSpan.FromHours(12); // 예: 12시간

        public int Priority => 20; // 감사 로그(10) 이후 수행
        public bool IsEnabled => true;

        public ManageApplicationPointSettingsCacheHandler(
            ICacheService cacheService,
            ILogger<ManageApplicationPointSettingsCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationPointSettingsChangedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId;
            var cacheKey = string.Format(POINT_SETTINGS_CACHE_KEY_FORMAT, applicationId);

            try
            {
                _logger.LogInformation(
                    "Updating point settings cache for AppId: {AppId}, NewRate: {NewRate}",
                    applicationId, @event.NewPointsPerApiCall);

                // 캐시에 저장할 새 설정 객체 (기존 핸들러 로직)
                var settings = new Dictionary<string, object>
                {
                    ["UsePointsForApiCalls"] = @event.NewUsePointsForApiCalls,
                    ["PointsPerApiCall"] = @event.NewPointsPerApiCall,
                    ["UpdatedAt"] = @event.OccurredAt // 이벤트 발생 시간
                };

                // ❗️ 새 설정 값을 캐시에 덮어쓰기
                await _cacheService.SetAsync(cacheKey, settings, PointSettingsCacheTTL, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Updating point settings cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update point settings cache for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}