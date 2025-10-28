// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/DeactivateExposedApiKeyHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyExposureEvent, ApplicationApiKeyDeactivatedEvent
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// API 키 노출 감지 시 해당 키를 자동으로 비활성화합니다.
    /// ApplicationApiKeyDeactivatedEvent를 발행하여 후속 조치를 트리거합니다.
    /// </summary>
    public class DeactivateExposedApiKeyHandler :
        IDomainEventHandler<ApplicationApiKeyExposureEvent>, // ❗️ 이름 변경된 이벤트
        IService
    {
        private readonly IEventBus _eventBus; 
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<DeactivateExposedApiKeyHandler> _logger;

        public int Priority => 10; // 감사 로그(1), 알림(5) 이후 수행
        public bool IsEnabled => true;

        public DeactivateExposedApiKeyHandler(
            IEventBus eventBus,
            IDateTimeProvider dateTimeProvider,
            ILogger<DeactivateExposedApiKeyHandler> logger)
        {
            _eventBus = eventBus;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyExposureEvent @event, CancellationToken cancellationToken = default) // ❗️ 이름 변경된 이벤트
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;

            if (applicationId == Guid.Empty)
            {
                 _logger.LogError("Cannot deactivate exposed API Key {ApiKeyId}: ApplicationId is missing.", apiKeyId);
                 return; // ApplicationId 없이는 비활성화 이벤트를 발행할 수 없음
            }

            try
            {
                _logger.LogWarning("Automatically deactivating exposed API Key {ApiKeyId} for AppId {AppId} due to exposure at {Location}",
                    apiKeyId, applicationId, @event.ExposureLocation);

                // 비활성화 이벤트 생성
                var deactivationEvent = new ApplicationApiKeyDeactivatedEvent(
                    apiKeyId: apiKeyId,
                    applicationId: applicationId,
                    organizationId: @event.OrganizationId ?? Guid.Empty, 
                    deactivatedByConnectedId: Guid.Empty, // 시스템 작업
                    deactivatedAt: _dateTimeProvider.UtcNow,
                    reason: $"Automatically deactivated due to exposure detected in {@event.ExposureLocation}"
                );

                // ❗️ [수정] CS1061 오류 수정: 메서드 호출이 아닌 속성 할당
                deactivationEvent.CorrelationId = @event.CorrelationId;
                deactivationEvent.CausationId = @event.EventId;

                // 비활성화 이벤트 발행
                await _eventBus.PublishAsync(deactivationEvent, cancellationToken);

                _logger.LogInformation("Published ApplicationApiKeyDeactivatedEvent for exposed key {ApiKeyId}", apiKeyId);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "CRITICAL FAILURE: Failed to automatically deactivate exposed API Key {ApiKeyId}", apiKeyId);
                // 이 핸들러의 실패는 매우 중요하므로 상위 레벨의 알림/모니터링 필요
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}