// File: AuthHive.Auth/Services/Handlers/ApplicationCore/PublishInsufficientPointsAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // InsufficientPointsEvent
using AuthHive.Core.Models.Business.Commerce.Points.Events; // InsufficientPointsAlert
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 포인트 부족 시, 관련 알림 이벤트를 발행(Publish)합니다.
    /// (ApplicationEventHandler 로직 분리)
    /// </summary>
    public class PublishInsufficientPointsAlertHandler :
        IDomainEventHandler<InsufficientPointsEvent>,
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly ILogger<PublishInsufficientPointsAlertHandler> _logger;

        public int Priority => 30; // 캐시(20) 이후 수행
        public bool IsEnabled => true;

        public PublishInsufficientPointsAlertHandler(
            IEventBus eventBus,
            ILogger<PublishInsufficientPointsAlertHandler> logger)
        {
            _eventBus = eventBus;
            _logger = logger;
        }

        public async Task HandleAsync(InsufficientPointsEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            try
            {
                // 알림 이벤트 생성
                var alertEvent = new InsufficientPointsAlert(
                    applicationId: applicationId,
                    connectedId: @event.ConnectedId,
                    requiredPoints: @event.RequiredPoints,
                    availablePoints: @event.AvailablePoints,
                    apiEndpoint: @event.ApiEndpoint,
                    alertLevel: "CRITICAL", // ❗️ Critical로 설정
                    correlationId: @event.CorrelationId,
                    causationId: @event.EventId
                );
                
                await _eventBus.PublishAsync(alertEvent, cancellationToken);
                _logger.LogCritical("Published InsufficientPointsAlert for AppId {AppId}, UserContext {ConnectedId}", applicationId, @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish InsufficientPointsAlert for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}