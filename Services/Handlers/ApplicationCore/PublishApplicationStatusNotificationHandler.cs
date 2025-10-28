// File: AuthHive.Auth/Services/Handlers/ApplicationCore/PublishApplicationStatusNotificationHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // 관련 이벤트들
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 상태 변경(삭제 포함) 시, 후속 알림 이벤트를 발행(Publish)합니다.
    /// (ApplicationEventHandler의 ProcessStatusChangeAsync 로직 및 삭제 로직 분리)
    /// </summary>
    public class PublishApplicationStatusNotificationHandler :
        IDomainEventHandler<ApplicationDeletedEvent>,
        IDomainEventHandler<ApplicationStatusChangedEvent>, // (추후 처리)
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly ILogger<PublishApplicationStatusNotificationHandler> _logger;

        public int Priority => 30; // 캐시 정리(20) 이후 수행
        public bool IsEnabled => true;

        public PublishApplicationStatusNotificationHandler(
            IEventBus eventBus,
            ILogger<PublishApplicationStatusNotificationHandler> logger)
        {
            _eventBus = eventBus;
            _logger = logger;
        }

        // --- ApplicationDeletedEvent 처리 ---
        public async Task HandleAsync(ApplicationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            // ❗️ SoftDelete인 경우에만 Deactivated 알림 발행 (기존 로직)
            if (@event.IsSoftDelete)
            {
                _logger.LogInformation("Application {AppId} was soft-deleted. Publishing ApplicationDeactivatedNotification.", @event.AggregateId);
                try
                {
                    // ❗️ [수정] CS1739 오류 수정: 'reason' 파라미터 제거
                    var notificationEvent = new ApplicationDeactivatedNotification(
                        applicationId: @event.AggregateId,
                        deactivatedAt: @event.DeletedAt,
                        // reason: "Application deleted (soft delete)", // <-- 삭제
                        correlationId: @event.CorrelationId,
                        causationId: @event.EventId
                    );

                    // ❗️ [수정] (선택적) Reason은 Metadata에 추가
                    notificationEvent.AddContext("Reason", "Application deleted (soft delete)");
                    
                    await _eventBus.PublishAsync(notificationEvent, cancellationToken);
                }
                catch (Exception ex)
                {
                     _logger.LogError(ex, "Failed to publish ApplicationDeactivatedNotification for AppId: {AppId}", @event.AggregateId);
                }
            }
        }

        // --- ApplicationStatusChangedEvent 처리 ---
        public async Task HandleAsync(ApplicationStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 상태 변경 로직 (기존 ApplicationEventHandler 로직)
                switch (@event.NewStatus)
                {
                    case ApplicationStatus.Suspended:
                        var suspendedEvent = new ApplicationSuspendedNotification(
                            @event.AggregateId,
                            @event.ChangedAt,
                            @event.Reason,
                            @event.CorrelationId,
                            @event.EventId
                        );
                        await _eventBus.PublishAsync(suspendedEvent, cancellationToken);
                        _logger.LogInformation("Published ApplicationSuspendedNotification for AppId={ApplicationId}", @event.AggregateId);
                        break;

                    case ApplicationStatus.Active:
                        if (@event.OldStatus != ApplicationStatus.Active)
                        {
                            var activatedEvent = new ApplicationActivatedNotification(
                                @event.AggregateId,
                                @event.ChangedAt,
                                @event.CorrelationId,
                                @event.EventId
                            );
                            await _eventBus.PublishAsync(activatedEvent, cancellationToken);
                            _logger.LogInformation("Published ApplicationActivatedNotification for AppId={ApplicationId}", @event.AggregateId);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish status notification for AppId: {AppId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}