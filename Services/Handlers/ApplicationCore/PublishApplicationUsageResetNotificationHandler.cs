// File: AuthHive.Auth/Services/Handlers/ApplicationCore/PublishApplicationUsageResetNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Models.PlatformApplication.Events; // UsageResetEvent, UsageResetNotification
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 사용량 초기화 시, 관련 알림 이벤트를 발행(Publish)합니다.
    /// (이전 이름: PublishUsageResetNotificationHandler)
    /// </summary>
    public class PublishApplicationUsageResetNotificationHandler : // ❗️ 이름 수정
        IDomainEventHandler<UsageResetEvent>,
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<PublishApplicationUsageResetNotificationHandler> _logger; // ❗️ 이름 수정

        public int Priority => 30; // 캐시(20) 이후 수행
        public bool IsEnabled => true;

        public PublishApplicationUsageResetNotificationHandler( // ❗️ 이름 수정
            IEventBus eventBus,
            IDateTimeProvider dateTimeProvider,
            ILogger<PublishApplicationUsageResetNotificationHandler> logger) // ❗️ 이름 수정
        {
            _eventBus = eventBus;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task HandleAsync(UsageResetEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            try
            {
                var nextResetDate = CalculateNextResetDate(@event.ResetType);

                // 알림 이벤트 생성 (UsageResetNotification는 정의된 클래스라고 가정)
                var notificationEvent = new UsageResetNotification(
                    applicationId: applicationId,
                    resetType: @event.ResetType,
                    nextResetDate: nextResetDate,
                    correlationId: @event.CorrelationId,
                    causationId: @event.EventId
                );
                
                await _eventBus.PublishAsync(notificationEvent, cancellationToken);
                _logger.LogInformation("Published UsageResetNotification for AppId {AppId}", applicationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish UsageResetNotification for AppId: {AppId}", applicationId);
            }
        }

        // 헬퍼 메서드 (기존 ApplicationEventHandler 로직)
        private DateTime CalculateNextResetDate(string resetType)
        {
            var now = _dateTimeProvider.UtcNow.Date;
            return resetType.ToLowerInvariant() switch
            {
                "daily" => now.AddDays(1),
                "weekly" => now.AddDays(7 - (int)now.DayOfWeek % 7), // 일요일(0) 기준
                "monthly" => new DateTime(now.Year, now.Month, 1).AddMonths(1),
                _ => now.AddDays(1) // 기본값
            };
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}