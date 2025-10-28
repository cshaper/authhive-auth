// File: AuthHive.Auth/Services/Handlers/OrganizationCore/PublishOrganizationStatusNotificationHandler.cs
using AuthHive.Core.Enums.Core; 
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ [수정] 이 네임스페이스로 통합
// using AuthHive.Core.Models.Notifications.Organization; // ❗️ [삭제] 잘못된 네임스페이스
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// [신규] 조직의 중대한 상태 변경(정지, 삭제) 시,
    /// IEventBus를 통해 외부 알림 시스템(이메일, SMS, 웹훅)으로 전파될
    /// 별도의 "알림용 이벤트"(Notification)를 발행(Publish)합니다.
    /// </summary>
    public class PublishOrganizationStatusNotificationHandler :
        IDomainEventHandler<OrganizationSuspendedEvent>,
        IDomainEventHandler<OrganizationDeletedEvent>,
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly ILogger<PublishOrganizationStatusNotificationHandler> _logger;

        public int Priority => 90; 
        public bool IsEnabled => true;

        public PublishOrganizationStatusNotificationHandler(
            IEventBus eventBus,
            ILogger<PublishOrganizationStatusNotificationHandler> logger)
        {
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 정지 시, OrganizationSuspendedNotificationEvent를 발행합니다.
        /// </summary>
        public async Task HandleAsync(OrganizationSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Publishing OrganizationSuspendedNotificationEvent for OrgId: {OrgId}", @event.AggregateId);

                // ❗️ 이제 OrganizationSuspendedNotificationEvent는
                // ❗️ AuthHive.Core.Models.Organization.Events 네임스페이스에 존재합니다.
                var notification = new OrganizationSuspendedNotificationEvent(
                    @event.AggregateId,
                    @event.Reason,
                    @event.PreviousStatus,
                    @event.TriggeredBy
                );

                await _eventBus.PublishAsync(notification, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish OrganizationSuspendedNotificationEvent for OrgId: {OrgId}", @event.AggregateId);
            }
        }

        /// <summary>
        /// 조직 삭제 시, OrganizationDeletedNotificationEvent를 발행합니다.
        /// </summary>
        public async Task HandleAsync(OrganizationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Publishing OrganizationDeletedNotificationEvent for OrgId: {OrgId}, IsSoft: {IsSoft}", @event.AggregateId, @event.IsSoftDelete);

                // ❗️ 이제 OrganizationDeletedNotificationEvent는
                // ❗️ AuthHive.Core.Models.Organization.Events 네임스페이스에 존재합니다.
                var notification = new OrganizationDeletedNotificationEvent(
                    @event.AggregateId,
                    @event.DeletionReason,
                    @event.IsSoftDelete,
                    @event.DeletedByConnectedId
                );
                
                await _eventBus.PublishAsync(notification, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish OrganizationDeletedNotificationEvent for OrgId: {OrgId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}