// File: AuthHive.Auth/Services/Handlers/Role/PublishRoleChangedIntegrationEventHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleChangedEvent, RoleAssignedEvent, RoleRemovedEvent
using AuthHive.Core.Models.Common; // BaseEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 역할 변경 관련 도메인 이벤트를 구독하여 표준 통합 이벤트(RoleChangedIntegrationEvent)를 발행합니다.
    /// </summary>
    public class PublishRoleChangedIntegrationEventHandler :
        IDomainEventHandler<RoleChangedEvent>,
        IDomainEventHandler<RoleAssignedEvent>, // ❗️ [수정] 인터페이스 추가
        IDomainEventHandler<RoleRemovedEvent>,  // (추후 추가될 이벤트)
        // ... (다른 Role 이벤트 인터페이스들) ...
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly ILogger<PublishRoleChangedIntegrationEventHandler> _logger;

        public int Priority => 50; // 통합 이벤트 발행은 다른 내부 처리 이후 가장 마지막에 수행
        public bool IsEnabled => true;

        public PublishRoleChangedIntegrationEventHandler(IEventBus eventBus, ILogger<PublishRoleChangedIntegrationEventHandler> logger)
        {
            _eventBus = eventBus;
            _logger = logger;
        }

        // --- RoleAssignedEvent 처리 (CS0535 오류 해결) ---
        public async Task HandleAsync(RoleAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            // 역할 할당 이벤트 정보를 RoleChangedIntegrationEvent로 변환하여 발행합니다.
            var integrationEvent = new RoleChangedIntegrationEvent(
                connectedId: @event.ConnectedId,
                organizationId: @event.OrganizationId,
                changeType: "ASSIGNED", // 할당 타입 명시
                oldRoleId: Guid.Empty, // 할당 시점에는 이전 역할 정보 없음
                newRoleId: @event.RoleId,
                triggeredBy: @event.AssignedByUserId
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
             _logger.LogInformation("Published RoleChangedIntegrationEvent (ASSIGNED) for ConnectedId {ConnectedId}", @event.ConnectedId);
        }

        // --- RoleRemovedEvent 처리 (추후 구현 예정) ---
        public async Task HandleAsync(RoleRemovedEvent @event, CancellationToken cancellationToken = default)
        {
            // 역할 제거 이벤트를 통합 이벤트로 변환하여 발행합니다.
            var integrationEvent = new RoleChangedIntegrationEvent(
                connectedId: @event.ConnectedId,
                organizationId: @event.OrganizationId,
                changeType: "REMOVED",
                oldRoleId: @event.RoleId, // 제거되는 역할이 OldRoleId
                newRoleId: Guid.Empty, // 새로운 역할 없음
                triggeredBy: @event.RemovedByUserId // (가정: 이벤트 모델에 RemovedByUserId가 있음)
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
             _logger.LogInformation("Published RoleChangedIntegrationEvent (REMOVED) for ConnectedId {ConnectedId}", @event.ConnectedId);
        }


        // --- RoleChangedEvent 처리 ---
        public async Task HandleAsync(RoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // 사용자에게 할당된 역할이 변경되었을 때 (OldRole -> NewRole)
            var integrationEvent = new RoleChangedIntegrationEvent(
                connectedId: @event.AggregateId,
                organizationId: @event.OrganizationId,
                changeType: "ASSIGNMENT_CHANGED",
                oldRoleId: @event.OldRoleId,
                newRoleId: @event.NewRoleId,
                triggeredBy: @event.ChangedByUserId
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
             _logger.LogInformation("Published RoleChangedIntegrationEvent (ASSIGNMENT_CHANGED) for ConnectedId {ConnectedId}", @event.AggregateId);
        }

        // ... (다른 Role 이벤트 핸들러들 추가 예정) ...

        /// <summary>
        /// 통합 이벤트를 Event Bus에 발행하는 내부 로직
        /// </summary>
        private async Task PublishIntegrationEventAsync(RoleChangedIntegrationEvent integrationEvent, CancellationToken cancellationToken)
        {
            try
            {
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);
                _logger.LogInformation(
                    "Published RoleChangedIntegrationEvent ({ChangeType}) for ConnectedId {ConnectedId}",
                    integrationEvent.ChangeType, integrationEvent.ConnectedId);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Publishing integration event for ConnectedId {ConnectedId} was canceled.", integrationEvent.ConnectedId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish RoleChangedIntegrationEvent for ConnectedId {ConnectedId}", integrationEvent.ConnectedId);
                // 발행 실패는 로깅만 하고 계속 진행
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}