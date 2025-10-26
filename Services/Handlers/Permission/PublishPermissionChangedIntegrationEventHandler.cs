// File: AuthHive.Auth/Services/Handlers/Permission/PublishPermissionChangedIntegrationEventHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // 권한 이벤트들
using AuthHive.Core.Models.Infra.Events.Permissions; // PermissionChangedIntegrationEvent
using Microsoft.Extensions.Logging;
using System;
using System.Linq; // For Select
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 변경 관련 도메인 이벤트를 구독하여 표준 통합 이벤트(PermissionChangedIntegrationEvent)를 발행합니다.
    /// (Granted, Revoked, Expired, Delegated, Inherited, Modified 이벤트 구독)
    /// </summary>
    public class PublishPermissionChangedIntegrationEventHandler :
        IDomainEventHandler<PermissionGrantedEvent>,
        IDomainEventHandler<PermissionRevokedEvent>,     // (추후 추가될 이벤트)
        IDomainEventHandler<PermissionExpiredEvent>,     // (추후 추가될 이벤트)
        IDomainEventHandler<PermissionDelegatedEvent>,   // (추후 추가될 이벤트)
        IDomainEventHandler<PermissionInheritedEvent>,   // (추후 추가될 이벤트)
        IDomainEventHandler<PermissionModifiedEvent>,    // (추후 추가될 이벤트)
        // Role 관련 이벤트도 구독하여 변환 가능
        IService
    {
        private readonly IEventBus _eventBus;
        private readonly ILogger<PublishPermissionChangedIntegrationEventHandler> _logger;

        // 통합 이벤트 발행은 다른 내부 처리(감사, 캐시) 이후 가장 마지막에 수행 (예: 50)
        public int Priority => 50;
        public bool IsEnabled => true;

        public PublishPermissionChangedIntegrationEventHandler(
            IEventBus eventBus,
            ILogger<PublishPermissionChangedIntegrationEventHandler> logger)
        {
            _eventBus = eventBus;
            _logger = logger;
        }

        // --- PermissionGrantedEvent 처리 ---
        public async Task HandleAsync(PermissionGrantedEvent @event, CancellationToken cancellationToken = default)
        {
            // UserId 또는 ConnectedId 중 무엇을 IntegrationEvent의 UserId로 사용할지 결정 필요 (UserId 사용 가정)
            // TriggeredBy도 UserId 인지 ConnectedId 인지 확인 필요 (UserId 가정)
            var integrationEvent = new PermissionChangedIntegrationEvent(
                changeType: "GRANTED",
                userId: @event.UserId,
                permissionScope: @event.PermissionScope,
                triggeredByUserId: @event.GrantedByUserId,
                reason: @event.Reason,
                expiresAt: @event.ExpiresAt
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
        }

        // --- PermissionRevokedEvent 처리 ---
        public async Task HandleAsync(PermissionRevokedEvent @event, CancellationToken cancellationToken = default)
        {
            var integrationEvent = new PermissionChangedIntegrationEvent(
                changeType: "REVOKED",
                userId: @event.UserId,
                permissionScope: @event.PermissionScope,
                triggeredByUserId: @event.RevokedByUserId,
                reason: @event.Reason
                // Revoked 이벤트에는 ExpiresAt이 없을 수 있음
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
        }

        // --- PermissionExpiredEvent 처리 ---
        public async Task HandleAsync(PermissionExpiredEvent @event, CancellationToken cancellationToken = default)
        {
            // 만료된 각 권한에 대해 이벤트 발행
            if (@event.ExpiredPermissions != null)
            {
                foreach(var scope in @event.ExpiredPermissions)
                {
                    var integrationEvent = new PermissionChangedIntegrationEvent(
                        changeType: "EXPIRED",
                        userId: @event.UserId,
                        permissionScope: scope,
                        triggeredByUserId: Guid.Empty, // 시스템에 의한 만료
                        reason: $"Permission expired due to {@event.ExpirationType}"
                    );
                    await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
                }
            }
        }

        // --- PermissionDelegatedEvent 처리 ---
        public async Task HandleAsync(PermissionDelegatedEvent @event, CancellationToken cancellationToken = default)
        {
            // 위임된 각 권한에 대해 이벤트 발행
             if (@event.DelegatedPermissions != null)
            {
                foreach(var scope in @event.DelegatedPermissions)
                {
                    var integrationEvent = new PermissionChangedIntegrationEvent(
                        changeType: "DELEGATED",
                        userId: @event.DelegateUserId, // 위임 받은 사람이 주체
                        permissionScope: scope,
                        triggeredByUserId: @event.DelegatorUserId,
                        reason: @event.Reason ?? $"Delegated by {@event.DelegatorUserId}",
                        expiresAt: @event.ExpiresAt
                    );
                    await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
                }
            }
        }

        // --- PermissionInheritedEvent 처리 ---
        public async Task HandleAsync(PermissionInheritedEvent @event, CancellationToken cancellationToken = default)
        {
             var integrationEvent = new PermissionChangedIntegrationEvent(
                changeType: "INHERITED",
                userId: @event.UserId,
                permissionScope: @event.PermissionScope,
                triggeredByUserId: Guid.Empty, // 상속은 시스템 규칙
                reason: $"Inherited from {@event.InheritanceType}: {@event.InheritedFromName}"
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
        }

        // --- PermissionModifiedEvent 처리 ---
        public async Task HandleAsync(PermissionModifiedEvent @event, CancellationToken cancellationToken = default)
        {
             var integrationEvent = new PermissionChangedIntegrationEvent(
                changeType: "DEFINITION_MODIFIED",
                userId: Guid.Empty, // 특정 사용자가 아닌 정의 변경
                permissionScope: @event.PermissionScope,
                triggeredByUserId: @event.ModifiedByUserId,
                reason: @event.Reason // 변경 내용은 Metadata로 전달될 수 있음
            );
            await PublishIntegrationEventAsync(integrationEvent, cancellationToken);
        }

        // --- (추가 필요) Role 관련 이벤트 처리 ---
        // ...

        /// <summary>
        /// 통합 이벤트를 Event Bus에 발행하는 내부 로직
        /// </summary>
        private async Task PublishIntegrationEventAsync(PermissionChangedIntegrationEvent integrationEvent, CancellationToken cancellationToken)
        {
            try
            {
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);
                _logger.LogInformation(
                    "Published {EventType} for User {UserId}, Scope {Scope}",
                    integrationEvent.ChangeType, integrationEvent.UserId, integrationEvent.PermissionScope);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Publishing integration event for User {UserId} was canceled.", integrationEvent.UserId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish PermissionChangedIntegrationEvent for User {UserId}, Scope {Scope}",
                    integrationEvent.UserId, integrationEvent.PermissionScope);
                // 발행 실패 시 재시도 로직은 Event Bus 구현에 따라 달라짐
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}