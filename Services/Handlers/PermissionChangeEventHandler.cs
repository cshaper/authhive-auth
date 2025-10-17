// AuthHive.Auth.Services.Handlers.PermissionChangeEventHandler.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // ✅ FIX: Newtonsoft.Json 대신 System.Text.Json 사용
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ✅ FIX: ICacheService 인터페이스 사용
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Auth.Permissions.Events;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Infra.Events.Permissions;


namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 권한 변경 이벤트 핸들러 구현체 - AuthHive v16 최종본
    /// 권한 관련 핵심 변경사항(감사, 캐시 무효화)을 트랜잭션으로 처리하고,
    /// IEventBus를 통해 관련 시스템에 이벤트를 전파하여 후속 조치(알림, 보안 분석 등)를 위임합니다.
    /// </summary>
    public class PermissionChangeEventHandler : IPermissionChangeEventHandler
    {
        #region Fields

        private readonly ILogger<PermissionChangeEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IPermissionService _permissionService;
        private readonly ICacheService _cacheService; // ✅ FIX: IMemoryCache, IDistributedCache 대신 통합 ICacheService 주입
        private readonly IEventBus _eventBus; // ✅ FIX: 알림, 보안 이벤트 등 후속 처리를 위한 이벤트 버스 주입
        private readonly IUnitOfWork _unitOfWork;

        #endregion

        #region Constructor

        public PermissionChangeEventHandler(
            ILogger<PermissionChangeEventHandler> logger,
            IAuditService auditService,
            IPermissionService permissionService,
            ICacheService cacheService,
            IEventBus eventBus,
            IUnitOfWork unitOfWork)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _permissionService = permissionService ?? throw new ArgumentNullException(nameof(permissionService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        }

        #endregion

        #region IPermissionChangeEventHandler Implementation

        /// <summary>
        /// 권한 만료 이벤트를 처리합니다.
        /// 트랜잭션 내에서 만료된 각 권한의 캐시를 무효화하고, 감사 로그를 기록한 후,
        /// 통합 이벤트를 발행하여 후속 조치를 위임합니다.
        /// </summary>
        public async Task HandlePermissionExpiredAsync(PermissionExpiredEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionExpiredEvent.");
                return;
            }

            if (eventData.ExpiredPermissions == null || !eventData.ExpiredPermissions.Any())
            {
                _logger.LogWarning("PermissionExpiredEvent for User {UserId} contained no expired permissions.", eventData.UserId);
                return;
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Processing PermissionExpiredEvent for User {UserId}, GrantId {GrantId}", eventData.UserId, eventData.AggregateId);

                // 1. 만료된 모든 권한에 대한 캐시 무효화
                var invalidationTasks = eventData.ExpiredPermissions
                    .Select(scope => InvalidatePermissionCacheAsync(eventData.UserId, scope, cancellationToken));
                await Task.WhenAll(invalidationTasks);

                // 2. 감사 로그 기록 (✅ FIX: eventData의 실제 속성 사용)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 시스템에 의한 자동 상태 변경
                    action: $"Permission(s) expired for user",
                    // 만료는 시스템(TriggeredBy = null) 또는 수동으로 발생할 수 있음
                    connectedId: eventData.TriggeredBy ?? eventData.UserId,
                    success: true,
                    resourceType: "PermissionGrant",
                    resourceId: eventData.AggregateId.ToString(), // 만료된 권한 부여(Grant)가 이벤트의 주체
                    metadata: new Dictionary<string, object>
                    {
                { "TargetUserId", eventData.UserId },
                { "ExpiredPermissions", eventData.ExpiredPermissions },
                { "ExpirationType", eventData.ExpirationType.ToString() },
                { "OriginallyGrantedBy", eventData.OriginallyGrantedBy }
                    },
                    cancellationToken: cancellationToken);

                // 3. 만료된 각 권한에 대해 별도의 통합 이벤트 발행
                var eventTasks = eventData.ExpiredPermissions.Select(scope =>
                {
                    var integrationEvent = new PermissionChangedIntegrationEvent(
                        changeType: "EXPIRED",
                        userId: eventData.UserId,
                        permissionScope: scope,
                        triggeredByUserId: eventData.TriggeredBy ?? Guid.Empty, // 시스템에 의해 발생했음을 의미
                        reason: $"Permission has expired ({eventData.ExpirationType})."
                    );
                    return _eventBus.PublishAsync(integrationEvent, cancellationToken);
                });
                await Task.WhenAll(eventTasks);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully processed PermissionExpiredEvent for User {UserId}", eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionExpiredEvent for User {UserId}", eventData.UserId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }

        /// <summary>
        /// 권한 부여 이벤트를 처리합니다.
        /// 감사 로그 기록 및 캐시 무효화를 수행한 후, 통합 이벤트를 발행합니다.
        /// </summary>
        public async Task HandlePermissionGrantedAsync(PermissionGrantedEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionGrantedEvent.");
                return;
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken); // ✅ FIX: 트랜잭션 시작
            try
            {
                _logger.LogInformation("Processing PermissionGrantedEvent for User {UserId}, Scope {Scope}", eventData.UserId, eventData.PermissionScope);

                // 1. 캐시 무효화
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope, cancellationToken);

                // 2. 감사 로그 생성 (이 핸들러의 핵심 책임)
                var permissionResult = await _permissionService.GetByScopeAsync(eventData.PermissionScope, cancellationToken);
                var permissionName = permissionResult.IsSuccess ? permissionResult.Data?.Name : eventData.PermissionScope;

                // 2. 감사 로그 생성 (✅ FIX: 명명된 인수를 사용하여 올바르게 호출)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: $"Granted permission '{permissionName}' to user",
                    connectedId: eventData.GrantedByUserId, // 감사 로그를 기록하는 주체
                    success: true,
                    resourceType: "Permission",
                    resourceId: eventData.PermissionScope,
                    metadata: new Dictionary<string, object>
                    {
                        { "TargetUserId", eventData.UserId },
                        { "ConnectedId", eventData.ConnectedId ?? Guid.Empty },
                        { "PermissionScope", eventData.PermissionScope },
                        { "PermissionName", permissionName ?? "N/A"},
                        { "ExpiresAt", eventData.ExpiresAt?.ToString("o") ?? "Never" },
                        { "Reason", eventData.Reason ?? "N/A" }
                    },
                    cancellationToken: cancellationToken);

                // 3. FIX: IEventBus를 통해 통합 이벤트 발행 (알림, 보안 분석 등 후속 처리는 다른 핸들러에 위임)
                var integrationEvent = new PermissionChangedIntegrationEvent(
                  changeType: "GRANTED", // ✅ FIX: 'C'를 소문자 'c'로 수정
                  userId: eventData.UserId,
                  permissionScope: eventData.PermissionScope,
                  triggeredByUserId: eventData.GrantedByUserId,
                  reason: eventData.Reason,
                  expiresAt: eventData.ExpiresAt
              );
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken); // ✅ FIX: 트랜잭션 커밋
                _logger.LogInformation("Successfully processed PermissionGrantedEvent for User {UserId}", eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionGrantedEvent for User {UserId}", eventData.UserId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken); // ✅ FIX: 오류 발생 시 롤백
                throw;
            }
        }

        /// <summary>
        /// 권한 취소 이벤트를 처리합니다.
        /// </summary>
        public async Task HandlePermissionRevokedAsync(PermissionRevokedEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionRevokedEvent.");
                return;
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Processing PermissionRevokedEvent for User {UserId}, Scope {Scope}", eventData.UserId, eventData.PermissionScope);

                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope, cancellationToken);

                var permissionResult = await _permissionService.GetByScopeAsync(eventData.PermissionScope, cancellationToken);
                var permissionName = permissionResult.IsSuccess ? permissionResult.Data?.Name : eventData.PermissionScope;

                // 3. 감사 로그 (✅ FIX: 명명된 인수를 사용하여 올바르게 호출)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: $"Revoked permission '{permissionName}' from user",
                    connectedId: eventData.RevokedByUserId, // 작업을 수행한 주체
                    success: true,
                    resourceType: "Permission",
                    resourceId: eventData.PermissionScope,
                    metadata: new Dictionary<string, object>
                    {
                        { "TargetUserId", eventData.UserId },
                        { "ConnectedId", eventData.ConnectedId ?? Guid.Empty },
                        { "PermissionScope", eventData.PermissionScope },
                        { "Reason", eventData.Reason ?? "No reason provided" }
                    },
                    cancellationToken: cancellationToken);


                var integrationEvent = new PermissionChangedIntegrationEvent(
    changeType: "REVOKED", // ✅ FIX: 'C'를 소문자 'c'로 수정
    userId: eventData.UserId,
    permissionScope: eventData.PermissionScope,
    triggeredByUserId: eventData.RevokedByUserId,
    reason: eventData.Reason,
    expiresAt: eventData.ExpiresAt
);
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully processed PermissionRevokedEvent for User {UserId}", eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionRevokedEvent for User {UserId}", eventData.UserId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }
        /// <summary>
        /// 권한 정의 수정 이벤트를 처리합니다.
        /// 트랜잭션 내에서 감사 로그를 기록하고, 관련된 캐시를 무효화한 후,
        /// 통합 이벤트를 발행하여 다른 시스템에 변경 사항을 알립니다.
        /// </summary>
        public async Task HandlePermissionModifiedAsync(PermissionModifiedEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionModifiedEvent.");
                return;
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Processing PermissionModifiedEvent for PermissionId {PermissionId}", eventData.AggregateId);

                // 1. 변경된 권한 정의에 대한 캐시 무효화 (사용자별 캐시가 아님)
                await InvalidatePermissionDefinitionCacheAsync(eventData.PermissionScope, cancellationToken);

                // 2. 감사 로그 기록 (eventData의 실제 속성 사용)
                var changes = BuildChangeList(eventData.OldValues, eventData.NewValues);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: $"Modified permission definition for '{eventData.PermissionScope}'",
                    connectedId: eventData.ModifiedByUserId,
                    success: true,
                    resourceType: "PermissionDefinition",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                { "PermissionScope", eventData.PermissionScope },
                { "Changes", changes },
                { "Reason", eventData.Reason ?? "No reason provided" }
                    },
                    cancellationToken: cancellationToken);

                // 3. 통합 이벤트 발행 (영향받는 사용자 ID 목록 없이 발행)
                // 후속 처리(예: 모든 관련 사용자에게 알림)는 이 이벤트를 구독하는 다른 서비스의 책임입니다.
                var integrationEvent = new PermissionChangedIntegrationEvent(
                    changeType: "DEFINITION_MODIFIED",
                    userId: Guid.Empty, // 특정 사용자가 아닌 권한 자체의 변경이므로 Empty
                    permissionScope: eventData.PermissionScope,
                    triggeredByUserId: eventData.ModifiedByUserId,
                    reason: eventData.Reason ?? $"Changes: {string.Join(", ", changes)}"
                );
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully processed PermissionModifiedEvent for PermissionId {PermissionId}", eventData.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionModifiedEvent for PermissionId {PermissionId}", eventData.AggregateId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }
        /// <summary>
        /// 권한 위임 이벤트를 처리합니다.
        /// 트랜잭션 내에서 위임된 각 권한의 캐시를 무효화하고, 단일 감사 로그를 기록한 후,
        /// 각 권한에 대한 통합 이벤트를 발행하여 후속 조치를 위임합니다.
        /// </summary>
        public async Task HandlePermissionDelegatedAsync(PermissionDelegatedEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionDelegatedEvent.");
                return;
            }

            if (eventData.DelegatedPermissions == null || !eventData.DelegatedPermissions.Any())
            {
                _logger.LogWarning("PermissionDelegatedEvent from Delegator {DelegatorId} contained no permissions to delegate.", eventData.DelegatorUserId);
                return;
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                _logger.LogInformation(
                    "Processing PermissionDelegatedEvent: {DelegatorId} -> {DelegateId} for {PermissionCount} permissions.",
                    eventData.DelegatorUserId, eventData.DelegateUserId, eventData.DelegatedPermissions.Count);

                // 1. 위임자와 수임자 모두에 대해 위임된 모든 권한의 캐시를 무효화합니다.
                var invalidationTasks = new List<Task>();
                foreach (var scope in eventData.DelegatedPermissions)
                {
                    invalidationTasks.Add(InvalidatePermissionCacheAsync(eventData.DelegatorUserId, scope, cancellationToken));
                    invalidationTasks.Add(InvalidatePermissionCacheAsync(eventData.DelegateUserId, scope, cancellationToken));
                }
                await Task.WhenAll(invalidationTasks);

                // 2. 단일 감사 로그를 기록합니다. (✅ FIX: eventData의 실제 속성 사용)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 위임은 기존 권한에 대한 상태 변경
                    action: $"User delegated {eventData.DelegatedPermissions.Count} permission(s) to another user",
                    connectedId: eventData.DelegatorUserId, // 위임한 사람이 작업의 주체
                    success: true,
                    resourceType: "PermissionDelegation",
                    resourceId: eventData.AggregateId.ToString(), // 위임 행위 자체가 이벤트의 주체
                    metadata: new Dictionary<string, object>
                    {
                { "DelegatorUserId", eventData.DelegatorUserId },
                { "DelegateUserId", eventData.DelegateUserId },
                { "DelegatedPermissions", eventData.DelegatedPermissions },
                { "DelegationType", eventData.DelegationType.ToString() },
                { "DelegationScope", eventData.DelegationScope.ToString() },
                { "CanSubDelegate", eventData.CanSubDelegate },
                { "ExpiresAt", eventData.ExpiresAt?.ToString() ?? "Never" },
                { "Reason", eventData.Reason ?? "No reason provided" }
                    },
                    cancellationToken: cancellationToken);

                // 3. 위임된 각 권한에 대해 별도의 통합 이벤트를 발행합니다.
                var eventTasks = eventData.DelegatedPermissions.Select(scope =>
                {
                    var integrationEvent = new PermissionChangedIntegrationEvent(
                        changeType: "DELEGATED",
                        userId: eventData.DelegateUserId, // 위임 받은 사람이 이벤트의 주체
                        permissionScope: scope,
                        triggeredByUserId: eventData.DelegatorUserId,
                        reason: eventData.Reason ?? $"Delegated by user {eventData.DelegatorUserId}",
                        expiresAt: eventData.ExpiresAt
                    );
                    return _eventBus.PublishAsync(integrationEvent, cancellationToken);
                });
                await Task.WhenAll(eventTasks);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully processed PermissionDelegatedEvent from {DelegatorId} to {DelegateId}", eventData.DelegatorUserId, eventData.DelegateUserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionDelegatedEvent from {DelegatorId}", eventData.DelegatorUserId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }
        /// <summary>
        /// 권한 정의와 관련된 일반 캐시를 무효화합니다.
        /// </summary>
        private async Task InvalidatePermissionDefinitionCacheAsync(string permissionScope, CancellationToken cancellationToken)
        {
            try
            {
                // 권한 정의 자체에 대한 캐시 키 (사용자 ID와 무관)
                var cacheKey = $"{AuthConstants.CacheKeys.PermissionPrefix}definition:{permissionScope}";

                // ICacheService를 사용하여 캐시 제거
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);

                _logger.LogDebug("Invalidated permission definition cache for Scope {Scope}", permissionScope);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate permission definition cache for scope {Scope}", permissionScope);
            }
        }

        // BuildChangeList 헬퍼 메서드는 그대로 유지됩니다.
        private List<string> BuildChangeList(Dictionary<string, object?> oldValues, Dictionary<string, object?> newValues)
        {
            var changes = new List<string>();
            if (newValues == null) return changes;

            foreach (var key in newValues.Keys)
            {
                var newValue = newValues[key];
                if (oldValues == null || !oldValues.TryGetValue(key, out var oldValue))
                {
                    changes.Add($"{key}: set to '{newValue}'");
                }
                else if (!Equals(oldValue, newValue))
                {
                    changes.Add($"{key}: changed from '{oldValue}' to '{newValue}'");
                }
            }
            return changes;
        }
        /// <summary>
        /// 권한 상속 이벤트를 처리합니다.
        /// </summary>
        public async Task HandlePermissionInheritedAsync(PermissionInheritedEvent eventData, CancellationToken cancellationToken = default)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionInheritedEvent.");
                return;
            }

            // ✅ FIX: 트랜잭션으로 데이터 정합성 보장
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                _logger.LogInformation(
                    "Processing PermissionInheritedEvent for User {UserId}, Scope {Scope} from {InheritedFromType}",
                    eventData.UserId, eventData.PermissionScope, eventData.InheritanceType);

                // 1. 캐시 무효화
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope, cancellationToken);

                // 2. 감사 로그 기록 (✅ FIX: eventData의 실제 속성 사용)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: $"User inherited permission '{eventData.PermissionScope}' from {eventData.InheritanceType}: {eventData.InheritedFromName}",
                    connectedId: eventData.ConnectedId ?? eventData.UserId, // 작업을 유발한 주체 (시스템일 경우 대상 사용자로 대체)
                    success: true,
                    resourceType: "PermissionInheritance",
                    resourceId: eventData.AggregateId.ToString(), // 이벤트의 주체는 '상속 관계' 그 자체
                    metadata: new Dictionary<string, object>
                    {
                { "TargetUserId", eventData.UserId },
                { "PermissionScope", eventData.PermissionScope },
                { "InheritanceType", eventData.InheritanceType.ToString() },
                { "InheritedFromId", eventData.InheritedFromId },
                { "InheritedFromName", eventData.InheritedFromName },
                { "InheritanceDepth", eventData.InheritanceDepth }
                    },
                    cancellationToken: cancellationToken);

                // 3. 통합 이벤트 발행 (✅ FIX: eventData의 실제 속성 사용)
                var integrationEvent = new PermissionChangedIntegrationEvent(
                    changeType: "INHERITED",
                    userId: eventData.UserId,
                    permissionScope: eventData.PermissionScope,
                    triggeredByUserId: Guid.Empty, // 상속은 시스템 규칙에 의해 발생
                    reason: $"Inherited from {eventData.InheritanceType}: {eventData.InheritedFromName}"
                );
                await _eventBus.PublishAsync(integrationEvent, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully processed PermissionInheritedEvent for User {UserId}", eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing PermissionInheritedEvent for User {UserId}", eventData.UserId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }
        #endregion

        #region Helper Methods

        /// <summary>
        /// 지정된 사용자와 권한에 대한 모든 관련 캐시를 무효화합니다.
        /// ICacheService를 사용하여 분산 캐시와 인-메모리 캐시를 모두 처리합니다.
        /// </summary>
        private async Task InvalidatePermissionCacheAsync(Guid userId, string permissionScope, CancellationToken cancellationToken)
        {
            try
            {
                // 여러 캐시 키를 한 번에 제거하기 위한 패턴 또는 개별 키 목록
                var cacheKeysToRemove = new[]
                {
                    $"{AuthConstants.CacheKeys.PermissionPrefix}{userId}",
                    $"{AuthConstants.CacheKeys.PermissionPrefix}{userId}:{permissionScope}",
                    $"{AuthConstants.CacheKeys.UserPrefix}permissions:{userId}"
                };

                // ✅ FIX: ICacheService의 RemoveMultipleAsync 또는 패턴 기반 제거 사용
                await _cacheService.RemoveMultipleAsync(cacheKeysToRemove, cancellationToken);

                _logger.LogDebug("Invalidated permission caches for User {UserId} and Scope {Scope}", userId, permissionScope);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate permission cache for user {UserId}", userId);
                // 캐시 무효화 실패는 트랜잭션을 롤백할 만큼 치명적이지 않으므로 경고만 기록하고 계속 진행합니다.
            }
        }

        #endregion
    }
}