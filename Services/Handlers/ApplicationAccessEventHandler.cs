// FIX: 올바른 using 문을 추가합니다.
using System;
using System.Collections.Generic; // Dictionary를 사용하기 위해 필요
using System.Text.Json; // JsonSerializer를 사용하기 위해 필요
using System.Threading; // CancellationToken을 사용하기 위해 필요
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Core; // AuditActionType Enum을 위해 필요
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Application.Handlers;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.PlatformApplication.Events;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Application.Handlers
{
    /// <summary>
    /// 애플리케이션 접근 권한 관련 도메인 이벤트를 처리합니다.
    /// 주요 역할은 권한 변경 시 관련 캐시를 무효화하고 감사 로그를 기록하는 것입니다.
    /// CancellationToken 지원 추가
    /// </summary>
    public class ApplicationAccessEventHandler : IApplicationAccessEventHandler
    {
        private readonly ILogger<ApplicationAccessEventHandler> _logger;
        private readonly ICacheService _cacheService;
        private readonly IUnitOfWork _unitOfWork; // UnitOfWork는 현재 사용되지 않으므로 제거 고려
        private readonly IAuditService _auditService;

        public ApplicationAccessEventHandler(
            ILogger<ApplicationAccessEventHandler> logger,
            ICacheService cacheService,
            IUnitOfWork unitOfWork,
            IAuditService auditService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
        }


        public async Task HandleAccessGrantedAsync(AccessGrantedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("AccessGranted", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                // LogActionAsync 호출 시그니처 및 매개변수 확인
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: "ACCESS_GRANTED",
                    connectedId: eventData.GrantedByConnectedId, // non-nullable Guid 전달
                    success: true,
                    // errorMessage: null, // Optional parameter
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object> // Dictionary<string, object> 타입 전달
                    {
                        { "AccessLevel", eventData.AccessLevel.ToString() },
                        // Nullable Guid?를 object로 할당 시 DBNull.Value 사용 권장
                        { "RoleId", eventData.RoleId.HasValue ? eventData.RoleId.Value : DBNull.Value },
                        { "TemplateId", eventData.TemplateId.HasValue ? eventData.TemplateId.Value : DBNull.Value }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandleAccessRevokedAsync(AccessRevokedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("AccessRevoked", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: "ACCESS_REVOKED",
                    connectedId: eventData.RevokedByConnectedId,
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        // Nullable string?을 object로 할당 시 null 체크 후 값 또는 DBNull.Value 사용 권장
                        { "Reason", !string.IsNullOrEmpty(eventData.Reason) ? eventData.Reason : DBNull.Value }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandleAccessModifiedAsync(AccessModifiedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("AccessModified", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "ACCESS_MODIFIED",
                    connectedId: eventData.ModifiedByConnectedId,
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        // ChangedProperties가 Dictionary<string, object>? 타입이라고 가정
                       { "ChangedProperties", eventData.ChangedProperties ?? new Dictionary<string, object?>() }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandleAccessExpiredAsync(AccessExpiredEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("AccessExpired", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.System,
                    action: "ACCESS_EXPIRED",
                    connectedId: Guid.Empty, // System action, no specific user
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        { "ExpiredAt", eventData.OccurredAt }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandleRoleChangedAsync(RoleChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("RoleChanged", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "ROLE_CHANGED",
                    connectedId: eventData.ChangedByConnectedId,
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        { "OldRoleId", eventData.OldRoleId.HasValue ? eventData.OldRoleId.Value : DBNull.Value },
                        { "NewRoleId", eventData.NewRoleId.HasValue ? eventData.NewRoleId.Value : DBNull.Value }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandlePermissionsAddedAsync(PermissionsAddedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync(
                "PermissionsAdded",
                eventData.ApplicationId ?? Guid.Empty,
                eventData.ConnectedId, // 대상 사용자 ID
                async () =>
                {
                    await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Update,
                        action: "PERMISSIONS_ADDED",
                        // [FIXED] AddedByConnectedId -> ChangedByConnectedId 로 수정!
                        connectedId: eventData.ChangedByConnectedId, // <-- 행위자 ID 전달
                        success: true,
                        resourceType: "UserApplicationAccess",
                        resourceId: eventData.AggregateId.ToString(),
                        metadata: new Dictionary<string, object>
                        {
                            { "AddedPermissions", eventData.AddedPermissions ?? Enumerable.Empty<string>() }
                        },
                        cancellationToken: cancellationToken
                    );
                }, cancellationToken);
        }
        public async Task HandlePermissionsRemovedAsync(PermissionsRemovedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("PermissionsRemoved", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "PERMISSIONS_REMOVED",
                    connectedId: eventData.RemovedByConnectedId,
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        // Assuming RemovedPermissions is IEnumerable<string>?
                        { "RemovedPermissions", eventData.RemovedPermissions ?? Enumerable.Empty<string>() }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        public async Task HandleTemplateAppliedAsync(TemplateAppliedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("TemplateApplied", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                     actionType: AuditActionType.Update,
                     action: "TEMPLATE_APPLIED",
                     connectedId: eventData.AppliedByConnectedId,
                     success: true,
                     resourceType: "UserApplicationAccess",
                     resourceId: eventData.AggregateId.ToString(),
                     metadata: new Dictionary<string, object>
                   {
                        { "TemplateId", eventData.TemplateId }
                   },
                     cancellationToken: cancellationToken
                 );
            }, cancellationToken);
        }

        public async Task HandleTemplateChangedAsync(TemplateChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Handling TemplateChanged event for TemplateId: {TemplateId}", eventData.AggregateId);
            try
            {
                await InvalidateTemplateCacheAsync(eventData.AggregateId, cancellationToken);
                _logger.LogInformation("Template {TemplateId} changed, affecting {Count} users. Cache invalidated.", eventData.AggregateId, eventData.AffectedUsersCount);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "TEMPLATE_CHANGED",
                    connectedId: eventData.ChangedByConnectedId,
                    success: true,
                    resourceType: "PlatformApplicationAccessTemplate",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        // Assuming ChangedProperties is Dictionary<string, object>?
                       { "ChangedProperties", eventData.ChangedProperties ?? new Dictionary<string, object?>() },
                        { "AffectedUsersCount", eventData.AffectedUsersCount }
                    },
                    cancellationToken: cancellationToken
                );
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("TemplateChanged event handling was canceled for TemplateId: {TemplateId}", eventData.AggregateId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling TemplateChanged event for TemplateId: {TemplateId}", eventData.AggregateId);
                throw;
            }
        }

        public async Task HandleTemplateRemovedAsync(TemplateRemovedEvent eventData, CancellationToken cancellationToken = default)
        {
            await HandleEventAsync("TemplateRemoved", eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId ?? Guid.Empty, eventData.ConnectedId, cancellationToken);
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "TEMPLATE_REMOVED",
                    connectedId: eventData.RemovedByConnectedId,
                    success: true,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.AggregateId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        { "TemplateId", eventData.TemplateId }
                    },
                    cancellationToken: cancellationToken
                );
            }, cancellationToken);
        }

        // HandleAccessInheritedAsync와 HandleInheritanceChainChangedAsync는
        // Not implemented 상태이므로 CancellationToken 추가 외 수정 없음
        public Task HandleAccessInheritedAsync(AccessInheritedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("Handler for 'AccessInheritedEvent' is not implemented. Review its necessity.");
            return Task.CompletedTask;
        }

        public Task HandleInheritanceChainChangedAsync(InheritanceChainChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("Handler for 'InheritanceChainChangedEvent' is not implemented. Consider using a background job for recalculation.");
            return Task.CompletedTask;
        }

        #region Private Helper Methods

        /// <summary>
        /// 이벤트 처리 공통 로직 (로깅, 예외 처리)
        /// CancellationToken 추가
        /// </summary>
        private async Task HandleEventAsync(
            string eventName,
            Guid applicationId,
            Guid connectedId,
            Func<Task> handlerAction,
            CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Handling {EventName} event for Application: {AppId}, ConnectedId: {ConnectedId}", eventName, applicationId, connectedId);
            try
            {
                // 핸들러 액션 실행 시 CancellationToken을 직접 전달할 필요는 없지만,
                // handlerAction 내부의 비동기 호출들이 cancellationToken을 사용합니다.
                await handlerAction();
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Event handling for {EventName} was canceled.", eventName);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling {EventName} event for App: {AppId}, ConnId: {ConnectedId}", eventName, applicationId, connectedId);
                throw; // 예외를 다시 던져 상위에서 처리하도록 함
            }
        }

        /// <summary>
        /// 특정 사용자의 애플리케이션 권한 캐시를 무효화합니다.
        /// CancellationToken 추가
        /// </summary>
        private async Task InvalidatePermissionCacheAsync(
            Guid applicationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = GetPermissionCacheKey(applicationId, connectedId);
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            _logger.LogInformation("Invalidated permission cache for App={AppId}, ConnectedId={ConnectedId}", applicationId, connectedId);
        }

        /// <summary>
        /// 특정 템플릿 관련 캐시를 무효화합니다.
        /// CancellationToken 추가
        /// </summary>
        private async Task InvalidateTemplateCacheAsync(
            Guid templateId,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = GetTemplateCacheKey(templateId);
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            _logger.LogInformation("Invalidated template cache for TemplateId={TemplateId}", templateId);
        }

        /// <summary>
        /// 권한 캐시 키 생성
        /// </summary>
        private static string GetPermissionCacheKey(Guid applicationId, Guid connectedId) => $"permissions:{applicationId}:{connectedId}";

        /// <summary>
        /// 템플릿 캐시 키 생성
        /// </summary>
        private static string GetTemplateCacheKey(Guid templateId) => $"templates:{templateId}";

        #endregion
    }
}