// FIX: 올바른 using 문을 추가합니다.
using System;
using System.Text.Json; // JsonSerializer를 사용하기 위해 필요
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
    /// </summary>
    public class ApplicationAccessEventHandler : IApplicationAccessEventHandler
    {
        private readonly ILogger<ApplicationAccessEventHandler> _logger;
        private readonly ICacheService _cacheService;
        private readonly IUnitOfWork _unitOfWork;
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

        // --- 모든 이벤트 핸들러의 감사 로그 호출 부분을 올바르게 수정 ---

        public async Task HandleAccessGrantedAsync(AccessGrantedEvent eventData)
        {
            await HandleEventAsync("AccessGranted", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                // FIX: LogActionAsync 호출 시그니처를 IAuditService 인터페이스에 맞게 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.GrantedByConnectedId,
                    action: "ACCESS_GRANTED",
                    actionType: AuditActionType.Create,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.AccessLevel, eventData.RoleId, eventData.TemplateId })
                );
            });
        }

        public async Task HandleAccessRevokedAsync(AccessRevokedEvent eventData)
        {
            await HandleEventAsync("AccessRevoked", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.RevokedByConnectedId,
                    action: "ACCESS_REVOKED",
                    actionType: AuditActionType.Delete,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.Reason })
                );
            });
        }

        public async Task HandleAccessModifiedAsync(AccessModifiedEvent eventData)
        {
            await HandleEventAsync("AccessModified", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.ModifiedByConnectedId,
                    action: "ACCESS_MODIFIED",
                    actionType: AuditActionType.Update,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.ChangedProperties })
                );
            });
        }
        
        public async Task HandleAccessExpiredAsync(AccessExpiredEvent eventData)
        {
            await HandleEventAsync("AccessExpired", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                 // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: Guid.Empty, // System Action
                    action: "ACCESS_EXPIRED",
                    actionType: AuditActionType.System,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.ExpiredAt })
                );
            });
        }

        public async Task HandleRoleChangedAsync(RoleChangedEvent eventData)
        {
            await HandleEventAsync("RoleChanged", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.ChangedByConnectedId,
                    action: "ROLE_CHANGED",
                    actionType: AuditActionType.Update,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.OldRoleId, eventData.NewRoleId })
                );
            });
        }

        public async Task HandlePermissionsAddedAsync(PermissionsAddedEvent eventData)
        {
            await HandleEventAsync("PermissionsAdded", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.AddedByConnectedId,
                    action: "PERMISSIONS_ADDED",
                    actionType: AuditActionType.Update,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.AddedPermissions })
                );
            });
        }

        public async Task HandlePermissionsRemovedAsync(PermissionsRemovedEvent eventData)
        {
            await HandleEventAsync("PermissionsRemoved", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.RemovedByConnectedId,
                    action: "PERMISSIONS_REMOVED",
                    actionType: AuditActionType.Update,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.RemovedPermissions })
                );
            });
        }
        
        public async Task HandleTemplateAppliedAsync(TemplateAppliedEvent eventData)
        {
             await HandleEventAsync("TemplateApplied", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.AppliedByConnectedId,
                    action: "TEMPLATE_APPLIED",
                    actionType: AuditActionType.Update,
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.TemplateId })
                );
            });
        }

        public async Task HandleTemplateChangedAsync(TemplateChangedEvent eventData)
        {
            await HandleEventAsync("TemplateChanged", Guid.Empty, Guid.Empty, async () =>
            {
                await InvalidateTemplateCacheAsync(eventData.TemplateId);
                _logger.LogInformation("Template {TemplateId} changed, affecting {Count} users. Cache invalidated.", eventData.TemplateId, eventData.AffectedUsersCount);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.ChangedByConnectedId,
                    action: "TEMPLATE_CHANGED",
                    actionType: AuditActionType.Update,
                    resourceType: "PlatformApplicationAccessTemplate",
                    resourceId: eventData.TemplateId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.ChangedProperties, eventData.AffectedUsersCount })
                );
            });
        }

        public async Task HandleTemplateRemovedAsync(TemplateRemovedEvent eventData)
        {
             await HandleEventAsync("TemplateRemoved", eventData.ApplicationId, eventData.ConnectedId, async () =>
            {
                await InvalidatePermissionCacheAsync(eventData.ApplicationId, eventData.ConnectedId);
                // FIX: LogActionAsync 호출 시그니처 수정
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.RemovedByConnectedId,
                    action: "TEMPLATE_REMOVED",
                    actionType: AuditActionType.Update, // 템플릿 연결이 해제된 것이므로 Update
                    resourceType: "UserApplicationAccess",
                    resourceId: eventData.UserApplicationAccessId.ToString(),
                    success: true,
                    metadata: JsonSerializer.Serialize(new { eventData.TemplateId })
                );
            });
        }

        public Task HandleAccessInheritedAsync(AccessInheritedEvent eventData)
        {
            _logger.LogWarning("Handler for 'AccessInheritedEvent' is not implemented. Review its necessity.");
            return Task.CompletedTask;
        }

        public Task HandleInheritanceChainChangedAsync(InheritanceChainChangedEvent eventData)
        {
            _logger.LogWarning("Handler for 'InheritanceChainChangedEvent' is not implemented. Consider using a background job for recalculation.");
            return Task.CompletedTask;
        }
        
        #region Private Helper Methods

        private async Task HandleEventAsync(string eventName, Guid applicationId, Guid connectedId, Func<Task> handlerAction)
        {
            _logger.LogInformation("Handling {EventName} event for Application: {AppId}, ConnectedId: {ConnectedId}", eventName, applicationId, connectedId);
            try
            {
                await handlerAction();
                // await _unitOfWork.CommitTransactionAsync(); 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling {EventName} event for App: {AppId}, ConnId: {ConnectedId}", eventName, applicationId, connectedId);
                // await _unitOfWork.RollbackTransactionAsync();
                throw;
            }
        }
        
        private async Task InvalidatePermissionCacheAsync(Guid applicationId, Guid connectedId)
        {
            var cacheKey = GetPermissionCacheKey(applicationId, connectedId);
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogInformation("Invalidated permission cache for App={AppId}, ConnectedId={ConnectedId}", applicationId, connectedId);
        }

        private async Task InvalidateTemplateCacheAsync(Guid templateId)
        {
            var cacheKey = GetTemplateCacheKey(templateId);
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogInformation("Invalidated template cache for TemplateId={TemplateId}", templateId);
        }

        private static string GetPermissionCacheKey(Guid applicationId, Guid connectedId) => $"permissions:{applicationId}:{connectedId}";
        private static string GetTemplateCacheKey(Guid templateId) => $"templates:{templateId}";

        #endregion
    }
}