// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionExpiredAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionExpiredEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For string.Join
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 사용자 권한 만료 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionExpiredAuditHandler :
        IDomainEventHandler<PermissionExpiredEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionExpiredAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionExpiredAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionExpiredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionExpiredEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionGrantId = @event.AggregateId; // The grant that expired
            var targetUserId = @event.UserId;
            // Expiration is usually system-triggered
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System action if null

            try
            {
                var expiredScopes = string.Join(", ", @event.ExpiredPermissions ?? new List<string>());
                _logger.LogWarning( // Expiration is a significant event
                    "Recording audit log for PermissionExpired event. TargetUser: {TargetUserId}, Expired Scopes: [{Scopes}]",
                    targetUserId, expiredScopes);

                var auditData = new Dictionary<string, object>
                {
                    ["target_user_id"] = targetUserId,
                    // ["connected_id"] = @event.ConnectedId ?? Guid.Empty, // 이벤트에 ConnectedId가 없음
                    ["expired_permissions"] = @event.ExpiredPermissions ?? new List<string>(),
                    ["expiration_type"] = @event.ExpirationType.ToString(),
                    ["originally_granted_by"] = @event.OriginallyGrantedBy,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator, // 시스템이면 Empty Guid
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 만료는 Warning
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.PermissionUpdated, // System update of permission status
                    "USER_PERMISSION_EXPIRED",
                    initiator, // connectedId (system if null)
                    success: true, // The expiration process succeeded
                    errorMessage: null,
                    resourceType: "UserPermissionGrant",
                    resourceId: permissionGrantId.ToString(), // ID of the grant that expired
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionExpiredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}