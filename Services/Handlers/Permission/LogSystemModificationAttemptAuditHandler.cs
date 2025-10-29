// File: AuthHive.Auth/Services/Handlers/Permission/LogSystemModificationAttemptAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // SystemPermissionModificationAttemptedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 시스템 권한 수정 시도 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogSystemModificationAttemptAuditHandler :
        IDomainEventHandler<SystemPermissionModificationAttemptedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogSystemModificationAttemptAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogSystemModificationAttemptAuditHandler(IAuditService auditService, ILogger<LogSystemModificationAttemptAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(SystemPermissionModificationAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionId = @event.AggregateId;
            var initiator = @event.AttemptedBy; // 시도한 주체 (ConnectedId 가정)

            try
            {
                _logger.LogCritical(
                    "Recording audit log for SystemPermissionModificationAttempted event. By: {Initiator}, Scope: {Scope}, Action: {Action}",
                    initiator, @event.PermissionScope, @event.Action);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = permissionId,
                    ["permission_scope"] = @event.PermissionScope,
                    ["action_attempted"] = @event.Action,
                    ["attempted_by_connected_id"] = initiator,
                    ["is_authorized"] = @event.IsAuthorized, // (보통 false)
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // 시스템 권한 무단 접근은 Critical
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.UnauthorizedAccess, // 무단 접근 액션 타입
                    "SYSTEM_PERMISSION_MOD_ATTEMPT",
                    initiator,
                    success: false, // 시도 자체는 실패로 기록 (차단 성공 가정)
                    errorMessage: $"Unauthorized attempt to modify system permission '{@event.PermissionScope}'",
                    resourceType: "SystemPermission",
                    resourceId: permissionId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SystemPermissionModificationAttemptedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}