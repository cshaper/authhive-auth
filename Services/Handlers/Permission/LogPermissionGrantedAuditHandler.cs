// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionGrantedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionGrantedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 사용자에게 권한이 부여되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionGrantedAuditHandler :
        IDomainEventHandler<PermissionGrantedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionGrantedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionGrantedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionGrantedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionGrantedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionGrantId = @event.AggregateId; // Grant ID
            var targetUserId = @event.UserId;
            var initiator = @event.GrantedByUserId; // 작업을 수행한 주체 (ConnectedId 가정)

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PermissionGranted event. TargetUser: {TargetUserId}, Scope: {Scope}, GrantedBy: {GrantedBy}",
                    targetUserId, @event.PermissionScope, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["target_user_id"] = targetUserId,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty, // 권한이 부여된 컨텍스트
                    ["permission_scope"] = @event.PermissionScope,
                    ["granted_by_user_id"] = initiator, // UserId인지 ConnectedId인지 명확히 해야 함 (ConnectedId로 가정)
                    ["reason"] = @event.Reason ?? "N/A",
                    ["expires_at"] = @event.OccurredAt, // 만료 시간 포함 (Nullable DateTime)
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 요청하신 대로 Info 레벨
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.PermissionUpdated, // 권한 변경의 일부 (생성/부여)
                    "USER_PERMISSION_GRANTED",
                    initiator, // connectedId (작업 수행 주체)
                    success: true,
                    errorMessage: null,
                    resourceType: "UserPermissionGrant", // 리소스는 '사용자 권한 부여'
                    resourceId: permissionGrantId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionGrantedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}