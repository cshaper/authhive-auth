// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionInheritedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionInheritedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 사용자 권한 상속 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionInheritedAuditHandler :
        IDomainEventHandler<PermissionInheritedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionInheritedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionInheritedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionInheritedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionInheritedEvent @event, CancellationToken cancellationToken = default)
        {
            var inheritanceId = @event.AggregateId; // Inheritance link ID
            var targetUserId = @event.UserId;
            // 상속은 시스템 규칙에 의해 발생
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System action if null

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PermissionInherited event. TargetUser: {TargetUserId}, Scope: {Scope}, InheritedFrom: {InheritedFrom}",
                    targetUserId, @event.PermissionScope, @event.InheritedFromName);

                var auditData = new Dictionary<string, object>
                {
                    ["target_user_id"] = targetUserId,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty,
                    ["permission_scope"] = @event.PermissionScope,
                    ["inheritance_type"] = @event.InheritanceType.ToString(),
                    ["inherited_from_id"] = @event.InheritedFromId,
                    ["inherited_from_name"] = @event.InheritedFromName,
                    ["inheritance_depth"] = @event.InheritanceDepth,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 상속은 정보 수준
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.PermissionUpdated, // 상속은 권한 상태 업데이트
                    "USER_PERMISSION_INHERITED",
                    initiator, // connectedId (system if null)
                    success: true,
                    errorMessage: null,
                    resourceType: "PermissionInheritance", // 리소스는 '상속 관계'
                    resourceId: inheritanceId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionInheritedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}