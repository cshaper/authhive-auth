// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogAccessRevokedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // AccessRevokedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 애플리케이션 접근 권한이 취소되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogAccessRevokedAuditHandler :
        IDomainEventHandler<AccessRevokedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAccessRevokedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogAccessRevokedAuditHandler(
            IAuditService auditService,
            ILogger<LogAccessRevokedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(AccessRevokedEvent @event, CancellationToken cancellationToken = default)
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user whose access was revoked
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.RevokedByConnectedId; // The user who revoked access

            try
            {
                _logger.LogWarning( // 권한 취소는 Warning 레벨로 로깅
                    "Recording audit log for AccessRevoked event. ConnectedId: {ConnectedId}, AppId: {AppId}, RevokedBy: {Initiator}",
                    connectedId, applicationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["reason"] = @event.Reason ?? "N/A",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["revoked_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 권한 취소는 Warning
                };
                // auditData.MergeMetadata(@event.Metadata, _logger); // 필요시 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Revoke, // 'Revoke' 또는 'Delete' 타입
                    action: "APPLICATION_ACCESS_REVOKED",
                    connectedId: initiator, // 행위자
                    success: true, // 취소 작업 자체는 성공
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // 접근 권한 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AccessRevokedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}