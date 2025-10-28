// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogApplicationPermissionsAddedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationPermissionsAddedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For string.Join
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 애플리케이션 접근 권한에 특정 퍼미션이 추가되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationPermissionsAddedAuditHandler :
        IDomainEventHandler<ApplicationPermissionsAddedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationPermissionsAddedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationPermissionsAddedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationPermissionsAddedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationPermissionsAddedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user whose permissions were added
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId; // The user who added the permissions

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationPermissionsAdded event. ConnectedId: {ConnectedId}, AppId: {AppId}, Added: {Count}",
                    connectedId, applicationId, @event.AddedPermissions?.Count ?? 0);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["added_permissions"] = @event.AddedPermissions ?? (object)DBNull.Value,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["changed_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // ❗️ 지침에 따라 .Info 사용
                };
                // auditData.MergeMetadata(@event.Metadata, _logger); // 필요시 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 권한 추가는 Update
                    action: "APPLICATION_PERMISSIONS_ADDED",
                    connectedId: initiator, // 행위자
                    success: true, // 추가 작업 자체는 성공
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // 접근 권한 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationPermissionsAddedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}