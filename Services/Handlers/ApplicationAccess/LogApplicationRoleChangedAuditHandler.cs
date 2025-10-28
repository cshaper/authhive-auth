// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogApplicationRoleChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationRoleChangedEvent 사용
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 사용자의 애플리케이션 내 역할이 변경되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationRoleChangedAuditHandler :
        IDomainEventHandler<ApplicationRoleChangedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationRoleChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationRoleChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationRoleChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationRoleChangedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user whose role changed
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId; // The user who changed the role

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationRoleChanged event. ConnectedId: {ConnectedId}, AppId: {AppId}, Role: {OldRole} -> {NewRole}",
                    connectedId, applicationId, @event.OldRoleId?.ToString() ?? "None", @event.NewRoleId?.ToString() ?? "None");

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["old_role_id"] = @event.OldRoleId ?? (object)DBNull.Value,
                    ["new_role_id"] = @event.NewRoleId ?? (object)DBNull.Value,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["changed_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 정보성 로그
                };
                // auditData.MergeMetadata(@event.Metadata, _logger); // 필요시 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 역할 변경은 Update
                    action: "APPLICATION_ROLE_CHANGED",
                    connectedId: initiator, // 행위자
                    success: true, // 변경 작업 자체는 성공
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // 접근 권한 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationRoleChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}