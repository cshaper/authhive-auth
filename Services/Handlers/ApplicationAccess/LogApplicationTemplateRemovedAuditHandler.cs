// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogApplicationTemplateRemovedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationTemplateRemovedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 사용자의 접근 권한에서 템플릿이 제거(연결 해제)되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationTemplateRemovedAuditHandler :
        IDomainEventHandler<ApplicationTemplateRemovedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationTemplateRemovedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationTemplateRemovedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationTemplateRemovedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationTemplateRemovedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user the template was removed from
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.RemovedByConnectedId; // The user who removed the template

            try
            {
                _logger.LogWarning( // 템플릿 제거는 Warning 레벨
                    "Recording audit log for ApplicationTemplateRemoved event. ConnectedId: {ConnectedId}, AppId: {AppId}, TemplateId: {TemplateId}",
                    connectedId, applicationId, @event.TemplateId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["template_id"] = @event.TemplateId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["removed_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 제거는 Warning
                };
                // auditData.MergeMetadata(@event.Metadata, _logger); // 필요시 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 템플릿 제거는 Update (또는 Revoke)
                    action: "APPLICATION_TEMPLATE_REMOVED",
                    connectedId: initiator, // 행위자
                    success: true, // 제거 작업 자체는 성공
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // 접근 권한 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationTemplateRemovedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}