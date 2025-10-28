// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogApplicationTemplateChangedAuditHandler.cs
using AuthHive.Auth.Extensions;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationTemplateChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.Json; // ❗️ System.Text.Json 사용 (지침 확인)
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 애플리케이션 접근 권한 템플릿이 수정되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationTemplateChangedAuditHandler :
        IDomainEventHandler<ApplicationTemplateChangedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationTemplateChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationTemplateChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationTemplateChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationTemplateChangedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var templateId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId; 

            try
            {
                _logger.LogWarning( 
                    "Recording audit log for ApplicationTemplateChanged event. TemplateId: {TemplateId}, AppId: {AppId}, AffectedUsers: {AffectedCount}",
                    templateId, applicationId, @event.AffectedUsersCount);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["template_id"] = templateId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["changed_by_connected_id"] = initiator,
                    ["affected_users_count"] = @event.AffectedUsersCount,
                    ["old_values"] = @event.OldValues, // 변경 전 값
                    ["new_values"] = @event.NewValues, // 변경 후 값
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger); // Reason 등 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "APPLICATION_TEMPLATE_CHANGED",
                    connectedId: initiator,
                    success: true, 
                    resourceType: "ApplicationAccessTemplate",
                    resourceId: templateId.ToString(), 
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationTemplateChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}