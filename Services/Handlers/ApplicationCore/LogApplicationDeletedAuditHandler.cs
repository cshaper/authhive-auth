// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogApplicationDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationDeletedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 삭제 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationDeletedAuditHandler :
        IDomainEventHandler<ApplicationDeletedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationDeletedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationDeletedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.DeletedByConnectedId;

            try
            {
                var action = @event.IsSoftDelete ? "APPLICATION_SOFT_DELETED" : "APPLICATION_DELETED";
                var severity = @event.IsSoftDelete ? AuditEventSeverity.Warning : AuditEventSeverity.Critical;

                _logger.LogWarning(
                    "Recording audit log for {Action} event. AppId: {AppId}, OrgId: {OrgId}",
                    action, applicationId, organizationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["deleted_by_connected_id"] = initiator,
                    ["is_soft_delete"] = @event.IsSoftDelete,
                    ["deleted_at"] = @event.DeletedAt,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: action,
                    connectedId: initiator, // 행위자
                    success: true,
                    resourceType: "Application",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}