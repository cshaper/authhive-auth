// File: AuthHive.Auth/Services/Handlers/OrganizationCore/LogOrganizationDeletedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core; // ❗️ 요청하신 using 구문
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ OrganizationDeletedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// 조직 삭제 이벤트(OrganizationDeletedEvent) 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogOrganizationDeletedAuditHandler :
        IDomainEventHandler<OrganizationDeletedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOrganizationDeletedAuditHandler> _logger;

        public int Priority => 10; // 1순위: 감사 로그 핸들러
        public bool IsEnabled => true;

        public LogOrganizationDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogOrganizationDeletedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(OrganizationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.DeletedByConnectedId; // ❗️ Guid? (TriggeredBy)

            try
            {
                // ❗️ 소프트 삭제 여부에 따라 액션 이름과 심각도 구분
                var action = @event.IsSoftDelete ? "ORGANIZATION_SOFT_DELETED" : "ORGANIZATION_DELETED";
                var severity = @event.IsSoftDelete ? AuditEventSeverity.Warning : AuditEventSeverity.Critical;

                _logger.LogWarning( // ❗️ 삭제 이벤트는 Warning/Critical 수준으로 로깅
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {InitiatorId}, IsSoft: {IsSoftDelete}",
                    action, organizationId, initiator ?? Guid.Empty, @event.IsSoftDelete);

                // ❗️ 이벤트 속성을 메타데이터로 구성 (<string, object>)
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["deletion_reason"] = @event.DeletionReason,
                    ["is_soft_delete"] = @event.IsSoftDelete,
                    ["deleted_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                // BaseEvent의 공통 메타데이터 병합
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete, // 'Delete' 타입
                    action: action,
                    connectedId: initiator ?? Guid.Empty,
                    success: true,
                    resourceType: "Organization",
                    resourceId: organizationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for OrganizationDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}