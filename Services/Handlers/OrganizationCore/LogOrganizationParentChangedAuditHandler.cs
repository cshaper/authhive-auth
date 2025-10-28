// File: AuthHive.Auth/Services/Handlers/OrganizationCore/LogOrganizationParentChangedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core; // ❗️ 요청하신 using 구문
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ OrganizationParentChangedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// 조직 부모 변경 이벤트(OrganizationParentChangedEvent) 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogOrganizationParentChangedAuditHandler :
        IDomainEventHandler<OrganizationParentChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOrganizationParentChangedAuditHandler> _logger;

        public int Priority => 10; // 1순위: 감사 로그 핸들러
        public bool IsEnabled => true;

        public LogOrganizationParentChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogOrganizationParentChangedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(OrganizationParentChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.UpdatedByConnectedId; // ❗️ Guid? (TriggeredBy)

            try
            {
                const string action = "ORGANIZATION_PARENT_CHANGED";
                // ❗️ 계층 구조 변경은 중요하므로 Warning 등급으로 설정
                var severity = AuditEventSeverity.Warning; 

                _logger.LogWarning( // ❗️ Warning 수준으로 로깅
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {InitiatorId}, OldParent: {OldParent}, NewParent: {NewParent}",
                    action, organizationId, initiator ?? Guid.Empty, @event.OldParentId, @event.NewParentId);

                // ❗️ 이벤트 속성을 메타데이터로 구성 (<string, object>)
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["old_parent_id"] = @event.OldParentId ?? Guid.Empty, // ❗️ null 처리
                    ["new_parent_id"] = @event.NewParentId ?? Guid.Empty, // ❗️ null 처리
                    ["change_reason"] = @event.ChangeReason,
                    ["changed_by_connected_id"] = initiator ?? Guid.Empty, // ❗️ null 처리
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                // BaseEvent의 공통 메타데이터 병합
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 구조 변경은 'Update'
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
                _logger.LogError(ex, "Failed to log audit for OrganizationParentChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}