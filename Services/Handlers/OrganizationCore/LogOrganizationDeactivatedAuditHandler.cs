// File: AuthHive.Auth/Services/Handlers/OrganizationCore/LogOrganizationDeactivatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core; // ❗️ 요청하신 using 구문
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ OrganizationDeactivatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// 조직 비활성화 이벤트(OrganizationDeactivatedEvent) 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogOrganizationDeactivatedAuditHandler :
        IDomainEventHandler<OrganizationDeactivatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOrganizationDeactivatedAuditHandler> _logger;

        public int Priority => 10; // 1순위: 감사 로그 핸들러
        public bool IsEnabled => true;

        public LogOrganizationDeactivatedAuditHandler(
            IAuditService auditService,
            ILogger<LogOrganizationDeactivatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(OrganizationDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.TriggeredBy; // ❗️ Guid? 타입

            try
            {
                const string action = "ORGANIZATION_DEACTIVATED";
                // ❗️ 비활성화는 Suspended/Deleted보다는 낮으므로 Warning 등급
                var severity = AuditEventSeverity.Warning; 

                _logger.LogWarning( // ❗️ Warning 수준으로 로깅
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {InitiatorId}, Reason: {Reason}",
                    action, organizationId, initiator ?? Guid.Empty, @event.Reason);

                // ❗️ 이벤트 속성을 메타데이터로 구성 (<string, object>)
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["previous_status"] = @event.PreviousStatus.ToString(),
                    ["reason"] = @event.Reason,
                    ["deactivated_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                // BaseEvent의 공통 메타데이터 병합
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 상태 변경은 'Update'
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
                _logger.LogError(ex, "Failed to log audit for OrganizationDeactivatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}