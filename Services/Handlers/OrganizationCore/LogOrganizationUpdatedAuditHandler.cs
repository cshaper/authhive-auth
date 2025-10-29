// File: AuthHive.Auth/Services/Handlers/OrganizationCore/LogOrganizationUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ 방금 보여주신 OrganizationUpdatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// 조직 정보 변경 이벤트(OrganizationUpdatedEvent) 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogOrganizationUpdatedAuditHandler :
        IDomainEventHandler<OrganizationUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOrganizationUpdatedAuditHandler> _logger;

        public int Priority => 10; // 1순위: 감사 로그 핸들러
        public bool IsEnabled => true;

        public LogOrganizationUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogOrganizationUpdatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(OrganizationUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            // ❗️ 이벤트의 'UpdatedByConnectedId' (TriggeredBy) 속성 사용
            var initiator = @event.UpdatedByConnectedId;

            try
            {
                const string action = "ORGANIZATION_UPDATED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {InitiatorId}",
                    action, organizationId, initiator ?? Guid.Empty);

                // ❗️ 보여주신 이벤트 속성(UpdatedFields, OldValues, NewValues)을 메타데이터로 구성
                // ❗️ (NRT 오류 방지를 위해 <string, object> 사용)
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["updated_fields"] = @event.UpdatedFields,
                    ["old_values"] = @event.OldValues, // object 타입
                    ["new_values"] = @event.NewValues, // object 타입
                    ["updated_by_connected_id"] = initiator ?? Guid.Empty, // ❗️ null인 경우 Guid.Empty
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                // BaseEvent의 공통 메타데이터 병합
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: action,
                    connectedId: initiator ?? Guid.Empty, // ❗️ 행위자 (null일 수 있음)
                    success: true,
                    resourceType: "Organization",
                    resourceId: organizationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for OrganizationUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}