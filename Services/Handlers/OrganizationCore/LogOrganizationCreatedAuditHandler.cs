// File: AuthHive.Auth/Services/Handlers/OrganizationCore/LogOrganizationCreatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// 조직 생성 이벤트(OrganizationCreatedEvent) 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogOrganizationCreatedAuditHandler :
        IDomainEventHandler<OrganizationCreatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogOrganizationCreatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogOrganizationCreatedAuditHandler(
            IAuditService auditService,
            ILogger<LogOrganizationCreatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(OrganizationCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.CreatedByConnectedId;

            try
            {
                const string action = "ORGANIZATION_CREATED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {Initiator}",
                    action, organizationId, initiator);

                // ❗️ [FIX 1] 딕셔너리 타입을 <string, object>로 변경
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["organization_key"] = @event.OrganizationKey,
                    ["name"] = @event.Name,
                    ["type"] = @event.Type.ToString(),
                    // ❗️ [FIX 2] nullable인 ParentOrganizationId를 Guid.Empty로 변환하여 object 타입으로 저장
                    ["parent_organization_id"] = @event.ParentOrganizationId ?? Guid.Empty,
                    ["created_by_connected_Id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                // ❗️ [FIX 3] 이제 auditData가 <string, object>이므로 MergeMetadata 호출이 유효합니다.
                // (@event.Metadata는 BaseEvent에 <string, object>로 선언되어 있음)
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "Organization",
                    resourceId: organizationId.ToString(),
                    // ❗️ [FIX 4] auditData가 <string, object>이므로 LogActionAsync 호출이 유효합니다.
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for OrganizationCreatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}