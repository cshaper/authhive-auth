// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ 리팩토링된 DomainUpdatedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.Json; // ❗️ JsonSerializer 사용
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // ❗️ OrganizationDomain 네임스페이스
{
    /// <summary>
    /// [신규] 조직의 도메인 정보가 수정되었을 때(DomainUpdatedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogDomainUpdatedAuditHandler :
        IDomainEventHandler<DomainUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainUpdatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainUpdatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // ❗️ DomainId
            var initiator = @event.UpdatedByConnectedId;
            var organizationId = @event.OrganizationId; // ❗️ BaseEvent에서 가져옴

            try
            {
                const string action = "ORGANIZATION_DOMAIN_UPDATED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. DomainId: {DomainId}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, domainId, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    // ❗️ [NRT Fix] Dictionary<string, object?>는 <string, object>에 할당할 수 없으므로, JSON 문자열로 직렬화합니다.
                    ["changed_properties_json"] = JsonSerializer.Serialize(@event.ChangedProperties),
                    ["updated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "OrganizationDomain", // ❗️ 리소스 타입
                    resourceId: domainId.ToString(), // ❗️ 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DomainUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}