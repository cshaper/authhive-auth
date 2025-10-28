// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainRemovedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ 리팩토링된 DomainRemovedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // ❗️ OrganizationDomain 네임스페이스
{
    /// <summary>
    /// [신규] 조직의 도메인이 제거되었을 때(DomainRemovedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogDomainRemovedAuditHandler :
        IDomainEventHandler<DomainRemovedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainRemovedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainRemovedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainRemovedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainRemovedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // ❗️ DomainId
            var initiator = @event.DeletedByConnectedId;
            var organizationId = @event.OrganizationId; // ❗️ BaseEvent에서 가져옴

            try
            {
                const string action = "ORGANIZATION_DOMAIN_REMOVED";
                var severity = AuditEventSeverity.Warning; // ❗️ 도메인 삭제는 Warning

                _logger.LogWarning( // ❗️ Warning 수준으로 로깅
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Domain, organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["domain_name"] = @event.Domain,
                    ["domain_type"] = @event.DomainType.ToString(),
                    ["deleted_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete, // ❗️ Delete 타입
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
                _logger.LogError(ex, "Failed to log audit for DomainRemovedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}