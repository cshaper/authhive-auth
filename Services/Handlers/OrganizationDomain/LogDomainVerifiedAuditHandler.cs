// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainVerifiedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ 리팩토링된 DomainVerifiedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // ❗️ OrganizationDomain 네임스페이스
{
    /// <summary>
    /// [신규] 조직의 도메인이 검증되었을 때(DomainVerifiedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogDomainVerifiedAuditHandler :
        IDomainEventHandler<DomainVerifiedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainVerifiedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainVerifiedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainVerifiedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // ❗️ DomainId
            var initiator = @event.TriggeredBy; // ❗️ Guid?
            var organizationId = @event.OrganizationId; // ❗️ BaseEvent에서 가져옴

            try
            {
                const string action = "ORGANIZATION_DOMAIN_VERIFIED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, Method: {Method}",
                    action, @event.DomainName, organizationId, @event.VerificationMethod);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["domain_name"] = @event.DomainName,
                    ["verification_method"] = @event.VerificationMethod,
                    ["verified_at"] = @event.VerifiedAt,
                    ["verified_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 검증은 'Update'
                    action: action,
                    connectedId: initiator ?? Guid.Empty,
                    success: true,
                    resourceType: "OrganizationDomain", // ❗️ 리소스 타입
                    resourceId: domainId.ToString(), // ❗️ 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DomainVerifiedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}