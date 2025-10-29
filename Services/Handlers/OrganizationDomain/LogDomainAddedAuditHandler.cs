// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainAddedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; 
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // ❗️ [수정] 새 네임스페이스
{
    /// <summary>
    /// [신규] 조직에 도메인이 추가되었을 때(DomainAddedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogDomainAddedAuditHandler :
        IDomainEventHandler<DomainAddedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainAddedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainAddedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainAddedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainAddedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; 
            var initiator = @event.CreatedByConnectedId;
            var organizationId = @event.OrganizationId; 

            try
            {
                const string action = "ORGANIZATION_DOMAIN_ADDED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, Initiator: {Initiator}",
                    action, @event.Domain, organizationId, initiator);
                
                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty, 
                    ["domain_name"] = @event.Domain,
                    ["domain_type"] = @event.DomainType.ToString(),
                    ["verification_token"] = @event.VerificationToken ?? string.Empty,
                    ["verification_method"] = @event.VerificationMethod ?? string.Empty,
                    ["added_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                auditData.MergeMetadata(@event.Metadata, _logger);
                
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: action,
                    connectedId: initiator,
                    success: true,
                    resourceType: "OrganizationDomain", 
                    resourceId: domainId.ToString(), 
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DomainAddedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}