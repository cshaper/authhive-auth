// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogDomainVerificationFailedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // ❗️ 리팩토링된 DomainVerificationFailedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // ❗️ OrganizationDomain 네임스페이스
{
    /// <summary>
    /// [신규] 조직 도메인 검증 실패 시(DomainVerificationFailedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogDomainVerificationFailedAuditHandler :
        IDomainEventHandler<DomainVerificationFailedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDomainVerificationFailedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDomainVerificationFailedAuditHandler(
            IAuditService auditService,
            ILogger<LogDomainVerificationFailedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(DomainVerificationFailedEvent @event, CancellationToken cancellationToken = default)
        {
            var domainId = @event.AggregateId; // ❗️ DomainId
            var initiator = @event.TriggeredBy; // ❗️ Guid?
            var organizationId = @event.OrganizationId; // ❗️ BaseEvent에서 가져옴

            try
            {
                const string action = "ORGANIZATION_DOMAIN_VERIFICATION_FAILED";
                var severity = AuditEventSeverity.Warning; // ❗️ 검증 실패는 Warning

                _logger.LogWarning( // ❗️ Warning 수준으로 로깅
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, Reason: {Reason}",
                    action, @event.Domain, organizationId, @event.Reason);

                var auditData = new Dictionary<string, object>
                {
                    ["domain_id"] = domainId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    ["domain_name"] = @event.Domain,
                    ["failure_reason"] = @event.Reason,
                    ["attempt_count"] = @event.AttemptCount,
                    ["failed_by_connected_id"] = initiator ?? Guid.Empty, // 시스템 이벤트일 수 있음
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // 검증 시도 및 결과는 'Update'의 일종
                    action: action,
                    connectedId: initiator ?? Guid.Empty,
                    success: false, // ❗️ 실패 이벤트이므로 false
                    errorMessage: @event.Reason, // ❗️ 실패 사유 기록
                    resourceType: "OrganizationDomain", // ❗️ 리소스 타입
                    resourceId: domainId.ToString(), // ❗️ 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DomainVerificationFailedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}