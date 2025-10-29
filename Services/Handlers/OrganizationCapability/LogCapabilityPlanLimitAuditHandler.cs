// File: AuthHive.Auth/Services/Handlers/OrganizationCapability/LogCapabilityPlanLimitAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // CapabilityPlanLimitEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCapability // Capability 네임스페이스
{
    /// <summary>
    /// [신규] 조직이 플랜 제한 기능을 사용하려 할 때(CapabilityPlanLimitEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogCapabilityPlanLimitAuditHandler :
        IDomainEventHandler<CapabilityPlanLimitEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogCapabilityPlanLimitAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogCapabilityPlanLimitAuditHandler(
            IAuditService auditService,
            ILogger<LogCapabilityPlanLimitAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(CapabilityPlanLimitEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // 조직 ID
            var initiator = @event.TriggeredBy; // Guid?

            try
            {
                const string action = "ORGANIZATION_CAPABILITY_PLAN_LIMIT_HIT";
                var severity = AuditEventSeverity.Warning; // 플랜 제한은 Warning

                _logger.LogWarning( // Warning 수준 로깅
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Capability: {CapabilityCode}, CurrentPlan: {CurrentPlan}, RequiredPlan: {RequiredPlan}",
                    action, organizationId, @event.CapabilityCode, @event.CurrentPlan, @event.RequiredPlan);

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["capability_code"] = @event.CapabilityCode,
                    ["current_plan"] = @event.CurrentPlan,
                    ["required_plan"] = @event.RequiredPlan,
                    ["triggered_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Security, // 플랜 제한 시도는 보안/정책 관련으로 볼 수 있음
                    action: action,
                    connectedId: initiator ?? Guid.Empty,
                    success: false, // 기능 사용 '실패'로 간주
                    errorMessage: $"Attempted to use capability '{ @event.CapabilityCode}' which requires plan '{ @event.RequiredPlan}', but current plan is '{ @event.CurrentPlan}'.",
                    resourceType: "OrganizationPlan", // 리소스 타입: 조직 플랜
                    resourceId: organizationId.ToString(), // 리소스 ID: 조직 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for CapabilityPlanLimitEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}