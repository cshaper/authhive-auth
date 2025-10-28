// File: AuthHive.Auth/Services/Handlers/OrganizationSSO/LogSamlConfigurationUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // SamlConfigurationUpdatedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationSSO // ❗️ 신규 네임스페이스
{
    /// <summary>
    /// [신규] 조직의 SAML/SSO 설정 변경 시(SamlConfigurationUpdatedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogSamlConfigurationUpdatedAuditHandler :
        IDomainEventHandler<SamlConfigurationUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogSamlConfigurationUpdatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogSamlConfigurationUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogSamlConfigurationUpdatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(SamlConfigurationUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // ❗️ 조직 ID
            var initiator = @event.TriggeredBy; // ❗️ 변경자 ID (Guid?)

            try
            {
                const string action = "ORGANIZATION_SAML_CONFIGURATION_UPDATED";
                var severity = AuditEventSeverity.Warning; // ❗️ SSO 설정 변경은 Warning

                _logger.LogWarning( // ❗️ Warning 수준 로깅
                    "Recording audit log for {Action} event. OrgId: {OrgId}, Initiator: {InitiatorId}",
                    action, organizationId, initiator ?? Guid.Empty);

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    // ❗️ 중요: 실제 변경된 SAML 설정값(예: IdP URL, Certificate)은 이벤트 자체에 없으므로,
                    // ❗️ 감사 로그만으로는 '무엇이' 변경되었는지 알기 어렵습니다.
                    // ❗️ 필요하다면 SamlConfigurationUpdatedEvent에 변경 내용을 포함하도록 모델 수정이 필요합니다.
                    ["updated_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: action,
                    connectedId: initiator ?? Guid.Empty, // 행위자
                    success: true,
                    resourceType: "OrganizationSSOConfiguration", // ❗️ 리소스 타입: SSO 설정
                    resourceId: organizationId.ToString(), // ❗️ 리소스 ID: 조직 ID (SSO 설정은 조직에 귀속)
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SamlConfigurationUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}