// File: AuthHive.Auth/Services/Handlers/OrganizationDomain/LogSslCertificateExpiringAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // SslCertificateExpiringEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationDomain // OrganizationDomain 네임스페이스
{
    /// <summary>
    /// [신규] 조직 도메인의 SSL 인증서 만료 예정 시(SslCertificateExpiringEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogSslCertificateExpiringAuditHandler :
        IDomainEventHandler<SslCertificateExpiringEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogSslCertificateExpiringAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogSslCertificateExpiringAuditHandler(
            IAuditService auditService,
            ILogger<LogSslCertificateExpiringAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(SslCertificateExpiringEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // 조직 ID
            // 이 이벤트는 시스템(백그라운드 잡 등)에 의해 트리거될 가능성이 높으므로 Initiator(TriggeredBy)는 null일 수 있습니다.
            var initiator = @event.TriggeredBy; 

            try
            {
                const string action = "ORGANIZATION_DOMAIN_SSL_EXPIRING";
                // 만료 임박 정도(daysRemaining)에 따라 심각도 조정 가능 (예: 7일 이내 Critical)
                var severity = @event.DaysRemaining <= 7 ? AuditEventSeverity.Critical : AuditEventSeverity.Warning;

                _logger.Log(severity == AuditEventSeverity.Critical ? LogLevel.Critical : LogLevel.Warning,
                    "Recording audit log for {Action} event. Domain: {Domain}, OrgId: {OrgId}, DaysLeft: {Days}",
                    action, @event.Domain, organizationId, @event.DaysRemaining);

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["domain_name"] = @event.Domain,
                    ["days_remaining"] = @event.DaysRemaining,
                    ["occurred_at"] = @event.OccurredAt,// 
                    ["triggered_by_connected_id"] = initiator ?? Guid.Empty, // 시스템 이벤트 가능성
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.System, // 시스템 이벤트로 분류
                    action: action,
                    connectedId: initiator ?? Guid.Empty, // 시스템이 수행 주체일 수 있음
                    success: true, // 이벤트 발생 자체가 성공
                    resourceType: "OrganizationDomainSSL", // 리소스 타입: 도메인 SSL
                    resourceId: @event.Domain, // 리소스 ID: 도메인 이름 사용 (ID가 없으므로)
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SslCertificateExpiringEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}