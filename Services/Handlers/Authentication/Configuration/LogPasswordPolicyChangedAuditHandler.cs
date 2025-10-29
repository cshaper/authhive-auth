// File: AuthHive.Auth/Services/Handlers/Authentication/Configuration/LogPasswordPolicyChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events;

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Configuration
{
    /// <summary>
    /// 조직의 비밀번호 정책 변경 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogPasswordPolicyChangedAuditHandler :
        IDomainEventHandler<PasswordPolicyChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPasswordPolicyChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPasswordPolicyChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogPasswordPolicyChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// PasswordPolicyChangedEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(PasswordPolicyChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // 수정된 이벤트에 따라 AggregateId에서 OrganizationId를 가져옵니다.
            var organizationId = @event.AggregateId; 
            var initiator = @event.TriggeredBy ?? Guid.Empty; // 시스템 변경일 수 있음

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PasswordPolicyChanged event. Organization: {OrganizationId}, TriggeredBy: {TriggeredBy}",
                    organizationId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["triggered_by"] = initiator,
                    ["source"] = @event.Source ?? "Unknown",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Medium.ToString() // 정책 변경은 중간 중요도
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Configuration, // '설정' 또는 '보안' 타입
                    "SECURITY_POLICY_PASSWORD_UPDATED",
                    initiator, // connectedId (작업 수행 주체)
                    success: true,
                    errorMessage: null,
                    resourceType: "OrganizationPolicy", // 리소스는 '조직 정책'
                    resourceId: organizationId.ToString(), // 리소스 ID는 '조직 ID'
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PasswordPolicyChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}