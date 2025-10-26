// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogBlockedIpAccessAttemptAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// BlockedIpAccessAttemptEvent 발생 시 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // 수정된 이벤트 사용
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// (한글 주석) 차단된 IP 접근 시도 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogBlockedIpAccessAttemptAuditHandler :
        IDomainEventHandler<BlockedIpAccessAttemptEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogBlockedIpAccessAttemptAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogBlockedIpAccessAttemptAuditHandler(
            IAuditService auditService,
            ILogger<LogBlockedIpAccessAttemptAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 차단된 IP 접근 시도 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(BlockedIpAccessAttemptEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Recording audit log for BlockedIpAccessAttempt event. IP: {IP}, Username: {Username}, Target: {Target}",
                    @event.IpAddress, @event.UsernameAttempted ?? "N/A", @event.TargetResource ?? "N/A"); // Warning 레벨

                // (한글 주석) 감사 로그 메타데이터 준비
                var attemptData = new Dictionary<string, object>
                {
                    ["ip_address"] = @event.IpAddress,
                    ["username_attempted"] = @event.UsernameAttempted ?? "N/A",
                    ["target_resource"] = @event.TargetResource ?? "N/A",
                    ["blocking_rule_id"] = @event.BlockingRuleId ?? "N/A",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // 차단된 IP 접근은 Critical
                };
                attemptData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 명확한 차단 액션
                    "BLOCKED_IP_ACCESS_ATTEMPT",
                    Guid.Empty, // 행위자는 특정 사용자가 아님 (시스템)
                    success: false, // 접근 시도 자체는 실패(차단)
                    errorMessage: $"Access attempt from blocked IP {@event.IpAddress}",
                    resourceType: "NetworkAccess",
                    resourceId: @event.IpAddress, // 리소스는 IP 주소 자체
                    metadata: attemptData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BlockedIpAccessAttemptEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}