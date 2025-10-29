// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogBruteForceAttackAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// BruteForceAttackDetectedEvent 발생 시 감사 로그를 기록합니다.
// (무차별 대입 공격 시도 추적)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For string.Join
using System.Threading;
using System.Threading.Tasks;
 // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// (한글 주석) 무차별 대입 공격 감지 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogBruteForceAttackAuditHandler :
        IDomainEventHandler<BruteForceAttackDetectedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogBruteForceAttackAuditHandler> _logger;

        public int Priority => 5; // 보안 이벤트 중 최우선 순위
        public bool IsEnabled => true;

        public LogBruteForceAttackAuditHandler(
            IAuditService auditService,
            ILogger<LogBruteForceAttackAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 무차별 대입 공격 감지 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(BruteForceAttackDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogCritical("Recording audit log for BruteForceAttackDetected event from IP: {IP}. Action Taken: {Action}, Affected Users: {UserCount}",
                    @event.IpAddress, @event.ActionTaken, @event.AffectedUsers?.Count ?? 0); // Critical 레벨로 로깅

                // (한글 주석) 감사 로그 메타데이터 준비
                var attackData = new Dictionary<string, object>
                {
                    ["ip_address"] = @event.IpAddress,
                    ["attempts_count"] = @event.AttemptsCount,
                    ["time_window_seconds"] = @event.TimeWindow.TotalSeconds,
                    ["action_taken"] = @event.ActionTaken,
                    ["affected_users"] = @event.AffectedUsers ?? new List<string>(), // null 방지
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty, // Nullable Guid
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // 심각도 포함
                };
                attackData.MergeMetadata(@event.Metadata, _logger); // BaseEvent Metadata 병합

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 공격 시도는 '차단' 또는 '시스템 경고'
                    "BRUTE_FORCE_ATTACK_DETECTED",
                    Guid.Empty, // 행위자는 특정 사용자가 아닌 시스템
                    success: false, // 보안 위협 이벤트는 실패(부정적)로 간주
                    errorMessage: $"Brute force attack detected from {@event.IpAddress} ({@event.AttemptsCount} attempts). Action: {@event.ActionTaken}",
                    resourceType: "SystemSecurity",
                    resourceId: @event.IpAddress, // 공격 근원지 IP를 리소스로 식별
                    metadata: attackData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BruteForceAttackDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}