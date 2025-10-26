// File: AuthHive.Auth/Services/Handlers/Authentication/Logout/LogLogoutAllDevicesAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Auth.Extensions; // for MergeMetadata
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Logout
{
    /// <summary>
    /// 모든 디바이스 로그아웃 이벤트(예: 비밀번호 변경 후) 발생 시 감사 로그를 기록합니다.
    /// 이 핸들러는 실제 세션 종료를 수행하지 않으며, 이미 종료된 사실을 로깅합니다.
    /// </summary>
    public class LogLogoutAllDevicesAuditHandler :
        IDomainEventHandler<LogoutAllDevicesEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogLogoutAllDevicesAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러는 중간 우선순위
        public bool IsEnabled => true;

        public LogLogoutAllDevicesAuditHandler(
            IAuditService auditService,
            ILogger<LogLogoutAllDevicesAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// LogoutAllDevicesEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(LogoutAllDevicesEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // 이벤트의 AggregateId는 UserId입니다.
            try
            {
                _logger.LogInformation(
                    "Recording audit log for LogoutAllDevices event. User: {UserId}, Reason: {Reason}, Count: {Count}, TriggeredBy: {TriggeredBy}",
                    userId, @event.Reason, @event.RevokedSessionCount, @event.TriggeredBy);

                // 감사 로그 메타데이터 준비 (LogForcedLogoutAuditHandler 패턴 사용)
                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["revoked_session_count"] = @event.RevokedSessionCount,
                    ["reason"] = @event.Reason,
                    // [수정됨] CS8601: Possible null reference assignment.
                    ["triggered_by"] = @event.TriggeredBy ?? Guid.Empty, 
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString() // 모든 세션 종료는 중요 이벤트
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Logout, // 또는 UserManagement
                    "USER_LOGOUT_ALL_SESSIONS", // ActionKey
                    // [수정됨] CS1503: cannot convert from 'Guid?' to 'Guid'
                    @event.TriggeredBy ?? Guid.Empty, 
                    success: true,
                    errorMessage: null,
                    resourceType: "User", // 리소스는 '사용자'
                    resourceId: userId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for LogoutAllDevicesEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}