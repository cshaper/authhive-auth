// File: AuthHive.Auth/Services/Handlers/Authentication/Logout/LogLogoutAuditHandler.cs
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
    /// 단일 세션 로그아웃 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogLogoutAuditHandler :
        IDomainEventHandler<LogoutEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogLogoutAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogLogoutAuditHandler(
            IAuditService auditService,
            ILogger<LogLogoutAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// LogoutEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(LogoutEvent @event, CancellationToken cancellationToken = default)
        {
            var sessionId = @event.AggregateId; // 이벤트의 AggregateId는 SessionId입니다.
            var userId = @event.UserId;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for Logout event. Session: {SessionId}, User: {UserId}, Reason: {Reason}, TriggeredBy: {TriggeredBy}",
                    sessionId, userId, @event.Reason, @event.TriggeredBy);

                // 감사 로그 메타데이터 준비
                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["session_id"] = sessionId,
                    ["reason"] = @event.Reason.ToString(),
                    ["triggered_by"] = @event.TriggeredBy ?? Guid.Empty,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info // 일반 로그아웃은 정보 수준
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Logout,
                    "USER_LOGOUT", // ActionKey
                    @event.TriggeredBy ?? Guid.Empty, // connectedId
                    success: true,
                    errorMessage: null,
                    resourceType: "Session", // 리소스는 '세션'
                    resourceId: sessionId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for LogoutEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}