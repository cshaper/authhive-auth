// File: AuthHive.Auth/Services/Handlers/Authentication/Logout/LogForcedLogoutAuditHandler.cs
// ----------------------------------------------------------------------
// [수정됨] ForcedLogoutEvent의 ConnectedId를 감사 로그에 포함합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.Logout
{
    /// <summary>
    /// (한글 주석) 세션 강제 종료 이벤트 발생 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogForcedLogoutAuditHandler :
        IDomainEventHandler<ForcedLogoutEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogForcedLogoutAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogForcedLogoutAuditHandler(
            IAuditService auditService,
            ILogger<LogForcedLogoutAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 강제 로그아웃 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ForcedLogoutEvent @event, CancellationToken cancellationToken = default)
        {
            var sessionId = @event.AggregateId;
            try
            {
                _logger.LogCritical("Recording audit log for ForcedLogout event. Session: {SessionId}, User: {UserId}, ConnectedId: {ConnectedId}, Reason: {Reason}",
                    sessionId, @event.UserId, @event.ConnectedId, @event.ForceReason); // ConnectedId 포함 로깅

                // (한글 주석) 감사 로그 메타데이터 준비
                var logoutData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId,
                    ["connected_id"] = @event.ConnectedId, // ❗️ ConnectedId 추가
                    ["session_id"] = sessionId,
                    ["reason"] = @event.ForceReason,
                    ["forced_by"] = @event.TriggeredBy ?? Guid.Empty,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty, // BaseEvent에서 OrganizationId 사용
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                logoutData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Logout,
                    "SESSION_FORCED_LOGOUT",
                    @event.TriggeredBy ?? Guid.Empty,
                    success: true,
                    errorMessage: null,
                    resourceType: "Session",
                    resourceId: sessionId.ToString(),
                    metadata: logoutData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ForcedLogoutEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}