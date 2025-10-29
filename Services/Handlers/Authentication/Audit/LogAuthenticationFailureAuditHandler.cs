// File: AuthHive.Auth/Services/Handlers/Authentication/Audit/LogAuthenticationFailureAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// AuthenticationFailureEvent 발생 시 감사 로그를 기록합니다.
// (LogAuthenticationAttemptAuditHandler를 보완하여 실패 상세 정보 기록)
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


namespace AuthHive.Auth.Handlers.Authentication.Audit
{
    /// <summary>
    /// (한글 주석) 인증 실패 시 상세 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAuthenticationFailureAuditHandler :
        IDomainEventHandler<AuthenticationFailureEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAuthenticationFailureAuditHandler> _logger;

        public int Priority => 11; // Attempt 핸들러 다음에 실행될 수 있도록
        public bool IsEnabled => true;

        public LogAuthenticationFailureAuditHandler(
            IAuditService auditService,
            ILogger<LogAuthenticationFailureAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 인증 실패 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AuthenticationFailureEvent @event, CancellationToken cancellationToken = default)
        {
            // (한글 주석) UserId는 AggregateId 사용 (null 가능)
            var userId = @event.AggregateId;
            var userIdOrDefault = userId == Guid.Empty ? (Guid?)null : userId; // UserId가 Empty면 null로 처리

            try
            {
                _logger.LogWarning("Recording audit log for AuthenticationFailure event. User: {UserId}, Username: {Username}, Method: {Method}, Reason: {Reason}",
                    userIdOrDefault ?? Guid.Empty, @event.Username, @event.AuthMethod, @event.FailureReason); // 실패는 Warning 레벨

                // (한글 주석) 감사 로그 메타데이터 준비
                var failureData = new Dictionary<string, object>
                {
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["user_id"] = userIdOrDefault ?? Guid.Empty, // Nullable Guid 처리
                    ["username_attempted"] = @event.Username ?? "N/A",
                    ["auth_method"] = @event.AuthMethod ?? "N/A",
                    ["failure_reason"] = @event.FailureReason ?? "Unknown",
                    ["ip_address"] = @event.ClientIpAddress ?? "N/A", // BaseEvent 속성 사용
                    ["user_agent"] = @event.UserAgent ?? "N/A", // BaseEvent 속성 사용
                    ["attempt_count"] = @event.AttemptCount,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 심각도 포함
                };
                failureData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.FailedLogin, // 명확한 실패 타입 사용
                    "AUTHENTICATION_FAILED",
                    userIdOrDefault ?? Guid.Empty, // 행위자 (사용자 ID)
                    success: false, // 실패 이벤트
                    errorMessage: @event.FailureReason, // 실패 사유
                    resourceType: "AuthenticationAttempt",
                    resourceId: userIdOrDefault?.ToString() ?? @event.Username, // ID 우선, 없으면 이름
                    metadata: failureData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AuthenticationFailureEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}