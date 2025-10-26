// File: AuthHive.Auth/Services/Handlers/Authentication/Audit/LogAuthenticationAttemptAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// AuthenticationAttemptedEvent 발생 시 감사 로그를 기록합니다.
// (성공/실패 모든 시도 기록)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Auth; // AuthenticationResult
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions;

namespace AuthHive.Auth.Handlers.Authentication.Audit // Authentication/Audit 폴더
{
    /// <summary>
    /// (한글 주석) 모든 인증 시도(성공/실패)에 대한 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAuthenticationAttemptAuditHandler :
        IDomainEventHandler<AuthenticationAttemptedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAuthenticationAttemptAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAuthenticationAttemptAuditHandler(
            IAuditService auditService,
            ILogger<LogAuthenticationAttemptAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 인증 시도 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AuthenticationAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            // (한글 주석) UserId가 null일 수 있으므로 AggregateId 사용 (OrgId)
            var orgId = @event.AggregateId;
            try
            {
                _logger.LogInformation("Recording audit log for AuthenticationAttempted event. Org: {OrgId}, User: {UserId}, Method: {Method}, Success: {Success}",
                    orgId, @event.UserId ?? Guid.Empty, @event.Method, @event.IsSuccess);

                // (한글 주석) 감사 로그 메타데이터 준비
                var attemptData = new Dictionary<string, object>
                {
                    ["organization_id"] = orgId,
                    ["user_id"] = @event.UserId ?? Guid.Empty, // Nullable Guid 처리
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty, // Nullable Guid 처리
                    ["username_attempted"] = @event.Username ?? "N/A", // Null 처리
                    ["method"] = @event.Method.ToString(),
                    ["is_success"] = @event.IsSuccess,
                    ["failure_reason"] = @event.FailureReason?.ToString() ?? "N/A", // Nullable Enum 처리
                    ["ip_address"] = @event.IpAddress ?? "N/A", // Null 처리
                    ["device_info"] = @event.DeviceInfo ?? "N/A", // Null 처리
                    ["occurred_at"] = @event.OccurredAt
                };
                attemptData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    // (한글 주석) 성공/실패에 따라 다른 ActionType 사용
                    @event.IsSuccess ? AuditActionType.Login : AuditActionType.FailedLogin,
                    "AUTHENTICATION_ATTEMPTED",
                    @event.ConnectedId ?? Guid.Empty, // 행위자 (ConnectedId가 있으면 사용)
                    success: @event.IsSuccess,
                    errorMessage: @event.IsSuccess ? null : @event.FailureReason?.ToString(), // 실패 시 이유 전달
                    resourceType: "AuthenticationAttempt",
                    resourceId: @event.UserId?.ToString() ?? @event.Username, // 사용자 특정 가능하면 ID, 아니면 이름
                    metadata: attemptData,
                    // (한글 주석) 심각도 설정 (CS1739 방지 위해 metadata에 포함)
                    cancellationToken: cancellationToken);

                // (한글 주석) metadata에 심각도 추가
                attemptData["severity"] = @event.IsSuccess ? AuditEventSeverity.Info.ToString() : AuditEventSeverity.Warning.ToString();

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AuthenticationAttemptedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}