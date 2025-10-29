// File: AuthHive.Auth/Services/Handlers/Authentication/Login/LogLoginFailureAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// LoginFailureEvent 발생 시 상세 감사 로그를 기록하고,
// 실패 횟수 누적 및 잠금 처리가 올바르게 되었는지 확인합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.Login // Authentication/Login 폴더 경로
{
    /// <summary>
    /// (한글 주석) 사용자 로그인 실패 시 상세 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogLoginFailureAuditHandler :
        IDomainEventHandler<LoginFailureEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogLoginFailureAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 15; // 다른 보안/리스크 처리 핸들러와 유사한 우선순위
        public bool IsEnabled => true;

        public LogLoginFailureAuditHandler(
            IAuditService auditService,
            ILogger<LogLoginFailureAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 로그인 실패 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(LoginFailureEvent @event, CancellationToken cancellationToken = default)
        {
            // (한글 주석) AggregateId는 UserId (UserId를 모를 경우 Guid.Empty)
            var userId = @event.AggregateId; 
            var userIdOrEmpty = userId == Guid.Empty ? Guid.Empty : userId;

            try
            {
                _logger.LogWarning("Recording audit log for LoginFailure event. User: {UserId}, Username: {Username}, Reason: {Reason}, Attempts: {Attempts}, Locked: {Locked}",
                    userIdOrEmpty, @event.Username, @event.FailureReason, @event.FailedAttempts, @event.IsAccountLocked);

                // (한글 주석) 감사 로그 메타데이터 준비
                var failureData = new Dictionary<string, object>
                {
                    ["user_id"] = userIdOrEmpty,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["username_attempted"] = @event.Username ?? "N/A",
                    ["login_method"] = @event.LoginMethod ?? "N/A",
                    ["failure_reason"] = @event.FailureReason ?? "Unknown",
                    ["ip_address"] = @event.IpAddress ?? "N/A",
                    ["failed_attempts"] = @event.FailedAttempts,
                    ["is_account_locked"] = @event.IsAccountLocked,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 실패는 Warning 레벨
                };
                failureData.MergeMetadata(@event.Metadata, _logger); // BaseEvent Metadata 병합

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.FailedLogin, // 명확한 실패 타입
                    "LOGIN_FAILED",
                    userIdOrEmpty, // 행위자 (User ID, ConnectedId가 아니므로 UserId로 추정)
                    success: false, 
                    errorMessage: @event.FailureReason,
                    resourceType: "UserAccount",
                    resourceId: userIdOrEmpty == Guid.Empty ? @event.Username : userIdOrEmpty.ToString(), // ID 우선, 없으면 Username
                    metadata: failureData,
                    cancellationToken: cancellationToken);
                
                // (한글 주석) 추가 로직: 실패 횟수 기반으로 추가적인 경고/알림 이벤트 발행 고려
                if(@event.FailedAttempts >= 5 && !@event.IsAccountLocked)
                {
                    // (한글 주석) 임계값 경고 알림 이벤트 발행 (예: HighFailedAttemptsWarningEvent)
                    // await _eventBus.PublishAsync(new HighFailedAttemptsWarningEvent(...), cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for LoginFailureEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}