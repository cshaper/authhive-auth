// File: AuthHive.Auth/Services/Handlers/Authentication/Mfa/RespondToMfaFailureThresholdHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// MfaFailureThresholdExceededEvent 발생 시 대응 조치를 수행합니다.
// (예: 감사 로그 기록, 계정 잠금 이벤트 발행)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService, IEventBus
// using AuthHive.Core.Interfaces.User.Service; // 필요 시 IUserService 주입
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
// using AuthHive.Core.Models.User.Events.Lifecycle; // AccountLockedEvent 등 사용 시
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.Mfa // (한글 주석) Authentication/Mfa 폴더 경로
{
    /// <summary>
    /// (한글 주석) MFA 실패 임계값 초과 시 감사 로그 기록 및 계정 잠금 등의 조치를 수행하는 핸들러입니다.
    /// </summary>
    public class RespondToMfaFailureThresholdHandler :
        IDomainEventHandler<MfaFailureThresholdExceededEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus; // 다른 조치를 위한 이벤트 발행
        // private readonly IUserService _userService; // 직접 계정 상태 변경 시 필요
        private readonly ILogger<RespondToMfaFailureThresholdHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public RespondToMfaFailureThresholdHandler(
            IAuditService auditService,
            IEventBus eventBus,
            // IUserService userService,
            ILogger<RespondToMfaFailureThresholdHandler> logger)
        {
            _auditService = auditService;
            _eventBus = eventBus;
            // _userService = userService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) MFA 실패 임계값 초과 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(MfaFailureThresholdExceededEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // 이벤트의 AggregateId가 사용자 ID
            try
            {
                _logger.LogWarning("MFA failure threshold exceeded for User {UserId}. Method: {Method}, Attempts: {Attempts}, AccountLocked: {Locked}",
                    userId, @event.Method, @event.FailedAttempts, @event.AccountLocked);

                // (한글 주석) 1. 감사 로그 기록
                var mfaFailureData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["method"] = @event.Method,
                    ["failed_attempts"] = @event.FailedAttempts,
                    ["account_locked"] = @event.AccountLocked,
                    ["locked_until"] = (object?)@event.LockedUntil?.ToString("yyyy-MM-dd HH:mm UTC") ?? DBNull.Value,
                    ["occurred_at"] = @event.OccurredAt
                };
                mfaFailureData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 임계값 초과는 일종의 차단/실패 상황
                    "MFA_FAILURE_THRESHOLD_EXCEEDED",
                    @event.TriggeredBy ?? userId, // 행위자 (보통 사용자 자신)
                    success: false, // 임계값 초과는 실패 상황으로 간주
                    resourceType: "UserAccountSecurity",
                    resourceId: userId.ToString(),
                    metadata: mfaFailureData,// 심각도 설정 (CS1739 오류 방지 위해 제거, metadata에 포함)
                    cancellationToken: cancellationToken);

                 // (한글 주석) metadata에 severity 추가 (CS1739 회피)
                 mfaFailureData["severity"] = AuditEventSeverity.Warning.ToString();


                // (한글 주석) 2. 계정이 잠겼다면 관련 조치 수행 (예: 이벤트 발행)
                if (@event.AccountLocked)
                {
                    _logger.LogWarning("Account {UserId} locked due to MFA failures.", userId);

                    // (한글 주석) 방법 A: UserAccountLockedEvent 발행 (권장 - 다른 핸들러가 처리)
                    // (가정) UserAccountLockedEvent 생성자가 필요한 파라미터를 받도록 정의되어 있음
                    // var lockedEvent = new UserAccountLockedEvent(
                    //     userId,
                    //     lockedBySystem: true, // 시스템에 의해 잠김
                    //     reason: $"Exceeded MFA failure threshold ({ @event.FailedAttempts } attempts on { @event.Method }).",
                    //     lockedUntil: @event.LockedUntil,
                    //     organizationId: @event.OrganizationId,
                    //     correlationId: @event.CorrelationId
                    // );
                    // await _eventBus.PublishAsync(lockedEvent, cancellationToken);


                    // (한글 주석) 방법 B: IUserService를 통해 직접 계정 상태 변경 (덜 권장 - 책임 분산 저해)
                    // await _userService.LockAccountAsync(userId, TimeSpan.FromMinutes(30), "MFA failure threshold exceeded", cancellationToken);
                }

                // (한글 주석) 3. 필요 시 사용자에게 알림 발송 (이벤트 발행 등)
                // var notificationEvent = new NotifyUserOfAccountActivityEvent(...);
                // await _eventBus.PublishAsync(notificationEvent, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process MfaFailureThresholdExceededEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("RespondToMfaFailureThresholdHandler initialized.");
             return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (가정) IAuditService, IEventBus가 IHealthCheckable 구현
             return IsEnabled
                    && await _auditService.IsHealthyAsync(cancellationToken)
                    && await _eventBus.IsHealthyAsync(cancellationToken);
                    // && await _userService.IsHealthyAsync(cancellationToken); // 필요 시 추가
        }
        #endregion
    }
}