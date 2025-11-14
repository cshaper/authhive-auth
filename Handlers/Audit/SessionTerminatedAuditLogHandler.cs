// [AuthHive.Auth] Handlers/Audit/SessionTerminatedAuditLogHandler.cs
// v17 CQRS "본보기": 'SessionTerminatedEvent' (알림)를 구독(Handle)합니다.
// (SOP 2-Notify-C)
//
// 1. INotificationHandler<T>: 'SessionTerminatedEvent'를 구독하는 "부가 작업" 전문가입니다.
// 2. "번역": 이벤트(Event)의 데이터를 감사(Audit) Command로 "번역"합니다.
// 3. "v16 로직 이관": 'ShouldAuditTermination' 로직을 포함하여, 'UserLogout' 등은 감사하지 않습니다.
// 4. Mediator (Send): 'CreateAuditLogCommand'를 전송하여 감사 로직을 위임합니다.

using AuthHive.Core.Enums.Auth; // SessionEndReason
using AuthHive.Core.Enums.Core; // AuditActionType
using AuthHive.Core.Models.Audit.Commands; // [v17] CreateAuditLogCommand
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionTerminatedEvent (구독 대상)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionEndReason

namespace AuthHive.Auth.Handlers.Audit
{
    /// <summary>
    /// [v17] "세션 종료 시 감사 로그" 핸들러 (SOP 2-Notify-C)
    /// 'SessionTerminatedEvent' 알림을 구독(Handle)하고,
    /// v16 'SessionEventHandler'의 감사 로직을 이관합니다.
    /// </summary>
    public class SessionTerminatedAuditLogHandler : INotificationHandler<SessionTerminatedEvent>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<SessionTerminatedAuditLogHandler> _logger;

        public SessionTerminatedAuditLogHandler(
            IMediator mediator,
            ILogger<SessionTerminatedAuditLogHandler> logger)
        {
            _mediator = mediator;
            _logger = logger;
        }

        /// <summary>
        /// SessionTerminatedEvent 알림을 처리합니다.
        /// </summary>
        public async Task Handle(SessionTerminatedEvent notification, CancellationToken cancellationToken)
        {
            // 1. [v17 로직 이관] v16 'ShouldAuditTermination' 로직 이관 
            // "계약서"에 따라 'EndReason'을 확인합니다.
            // 사용자의 '정상 로그아웃'이나 '단순 만료'는 감사할 필요가 없습니다.
            if (notification.EndReason == SessionEndReason.UserLogout || 
                notification.EndReason == SessionEndReason.Expired)
            {
                _logger.LogDebug("Skipping audit for normal session termination (Reason: {Reason}) for Session {SessionId}.",
                    notification.EndReason, notification.AggregateId);
                return; // 감사(Audit) 중지
            }

            _logger.LogInformation("Handling SessionTerminatedEvent for Session {SessionId} (Reason: {Reason}). Translating to CreateAuditLogCommand.",
                notification.AggregateId, notification.EndReason);

            try
            {
                // 2. [v17 "번역" 로직] 이벤트(Event) -> 커맨드(Command)
                // v16 'SessionEventHandler'의 'SESSION_TERMINATED' 로직을 이관합니다. [cite: 375]
                
                // "계약서"에서 확인한 'CreateAuditLogCommand'의 생성자를 호출합니다.
                var auditCommand = new CreateAuditLogCommand(
                    actionType: AuditActionType.Logout, // v16 'AuditActionType.Logout' 사용 [cite: 376]
                    action: "SESSION_TERMINATED", // v16 [cite: 375]
                    success: true, // 종료 작업 자체는 성공 [cite: 378]
                    
                    // Context (Event -> Command)
                    organizationId: notification.OrganizationId,
                    applicationId: null, // 세션 종료는 앱 컨텍스트가 아님
                    connectedId: notification.TriggeredBy, // 이벤트를 발생시킨 주체
                    ipAddress: null, // 종료 이벤트는 특정 IP에서 발생하지 않음
                    userAgent: null,
                    requestId: notification.RequestId,
                    
                    // Payload (Event -> Command)
                    resourceType: "Session", // v16 [cite: 377]
                    resourceId: notification.AggregateId.ToString(), // SessionId
                    errorCode: null,
                    errorMessage: null,
                    
                    // v16 [cite: 382-386]와 동일하게 종료 사유와 세션 시간을 메타데이터로 저장
                    metadata: JsonSerializer.Serialize(new 
                    { 
                        EndReason = notification.EndReason.ToString(),
                        DurationMinutes = notification.Duration.TotalMinutes
                    }),
                    
                    durationMs: null,
                    severity: AuditEventSeverity.Warning // 정상 종료가 아니므로 'Warning' 레벨
                );

                // 3. [v17 전문가 위임]
                // 'CreateAuditLogCommandHandler'에게 "감사 로그 생성"을 Send로 위임합니다.
                await _mediator.Send(auditCommand, cancellationToken);
            }
            catch (Exception ex)
            {
                // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
                _logger.LogError(ex, "Failed to create audit log for SessionTerminatedEvent {SessionId}", notification.AggregateId);
            }
        }
    }
}