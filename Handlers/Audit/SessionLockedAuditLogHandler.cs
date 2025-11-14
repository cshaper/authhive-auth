// [AuthHive.Auth] Handlers/Audit/SessionLockedAuditLogHandler.cs
// v17 CQRS "본보기": 'SessionLockedEvent' (알림)를 구독(Handle)합니다.
// (SOP 2-Notify-C)
//
// 1. INotificationHandler<T>: 'SessionLockedEvent'를 구독하는 "부가 작업" 전문가입니다.
// 2. "v16 로직 이관": 'RiskScore > 80'일 때만 감사하는 "조건부" 로직을 이관합니다.
// 3. "번역": 이벤트(Event)의 데이터를 감사(Audit) Command로 "번역"합니다.
// 4. Mediator (Send): 'CreateAuditLogCommand'를 전송하여 감사 로직을 위임합니다.

using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core; // [v17] AuditActionType, AuditEventSeverity
using AuthHive.Core.Models.Audit.Commands; // [v17] CreateAuditLogCommand
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionLockedEvent (구독 대상)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Audit
{
    /// <summary>
    /// [v17] "세션 잠금 시 조건부 감사" 핸들러 (SOP 2-Notify-C)
    /// 'SessionLockedEvent' 알림을 구독(Handle)하고,
    /// v16 'SessionEventHandler'의 조건부 감사 로직을 이관합니다.
    /// </summary>
    /// <remarks>
    /// ### [v17 아키텍처 설명]
    /// 
    /// **1. 언제(When) 이 핸들러가 실행되는가?**
    ///    - 'SessionLockedCacheHandler'와 *동시에* 실행됩니다.
    ///    - 시스템이 'SessionLockedEvent'를 발행(Publish)할 때, MediatR이 이 이벤트를 구독하는
    ///      모든 핸들러(Cache, Audit 등)를 실행합니다.
    /// 
    /// **2. 왜(Why) 이 작업이 필요한가? (v16 로직 이관)**
    ///    - v16 'SessionEventHandler' 는 모든 세션 잠금을 감사하지 않았습니다.
    ///    - "단순 임계값"을 초과하는(예: RiskScore > 80) "심각한" 보안 위협만
    ///      감사 로그(Audit Log)에 기록하도록 "조건부" 로직을 수행했습니다.
    ///    - 이 핸들러는 v16의 해당 "조건부" 로직을 그대로 이관합니다.
    /// 
    /// **3. 어떻게(How) 작동하는가?**
    ///    - 'SessionLockedEvent'로부터 'RiskScore'를 확인합니다.
    ///    - v16 "본보기" [cite: 429]와 동일하게 'RiskScore > 80'인지 검사합니다.
    ///    - 조건이 충족되면, 이벤트를 'CreateAuditLogCommand'로 "번역"하여
    ///      'IMediator.Send()'로 전송(Send)합니다.
    /// </remarks>
    public class SessionLockedAuditLogHandler : INotificationHandler<SessionLockedEvent>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<SessionLockedAuditLogHandler> _logger;

        public SessionLockedAuditLogHandler(
            IMediator mediator,
            ILogger<SessionLockedAuditLogHandler> logger)
        {
            _mediator = mediator;
            _logger = logger;
        }

        /// <summary>
        /// SessionLockedEvent 알림을 처리합니다.
        /// </summary>
        public async Task Handle(SessionLockedEvent notification, CancellationToken cancellationToken)
        {
            // 1. [v17 로직 이관] v16 '조건부 감사' 로직 이관 [cite: 428-429]
            // "계약서"에서 확인된 'RiskScore' 속성을 검사합니다.
            if (notification.RiskScore <= 80)
            {
                _logger.LogDebug("Skipping audit for low-risk session lock (Risk: {RiskScore}) for Session {SessionId}.",
                    notification.RiskScore, notification.AggregateId);
                return; // 감사(Audit) 중지
            }

            _logger.LogWarning("Handling SessionLockedEvent for Session {SessionId} (Risk: {RiskScore}). Translating to CreateAuditLogCommand.",
                notification.AggregateId, notification.RiskScore);

            try
            {
                // 2. [v17 "번역" 로직] 이벤트(Event) -> 커맨드(Command)
                // v16 'SessionEventHandler'의 'SESSION_LOCKED_HIGH_RISK' 로직을 이관합니다.
                
                // "계약서"에서 확인한 'CreateAuditLogCommand'의 생성자를 호출합니다.
                var auditCommand = new CreateAuditLogCommand(
                    actionType: AuditActionType.Blocked, // v16 'AuditActionType.Blocked' 사용 [cite: 433]
                    action: "SESSION_LOCKED_HIGH_RISK", // v16
                    success: false, // v16 (보안 위협으로 '실패/차단' 처리) [cite: 436]
                    
                    // Context (Event -> Command)
                    organizationId: notification.OrganizationId,
                    applicationId: null, 
                    connectedId: notification.TriggeredBy, // "계약서" 확인
                    ipAddress: null, // (이벤트 "계약서"에 IP가 없음)
                    userAgent: null,
                    requestId: notification.RequestId,
                    
                    // Payload (Event -> Command)
                    resourceType: "Session", // v16 [cite: 434]
                    resourceId: notification.AggregateId.ToString(), // SessionId
                    errorCode: "HIGH_RISK_SESSION",
                    errorMessage: notification.LockReason,
                    
                    // v16 [cite: 438-441]과 동일하게 위험 점수와 사유를 메타데이터로 저장
                    metadata: JsonSerializer.Serialize(new 
                    { 
                        RiskScore = notification.RiskScore,
                        LockReason = notification.LockReason
                    }),
                    
                    durationMs: null,
                    severity: AuditEventSeverity.Critical // v16 (높은 위험)
                );

                // 3. [v17 전문가 위임]
                // 'CreateAuditLogCommandHandler'에게 "감사 로그 생성"을 Send로 위임합니다.
                await _mediator.Send(auditCommand, cancellationToken);
            }
            catch (Exception ex)
            {
                // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
                _logger.LogError(ex, "Failed to create audit log for SessionLockedEvent {SessionId}", notification.AggregateId);
            }
        }
    }
}