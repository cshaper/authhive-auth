// [AuthHive.Auth] Handlers/Audit/SessionCreatedAuditLogHandler.cs
// v17 CQRS "본보기": 'SessionCreatedEvent' (알림)를 구독(Handle)합니다.
// (SOP 2-Notify-C)
//
// 1. INotificationHandler<T>: 'SessionCreatedEvent'를 구독하는 "부가 작업" 전문가입니다.
// 2. "번역": 이벤트(Event)의 데이터를 감사(Audit) Command로 "번역"합니다.
// 3. Mediator (Send): 'CreateAuditLogCommand'를 전송하여 감사 로직을 위임합니다.

using AuthHive.Core.Enums.Auth; // [v17] AuthenticationMethod (번역 소스)
using AuthHive.Core.Enums.Core; // [v17] AuditActionType (번역 대상)
using AuthHive.Core.Models.Audit.Commands; // [v17] CreateAuditLogCommand
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionCreatedEvent (구독 대상)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Audit
{
    /// <summary>
    /// [v17] "세션 생성 시 감사 로그" 핸들러 (SOP 2-Notify-C)
    /// 'SessionCreatedEvent' 알림을 구독(Handle)하고,
    /// 'CreateAuditLogCommand'로 "번역"하여 Mediator로 전송(Send)합니다.
    /// v16 'SessionEventHandler'의 감사 로직을 이관받습니다.
    /// </summary>
    public class SessionCreatedAuditLogHandler : INotificationHandler<SessionCreatedEvent>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<SessionCreatedAuditLogHandler> _logger;

        public SessionCreatedAuditLogHandler(
            IMediator mediator,
            ILogger<SessionCreatedAuditLogHandler> logger)
        {
            _mediator = mediator;
            _logger = logger;
        }

        /// <summary>
        /// SessionCreatedEvent 알림을 처리합니다.
        /// </summary>
        public async Task Handle(SessionCreatedEvent notification, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling SessionCreatedEvent for Session {SessionId}. Translating to CreateAuditLogCommand.", notification.AggregateId);

            try
            {
                // 1. [v17 "번역" 로직] 이벤트(Event) -> 커맨드(Command)
                // "세션 생성" 이벤트를 "감사 로그 생성" 명령으로 "번역"합니다.
                // v16 'SessionEventHandler'가 'AuditActionType.Login'을 사용했던 로직을 이관합니다.
                var auditAction = TranslateAuthMethodToAuditAction(notification.AuthenticationMethod);

                // "계약서"에서 확인한 'CreateAuditLogCommand'의 생성자를 호출합니다.
                var auditCommand = new CreateAuditLogCommand(
                    actionType: auditAction.ActionType,
                    action: auditAction.ActionName,
                    success: true,
                    
                    // Context (Event -> Command)
                    organizationId: notification.OrganizationId,
                    applicationId: null, // 세션 생성은 특정 앱 컨텍스트가 아님
                    connectedId: notification.ConnectedId, // [v17] 'TriggeredBy'는 ConnectedId
                    ipAddress: notification.IpAddress,
                    userAgent: notification.UserAgent,
                    requestId: notification.RequestId, // BaseEvent에서 상속됨
                    
                    // Payload (Event -> Command)
                    resourceType: "Session", // 감사 대상 리소스
                    resourceId: notification.AggregateId.ToString(), // SessionId
                    errorCode: null,
                    errorMessage: null,
                    
                    // 이벤트의 핵심 페이로드만 단순 직렬화하여 Metadata에 저장
                    metadata: JsonSerializer.Serialize(new 
                    { 
                        UserId = notification.UserId,
                        Method = notification.AuthenticationMethod.ToString(),
                        SessionType = notification.SessionType.ToString(),
                        Level = notification.Level.ToString()
                    }),
                    
                    durationMs: (int)(DateTime.UtcNow - notification.OccurredAt).TotalMilliseconds, // 이벤트 발생 후 핸들러 실행까지의 시간
                    severity: AuditEventSeverity.Info // 로그인은 'Info' 레벨
                );

                // 2. [v17 전문가 위임]
                // 'CreateAuditLogCommandHandler'에게 "감사 로그 생성"을 Send로 위임합니다.
                // 이 핸들러는 감사 로그 저장(DB)에 대한 책임을 지지 않습니다.
                await _mediator.Send(auditCommand, cancellationToken);
            }
            catch (Exception ex)
            {
                // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
                // 예외를 전파하면 'SessionCreatedEvent'를 구독하는 다른 핸들러(예: 캐시 핸들러)가
                // 실행되지 못하고 트랜잭션이 롤백될 수 있습니다.
                _logger.LogError(ex, "Failed to create audit log for SessionCreatedEvent {SessionId}", notification.AggregateId);
            }
        }

        /// <summary>
        /// v17 "번역" 헬퍼 메서드
        /// 인증 방법(Event)을 감사 액션(Command)으로 변환합니다.
        /// </summary>
        private (AuditActionType ActionType, string ActionName) TranslateAuthMethodToAuditAction(AuthenticationMethod method)
        {
            // "계약서"에서 확인한 'AuditActionType' Enum을 사용합니다.
            // v16 'SessionEventHandler'는 'AuditActionType.Login'을 사용했습니다.
            switch (method)
            {
                case AuthenticationMethod.SSO:
                case AuthenticationMethod.SAML:
                    return (AuditActionType.Login, "sso.login.success"); // 'Login' 타입, 'sso.login.success' 액션
                
                case AuthenticationMethod.SocialLogin:
                    return (AuditActionType.Login, "social.login.success");

                case AuthenticationMethod.Password:
                case AuthenticationMethod.MagicLink:
                case AuthenticationMethod.EmailOTP:
                case AuthenticationMethod.SMS:
                case AuthenticationMethod.Biometric:
                case AuthenticationMethod.Passkey:
                    return (AuditActionType.Login, "auth.login.success"); // 'Login' 타입

                default:
                    return (AuditActionType.Authentication, "auth.session.created"); // 기타 'Authentication' 타입
            }
        }
    }
}