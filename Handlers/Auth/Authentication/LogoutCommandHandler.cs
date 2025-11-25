// // [AuthHive.Auth] Handlers/Auth/Authentication/LogoutCommandHandler.cs
// // v17 CQRS "본보기": 'LogoutCommand' (로그아웃)를 처리합니다.
// // (SOP 2-Write-U/D)
// //
// // 1. Logic (v16 이관): AuthenticationManager.RevokeTokenAsync/RevokeAllSessionsAsync 로직을 이관합니다.
// // 2. Logic (v17 위임): v16이 ISessionService.EndSessionAsync를 호출하던 것을,
// //    이 핸들러가 직접 Session 엔티티를 수정하도록 변경합니다.
// // 3. Mediator (Publish): 'LogoutEvent'를 발행하여 캐시/감사 작업을 위임합니다.
// // 4. Response: 'IRequest<Unit>' 계약에 따라 Unit.Value (void)를 반환합니다.

// using AuthHive.Core.Entities.Auth;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Models.Auth.Authentication.Commands;
// using AuthHive.Core.Models.Auth.Authentication.Events; // LogoutEvent
// using MediatR;
// using Microsoft.Extensions.Logging;
// using Microsoft.EntityFrameworkCore; // [v17] ToListAsync()를 위해 추가
// using System;
// using System.Linq; // [v17] Where()를 위해 추가
// using System.Threading;
// using System.Threading.Tasks;
// using static AuthHive.Core.Enums.Auth.SessionEnums;

// namespace AuthHive.Auth.Handlers.Auth.Authentication
// {
//     /// <summary>
//     /// [v17] "로그아웃" 유스케이스 핸들러 (SOP 2-Write-U/D)
//     /// v16 AuthenticationManager.RevokeTokenAsync/RevokeAllSessionsAsync 로직 이관
//     /// </summary>
//     public class LogoutCommandHandler : IRequestHandler<LogoutCommand, Unit>
//     {
//         private readonly ISessionRepository _sessionRepository;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly ILogger<LogoutCommandHandler> _logger;
//         private readonly IDateTimeProvider _dateTimeProvider;

//         public LogoutCommandHandler(
//             ISessionRepository sessionRepository,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             ILogger<LogoutCommandHandler> logger,
//             IDateTimeProvider dateTimeProvider)
//         {
//             _sessionRepository = sessionRepository;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _logger = logger;
//             _dateTimeProvider = dateTimeProvider;
//         }

//         public async Task<Unit> Handle(LogoutCommand command, CancellationToken cancellationToken)
//         {
//             // v17: 이 핸들러는 'TerminateAllSessions' 플래그를 처리할 책임이 있습니다.
//             // v16 AuthenticationManager.RevokeAllSessionsAsync 로직 이관 
//             if (command.TerminateAllSessions)
//             {
//                 await HandleTerminateAllSessions(command, cancellationToken);
//                 return Unit.Value;
//             }

//             // --- v16 AuthenticationManager.RevokeTokenAsync 로직 이관  ---
            
//             // 1. [SOP 2.3.2] 엔티티 조회
//             var session = await _sessionRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 SessionId

//             if (session == null)
//             {
//                 _logger.LogWarning("LogoutCommand failed: Session {SessionId} not found", command.AggregateId);
//                 return Unit.Value; // v16과 동일하게 실패 시 조용히 반환 [cite: 191-193]
//             }
            
//             // 2. [SOP 2.3.1] 유효성 검증
//             if (session.UserId != command.UserId)
//             {
//                  _logger.LogWarning("LogoutCommand failed: Session {SessionId} owner mismatch. Expected {ExpectedUser}, Got {GotUser}", 
//                     command.AggregateId, command.UserId, session.UserId);
//                 return Unit.Value; // 보안: 사용자 불일치 시 조용히 반환
//             }
            
//             if (session.Status == SessionStatus.Terminated || session.Status == SessionStatus.Expired)
//             {
//                 _logger.LogInformation("LogoutCommand: Session {SessionId} is already terminated.", session.Id);
//                 return Unit.Value; // 멱등성
//             }

//             var utcNow = _dateTimeProvider.UtcNow;
//             TimeSpan duration = utcNow - session.CreatedAt;

//             // 3. [SOP 2.3.3] 엔티티 상태 변경
//             session.End(command.Reason); // v17 SessionEntity 메서드 사용 [cite: 139-144]

//             // 4. [SOP 2.3.4, 2.3.5] 저장
//             await _sessionRepository.UpdateAsync(session, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 5. [SOP 2.3.6] 이벤트 발행 (v16 감사/캐시 로직 위임)
//             // LogoutEvent 발행
//             var logoutEvent = new LogoutEvent(
//                 sessionId: session.Id,
//                 userId: session.UserId,
//                 reason: command.Reason,
//                 triggeredBy: command.TriggeredBy
//             );
//             await _mediator.Publish(logoutEvent, cancellationToken);
            
//             _logger.LogInformation("LogoutCommand successful: Session {SessionId} ended for User {UserId}. Reason: {Reason}",
//                 session.Id, command.UserId, command.Reason);

//             // 6. [SOP 2.3.7] 응답 반환
//             return Unit.Value;
//         }

//         /// <summary>
//         /// v16 AuthenticationManager.RevokeAllSessionsAsync 로직 이관 
//         /// </summary>
//         private async Task HandleTerminateAllSessions(LogoutCommand command, CancellationToken cancellationToken)
//         {
//             _logger.LogInformation("Handling TerminateAllSessions for User {UserId}, excluding Session {SessionId}",
//                 command.UserId, command.AggregateId);
                
//             // v16 로직: 사용자의 "모든" 세션 조회 (v17 Repository 사용) [cite: 593-601]
//             var allSessions = await _sessionRepository.GetByUserIdAsync(command.UserId, cancellationToken);

//             // v16 SessionService의 필터링 로직을 핸들러로 이관 [cite: 847-848]
//             var activeSessions = allSessions.Where(s => s.Status == SessionStatus.Active);

//             var utcNow = _dateTimeProvider.UtcNow;
//             int revokedCount = 0;

//             foreach (var session in activeSessions)
//             {
//                 // v16 로직: 현재 세션(AggregateId)은 제외 [cite: 603-616]
//                 if (session.Id == command.AggregateId)
//                 {
//                     continue; 
//                 }

//                 // v16 로직: 각 세션 종료 [cite: 619-640]
//                 TimeSpan duration = utcNow - session.CreatedAt;
//                 session.End(command.Reason); // v17 Entity 메서드 사용 [cite: 139-144]
                
//                 await _sessionRepository.UpdateAsync(session, cancellationToken);
                
//                 // v17 이벤트 발행
//                 var logoutEvent = new LogoutEvent(
//                     sessionId: session.Id,
//                     userId: session.UserId,
//                     reason: command.Reason,
//                     triggeredBy: command.TriggeredBy
//                 );
//                 await _mediator.Publish(logoutEvent, cancellationToken);
//                 revokedCount++;
//             }

//             if (revokedCount > 0)
//             {
//                 await _unitOfWork.SaveChangesAsync(cancellationToken);
//                 _logger.LogInformation("Revoked {Count} other sessions for User {UserId}", revokedCount, command.UserId);
//             }
//         }
//     }
// }