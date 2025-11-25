// // [AuthHive.Auth] Handlers/Auth/Session/BulkEndSessionsCommandHandler.cs
// // v17 CQRS "본보기": 'BulkEndSessionsCommand' (세션 일괄 종료)를 처리합니다.
// // (SOP 2-Write-U/D)
// //
// // 1. Logic (v16 이관): SessionService.EndAllSessionsAsync/EndOrganizationSessionsAsync 로직을 이관합니다.
// // 2. Entity: 루프를 돌며 각 엔티티의 'End' 메서드를 호출합니다.
// // 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// // 4. Mediator (Publish): 각 세션마다 'SessionTerminatedEvent'를 발행합니다.
// // 5. Response: 'BulkSessionOperationResponse' DTO로 작업 결과를 요약하여 반환합니다.

// using AuthHive.Core.Entities.Auth;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Models.Auth.Session.Commands;
// using AuthHive.Core.Models.Auth.Session.Common; // SessionBulkOperationDetailInfo
// using AuthHive.Core.Models.Auth.Session.Events;
// using AuthHive.Core.Models.Auth.Session.Responses;
// using MediatR;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Collections.Generic;
// using System.Diagnostics; // Stopwatch
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using static AuthHive.Core.Enums.Auth.SessionEnums;

// namespace AuthHive.Auth.Handlers.Auth.Session
// {
//     /// <summary>
//     /// [v17] "세션 일괄 종료" 유스케이스 핸들러 (SOP 2-Write-U/D)
//     /// v16 SessionService.EndAllSessionsAsync, EndOrganizationSessionsAsync 로직 이관
//     /// </summary>
//     public class BulkEndSessionsCommandHandler : IRequestHandler<BulkEndSessionsCommand, BulkSessionOperationResponse>
//     {
//         private readonly ISessionRepository _sessionRepository;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly ILogger<BulkEndSessionsCommandHandler> _logger;
//         private readonly IDateTimeProvider _dateTimeProvider;

//         public BulkEndSessionsCommandHandler(
//             ISessionRepository sessionRepository,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             ILogger<BulkEndSessionsCommandHandler> logger,
//             IDateTimeProvider dateTimeProvider)
//         {
//             _sessionRepository = sessionRepository;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _logger = logger;
//             _dateTimeProvider = dateTimeProvider;
//         }

//         public async Task<BulkSessionOperationResponse> Handle(BulkEndSessionsCommand command, CancellationToken cancellationToken)
//         {
//             var stopwatch = Stopwatch.StartNew();
//             var utcNow = _dateTimeProvider.UtcNow;
//             var results = new List<SessionBulkOperationDetailInfo>();
//             int successCount = 0;

//             // 1. [SOP 2.3.2] 엔티티 일괄 조회
//             var sessionsToEnd = await _sessionRepository.Query()
//                    .Where(s => command.SessionIds.Contains(s.Id) && s.OrganizationId == command.OrganizationId)
//                    .ToListAsync(cancellationToken);

//             if (!sessionsToEnd.Any())
//             {
//                 _logger.LogWarning("BulkEndSessionsCommand: No matching sessions found for Organization {OrgId}", command.OrganizationId);
//                 return new BulkSessionOperationResponse(true, command.SessionIds.Count, 0, command.SessionIds.Count, stopwatch.ElapsedMilliseconds, null);
//             }

//             // 2. [SOP 2.3.3] 엔티티 상태 변경 (루프)
//             foreach (var session in sessionsToEnd)
//             {
//                 try
//                 {
//                     // v16 로직: 이미 종료된 세션은 건너뜀 [cite: 110-116]
//                     if (session.Status == SessionStatus.Terminated || session.Status == SessionStatus.Expired)
//                     {
//                         // SessionBulkOperationDetailInfo DTO 계약서 준수 
//                         results.Add(new SessionBulkOperationDetailInfo(session.Id, true, "Already terminated"));
//                         successCount++;
//                         continue;
//                     }

//                     TimeSpan duration = utcNow - session.CreatedAt;

//                     // v17 Entity 메서드 호출 [cite: 139-144]
//                     session.End(command.EndReason);

//                     // 3. [SOP 2.3.4] 저장 (UpdateAsync)
//                     await _sessionRepository.UpdateAsync(session, cancellationToken);

//                     // 4. [SOP 2.3.6] 이벤트 발행 (v16 캐시/감사 로직 위임) [cite: 240-258, 290-302]
//                     var terminatedEvent = new SessionTerminatedEvent(
//                         sessionId: session.Id,
//                         userId: session.UserId,
//                         organizationId: session.OrganizationId,
//                         endReason: command.EndReason,
//                         duration: duration,
//                         triggeredBy: command.EndedByConnectedId ?? session.UserId
//                     );
//                     await _mediator.Publish(terminatedEvent, cancellationToken);

//                     results.Add(new SessionBulkOperationDetailInfo(session.Id, true));
//                     successCount++;
//                 }
//                 catch (Exception ex)
//                 {
//                     _logger.LogError(ex, "Failed to end session {SessionId} during bulk operation.", session.Id);

//                     // [v17 수정] ErrorCode가 없는 DTO 생성자 사용 
//                     results.Add(new SessionBulkOperationDetailInfo(session.Id, false, ex.Message));

//                     if (!command.ContinueOnError)
//                     {
//                         break; // 오류 시 중단
//                     }
//                 }
//             }

//             // 5. [SOP 2.3.5] 최종 커밋
//             try
//             {
//                 await _unitOfWork.SaveChangesAsync(cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogCritical(ex, "Failed to commit UnitOfWork during BulkEndSessionsCommand for Org {OrgId}", command.OrganizationId);
//                 return new BulkSessionOperationResponse(false, command.SessionIds.Count, 0, command.SessionIds.Count, stopwatch.ElapsedMilliseconds, results);
//             }

//             stopwatch.Stop();
//             // [v17 수정] 실패 카운트는 요청 수에서 성공 수를 빼서 계산
//             int failureCount = command.SessionIds.Count - successCount;

//             _logger.LogInformation(
//                 "BulkEndSessionsCommand completed for Org {OrgId}: {SuccessCount} succeeded, {FailureCount} failed.",
//                 command.OrganizationId, successCount, failureCount);

//             // 6. [SOP 2.3.7] 응답 반환
//             // BulkSessionOperationResponse 계약서 준수 [cite: 11-30]
//             return new BulkSessionOperationResponse(
//                 success: failureCount == 0,
//                 totalRequested: command.SessionIds.Count,
//                 succeededCount: successCount,
//                 failureCount: failureCount,
//                 processingTimeMs: stopwatch.ElapsedMilliseconds,
//                 details: results
//             );
//         }
//     }
// }