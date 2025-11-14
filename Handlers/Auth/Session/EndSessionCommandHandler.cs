// [AuthHive.Auth] Handlers/Auth/Session/EndSessionCommandHandler.cs
// v17 CQRS "본보기": 'EndSessionCommand' (세션 종료)를 처리합니다.
// (SOP 2-Write-U/D)
//
// 1. Validator: ISessionValidator를 호출하여 종료 권한 등을 검증합니다.
// 2. Logic (v16 이관): SessionService의 자식 세션 연쇄 종료 로직을 이관합니다.
// 3. Entity: 엔티티의 'End' 메서드를 호출하여 상태를 'Terminated'로 변경합니다.
// 4. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 5. Mediator (Publish): 'SessionTerminatedEvent'를 발행하여 캐시/감사 작업을 위임합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.Session.Commands;
using AuthHive.Core.Models.Auth.Session.Events;
using AuthHive.Core.Models.Auth.Session.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Handlers.Auth.Session
{
    /// <summary>
    /// [v17] "세션 종료" 유스케이스 핸들러 (SOP 2-Write-U/D)
    /// </summary>
    public class EndSessionCommandHandler : IRequestHandler<EndSessionCommand, EndSessionResponse>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionValidator _sessionValidator;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<EndSessionCommandHandler> _logger;

        public EndSessionCommandHandler(
            ISessionRepository sessionRepository,
            ISessionValidator sessionValidator,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            IDateTimeProvider dateTimeProvider,
            ILogger<EndSessionCommandHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _sessionValidator = sessionValidator;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<EndSessionResponse> Handle(EndSessionCommand command, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 엔티티 조회
            // Command의 AggregateId가 SessionId임 [cite: 25-30]
            var session = await _sessionRepository.GetByIdAsync(command.AggregateId, cancellationToken);

            if (session == null)
            {
                _logger.LogWarning("EndSessionCommand failed: Session {SessionId} not found", command.AggregateId);
                return new EndSessionResponse(false, command.AggregateId, command.EndReason, 0, false, "Session not found");
            }

            // 2. [SOP 2.3.1] 유효성 검증 (v16 로직 이관)
            // v16 SessionService.EndSessionAsync 로직: 이미 종료되었는지 확인 [cite: 110-116]
            if (!command.ForceEnd && (session.Status == SessionStatus.Terminated || session.Status == SessionStatus.Expired))
            {
                _logger.LogInformation("EndSessionCommand: Session {SessionId} is already terminated.", session.Id);
                return new EndSessionResponse(true, session.Id, session.EndReason ?? command.EndReason, 0, false);
            }

            // v17 ISessionValidator 계약서에 따른 검증
            var validationResult = await _sessionValidator.ValidateTerminationAsync(
                session.Id, command.EndReason, command.EndedByConnectedId, cancellationToken);
            
            if (!validationResult.IsSuccess && !command.ForceEnd)
            {
                _logger.LogWarning("EndSessionCommand failed: Validation failed for Session {SessionId}. Reason: {Reason}", session.Id, validationResult.ErrorCode);
                return new EndSessionResponse(false, session.Id, command.EndReason, 0, false, validationResult.ErrorMessage);
            }
            
            var utcNow = _dateTimeProvider.UtcNow;
            TimeSpan duration = utcNow - session.CreatedAt;
            
            // 3. [SOP 2.3.3] 엔티티 상태 변경
            // v17 SessionEntity 계약서의 메서드를 사용 [cite: 139-144]
            session.End(command.EndReason);

            // 4. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            
            // 5. [SOP 2.3.6] 이벤트 발행 (v16 로직 -> v17 이벤트 위임)
            // v16의 캐시 제거 , 감사 로그  책임을 이벤트로 위임
            var terminatedEvent = new SessionTerminatedEvent(
                sessionId: session.Id,
                userId: session.UserId,
                organizationId: session.OrganizationId,
                endReason: command.EndReason,
                duration: duration,
                triggeredBy: command.EndedByConnectedId ?? session.UserId
            );
            await _mediator.Publish(terminatedEvent, cancellationToken);

            int relatedSessionsEnded = 0;
            bool trustedDeviceRevoked = false; // TODO: v17 로직 구현 필요

            // 6. [SOP 2.3.3] 비즈니스 로직 (v16 로직 이관: 자식 세션 종료)
            // v16 SessionService.EndSessionAsync 로직 [cite: 141-149]
            if (command.EndRelatedSessions && session.Level == SessionLevel.Global)
            {
                var childSessions = await _sessionRepository.GetChildSessionsAsync(session.Id, activeOnly: true, cancellationToken);
                foreach (var child in childSessions)
                {
                    // v17 Entity 메서드 호출
                    child.End(SessionEndReason.ParentSessionTerminated);
                    await _sessionRepository.UpdateAsync(child, cancellationToken);
                    
                    var childDuration = utcNow - child.CreatedAt;

                    // v17 이벤트 발행 (자식 세션용)
                    var childTerminatedEvent = new SessionTerminatedEvent(
                        sessionId: child.Id,
                        userId: child.UserId,
                        organizationId: child.OrganizationId,
                        endReason: SessionEndReason.ParentSessionTerminated,
                        duration: childDuration,
                        triggeredBy: command.EndedByConnectedId ?? session.UserId
                    );
                    await _mediator.Publish(childTerminatedEvent, cancellationToken);
                    relatedSessionsEnded++;
                }
            }
            
            // 7. [SOP 2.3.5] 최종 커밋
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 8. [SOP 2.3.7] 응답 반환
            _logger.LogInformation("Session {SessionId} ended. Reason: {Reason}", session.Id, command.EndReason);

            // EndSessionResponse 계약서에 따라 성공 응답 반환 [cite: 17-29]
            return new EndSessionResponse(
                isSuccess: true,
                sessionId: session.Id,
                endReason: command.EndReason,
                relatedSessionsEnded: relatedSessionsEnded,
                trustedDeviceRevoked: trustedDeviceRevoked
            );
        }
    }
}