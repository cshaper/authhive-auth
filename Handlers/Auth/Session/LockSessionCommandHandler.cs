// [AuthHive.Auth] Handlers/Auth/Session/LockSessionCommandHandler.cs
// v17 CQRS "본보기": 'LockSessionCommand' (세션 잠금)를 처리합니다.
// (SOP 2-Write-U)
//
// 1. Logic (v16 이관): SessionService.LockSessionAsync 로직을 이관합니다.
// 2. Entity: 엔티티의 'Lock' 메서드를 호출하여 상태를 변경합니다.
// 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 4. Mediator (Publish): 'SessionLockedEvent'를 발행하여 캐시/감사 작업을 위임합니다.
// 5. Response: 'IRequest<Unit>' 계약에 따라 Unit.Value (void)를 반환합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.Session.Commands;
using AuthHive.Core.Models.Auth.Session.Events;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Auth.Session
{
    /// <summary>
    /// [v17] "세션 잠금" 유스케이스 핸들러 (SOP 2-Write-U)
    /// </summary>
    public class LockSessionCommandHandler : IRequestHandler<LockSessionCommand, Unit>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionValidator _sessionValidator;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<LockSessionCommandHandler> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public LockSessionCommandHandler(
            ISessionRepository sessionRepository,
            ISessionValidator sessionValidator,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<LockSessionCommandHandler> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _sessionRepository = sessionRepository;
            _sessionValidator = sessionValidator;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<Unit> Handle(LockSessionCommand command, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 엔티티 조회
            var session = await _sessionRepository.GetByIdAsync(command.AggregateId, cancellationToken);

            if (session == null)
            {
                _logger.LogWarning("LockSessionCommand failed: Session {SessionId} not found", command.AggregateId);
                // v17: 핸들러는 예외를 던지거나 Unit.Value를 반환합니다. 여기서는 조용히 무시.
                return Unit.Value;
            }

            // v16 SessionService.LockSessionAsync 로직 이관 
            if (session.IsLocked && session.LockReason == command.LockReason)
            {
                _logger.LogInformation("Session {SessionId} is already locked with the same reason.", session.Id);
                return Unit.Value; // 멱등성(Idempotency)
            }

            // 2. [SOP 2.3.1] 유효성 검증 (필요시)
            // (v16 LockSessionAsync에는 별도 Validator가 없었음 )

            // 3. [SOP 2.3.3] 엔티티 상태 변경
            // v17 SessionEntity 계약서의 'Lock' 메서드 사용 [cite: 136-141]
            session.Lock(command.LockReason);
            
            // [v17] Command의 신규 속성(UnlockAt) 반영 [cite: 36]
            if(command.UnlockAt.HasValue)
            {
                session.LockedUntil = command.UnlockAt.Value;
            }

            // 4. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 5. [SOP 2.3.6] 이벤트 발행 (v16 로직 -> v17 이벤트 위임)
            // v16의 캐시/감사 로직을 이벤트 발행으로 대체
            var lockedEvent = new SessionLockedEvent(
                sessionId: session.Id,
                userId: session.UserId,
                organizationId: session.OrganizationId,
                lockReason: command.LockReason,
                riskScore: session.RiskScore,
                triggeredBy: command.TriggeredByConnectedId ?? session.UserId
            );
            await _mediator.Publish(lockedEvent, cancellationToken);
            
            _logger.LogInformation("Session {SessionId} locked. Reason: {Reason}", session.Id, command.LockReason);

            // 6. [SOP 2.3.7] 응답 반환
            // IRequest<Unit> 계약에 따라 Unit.Value 반환 
            return Unit.Value;
        }
    }
}