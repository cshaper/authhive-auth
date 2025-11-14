// [AuthHive.Auth] Handlers/Auth/Session/UnlockSessionCommandHandler.cs
// v17 CQRS "본보기": 'UnlockSessionCommand' (세션 잠금 해제)를 처리합니다.
// (SOP 2-Write-U)
//
// 1. Logic (v16 이관): SessionService.UnlockSessionAsync 로직을 이관합니다.
// 2. Entity: 엔티티의 'IsLocked', 'LockedAt' 등 속성을 직접 수정합니다.
// 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 4. Mediator (Publish): 'SessionUnlockedEvent'를 발행하여 캐시/감사 작업을 위임합니다.
// 5. Response: 'IRequest<Unit>' 계약에 따라 Unit.Value (void)를 반환합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
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
    /// [v17] "세션 잠금 해제" 유스케이스 핸들러 (SOP 2-Write-U)
    /// v16 SessionService.UnlockSessionAsync 로직 이관
    /// </summary>
    public class UnlockSessionCommandHandler : IRequestHandler<UnlockSessionCommand, Unit>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<UnlockSessionCommandHandler> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public UnlockSessionCommandHandler(
            ISessionRepository sessionRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<UnlockSessionCommandHandler> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _sessionRepository = sessionRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<Unit> Handle(UnlockSessionCommand command, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 엔티티 조회
            var session = await _sessionRepository.GetByIdAsync(command.AggregateId, cancellationToken);

            if (session == null)
            {
                _logger.LogWarning("UnlockSessionCommand failed: Session {SessionId} not found", command.AggregateId);
                return Unit.Value;
            }

            // 2. [SOP 2.3.1] 유효성 검증 (v16 로직 이관)
            // v16 SessionService.UnlockSessionAsync 로직 (멱등성)
            if (!session.IsLocked)
            {
                _logger.LogInformation("Session {SessionId} is already unlocked.", session.Id);
                return Unit.Value;
            }
            
            // TODO: v17 ISessionValidator.ValidateUnlockAsync(...) 호출 (권한 검증 등)

            // 3. [SOP 2.3.3] 엔티티 상태 변경
            // v17 SessionEntity 계약서의 'set' 속성 사용 [cite: 106-111]
            // (SessionEntity에 Unlock() 메서드가 없으므로 [cite: 129-144] 직접 속성 변경)
            session.IsLocked = false;
            session.LockedAt = null;
            session.LockedUntil = null;
            session.LockReason = command.UnlockReason; // 잠금 해제 사유로 업데이트
            session.UpdatedAt = _dateTimeProvider.UtcNow; // v16 UpdateMetadataAsync 로직 참조 [cite: 730-783]
            session.UpdatedByConnectedId = command.UnlockedByConnectedId;

            // 4. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 5. [SOP 2.3.6] 이벤트 발행 (v16 캐시/감사 로직 위임)
            var unlockedEvent = new SessionUnlockedEvent(
                sessionId: session.Id,
                userId: session.UserId,
                organizationId: session.OrganizationId,
                unlockReason: command.UnlockReason,
                triggeredBy: command.UnlockedByConnectedId ?? session.UserId
            );
            await _mediator.Publish(unlockedEvent, cancellationToken);
            
            _logger.LogInformation("Session {SessionId} unlocked. Reason: {Reason}", session.Id, command.UnlockReason);

            // 6. [SOP 2.3.7] 응답 반환
            // IRequest<Unit> 계약에 따라 Unit.Value 반환
            return Unit.Value;
        }
    }
}