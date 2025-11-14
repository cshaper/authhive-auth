// [AuthHive.Auth] Handlers/Auth/Session/LogSessionActivityCommandHandler.cs
// v17 CQRS "본보기": 'LogSessionActivityCommand' (세션 활동 기록)를 처리합니다.
// (SOP 2-Write-U)
//
// 1. Logic (v16 이관): SessionService.UpdateActivityAsync의 메트릭(PageViews, ApiCalls) 업데이트 로직을 이관합니다.
// 2. Entity: 엔티티의 'LastActivityAt' 및 'PageViews'/'ApiCalls' 속성을 직접 수정합니다.
// 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 4. Mediator (Publish): 'SessionActivityEvent'를 발행하여 감사 로그 저장을 위임합니다.
// 5. Response: 'SessionActivityResponse' DTO를 반환합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.Session.Commands;
using AuthHive.Core.Models.Auth.Session.Events;
using AuthHive.Core.Models.Auth.Session.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Handlers.Auth.Session
{
    /// <summary>
    /// [v17] "세션 활동 기록" 유스케이스 핸들러 (SOP 2-Write-U)
    /// v16 SessionService.UpdateActivityAsync 로직 이관
    /// </summary>
    public class LogSessionActivityCommandHandler : IRequestHandler<LogSessionActivityCommand, SessionActivityResponse>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<LogSessionActivityCommandHandler> _logger;
        // v16의 ISessionActivityLogRepository는 v17 이벤트 발행으로 대체됨

        public LogSessionActivityCommandHandler(
            ISessionRepository sessionRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            IDateTimeProvider dateTimeProvider,
            ILogger<LogSessionActivityCommandHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<SessionActivityResponse> Handle(LogSessionActivityCommand command, CancellationToken cancellationToken)
        {
            var utcNow = _dateTimeProvider.UtcNow;

            // 1. [SOP 2.3.2] 엔티티 조회
            var session = await _sessionRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 SessionId [cite: 68-73]

            if (session == null)
            {
                _logger.LogWarning("LogSessionActivity failed: Session {SessionId} not found", command.AggregateId);
                return SessionActivityResponse.Failure("Session not found", "SESSION_NOT_FOUND", command.AggregateId, command.ActivityType);
            }

            // 2. [SOP 2.3.1] 유효성 검증 (v16 로직 이관) [cite: 679-693]
            if (session.Status != SessionStatus.Active)
            {
                _logger.LogWarning("LogSessionActivity failed: Session {SessionId} is not active. Status: {Status}", session.Id, session.Status);
                return SessionActivityResponse.Failure($"Cannot log activity for inactive session. Status: {session.Status}", "SESSION_INACTIVE", session.Id, command.ActivityType);
            }
            if (session.ExpiresAt < utcNow)
            {
                session.End(SessionEndReason.Expired); // v17 Entity 메서드 사용 [cite: 139-144]
                await _sessionRepository.UpdateAsync(session, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                _logger.LogWarning("LogSessionActivity failed: Session {SessionId} has expired. Status set to Expired.", session.Id);
                // TODO: SessionTerminatedEvent 발행
                return SessionActivityResponse.Failure("Session has expired", "SESSION_EXPIRED", session.Id, command.ActivityType);
            }

            // 3. [SOP 2.3.3] 엔티티 상태 변경 (v16 로직 이관) [cite: 695-713]
            session.LastActivityAt = utcNow;

            switch (command.ActivityType)
            {
                case SessionActivityType.PageView:
                    session.PageViews++;
                    break;
                case SessionActivityType.ApiCall:
                    session.ApiCalls++;
                    break;
                // v16 로직: 기타 활동은 ApiCalls로 카운트
                case SessionActivityType.SecurityChange:
                case SessionActivityType.PermissionChange:
                case SessionActivityType.DataAccess:
                    session.ApiCalls++;
                    break;
            }

            // 4. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);
            var newActivityLogId = Guid.NewGuid();
            // 5. [SOP 2.3.6] 이벤트 발행 (v16 로직 -> v17 이벤트 위임)
            // v16의 _activityLogRepository.AddAsync  호출을 이벤트 발행으로 대체
            var activityEvent = new SessionActivityEvent(
                sessionId: session.Id,
                userId: session.UserId,
                organizationId: session.OrganizationId,
                activityType: command.ActivityType,
                activityDetails: command.Description ?? command.ApiEndpoint ?? command.PageUrl ?? command.ActivityType.ToString(),
                ipAddress: command.IpAddress ?? session.IpAddress ?? string.Empty
            );
            await _mediator.Publish(activityEvent, cancellationToken);

            // 6. [SOP 2.3.7] 응답 반환
            // SessionActivityResponse DTO 계약서 준수 [cite: 21-41]
            return new SessionActivityResponse(
                success: true,
                activityId: newActivityLogId, // 이벤트 ID를 활동 ID로 사용
                sessionId: session.Id,
                activityType: command.ActivityType,
                occurredAt: utcNow,
                riskScore: session.RiskScore, // 현재 세션의 위험 점수
                hasSecurityAlert: false // TODO: v16 CheckSuspiciousActivityAsync 로직 이관 필요 [cite: 730-752]
            );
        }
    }
}