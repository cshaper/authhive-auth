// // [AuthHive.Auth] Handlers/Auth/Session/RefreshSessionCommandHandler.cs
// // v17 CQRS "본보기": 'RefreshSessionCommand' (세션 갱신)를 처리합니다.
// // (SOP 2-Write-U)
// //
// // 1. Validator: ISessionValidator를 호출하여 세션 상태(활성, 만료)를 검증합니다.
// // 2. Logic (v16 이관): SessionService의 만료 시간 계산 로직을 이관합니다.
// // 3. Entity: 엔티티의 'UpdateLastActivity' 메서드를 호출하여 상태를 변경합니다.
// // 4. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// // 5. Mediator (Publish): 'SessionRefreshedEvent'를 발행하여 캐시/감사 작업을 위임합니다.

// using AuthHive.Core.Entities.Auth;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Auth.Validator;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Models.Auth.Session.Commands;
// using AuthHive.Core.Models.Auth.Session.Common;
// using AuthHive.Core.Models.Auth.Session.Events;
// using AuthHive.Core.Models.Auth.Session.Responses;
// using MediatR;
// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using static AuthHive.Core.Enums.Auth.SessionEnums;

// namespace AuthHive.Auth.Handlers.Auth.Session
// {
//     /// <summary>
//     /// [v17] "세션 갱신" 유스케이스 핸들러 (SOP 2-Write-U)
//     /// </summary>
//     public class RefreshSessionCommandHandler : IRequestHandler<RefreshSessionCommand, RefreshSessionResponse>
//     {
//         private readonly ISessionRepository _sessionRepository;
//         private readonly ISessionValidator _sessionValidator;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly IDateTimeProvider _dateTimeProvider;
//         private readonly IConfiguration _configuration;
//         private readonly ILogger<RefreshSessionCommandHandler> _logger;

//         public RefreshSessionCommandHandler(
//             ISessionRepository sessionRepository,
//             ISessionValidator sessionValidator,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             IDateTimeProvider dateTimeProvider,
//             IConfiguration configuration,
//             ILogger<RefreshSessionCommandHandler> logger)
//         {
//             _sessionRepository = sessionRepository;
//             _sessionValidator = sessionValidator;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _dateTimeProvider = dateTimeProvider;
//             _configuration = configuration;
//             _logger = logger;
//         }

//         public async Task<RefreshSessionResponse> Handle(RefreshSessionCommand command, CancellationToken cancellationToken)
//         {
//             // 1. [SOP 2.3.2] 엔티티 조회 (v17 Repository 사용)
//             // ISessionRepository 계약서에 따라 Token으로 세션을 조회합니다.
//             var session = await _sessionRepository.GetByTokenAsync(command.CurrentSessionToken, cancellationToken);

//             if (session == null)
//             {
//                 _logger.LogWarning("RefreshSessionCommand failed: Session not found for token.");
//                 // RefreshSessionResponse 계약서에 따라 실패 응답 반환
//                 return new RefreshSessionResponse(false, true, errorMessage: "Session not found", errorCode: "SESSION_NOT_FOUND");
//             }

//             var utcNow = _dateTimeProvider.UtcNow;

//             // 2. [SOP 2.3.1] 유효성 검증 (v16 로직 이관 + v17 Validator 사용)
//             // v16 SessionService 로직: 활성 상태가 아니면 실패
//             if (session.Status != SessionStatus.Active)
//             {
//                 _logger.LogWarning("RefreshSessionCommand failed: Session {SessionId} is not active. Status: {Status}", session.Id, session.Status);
//                 return new RefreshSessionResponse(false, true, errorMessage: $"Cannot refresh inactive session. Current status: {session.Status}", errorCode: "SESSION_INACTIVE");
//             }

//             // v16 SessionService 로직: 이미 만료되었으면 실패
//             if (session.ExpiresAt < utcNow)
//             {
//                 _logger.LogWarning("RefreshSessionCommand failed: Session {SessionId} has already expired at {ExpiresAt}", session.Id, session.ExpiresAt);
                
//                 // v17 Entity 메서드를 사용하여 상태 변경
//                 session.End(SessionEndReason.Expired);
//                 await _sessionRepository.UpdateAsync(session, cancellationToken);
//                 await _unitOfWork.SaveChangesAsync(cancellationToken);
                
//                 // TODO: SessionTerminatedEvent 발행 (v16 로직에는 없었으나 v17에서는 권장됨)
                
//                 return new RefreshSessionResponse(false, true, errorMessage: "Session has already expired", errorCode: "SESSION_EXPIRED");
//             }
            
//             // v17 ISessionValidator 계약서에 따른 추가 검증 (RefreshToken 등)
//             // (v16 로직에는 RefreshToken 검증이 없었으므로, command.RefreshToken은 현재 사용되지 않음)
//             var validationResult = await _sessionValidator.ValidateRefreshAsync(session.Id, command.RefreshToken, cancellationToken);
//             if (!validationResult.IsSuccess)
//             {
//                 return new RefreshSessionResponse(
//                     isSuccess: false,
//                     requiresReauthentication: true, 
//                     errorMessage: validationResult.ErrorMessage ?? "Session refresh validation failed.",
//                     errorCode: validationResult.ErrorCode ?? "REFRESH_VALIDATION_FAILED");
//             }

//             var oldExpiresAt = session.ExpiresAt; // 5단계 이벤트를 위해 이전 값 저장

//             // 3. [SOP 2.3.3] 비즈니스 로직 (v16 로직 이관)
//             // v16 SessionService의 만료 시간 계산 로직
//             int durationMinutes;
//             if (command.ExtendMinutes.HasValue)
//             {
//                 durationMinutes = command.ExtendMinutes.Value;
//             }
//             else
//             {
//                 // v16 SessionService 로직 (Configuration에서 값 조회)
//                 durationMinutes = _configuration.GetValue<int>(
//                     $"Session:{session.SessionType}TimeoutMinutes", 30);
//             }

//             var newExpiresAt = utcNow.AddMinutes(durationMinutes);

//             // v17 SessionEntity 계약서의 메서드를 사용하여 엔티티 상태 변경
//             session.UpdateLastActivity(utcNow, newExpiresAt);

//             // 4. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
//             await _sessionRepository.UpdateAsync(session, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 5. [SOP 2.3.6] 이벤트 발행 (v16 로직 -> v17 이벤트 위임)
//             // v16의 캐시 설정, 활동 로그 기록을 이벤트 발행으로 대체
//             var refreshedEvent = new SessionRefreshedEvent(
//                 sessionId: session.Id,
//                 userId: session.UserId,
//                 organizationId: session.OrganizationId,
//                 oldExpiresAt: oldExpiresAt,
//                 newExpiresAt: session.ExpiresAt // entity의 최종 값
//             );
//             await _mediator.Publish(refreshedEvent, cancellationToken);

//             // 6. [SOP 2.3.7] 응답 반환
//             _logger.LogInformation("Session {SessionId} refreshed for User {UserId}. New expiry: {ExpiresAt}",
//                 session.Id, session.UserId, session.ExpiresAt);

//             // RefreshSessionResponse 계약서에 따라 성공 응답 반환
//             return new RefreshSessionResponse(
//                 isSuccess: true,
//                 requiresReauthentication: false,
//                 session: MapToSessionInfo(session),
//                 newSessionToken: null, // v16 로직은 토큰을 교체(rotate)하지 않음
//                 newRefreshToken: null, // v16 로직은 리프레시 토큰을 사용하지 않음
//                 newExpiresAt: session.ExpiresAt
//             );
//         }

//         /// <summary>
//         /// v17 Entity를 v17 응답 DTO(SessionInfo)로 매핑합니다.
//         /// (추론 방지: Navigational property(User, Org)는 로드되지 않았으므로 null로 매핑)
//         /// </summary>
//         private SessionInfo MapToSessionInfo(SessionEntity entity)
//         {
//             // SessionInfo.cs 생성자 계약서 준수
//             return new SessionInfo(
//                 id: entity.Id,
//                 sessionToken: entity.SessionToken,
//                 userId: entity.UserId,
//                 sessionType: entity.SessionType,
//                 level: entity.Level,
//                 status: entity.Status,
//                 expiresAt: entity.ExpiresAt,
//                 lastActivityAt: entity.LastActivityAt,
//                 riskScore: entity.RiskScore,
//                 grpcEnabled: entity.GrpcEnabled,
//                 pubSubNotifications: entity.PubSubNotifications,
//                 permissionCacheEnabled: entity.PermissionCacheEnabled,
//                 pageViews: entity.PageViews,
//                 apiCalls: entity.ApiCalls,
//                 isLocked: entity.IsLocked,
//                 createdAt: entity.CreatedAt,
//                 createdBy: entity.CreatedByConnectedId,
//                 lastModifiedAt: entity.UpdatedAt,
//                 lastModifiedBy: entity.UpdatedByConnectedId,
//                 organizationId: entity.OrganizationId,
//                 connectedId: entity.ConnectedId,
//                 parentSessionId: entity.ParentSessionId,
//                 ipAddress: entity.IpAddress,
//                 userAgent: entity.UserAgent,
//                 deviceInfo: entity.DeviceInfo,
//                 lockReason: entity.LockReason,
//                 lockedAt: entity.LockedAt,
//                 // Navigational properties (User, Organization)는 GetByTokenAsync에서
//                 // 로드되지 않았으므로 null 또는 0으로 매핑합니다.
//                 userName: null, 
//                 organizationName: null,
//                 childSessionCount: 0 
//             );
//         }
//     }
// }