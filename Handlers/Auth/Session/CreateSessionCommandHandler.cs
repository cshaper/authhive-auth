// [AuthHive.Auth] Handlers/Auth/Session/CreateSessionCommandHandler.cs
// v17 CQRS "본보기": 'CreateSessionCommand' (세션 생성)를 처리합니다.
// (SOP 1-Write-C)
//
// 1. Command(DTO) -> Entity(Model) 매핑: 'public init'으로 수정된 SessionEntity에 값을 매핑합니다.
// 2. Repository/UnitOfWork: 엔티티를 DB에 저장(Commit)합니다.
// 3. Mediator (Publish): 'SessionCreatedEvent'를 발행하여 감사/캐시 등 후속 작업을 위임합니다.

using AuthHive.Core.Interfaces.Auth.Repository; // [v17] ISessionRepository
using AuthHive.Core.Interfaces.Base; // [v17] IUnitOfWork
using AuthHive.Core.Interfaces.Infra; // [v17] IDateTimeProvider
using AuthHive.Core.Models.Auth.Session.Commands; // [v17] CreateSessionCommand (ExpiresAt 수정본)
using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionCreatedEvent (createdAt 수정본)
using AuthHive.Core.Models.Auth.Session.Responses; // [v17] CreateSessionResponse
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography; // 세션 토큰 생성을 위해 추가
using System.Text.Json; // DeviceInfo 직렬화를 위해 추가
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Auth.Session
{
    /// <summary>
    /// [v17] "세션 생성" 유스케이스 핸들러 (SOP 1-Write-C)
    /// 인증 핸들러(Password/Social)의 요청을 받아 실제 세션 엔티티를 생성하고 저장합니다.
    /// </summary>
    public class CreateSessionCommandHandler : IRequestHandler<CreateSessionCommand, CreateSessionResponse>
    {
        private readonly IMediator _mediator;
        private readonly ISessionRepository _sessionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<CreateSessionCommandHandler> _logger;

        public CreateSessionCommandHandler(
            IMediator mediator,
            ISessionRepository sessionRepository,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            ILogger<CreateSessionCommandHandler> logger)
        {
            _mediator = mediator;
            _sessionRepository = sessionRepository;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<CreateSessionResponse> Handle(CreateSessionCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling CreateSessionCommand for User {UserId}", command.AggregateId);

            var utcNow = _dateTimeProvider.UtcNow;

            // 1. [v17 전문가 위임] 세션 토큰 생성
            var sessionToken = GenerateSecureSessionToken();

            // 2. [v17 "본보기"] Command(DTO) -> Entity(Model) 매핑
            // "하이브리드"로 수정된 SessionEntity의 'public init' 속성을 사용하여
            // 'new'와 동시에 모든 Command 데이터를 매핑합니다.
            var sessionEntity = new SessionEntity
            {
                // Core Properties (Creation-Time)
                SessionToken = sessionToken,
                UserId = command.AggregateId, // BaseCommand의 AggregateId가 UserId임
                OrganizationId = command.OrganizationId,
                ApplicationId = command.ApplicationId,
                ConnectedId = command.ConnectedId,
                ParentSessionId = null,

                // State & Type
                SessionType = command.SessionType,
                Level = command.Level,
                Status = command.InitialStatus, 

                // Client Info (Creation-Time)
                IpAddress = command.IpAddress,
                UserAgent = command.UserAgent,
                DeviceInfo = command.DeviceInfo != null ? JsonSerializer.Serialize(command.DeviceInfo) : null,
                OperatingSystem = command.OperatingSystem,
                Browser = command.Browser,
                Location = command.Location,

                // State & Metrics (Creation-Time)
                RiskScore = command.InitialRiskScore,

                // Feature Flags (Creation-Time)
                GrpcEnabled = command.EnableGrpc,
                PubSubNotifications = command.EnablePubSubNotifications,
                PermissionCacheEnabled = command.EnablePermissionCache,
                
                // [v17 CS0266/CS8629 해결]
                // CreateSessionCommand DTO "계약서"에서 'new DateTime ExpiresAt'를 사용하므로
                // command.ExpiresAt은 'DateTime' (non-null)임이 보장됩니다.
                ExpiresAt = command.ExpiresAt,
                
                // Lifecycle Properties (Runtime-Managed) - 초기값 설정
                LastActivityAt = utcNow,
                PageViews = 0,
                ApiCalls = 0,
                IsLocked = false,
                
                // [v17] SystemGlobalBaseEntity 속성 설정
                CreatedAt = utcNow,
                
                // [v17 CS0117/CS0029 해결]
                // SystemGlobalBaseEntity "계약서"는 'CreatedByConnectedId' (Guid?)를 요구합니다.
                // command.AggregateId (UserId)는 Guid이므로 타입이 일치합니다.
                CreatedByConnectedId = command.AggregateId 
            };

            // 3. [v17 "본보기"] 데이터 저장
            SessionEntity createdEntity;
            try
            {
                createdEntity = await _sessionRepository.AddAsync(sessionEntity, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add SessionEntity to database for User {UserId}", command.AggregateId);
                throw new InvalidOperationException("Failed to create session.", ex);
            }

            _logger.LogInformation("SessionEntity {SessionId} created for User {UserId}", createdEntity.Id, createdEntity.UserId);

            // 4. [v17 "본보기"] 이벤트 발행 (Notify)
            // v16 SessionEventHandler의 책임을 위임합니다.
            
            // [v17 CS1739/CS7036 해결]
            // 수정된 SessionCreatedEvent "계약서"의 모든 필수 인자
            // (level 포함)와 "실제" 생성 시간(createdAt)을 정확히 전달합니다.
            var sessionCreatedEvent = new SessionCreatedEvent(
                sessionId: createdEntity.Id,
                userId: createdEntity.UserId,
                organizationId: createdEntity.OrganizationId,
                connectedId: createdEntity.ConnectedId,
                sessionType: createdEntity.SessionType,
                level: createdEntity.Level, 
                ipAddress: createdEntity.IpAddress ?? string.Empty,
                userAgent: createdEntity.UserAgent,
                expiresAt: createdEntity.ExpiresAt,
                createdAt: createdEntity.CreatedAt, 
                authenticationMethod: command.AuthenticationMethod
            );
            await _mediator.Publish(sessionCreatedEvent, cancellationToken);

            // Command의 반환 타입인 'CreateSessionResponse' "계약서"에 맞춰 응답을 생성합니다.
            return new CreateSessionResponse(
                isSuccess: true,
                sessionToken: createdEntity.SessionToken,
                sessionType: createdEntity.SessionType,
                requiresTwoFactor: false, 
                isTrustedDevice: false, 
                sessionId: createdEntity.Id,
                sessionData: null, 
                sessionIdentifier: null,
                expiresAt: createdEntity.ExpiresAt
            );
        }

        /// <summary>
        /// 암호학적으로 안전한 랜덤 문자열을 생성하여 세션 토큰으로 사용합니다.
        /// </summary>
        private string GenerateSecureSessionToken()
        {
            var randomNumber = new byte[32]; // 256비트
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('='); // URL-safe Base64
        }
    }
}