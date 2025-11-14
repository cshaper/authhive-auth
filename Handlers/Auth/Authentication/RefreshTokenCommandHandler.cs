// [AuthHive.Auth] Handlers/Auth/Authentication/RefreshTokenCommandHandler.cs
// v17 CQRS "본보기": 'RefreshTokenCommand' (토큰 재발급)를 처리합니다.
// (SOP 2-Write-C)
//
// 1. Logic (v16 이관): v16 AuthenticationManager.RefreshTokenAsync 로직을 이관합니다.
// 2. v17 전문가 위임:
//    - ISessionRepository로 세션 조회 (v16 ISessionService.GetSessionByTokenAsync 대체)
//    - Session.UpdateLastActivity() 호출 (v16 ISessionService.RefreshSessionAsync 대체)
//    - ITokenProvider로 새 토큰 2개 발행
// 3. Mediator (Publish): 'TokenRefreshedEvent'를 발행하여 감사 작업을 위임합니다.
// 4. Response: 'AuthenticationResult' DTO를 반환합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Auth.Provider; // ITokenProvider
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Common; // AuthenticationResult, TokenInfo
using AuthHive.Core.Models.Auth.Authentication.Events; // TokenRefreshedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic; // List
using System.Security.Claims; // Claim
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations; // ValidationException

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "토큰 재발급" 유스케이스 핸들러 (SOP 2-Write-C)
    /// v16 AuthenticationManager.RefreshTokenAsync 로직 이관
    /// </summary>
    public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, AuthenticationResult>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IUserRepository _userRepository; // User(Claims) 조회용
        private readonly ITokenProvider _tokenProvider;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<RefreshTokenCommandHandler> _logger;

        public RefreshTokenCommandHandler(
            ISessionRepository sessionRepository,
            IUserRepository userRepository,
            ITokenProvider tokenProvider,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            IDateTimeProvider dateTimeProvider,
            ILogger<RefreshTokenCommandHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _userRepository = userRepository;
            _tokenProvider = tokenProvider;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<AuthenticationResult> Handle(RefreshTokenCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling RefreshTokenCommand");

            // 1. [v16 이관] RefreshToken(v16의 SessionToken)으로 세션 조회
            // (v16 _sessionService.GetSessionByTokenAsync(refreshToken) [cite: 205-206] 로직 이관)
            // TODO: v16 로직은 RefreshToken을 SessionToken처럼 취급. v17에서는 IRefreshTokenRepository.ValidateAsync(token)이 맞음.
            //       현재는 v16 로직을 그대로 이관합니다.
            var session = await _sessionRepository.GetByTokenAsync(command.RefreshToken, cancellationToken);
            if (session == null)
            {
                _logger.LogWarning("RefreshTokenCommand failed: Session not found for token.");
                throw new ValidationException("Invalid refresh token."); // v16 로직 [cite: 207-210]
            }

            // 2. [v16 이관] 세션 갱신 (v16 _sessionService.RefreshSessionAsync 호출 대체) [cite: 216-217]
            var utcNow = _dateTimeProvider.UtcNow;
            
            // TODO: 만료 시간은 Configuration에서 읽어와야 함 (v16 RefreshSessionAsync 로직 [cite: 601-605])
            var newExpiresAt = utcNow.AddHours(8); 
            
            session.UpdateLastActivity(utcNow, newExpiresAt); // v17 Entity 메서드 사용 [cite: 129-135]
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            
            // 3. [v16 이관] 토큰 발급에 필요한 User 정보(Claims) 조회 [cite: 220-234]
            var user = await _userRepository.GetByIdAsync(session.UserId, cancellationToken);
            if (user == null)
            {
                 _logger.LogError("RefreshToken failed: User {UserId} not found for Session {SessionId}", session.UserId, session.Id);
                 throw new KeyNotFoundException("User associated with session not found.");
            }
            
            var claims = new List<Claim> { new Claim("user_id", user.Id.ToString()) };
            if (session.ConnectedId.HasValue)
            {
                claims.Add(new Claim("connected_id", session.ConnectedId.Value.ToString())); 
            }
            if (session.OrganizationId.HasValue)
            {
                claims.Add(new Claim("org_id", session.OrganizationId.Value.ToString()));
            }

            // 4. [v17 전문가 위임] 새 토큰 발행
            // (v16 _tokenProvider.GenerateAccessTokenAsync/GenerateRefreshTokenAsync 호출 이관) [cite: 236-245]
            var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, session.Id, claims, cancellationToken);
            var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(user.Id, cancellationToken); // v16 로직은 새 RefreshToken도 발행

            if (!accessTokenResult.IsSuccess || !refreshTokenResult.IsSuccess || accessTokenResult.Data == null || refreshTokenResult.Data == null)
            {
                 _logger.LogError("Token generation failed for Session {SessionId} during refresh.", session.Id);
                 throw new InvalidOperationException("Session refreshed, but token generation failed.");
            }
            
            // [v17] SessionEntity.TokenId (v16 Paseto JTI)
            var oldTokenId = session.TokenId ?? "unknown"; 
            
            // 5. [SOP 2.3.5] 최종 커밋
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 6. [SOP 2.3.6] 이벤트 발행
            // [CS1061 해결] 수정된 TokenInfo DTO의 TokenId 사용 
            await _mediator.Publish(new TokenRefreshedEvent(
                oldTokenId: oldTokenId,
                newTokenId: accessTokenResult.Data.TokenId, 
                userId: user.Id,
                organizationId: session.OrganizationId
            ), cancellationToken);

            _logger.LogInformation("Token refreshed successfully for Session {SessionId}", session.Id);

            // 7. [SOP 2.3.7] 응답 반환
            // (v16 AuthenticationOutcome DTO 구조 반환) [cite: 246-275]
            return new AuthenticationResult(
                success: true,
                requiresMfa: false,
                mfaVerified: false,
                isFirstLogin: false,
                requiresPasswordChange: false,
                userId: user.Id,
                connectedId: session.ConnectedId,
                sessionId: session.Id,
                accessToken: accessTokenResult.Data.AccessToken,
                refreshToken: refreshTokenResult.Data, // v16 로직은 새 RefreshToken 반환
                expiresAt: accessTokenResult.Data.ExpiresAt,
                organizationId: session.OrganizationId,
                authenticationMethod: "RefreshToken" // v16 로직
            );
        }
    }
}