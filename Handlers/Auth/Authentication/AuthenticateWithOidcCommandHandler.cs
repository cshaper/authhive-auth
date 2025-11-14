// [AuthHive.Auth] Handlers/Auth/Authentication/AuthenticateWithOidcCommandHandler.cs
// v17 CQRS "본보기": 'AuthenticateWithOidcCommand' (OIDC/SSO 로그인)를 처리합니다.
// (SOP 2-Write-C)
//
// 1. v17 전문가 위임: IOAuthProviderService를 호출하여 Code -> Token 교환, UserProfile 조회를 수행합니다.
// 2. v17 전문가 위임: GetOrCreateUserByExternalIdCommand를 Send하여 JIT 프로비저닝을 위임합니다.
// 3. v17 "본보기" 재사용: AuthFrame(Mode 2) 검사, 세션 생성, 토큰 발행 로직을 수행합니다.

using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Auth.Provider; // ITokenProvider
using AuthHive.Core.Interfaces.Auth.External; // [v17] IOAuthProviderService
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Common; // AuthenticationResult, TokenInfo, UserProfileDto
using AuthHive.Core.Models.Auth.Authentication.Events; // LoginSuccessEvent
using AuthHive.Core.Models.Auth.Session.Commands; // CreateSessionCommand
using AuthHive.Core.Models.Auth.Session.Responses; // CreateSessionResponse
using AuthHive.Core.Models.User.Commands; // GetOrCreateUserByExternalIdCommand
using AuthHive.Core.Models.User.Responses; // UserDetailResponse
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthenticationResult = AuthHive.Core.Models.Auth.Authentication.Common.AuthenticationResult;

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "OIDC 인증" 유스케이스 핸들러 (SOP 2-Write-C)
    /// v17 AuthFrame '모드 2' (SSO 위임) 로직을 처리합니다.
    /// </summary>
    public class AuthenticateWithOidcCommandHandler : IRequestHandler<AuthenticateWithOidcCommand, AuthenticationResult>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<AuthenticateWithOidcCommandHandler> _logger;
        private readonly IOrganizationRepository _orgRepository;
        private readonly ITokenProvider _tokenProvider;
        private readonly IOAuthProviderService _oauthProviderService; // [v17] OIDC 전문가 서비스
        private readonly IDateTimeProvider _dateTimeProvider;

        public AuthenticateWithOidcCommandHandler(
            IMediator mediator,
            ILogger<AuthenticateWithOidcCommandHandler> logger,
            IOrganizationRepository orgRepository,
            ITokenProvider tokenProvider,
            IOAuthProviderService oauthProviderService,
            IDateTimeProvider dateTimeProvider)
        {
            _mediator = mediator;
            _logger = logger;
            _orgRepository = orgRepository;
            _tokenProvider = tokenProvider;
            _oauthProviderService = oauthProviderService;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<AuthenticationResult> Handle(AuthenticateWithOidcCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling AuthenticateWithOidcCommand for Org {OrgId}, Provider {Provider}",
                command.OrganizationId, command.Provider);

            // 1. [v17 게이트키퍼] AuthFrame "모드 2" 검사
            var organization = await _orgRepository.GetByIdAsync(command.OrganizationId, cancellationToken);
            if (organization == null)
            {
                throw new KeyNotFoundException($"Organization not found: {command.OrganizationId}");
            }
            
            // [v17] OIDC/SAML 로그인은 v17 AuthFrame "모드 2" (SSO 위임)에서만 허용됩니다. [cite: 326-327]
            if (organization.AuthenticationMode != "SsoDelegated")
            {
                _logger.LogWarning("Authentication denied: Org {OrgId} is not configured for SSO (Mode 2).", organization.Id);
                throw new ValidationException("OIDC login is not enabled for this organization.");
            }

            // 2. [v17 전문가 위임] OIDC Code -> Access Token 교환
            // (v16 OAuthProviderService.ExchangeTokenAsync  호출)
            var tokenResult = await _oauthProviderService.ExchangeTokenAsync(
                command.Provider, command.Code, command.RedirectUri, cancellationToken);
            
            if (!tokenResult.IsSuccess || tokenResult.Data == null || string.IsNullOrEmpty(tokenResult.Data.AccessToken))
            {
                _logger.LogWarning("OIDC Code exchange failed for Provider {Provider}. Reason: {Error}", command.Provider, tokenResult.ErrorMessage);
                throw new ValidationException("Failed to exchange OIDC code for token.");
            }

            // 3. [v17 전문가 위임] Access Token -> User Profile 조회
            // (v16 OAuthProviderService.GetUserProfileAsync  호출)
            var profileResult = await _oauthProviderService.GetUserProfileAsync(
                command.Provider, tokenResult.Data.AccessToken, cancellationToken);

            if (!profileResult.IsSuccess || profileResult.Data == null || string.IsNullOrEmpty(profileResult.Data.ExternalId) || string.IsNullOrEmpty(profileResult.Data.Email))
            {
                _logger.LogWarning("OIDC GetUserProfile failed for Provider {Provider}. Reason: {Error}", command.Provider, profileResult.ErrorMessage);
                throw new ValidationException("Failed to retrieve user profile from OIDC provider.");
            }
            var userProfile = profileResult.Data;

            // 4. [v17 전문가 위임] JIT 프로비저닝 (Social 핸들러 "본보기" 재사용 [cite: 83-109])
            var jitCommand = new GetOrCreateUserByExternalIdCommand(
                externalSystemType: command.Provider,
                externalUserId: userProfile.ExternalId,
                email: userProfile.Email,
                displayName: userProfile.DisplayName ?? userProfile.Name,
                username: userProfile.Email.Split('@').FirstOrDefault() // (v16 로직)
            );
            
            UserDetailResponse userResponse = await _mediator.Send(jitCommand, cancellationToken);
            if (userResponse == null || userResponse.Id == Guid.Empty)
            {
                throw new InvalidOperationException("JIT Provisioning (GetOrCreateUserByExternalIdCommand) failed.");
            }

            // [Password Handler "본보기" 패턴 적용 시작 - 7단계부터]
            // -----------------------------------------------------------------

            // 7. ConnectedId 조회 [cite: 251-252]
            var connectedId = userResponse.Organizations
                .FirstOrDefault(orgInfo => orgInfo.OrganizationId == organization.Id)?
                .ConnectedId;
            
            if (connectedId == null)
            {
                _logger.LogWarning("User {UserId} logged in via OIDC but has no active ConnectedId for Org {OrgId}. Manual selection required.", userResponse.Id, organization.Id);
                // JIT 프로비저닝의 일부로 ConnectedId가 생성되었어야 함 (v17 SCIM/JIT 철학) [cite: 481-487]
                // (이 핸들러는 JIT 핸들러를 신뢰함)
            }

            // 8. 세션 생성 (Send Command) [cite: 260-277]
            var sessionCommand = new CreateSessionCommand(
                userId: userResponse.Id,
                organizationId: organization.Id,
                applicationId: null, 
                ipAddress: command.IpAddress,
                userAgent: command.UserAgent,
                expiresAt: _dateTimeProvider.UtcNow.AddHours(8), // (설정값으로 대체 필요)
                authenticationMethod: AuthenticationMethod.SSO, // [v17] SSO (OIDC/SAML)
                level: SessionLevel.Organization, 
                connectedId: connectedId
            );

            var sessionResponse = await _mediator.Send(sessionCommand, cancellationToken);
            if (!sessionResponse.IsSuccess || sessionResponse.SessionId == null)
            {
                throw new InvalidOperationException("OIDC login succeeded, but session creation failed.");
            }

            // 9. 토큰 발행 (v17 전문가 위임) [cite: 279-301]
            var claims = new List<Claim> { new Claim("user_id", userResponse.Id.ToString()) };
            
            var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(userResponse.Id, sessionResponse.SessionId.Value, claims, cancellationToken);
            var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(userResponse.Id, cancellationToken);

            if (!accessTokenResult.IsSuccess || !refreshTokenResult.IsSuccess || accessTokenResult.Data == null || refreshTokenResult.Data == null)
            {
                 throw new InvalidOperationException("Session created, but token generation failed.");
            }

            // 10. 이벤트 발행 (Notify) - LoginSuccessEvent 
            await _mediator.Publish(new LoginSuccessEvent(
                userId: userResponse.Id,
                sessionId: sessionResponse.SessionId.Value,
                organizationId: organization.Id,
                connectedId: connectedId,
                loginMethod: $"OIDC-{command.Provider}", // [v17]
                ipAddress: command.IpAddress ?? "N/A",
                userAgent: command.UserAgent,
                location: null
            ), cancellationToken);

            // 11. 최종 응답 반환 [cite: 317-323]
            return new AuthenticationResult(
                success: true,
                requiresMfa: false,
                mfaVerified: true, // [v17] OIDC/SSO 공급자가 MFA를 처리한 것으로 간주
                isFirstLogin: userResponse.IsNewUser,
                requiresPasswordChange: false,
                userId: userResponse.Id,
                connectedId: connectedId,
                sessionId: sessionResponse.SessionId,
                accessToken: accessTokenResult.Data.AccessToken,
                refreshToken: refreshTokenResult.Data, 
                expiresAt: accessTokenResult.Data.ExpiresAt,
                organizationId: organization.Id,
                authenticationMethod: "OIDC"
            );
        }
    }
}