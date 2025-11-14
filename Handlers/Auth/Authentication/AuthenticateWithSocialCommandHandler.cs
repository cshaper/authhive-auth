// [AuthHive.Auth] Handlers/Auth/Authentication/AuthenticateWithSocialCommandHandler.cs
// v17 CQRS "본보기": 'AuthenticateWithSocialCommand' (소셜 로그인)를 처리합니다.
// (SOP 1-Write-R)
//
// 1. ISocialAuthenticationService: 소셜 토큰을 검증하고 외부 ID를 획득합니다. (v16 Service 위임)
// 2. IMediator (Send): GetOrCreateUserByExternalIdCommand를 전송하여 JIT 프로비저닝을 위임합니다.
// 3. PasswordHandler Pattern: AuthFrame/MFA 검사, 세션 생성, 토큰 발행 로직을 재사용합니다.

using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth.ConnectedId;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Auth.Provider; // [v17] ITokenProvider
using AuthHive.Core.Interfaces.Auth.Service; // [v17] ISocialAuthenticationService
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Common; // AuthenticationResult, TokenInfo
using AuthHive.Core.Models.Auth.Authentication.Events; // LoginSuccessEvent
using AuthHive.Core.Models.Auth.Session.Commands; // CreateSessionCommand
using AuthHive.Core.Models.Auth.Session.Responses; // CreateSessionResponse
using AuthHive.Core.Models.User.Commands; // [v17] GetOrCreateUserByExternalIdCommand
using AuthHive.Core.Models.User.Responses; // [v17] UserDetailResponse
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims; // Claim
using System.Collections.Generic; // List
using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionType
using AuthHive.Core.Enums.Auth; // [v17 CS0117 해결] AuthenticationMethod Enum
using AuthenticationResult = AuthHive.Core.Models.Auth.Authentication.Common.AuthenticationResult;

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "소셜 인증" 유스케이스 핸들러 (SOP 1-Write-R)
    /// v17 AuthFrame 정책을 검사하고, v16 소셜 인증 로직을 v17 부품(Service/Command)에 위임합니다.
    /// </summary>
    public class AuthenticateWithSocialCommandHandler : IRequestHandler<AuthenticateWithSocialCommand, AuthenticationResult>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<AuthenticateWithSocialCommandHandler> _logger;
        private readonly IOrganizationRepository _orgRepository;
        private readonly ITokenProvider _tokenProvider;
        private readonly ISocialAuthenticationService _socialAuthService; 

        public AuthenticateWithSocialCommandHandler(
            IMediator mediator,
            ILogger<AuthenticateWithSocialCommandHandler> logger,
            IOrganizationRepository orgRepository,
            ITokenProvider tokenProvider,
            ISocialAuthenticationService socialAuthService) 
        {
            _mediator = mediator;
            _logger = logger;
            _orgRepository = orgRepository;
            _tokenProvider = tokenProvider;
            _socialAuthService = socialAuthService;
        }

        public async Task<AuthenticationResult> Handle(AuthenticateWithSocialCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling AuthenticateWithSocialCommand for Provider {Provider}", command.Provider);

            // 1. [v17 전문가 위임] 소셜 토큰 검증 (SOP 1c 계약서 확인)
            // ISocialAuthenticationService의 (string, string) 시그니처를 사용합니다.
            var (isValid, email, name, providerUserId) = await _socialAuthService.ValidateSocialTokenAsync(
                command.Provider, command.Token);

            if (!isValid || string.IsNullOrEmpty(providerUserId) || string.IsNullOrEmpty(email))
            {
                _logger.LogWarning("Authentication failed: Invalid social token for {Provider}.", command.Provider);
                throw new ValidationException("Invalid social authentication token.");
            }

            // 2. [v17 전문가 위임] JIT 프로비저닝 (SOP 1c 계약서 확인)
            // GetOrCreateUserByExternalIdCommandHandler에게 User 조회/생성을 위임합니다.
            var jitCommand = new GetOrCreateUserByExternalIdCommand(
                externalSystemType: command.Provider,
                externalUserId: providerUserId,
                email: email,
                displayName: name,
                username: null 
            );
            
            // JIT 핸들러는 v17 'UserDetailResponse' DTO를 반환합니다.
            UserDetailResponse userResponse;
            try
            {
                userResponse = await _mediator.Send(jitCommand, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "JIT Provisioning (GetOrCreateUserByExternalIdCommand) failed for {Email}", email);
                throw new InvalidOperationException("Failed to get or create user account during login.", ex);
            }

            if (userResponse == null || userResponse.Id == Guid.Empty)
            {
                throw new InvalidOperationException("JIT Provisioning returned an invalid user.");
            }
            
            // [Password Handler "본보기" 패턴 적용 시작]
            // -----------------------------------------------------------------

            // 3. [v17 핵심 로직] AuthFrame 검사 (Password Handler와 동일)
            
            // [v17 CS1061 해결] UserDetailResponse DTO "계약서"에 따라 'Organizations' 리스트를 참조합니다.
            // (UserOrganizationInfo.cs 계약서에서 'OrganizationId' 속성 확인 완료)
            var orgIdToCheck = command.OrganizationId ?? userResponse.Organizations.FirstOrDefault()?.OrganizationId;
            
            if (orgIdToCheck == null || orgIdToCheck == Guid.Empty)
            {
                _logger.LogError("Authentication failed: Cannot determine organization context for User {UserId}", userResponse.Id);
                throw new ValidationException("Authentication failed: Organization context is missing.");
            }

            var organization = await _orgRepository.GetByIdAsync(orgIdToCheck.Value, cancellationToken);
            if (organization == null)
            {
                throw new KeyNotFoundException($"Organization not found: {orgIdToCheck.Value}");
            }

            // 4. [v17 게이트키퍼] 모드 2(SSO) 검사 (Password Handler와 동일)
            if (organization.AuthenticationMode == "SsoDelegated")
            {
                _logger.LogWarning("Authentication denied: Org {OrgId} is SSO-Only (Mode 2), but user {UserId} attempted Social login.",
                    organization.Id, userResponse.Id);
                throw new ValidationException("Social login is disabled for this organization. Please use SSO.");
            }

            // 5. 계정 상태 확인 (Password Handler와 동일)
            if (userResponse.Status != UserStatus.Active && userResponse.Status != UserStatus.PendingVerification)
            {
                _logger.LogWarning("Authentication failed: Account status is {Status} for User {UserId}", userResponse.Status, userResponse.Id);
                throw new ValidationException($"Account is {userResponse.Status}. Login denied.");
            }

            // 6. [v17 MFA 정책] AuthFrame의 MFA 정책 검사 (Password Handler와 동일)
            bool requiresMfa = false;
            if (organization.MfaPolicy == "Required")
            {
                requiresMfa = true; // 조직 강제
            }
            else if (organization.MfaPolicy == "Optional" && userResponse.IsTwoFactorEnabled)
            {
                requiresMfa = true; // 개인 설정
            }

            if (requiresMfa)
            {
                _logger.LogInformation("Authentication successful (Phase 1), MFA required for User {UserId}", userResponse.Id);
                return new AuthenticationResult(
                    success: false,
                    requiresMfa: true,
                    mfaVerified: false,
                    // [v17 CS1061 해결] UserDetailResponse.cs "계약서"에 'IsNewUser' 속성 추가 확인
                    isFirstLogin: userResponse.IsNewUser, 
                    requiresPasswordChange: false,
                    userId: userResponse.Id,
                    message: "MFA verification is required."
                );
            }

            // 7. 로그인 성공 (세션 생성 위임)
            _logger.LogInformation("Authentication successful (Social: {Provider}) for User {UserId}", command.Provider, userResponse.Id);
            
            // UserDetailResponse.cs "계약서"에 따라 'Organizations' 리스트에서
            // 'UserOrganizationInfo' DTO를 찾고, 그 안의 'ConnectedId' 속성을 사용합니다. (계약서 확인 완료)
            var connectedId = userResponse.Organizations
                .FirstOrDefault(orgInfo => orgInfo.OrganizationId == organization.Id)?
                .ConnectedId;

            if (connectedId == null)
            {
                 _logger.LogWarning("User {UserId} logged in but has no active ConnectedId for Org {OrgId}. Manual selection required.", userResponse.Id, organization.Id);
            }

            // 8. [v17 "본보기"] (1/2) 세션 생성 (Password Handler와 동일)
            var sessionCommand = new CreateSessionCommand(
                userId: userResponse.Id,
                organizationId: organization.Id,
                applicationId: null,
                ipAddress: command.IpAddress,
                userAgent: command.UserAgent,
                expiresAt: DateTime.UtcNow.AddHours(8), // (설정값으로 대체 필요)
                
                // [v17 CS0117 해결] AuthEnums.cs "계약서"에 정의된 'SocialLogin'을 사용합니다.
                authenticationMethod: AuthenticationMethod.SocialLogin, 
                
                level: SessionLevel.Organization,
                connectedId: connectedId
            );

            var sessionResponse = await _mediator.Send(sessionCommand, cancellationToken);
            if (!sessionResponse.IsSuccess || sessionResponse.SessionId == null)
            {
                _logger.LogError("Session creation failed for User {UserId} after successful social login.", userResponse.Id);
                throw new InvalidOperationException("Authentication succeeded, but session creation failed.");
            }

            // 9. [v17 "본보기"] (2/2) 토큰 발행 (Password Handler와 동일)
            var claims = new List<Claim> { new Claim("user_id", userResponse.Id.ToString()) }; 
            var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(userResponse.Id, sessionResponse.SessionId.Value, claims, cancellationToken);
            var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(userResponse.Id, cancellationToken);

            if (!accessTokenResult.IsSuccess || !refreshTokenResult.IsSuccess || accessTokenResult.Data == null || refreshTokenResult.Data == null)
            {
                _logger.LogError("Token generation failed for Session {SessionId} after successful social login.", sessionResponse.SessionId);
                throw new InvalidOperationException("Session created, but token generation failed.");
            }

            // 10. 이벤트 발행 (Notify) (Password Handler와 동일)
            await _mediator.Publish(new LoginSuccessEvent(
                userId: userResponse.Id,
                sessionId: sessionResponse.SessionId.Value,
                organizationId: organization.Id,
                connectedId: connectedId,
                loginMethod: command.Provider, 
                ipAddress: command.IpAddress ?? "N/A",
                userAgent: command.UserAgent,
                location: null
            ), cancellationToken);

            // 11. 최종 응답 반환
            return new AuthenticationResult(
                success: true,
                requiresMfa: false,
                mfaVerified: false,
                isFirstLogin: userResponse.IsNewUser,
                requiresPasswordChange: false,
                userId: userResponse.Id,
                connectedId: connectedId,
                sessionId: sessionResponse.SessionId,
                accessToken: accessTokenResult.Data.AccessToken,
                refreshToken: refreshTokenResult.Data, 
                expiresAt: accessTokenResult.Data.ExpiresAt,
                organizationId: organization.Id,
                authenticationMethod: command.Provider 
            );
        }
    }
}