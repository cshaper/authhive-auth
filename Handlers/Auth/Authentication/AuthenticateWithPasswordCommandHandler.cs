// [AuthHive.Auth] AuthenticateWithPasswordCommandHandler.cs
// v17 CQRS "본보기": 'AuthenticateWithPasswordCommand' (ID/PW)를 처리합니다.
// [v17.4 수정] v17 ITokenProvider의 2-step(Access/Refresh) 호출, AuthFrame 검사,
// ConnectedId 'using' 누락(CS0246), RefreshToken '추론'(CS1061) 오류를 모두 수정한 최종본입니다.

using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth.ConnectedId; // Ensure the correct namespace for ConnectedId
using AuthHive.Core.Entities.Auth; // Ensure the correct namespace for ConnectedId
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Auth.Provider; // [v17] ITokenProvider
using AuthHive.Core.Interfaces.Infra.Security; // IPasswordHashProvider
using AuthHive.Core.Interfaces.User.Service; // IAccountSecurityService
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Common; // AuthenticationResult, TokenInfo
using AuthHive.Core.Models.Auth.Authentication.Events; // LoginSuccessEvent
using AuthHive.Core.Models.Auth.Session.Commands; // CreateSessionCommand
using AuthHive.Core.Models.Auth.Session.Responses; // CreateSessionResponse
using System.Linq;
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Linq; // .FirstOrDefault()
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims; // Claim
using System.Collections.Generic; // List
using static AuthHive.Core.Enums.Core.UserEnums; // UserStatus
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionType
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Enums.Auth;
using AuthenticationResult = AuthHive.Core.Models.Auth.Authentication.Common.AuthenticationResult;

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "비밀번호 인증" 유스케이스 핸들러 (SOP 1-Write-R)
    /// v17 AuthFrame 정책을 검사하고, v16 인증 공급자 로직을 이관합니다.
    /// </summary>
    public class AuthenticateWithPasswordCommandHandler : IRequestHandler<AuthenticateWithPasswordCommand, AuthenticationResult>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<AuthenticateWithPasswordCommandHandler> _logger;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _orgRepository;
        private readonly IAccountSecurityService _accountSecurityService;
        private readonly IPasswordHashProvider _passwordHashProvider;
        private readonly ITokenProvider _tokenProvider; // [v17] ITokenProvider 주입

        public AuthenticateWithPasswordCommandHandler(
            IMediator mediator,
            ILogger<AuthenticateWithPasswordCommandHandler> logger,
            IUserRepository userRepository,
            IOrganizationRepository orgRepository,
            IAccountSecurityService accountSecurityService,
            IPasswordHashProvider passwordHashProvider,
            ITokenProvider tokenProvider) // [v17]
        {
            _mediator = mediator;
            _logger = logger;
            _userRepository = userRepository;
            _orgRepository = orgRepository;
            _accountSecurityService = accountSecurityService;
            _passwordHashProvider = passwordHashProvider;
            _tokenProvider = tokenProvider;
            // [v17 수정] ISessionService/ITokenService 제거
        }

        public async Task<AuthenticationResult> Handle(AuthenticateWithPasswordCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling AuthenticateWithPasswordCommand for {Email}", command.Email);

            // 1. 사용자 조회 (v16 Provider.FindUserAsync 로직 이관)
            var user = await _userRepository.FindByEmailAsync(command.Email, true, cancellationToken);
            if (user == null)
            {
                _logger.LogWarning("Authentication failed: User not found ({Email})", command.Email);
                throw new ValidationException("Invalid email or password.");
            }
            // (로직 1: 검사할 '조직' 확정)
            //   사용자가 'command.OrganizationId' (예: acme.authhive.com)를 명시적으로 제공했을 수 있습니다.
            //   만약 제공하지 않았다면(플랫폼 전역 로그인), 'user.OrganizationId'에 저장된
            //   '기본 조직'의 정책을 따라야 합니다.
            //
            // (로직 2: 'AuthFrame' 조회)
            //   확정된 'orgIdToCheck'를 사용하여 'Organization' 엔티티를 조회합니다.
            //   이 엔티티에는 우리가 v6.17에서 "본보기"로 추가한 'AuthenticationMode'와 'MfaPolicy' 필드가 포함되어 있습니다.
            //
            // (다음 3단계에서) 이 'AuthenticationMode'를 검사하여 '모드 2(SsoDelegated)'일 경우,
            //   이 핸들러는 즉시 인증을 '거부(DENY)'해야 합니다.
            // 2. [v17 핵심 로직] AuthFrame 검사
            var orgIdToCheck = command.OrganizationId ?? user.OrganizationId;
            if (orgIdToCheck == null || orgIdToCheck == Guid.Empty)
            {
                _logger.LogError("Authentication failed: Cannot determine organization context for User {UserId}", user.Id);
                throw new ValidationException("Authentication failed: Organization context is missing.");
            }

            var organization = await _orgRepository.GetByIdAsync(orgIdToCheck.Value, cancellationToken);
            if (organization == null)
            {
                throw new KeyNotFoundException($"Organization not found: {orgIdToCheck.Value}");
            }
            // (v17 철학의 해결책):
            //   v17 "본보기" 핸들러는 'Password'가 유효한지 검사하기 *전에*,
            //   2단계에서 조회한 'organization.AuthenticationMode' (v17 엔티티 수정 필드)를
            //   *먼저* 확인합니다.
            //
            // (로직 1: 모드 1 통과)
            //   'AuthenticationMode'가 "AuthHiveManaged" (모드 1)이면,
            //   비밀번호 로그인이 '허용'되므로, 이 검사를 통과(Pass)하고
            //   5단계(비밀번호 검증)로 넘어갑니다.
            //
            // (로직 2: 모드 2 거부)
            //   'AuthenticationMode'가 "SsoDelegated" (모드 2)이면,
            //   이 'Organization'은 비밀번호 로그인을 *금지*하고 SAML/OIDC 등
            //   SSO 공급자에게 인증을 *위임(Delegate)*한 상태입니다.
            //
            //   따라서 이 핸들러는 즉시 'ValidationException'을 발생시켜
            //   비밀번호 인증 시도를 '거부(DENY)'해야 합니다.
            // 3. [v17 게이트키퍼] 모드 2(SSO) 검사 (v17 신규 로직)
            if (organization.AuthenticationMode == "SsoDelegated") // [SOP 1.3]
            {
                _logger.LogWarning("Authentication denied: Org {OrgId} is SSO-Only (Mode 2), but user {UserId} attempted Password login.",
                    organization.Id, user.Id);
                throw new ValidationException("Password login is disabled for this organization. Please use SSO.");
            }

            // 4. 계정 상태 확인 (v16 Provider.ValidateAccountStatusAsync 로직 이관)
            if (user.Status != UserStatus.Active && user.Status != UserStatus.PendingVerification)
            {
                _logger.LogWarning("Authentication failed: Account status is {Status} for User {UserId}", user.Status, user.Id);
                throw new ValidationException($"Account is {user.Status}. Login denied.");
            }

            // 5. [v17 전문가 위임] 비밀번호 검증
            if (string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                throw new ValidationException("Password authentication is not available for this account.");
            }

            var isPasswordValid = await _passwordHashProvider.VerifyPasswordAsync(command.Password, user.PasswordHash);
            if (!isPasswordValid)
            {
                await _accountSecurityService.IncrementFailedAttemptsAsync(user.Id, cancellationToken);
                _logger.LogWarning("Authentication failed: Invalid password for User {UserId}", user.Id);
                throw new ValidationException("Invalid email or password.");
            }

            await _accountSecurityService.ResetFailedAttemptsAsync(user.Id, cancellationToken);

            // 6. [v17 MFA 정책] AuthFrame의 MFA 정책 검사
            bool requiresMfa = false;
            if (organization.MfaPolicy == "Required") // [SOP 1.3]
            {
                requiresMfa = true; // 조직 강제
            }
            else if (organization.MfaPolicy == "Optional" && user.IsTwoFactorEnabled) // [SOP 1.3]
            {
                requiresMfa = true; // 개인 설정
            }

            if (requiresMfa)
            {
                _logger.LogInformation("Authentication successful (Phase 1), MFA required for User {UserId}", user.Id);
                return new AuthenticationResult(
                    success: false,
                    requiresMfa: true,
                    mfaVerified: false,
                    isFirstLogin: false,
                    requiresPasswordChange: false,
                    userId: user.Id,
                    message: "MFA verification is required."
                );
            }

            // 7. 로그인 성공 (세션 생성 위임)
            // [시나리오 1: connectedId != null]
            //   'User'가 대상 'Organization'의 멤버임을 확인했습니다.
            //   이 'connectedId'를 사용하여 '조직 세션'을 생성합니다.
            //
            // [시나리오 2: connectedId == null]
            //   'User'는 존재하지만(플랫폼 가입자), 이 'Organization'의 멤버가 아닙니다.
            //   (예: "Beta Corp." 멤버가 "Acme Inc."의 로그인 페이지로 접근한 경우)
            //   이 경우, '플랫폼 세션'만 생성되거나(v16 로직),
            //   "조직 선택(Manual selection required)" 화면으로 리디렉션해야 함을 의미합니다.
            _logger.LogInformation("Authentication successful (Password) for User {UserId}", user.Id);
            var connectedId = user.ConnectedIds?.FirstOrDefault(c => c.OrganizationId == organization.Id)?.Id;
            if (connectedId == null)
            {
                _logger.LogWarning("User {UserId} logged in but has no active ConnectedId for Org {OrgId}. Manual selection required.", user.Id, organization.Id);
            }

            // 8. [v17 "본보기"] (1/2) 세션 생성 (v16 ISessionService 대체)
            var sessionCommand = new CreateSessionCommand(
                userId: user.Id,
                organizationId: organization.Id,
                applicationId: null,
                ipAddress: command.IpAddress,
                userAgent: command.UserAgent,
                expiresAt: DateTime.UtcNow.AddHours(8), // (설정값으로 대체 필요)
                authenticationMethod: AuthenticationMethod.Password,
                level: SessionLevel.Organization,
                connectedId: connectedId
            );

            var sessionResponse = await _mediator.Send(sessionCommand, cancellationToken);
            if (!sessionResponse.IsSuccess || sessionResponse.SessionId == null)
            {
                _logger.LogError("Session creation failed for User {UserId} after successful login.", user.Id);
                throw new InvalidOperationException("Authentication succeeded, but session creation failed.");
            }

            // 9. [v17 "본보기"] (2/2) 토큰 발행 (v16 ITokenService 대체)
            // [CS1061 해결] v17 ITokenProvider의 2개 전문가 메서드를 순차 호출
            var claims = new List<Claim> { new Claim("user_id", user.Id.ToString()) }; // (v16 Provider 로직)
            var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, sessionResponse.SessionId.Value, claims, cancellationToken);
            var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(user.Id, cancellationToken);

            if (!accessTokenResult.IsSuccess || !refreshTokenResult.IsSuccess || accessTokenResult.Data == null || refreshTokenResult.Data == null)
            {
                _logger.LogError("Token generation failed for Session {SessionId} after successful login.", sessionResponse.SessionId);
                throw new InvalidOperationException("Session created, but token generation failed.");
            }

            // 10. 이벤트 발행 (Notify)
            await _mediator.Publish(new LoginSuccessEvent(
                userId: user.Id,
                sessionId: sessionResponse.SessionId.Value,
                organizationId: organization.Id,
                connectedId: connectedId,
                loginMethod: "Password",
                ipAddress: command.IpAddress ?? "N/A",
                userAgent: command.UserAgent,
                location: null
            ), cancellationToken);

            // 11. 최종 응답 반환
            // [CS1061 해결] v17 TokenInfo 및 string에서 값 조합
            return new AuthenticationResult(
                success: true,
                requiresMfa: false,
                mfaVerified: false,
                isFirstLogin: false,
                requiresPasswordChange: false,
                userId: user.Id,
                connectedId: connectedId,
                sessionId: sessionResponse.SessionId,
                accessToken: accessTokenResult.Data.AccessToken,
                refreshToken: refreshTokenResult.Data, // string
                expiresAt: accessTokenResult.Data.ExpiresAt,
                organizationId: organization.Id,
                authenticationMethod: "Password"
            );
        }
    }
}