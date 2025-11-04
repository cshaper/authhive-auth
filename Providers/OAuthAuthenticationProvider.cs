// using System;
// using System.Collections.Generic;
// using System.Linq;
// using System.Security.Claims;
// using System.Text.Json;
// // using System.Threading.Tasks;
// using AuthHive.Auth.Data.Context;
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Enums.Auth;
// using AuthHive.Core.Interfaces.Auth.Provider;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.External;
// using AuthHive.Core.Models.Auth.Authentication;
// using AuthHive.Core.Models.Auth.Authentication.Common;
// using AuthHive.Core.Models.Common;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Distributed;
// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Logging;
// using static AuthHive.Core.Enums.Auth.SessionEnums;

// namespace AuthHive.Auth.Providers.Authentication
// {
//     /// <summary>
//     /// OAuth 2.0 인증 제공자 - AuthHive v15
//     /// 표준 OAuth 2.0 프로토콜을 사용한 인증
//     /// Google, GitHub, Microsoft 등 다양한 OAuth Provider 지원
//     /// </summary>
//     public class OAuthAuthenticationProvider : BaseAuthenticationProvider
//     {
//         private readonly ITokenProvider _tokenProvider;
//         private readonly IConfiguration _configuration;
//         private readonly IOAuthService _oauthService;

//         public override string ProviderName => "OAuth";
//         public override string ProviderType => "External";

//         public OAuthAuthenticationProvider(
//             ILogger<OAuthAuthenticationProvider> logger,
//             IDistributedCache cache,
//             IAuthenticationAttemptLogRepository attemptLogRepository,
//             ISessionService sessionService,
//             IConnectedIdService connectedIdService,
//             AuthDbContext context,
//             ITokenProvider tokenProvider,
//             IConfiguration configuration,
//             IOAuthService oauthService)
//             : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
//         {
//             _tokenProvider = tokenProvider;
//             _configuration = configuration;
//             _oauthService = oauthService;
//         }
//         protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
//             AuthenticationRequest request)
//         {
//             try
//             {
//                 // OAuth 인증 코드 확인
//                 if (string.IsNullOrEmpty(request.Code))
//                 {
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "OAuth authorization code is required",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: null, connectedId: null, externalId: null, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: false,
//                             message: "OAuth authorization code is required",
//                             expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                             roles: null, permissions: null, authenticationMethod: null,
//                             isFirstLogin: false, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: null,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 if (string.IsNullOrEmpty(request.Provider))
//                 {
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "OAuth provider is required",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: null, connectedId: null, externalId: null, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: false,
//                             message: "OAuth provider is required",
//                             expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                             roles: null, permissions: null, authenticationMethod: null,
//                             isFirstLogin: false, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: null,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 // OAuth 토큰 교환
//                 // [FIX] RedirectUri가 null일 경우를 대비하여 명시적으로 확인하고 실패 처리합니다.
//                 var redirectUri = request.RedirectUri ?? _configuration[$"OAuth:{request.Provider}:RedirectUri"];
//                 if (string.IsNullOrEmpty(redirectUri))
//                 {
//                     _logger.LogWarning("RedirectUri is not configured for OAuth provider {Provider}", request.Provider);
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         $"RedirectUri is not configured for provider {request.Provider}",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: null, connectedId: null, externalId: null, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: false,
//                             message: $"RedirectUri is not configured for provider {request.Provider}",
//                             expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                             roles: null, permissions: null, authenticationMethod: null,
//                             isFirstLogin: false, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: null,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 var tokenResult = await _oauthService.ExchangeCodeForTokenAsync(
//                     request.Provider,
//                     request.Code,
//                     redirectUri);

//                 if (!tokenResult.IsSuccess || tokenResult.Data == null)
//                 {
//                     _logger.LogWarning("Failed to exchange OAuth code for {Provider}", request.Provider);
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "Failed to exchange authorization code",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: null, connectedId: null, externalId: null, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: false,
//                             message: "Failed to exchange authorization code",
//                             expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                             roles: null, permissions: null, authenticationMethod: null,
//                             isFirstLogin: false, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: null,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 // 사용자 정보 가져오기
//                 var userInfoResult = await _oauthService.GetUserInfoAsync(
//                     request.Provider,
//                     tokenResult.Data.AccessToken);

//                 if (!userInfoResult.IsSuccess || userInfoResult.Data == null)
//                 {
//                     _logger.LogWarning("Failed to get user info from {Provider}", request.Provider);
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "Failed to retrieve user information",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: null, connectedId: null, externalId: null, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: false,
//                             message: "Failed to retrieve user information",
//                             expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                             roles: null, permissions: null, authenticationMethod: null,
//                             isFirstLogin: false, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: null,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 var oauthUser = userInfoResult.Data;

//                 // ConnectedId에서 OAuth 정보로 사용자 찾기
//                 var connectedId = await _context.ConnectedIds
//                     .Include(ci => ci.User)
//                     .FirstOrDefaultAsync(ci =>
//                         ci.Provider == request.Provider &&
//                         ci.ProviderUserId == oauthUser.Id);

//                 User? user = null;
//                 Guid connectedIdValue;

//                 // v17: isFirstLogin, isNewUser 변수 추적
//                 bool isFirstLogin = (connectedId == null);
//                 bool isNewUser = false;

//                 if (connectedId != null)
//                 {
//                     // 기존 사용자
//                     user = connectedId.User;
//                     connectedIdValue = connectedId.Id;

//                     // OAuth 토큰 업데이트
//                     connectedId.AccessToken = tokenResult.Data.AccessToken;
//                     connectedId.RefreshToken = tokenResult.Data.RefreshToken;
//                     // [FIX] non-nullable 'int' 타입에 '??' 연산자를 사용할 수 없으므로 제거합니다.
//                     connectedId.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenResult.Data.ExpiresIn);
//                     await _context.SaveChangesAsync();
//                 }
//                 else
//                 {
//                     // 이메일로 기존 사용자 찾기
//                     if (!string.IsNullOrEmpty(oauthUser.Email))
//                     {
//                         user = await _context.Users
//                             .FirstOrDefaultAsync(u => u.Email == oauthUser.Email);
//                     }

//                     // 사용자가 없으면 새로 생성
//                     if (user == null)
//                     {
//                         // v17: 신규 유저 플래그 설정
//                         isNewUser = true;

//                         // [FIX] 신규 사용자 생성 시 이메일이 없으면 실패 처리하여 Null 할당을 방지합니다.
//                         if (string.IsNullOrEmpty(oauthUser.Email))
//                         {
//                             _logger.LogWarning("OAuth provider {Provider} did not return an email for a new user.", request.Provider);
//                             // v17 생성자에 맞게 Failure 객체 반환
//                             return ServiceResult<AuthenticationOutcome>.Failure(
//                                 "An email is required for new user registration.",
//                                 new AuthenticationOutcome(
//                                     success: false,
//                                     userId: null, connectedId: null, externalId: oauthUser.Id, sessionId: null,
//                                     accessToken: null, refreshToken: null, isNewUser: true, // New user, but failed
//                                     message: "An email is required for new user registration.",
//                                     expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                                     roles: null, permissions: null, authenticationMethod: null,
//                                     isFirstLogin: true, requiresPasswordChange: false,
//                                     provider: request.Provider, providerId: oauthUser.Id,
//                                     requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                                     requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                                     requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                                     requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                                     biometricChallenge: null, biometricOptions: null,
//                                     isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                                 )
//                             );
//                         }

//                         user = new User
//                         {
//                             Id = Guid.NewGuid(),
//                             Username = oauthUser.Username ?? oauthUser.Email.Split('@')[0] ?? $"user_{Guid.NewGuid():N}",
//                             // 위에서 null 체크를 통과했으므로 이 할당은 이제 안전합니다.
//                             Email = oauthUser.Email,
//                             EmailVerified = oauthUser.EmailVerified
//                         };

//                         await _context.Users.AddAsync(user);
//                     }

//                     // 조직 결정
//                     var organizationId = request.OrganizationId ??
//                         _configuration.GetValue<Guid>("Auth:GlobalOrganizationId",
//                             Guid.Parse("00000000-0000-0000-0000-000000000001"));

//                     // ConnectedId 생성
//                     var createRequest = new CreateConnectedIdRequest
//                     {
//                         UserId = user.Id,
//                         OrganizationId = organizationId,
//                         ApplicationId = request.ApplicationId
//                     };

//                     var createResult = await _connectedIdService.CreateAsync(createRequest);
//                     if (!createResult.IsSuccess || createResult.Data == null)
//                     {
//                         // v17 생성자에 맞게 Failure 객체 반환
//                         return ServiceResult<AuthenticationOutcome>.Failure(
//                             "Failed to create connected identity",
//                             new AuthenticationOutcome(
//                                 success: false,
//                                 userId: user.Id, connectedId: null, externalId: oauthUser.Id, sessionId: null,
//                                 accessToken: null, refreshToken: null, isNewUser: isNewUser,
//                                 message: "Failed to create connected identity",
//                                 expiresAt: null, claims: null, organizationId: organizationId, applicationId: request.ApplicationId,
//                                 roles: null, permissions: null, authenticationMethod: null,
//                                 isFirstLogin: true, requiresPasswordChange: false,
//                                 provider: request.Provider, providerId: oauthUser.Id,
//                                 requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                                 requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                                 requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                                 requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                                 biometricChallenge: null, biometricOptions: null,
//                                 isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                             )
//                         );
//                     }

//                     connectedIdValue = createResult.Data.Id;

//                     // OAuth 정보 저장
//                     var createdConnectedId = await _context.ConnectedIds
//                         .FirstOrDefaultAsync(ci => ci.Id == connectedIdValue);

//                     if (createdConnectedId != null)
//                     {
//                         createdConnectedId.Provider = request.Provider;
//                         createdConnectedId.ProviderUserId = oauthUser.Id;
//                         createdConnectedId.AccessToken = tokenResult.Data.AccessToken;
//                         createdConnectedId.RefreshToken = tokenResult.Data.RefreshToken;
//                         // [FIX] non-nullable 'int' 타입에 '??' 연산자를 사용할 수 없으므로 제거합니다.
//                         createdConnectedId.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenResult.Data.ExpiresIn);
//                         createdConnectedId.ProviderData = JsonSerializer.Serialize(oauthUser);

//                         // 프로필 정보 업데이트
//                         createdConnectedId.FirstName = oauthUser.FirstName;
//                         createdConnectedId.LastName = oauthUser.LastName;
//                         createdConnectedId.ProfilePictureUrl = oauthUser.Picture;
//                         // DisplayName 설정: OAuth에서 제공한 이름 > Username > Email prefix
//                         createdConnectedId.ProfileDisplayName = oauthUser.Username ??
//                                                                 oauthUser.Email?.Split('@')[0] ??
//                                                                 "User";

//                         await _context.SaveChangesAsync();
//                     }
//                 }

//                 var finalOrganizationId = connectedId?.OrganizationId ?? request.OrganizationId ??
//                     _configuration.GetValue<Guid>("Auth:GlobalOrganizationId",
//                         Guid.Parse("00000000-0000-0000-0000-000000000001"));

//                 // 세션 생성
//                 var sessionResult = await _sessionService.CreateSessionAsync(
//                     new Core.Models.Auth.Session.Requests.CreateSessionRequest
//                     {
//                         ConnectedId = connectedIdValue,
//                         OrganizationId = finalOrganizationId,
//                         SessionType = SessionType.Web,
//                         IpAddress = request.IpAddress,
//                         UserAgent = request.UserAgent,
//                         DeviceInfo = request.DeviceId,
//                         OperatingSystem = request.DeviceInfo?.OperatingSystem,
//                         Browser = request.DeviceInfo?.Browser,
//                         Location = request.DeviceInfo?.Location,
//                         ExpiresAt = DateTime.UtcNow.AddHours(24),
//                         InitialStatus = SessionStatus.Active,
//                         Metadata = JsonSerializer.Serialize(new
//                         {
//                             AuthenticationMethod = AuthenticationMethod.OAuth.ToString(),
//                             Provider = request.Provider,
//                             ApplicationId = request.ApplicationId
//                         })
//                     });

//                 if (!sessionResult.IsSuccess || sessionResult.Data == null)
//                 {
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "Session creation failed",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: user.Id, connectedId: connectedIdValue, externalId: oauthUser.Id, sessionId: null,
//                             accessToken: null, refreshToken: null, isNewUser: isNewUser,
//                             message: "Session creation failed",
//                             expiresAt: null, claims: null, organizationId: finalOrganizationId, applicationId: request.ApplicationId,
//                             roles: null, permissions: null, authenticationMethod: AuthenticationMethod.OAuth.ToString(),
//                             isFirstLogin: isFirstLogin, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: oauthUser.Id,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 // 토큰 생성
//                 var claims = new List<Claim>
//         {
//             new Claim("user_id", user.Id.ToString()),
//             new Claim("connected_id", connectedIdValue.ToString()),
//             new Claim("org_id", finalOrganizationId.ToString()),
//             new Claim("auth_method", "oauth"),
//             new Claim("oauth_provider", request.Provider),
//             new Claim("session_id", sessionResult.Data?.SessionId.ToString() ?? "")
//         };

//                 if (!string.IsNullOrEmpty(user.Email))
//                 {
//                     claims.Add(new Claim("email", user.Email));
//                 }

//                 var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(
//                     user.Id,
//                     connectedIdValue,
//                     claims);

//                 if (!accessTokenResult.IsSuccess || accessTokenResult.Data == null)
//                 {
//                     // v17 생성자에 맞게 Failure 객체 반환
//                     return ServiceResult<AuthenticationOutcome>.Failure(
//                         "Token generation failed",
//                         new AuthenticationOutcome(
//                             success: false,
//                             userId: user.Id, connectedId: connectedIdValue, externalId: oauthUser.Id, sessionId: sessionResult.Data.SessionId,
//                             accessToken: null, refreshToken: null, isNewUser: isNewUser,
//                             message: "Token generation failed",
//                             expiresAt: null, claims: null, organizationId: finalOrganizationId, applicationId: request.ApplicationId,
//                             roles: null, permissions: null, authenticationMethod: AuthenticationMethod.OAuth.ToString(),
//                             isFirstLogin: isFirstLogin, requiresPasswordChange: false,
//                             provider: request.Provider, providerId: oauthUser.Id,
//                             requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                             requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                             requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                             requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                             biometricChallenge: null, biometricOptions: null,
//                             isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                         )
//                     );
//                 }

//                 var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

//                 // v17의 생성자 방식 (수정 완료)
//                 return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome(
//                     success: true,
//                     userId: user.Id,
//                     connectedId: connectedIdValue,
//                     externalId: oauthUser.Id, // externalId로 providerId 전달
//                     sessionId: sessionResult.Data?.SessionId ?? Guid.Empty,
//                     accessToken: accessTokenResult.Data?.AccessToken,
//                     refreshToken: refreshToken.Data,
//                     isNewUser: isNewUser, // v17: 추적한 값 사용
//                     message: null,
//                     expiresAt: accessTokenResult.Data?.ExpiresAt,
//                     claims: null, // 토큰에 이미 포함됨 (필요시 별도 전달)
//                     organizationId: finalOrganizationId,
//                     applicationId: request.ApplicationId,
//                     roles: null, // 필요시 조회 후 전달
//                     permissions: null, // 필요시 조회 후 전달
//                     authenticationMethod: AuthenticationMethod.OAuth.ToString(),
//                     isFirstLogin: isFirstLogin, // v17: 추적한 값 사용
//                     requiresPasswordChange: false, // OAuth는 패스워드 변경 불필요
//                     provider: request.Provider,
//                     providerId: oauthUser.Id,
//                     requiresMfa: false, // MFA는 이 단계 이후에 결정됨
//                     mfaMethods: null,
//                     mfaVerified: false,
//                     requiresMagicLinkRegistration: false,
//                     requiresPasskeyRegistration: false,
//                     requiresPasskeyAuthentication: false,
//                     passkeyChallenge: null,
//                     passkeyOptions: null,
//                     requiresBiometricEnrollment: false,
//                     requiresBiometricVerification: false,
//                     biometricChallenge: null,
//                     biometricOptions: null,
//                     isBiometric: false,
//                     biometricType: null,
//                     requiresCertificateRegistration: false,
//                     authenticationStrength: AuthenticationStrength.Medium // OAuth는 일반적으로 Medium
//                 ));
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "OAuth authentication failed");

//                 // vI7 생성자에 맞게 Failure 객체 반환
//                 return ServiceResult<AuthenticationOutcome>.Failure(
//                     "Authentication failed",
//                     new AuthenticationOutcome(
//                         success: false,
//                         userId: null, connectedId: null, externalId: null, sessionId: null,
//                         accessToken: null, refreshToken: null, isNewUser: false,
//                         message: "Authentication failed",
//                         expiresAt: null, claims: null, organizationId: null, applicationId: null,
//                         roles: null, permissions: null, authenticationMethod: null,
//                         isFirstLogin: false, requiresPasswordChange: false,
//                         provider: request.Provider, // request가 null일 수 있으므로 주의 (이 컨텍스트에선 괜찮음)
//                         providerId: null,
//                         requiresMfa: false, mfaMethods: null, mfaVerified: false,
//                         requiresMagicLinkRegistration: false, requiresPasskeyRegistration: false,
//                         requiresPasskeyAuthentication: false, passkeyChallenge: null, passkeyOptions: null,
//                         requiresBiometricEnrollment: false, requiresBiometricVerification: false,
//                         biometricChallenge: null, biometricOptions: null,
//                         isBiometric: false, biometricType: null, requiresCertificateRegistration: false
//                     )
//                 );
//             }
//         }
//         protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
//         {
//             // OAuth는 코드 교환 후 사용자 정보를 가져오므로 이 메서드는 사용하지 않음
//             return Task.FromResult<UserProfile?>(null);
//         }

//         public override async Task<ServiceResult<bool>> ValidateAsync(string token)
//         {
//             var result = await _tokenProvider.ValidateAccessTokenAsync(token);
//             return ServiceResult<bool>.Success(result.IsSuccess);
//         }

//         public override async Task<ServiceResult> RevokeAsync(string tokenOrSessionId)
//         {
//             if (Guid.TryParse(tokenOrSessionId, out var sessionId))
//             {
//                 var session = await _context.Sessions
//                     .FirstOrDefaultAsync(s => s.Id == sessionId && s.Status == SessionStatus.Active);

//                 if (session != null)
//                 {
//                     session.Status = SessionStatus.LoggedOut;
//                     session.EndedAt = DateTime.UtcNow;
//                     session.EndReason = SessionEndReason.UserLogout;
//                     await _context.SaveChangesAsync();
//                 }
//             }

//             return ServiceResult.Success();
//         }

//         public override async Task<bool> IsEnabledAsync()
//         {
//             var isEnabled = _configuration.GetValue<bool>("OAuth:Enabled");
//             return await Task.FromResult(isEnabled);
//         }

//         public class AuthenticationRequest
//         {
//         }
//     }
// }