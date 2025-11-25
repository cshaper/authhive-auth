// using System;
// using System.Collections.Generic;
// using System.Security.Claims;
// using System.Text.Json;
// using System.Threading; // CancellationToken 사용을 위해 추가
// using System.Threading.Tasks;
// using AuthHive.Auth.Data.Context;
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Enums.Auth;
// using AuthHive.Core.Interfaces.Auth.Provider;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.Organization.Service;
// using AuthHive.Core.Interfaces.Base; // IUnitOfWork 등
// using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider, IAuditService 등
// using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
// using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
// using AuthHive.Core.Interfaces.Business.Platform; // IPlanRestrictionService
// using AuthHive.Core.Models.Auth.Authentication;
// using AuthHive.Core.Models.Common;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Distributed;
// using Microsoft.Extensions.Logging;
// using static AuthHive.Core.Enums.Auth.SessionEnums;
// using AuthHive.Core.Interfaces.Audit;
// using AuthHive.Core.Models.Auth.Authentication.Common;


// namespace AuthHive.Auth.Providers
// {
//     public class SsoAuthenticationProvider : BaseAuthenticationProvider
//     {
//         private readonly ITokenProvider _tokenProvider;
//         private readonly IOrganizationSSOService _ssoService;

//         private readonly AuthDbContext _context;
//         private readonly ISessionService _sessionService;

//         public override string ProviderName => "SSO";
//         public override string ProviderType => "External";

//         public SsoAuthenticationProvider(
//             ILogger<SsoAuthenticationProvider> logger,
//             ICacheService cacheService,
//             IAuthenticationAttemptLogRepository attemptLogRepository, // BaseProvider에 남기지 않고 Service/Repository로 처리했다고 가정

//             // Base Provider에서 제거되어 SsoProvider가 직접 사용하는 인자
//             ISessionService sessionService,
//             AuthDbContext context,

//             // SsoProvider 고유의 인자
//             ITokenProvider tokenProvider,
//             IOrganizationSSOService ssoService,

//             // 🚨 Base Provider의 최종 생성자에 필요한 모든 인자
//             IUnitOfWork unitOfWork,
//             IDateTimeProvider dateTimeProvider,
//             IAuditService auditService,
//             IUserRepository userRepository,
//             IConnectedIdRepository connectedIdRepository,
//             IAccountSecurityService accountSecurityService,
//             IPlanRestrictionService planRestrictionService)

//             // 🚨 Base() 호출: BaseProvider의 최종 시그니처에 맞게 인자를 순서대로 전달 (CS7036 해결)
//             : base(
//                 logger,
//                 cacheService,
//                 unitOfWork,
//                 dateTimeProvider,
//                 auditService,
//                 userRepository,
//                 connectedIdRepository,
//                 accountSecurityService,
//                 planRestrictionService)
//         {
//             _tokenProvider = tokenProvider;
//             _ssoService = ssoService;

//             // 🚨 SsoProvider 내부에서 사용할 필드 초기화 (CS0103 해결)
//             _context = context;
//             _sessionService = sessionService;
//         }

//         // 🚨 CancellationToken 추가 (CS0534/CS0115 해결)
//         protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
//             AuthenticationRequest request,
//             CancellationToken cancellationToken)
//         {
//             if (!request.OrganizationId.HasValue || string.IsNullOrEmpty(request.SamlResponse))
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("Organization ID and SAML response are required.", "INVALID_REQUEST");
//             }

//             try
//             {
//                 // 🚨 CancellationToken 전달
//                 var ssoResult = await _ssoService.ProcessSsoResponseAsync(request.OrganizationId.Value, request.SamlResponse, cancellationToken);
//                 if (!ssoResult.IsSuccess || ssoResult.Data == null)
//                 {
//                     _logger.LogWarning("SSO authentication failed for organization {OrganizationId}. Reason: {Reason}", request.OrganizationId, ssoResult.ErrorMessage);
//                     return ServiceResult<AuthenticationOutcome>.Failure(ssoResult.ErrorMessage ?? "SSO authentication failed.", ssoResult.ErrorCode);
//                 }

//                 var ssoData = ssoResult.Data;

//                 if (!ssoData.UserId.HasValue)
//                 {
//                     _logger.LogError("SSO authentication succeeded, but the user ID was null. SSO Provider: {Provider}", ssoData.Provider);
//                     return ServiceResult<AuthenticationOutcome>.Failure("Failed to retrieve user ID from SSO provider.");
//                 }

//                 // 🚨 _context 사용 및 CancellationToken 전달 (CS0103 해결)
//                 // NOTE: EF Core의 FindAsync는 기본적으로 비동기입니다.
//                 var user = await _context.Users.FindAsync(new object[] { ssoData.UserId.Value }, cancellationToken);
//                 if (user == null)
//                 {
//                     return ServiceResult<AuthenticationOutcome>.Failure("User not found after SSO processing.", "USER_NOT_FOUND");
//                 }

//                 // 🚨 _sessionService 사용 및 CancellationToken 전달 (CS0103 해결)
//                 var sessionResult = await _sessionService.CreateSessionAsync(new CreateSessionRequest
//                 {
//                     UserId = ssoData.UserId.Value,
//                     ConnectedId = ssoData.ConnectedId ?? Guid.Empty,
//                     OrganizationId = request.OrganizationId,
//                     ApplicationId = request.ApplicationId,
//                     SessionType = SessionType.Web,
//                     Level = SessionLevel.Organization,
//                     IpAddress = request.IpAddress,
//                     UserAgent = request.UserAgent,
//                     DeviceInfo = request.DeviceInfo != null ? JsonSerializer.Serialize(request.DeviceInfo) : null,
//                     Provider = "SSO",
//                     AuthenticationMethod = AuthenticationMethod.SSO,
//                     SecurityLevel = SessionSecurityLevel.High,
//                     Metadata = JsonSerializer.Serialize(new { ssoData.Provider, ssoData.ExternalId })
//                 }, cancellationToken);

//                 if (!sessionResult.IsSuccess || sessionResult.Data == null)
//                 {
//                     return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed after SSO login.", "SESSION_ERROR");
//                 }

//                 var claims = new List<Claim>
//                 {
//                     new Claim("user_id", ssoData.UserId.ToString() ?? string.Empty),
//                     new Claim("connected_id", ssoData.ConnectedId.ToString() ?? string.Empty),
//                     new Claim("org_id", request.OrganizationId.Value.ToString()),
//                     new Claim("auth_method", "sso"),
//                     new Claim("sso_provider", ssoData.Provider ?? string.Empty),
//                     new Claim("session_id", sessionResult.Data.SessionId?.ToString() ?? string.Empty)
//                 };

//                 // 🚨 CancellationToken 전달
//                 var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, ssoData.ConnectedId ?? Guid.Empty, claims, cancellationToken);
//                 if (!tokenResult.IsSuccess || tokenResult.Data == null)
//                 {
//                     return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed.", "TOKEN_ERROR");
//                 }

//                 // 🚨 CancellationToken 전달
//                 var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id, cancellationToken);

//                 return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
//                 {
//                     Success = true,
//                     UserId = ssoData.UserId,
//                     ConnectedId = ssoData.ConnectedId,
//                     SessionId = sessionResult.Data.SessionId,
//                     AccessToken = tokenResult.Data.AccessToken,
//                     RefreshToken = refreshToken.Data,
//                     ExpiresAt = tokenResult.Data.ExpiresAt,
//                     OrganizationId = request.OrganizationId,
//                     ApplicationId = request.ApplicationId,
//                     AuthenticationMethod = AuthenticationMethod.SSO.ToString(),
//                     IsNewUser = ssoData.IsNewUser,
//                     AuthenticationStrength = AuthenticationStrength.High
//                 });
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "An unexpected error occurred during SSO authentication for organization {OrganizationId}", request.OrganizationId);
//                 return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred during SSO authentication.", "SYSTEM_ERROR");
//             }
//         }

//         // 🚨 CancellationToken 추가 (CS0534/CS0115 해결)
//         public override async Task<ServiceResult<bool>> ValidateAsync(string token, CancellationToken cancellationToken = default)
//         {
//             // 🚨 CancellationToken 전달
//             var result = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);
//             return ServiceResult<bool>.Success(result.IsSuccess);
//         }

//         // 🚨 CancellationToken 추가 (CS0534/CS0115 해결)
//         public override async Task<ServiceResult> RevokeAsync(string token, CancellationToken cancellationToken = default)
//         {
//             // 🚨 CancellationToken 전달
//             var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);
//             if (!validationResult.IsSuccess || validationResult.Data == null) return ServiceResult.Failure("Invalid token.");

//             var sessionIdClaim = validationResult.Data.FindFirst("session_id");
//             if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
//             {
//                 return ServiceResult.Failure("Session ID not found in token.");
//             }

//             // 🚨 CancellationToken 전달
//             return await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout, cancellationToken);
//         }
//         // 🚨 CancellationToken 추가 (CS0534/CS0115 해결)
//         public override Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
//         {
//             return Task.FromResult(true);
//         }

//     }
// }