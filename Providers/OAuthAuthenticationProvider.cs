using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.External;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Providers.Authentication
{
    /// <summary>
    /// OAuth 2.0 인증 제공자 - AuthHive v15
    /// 표준 OAuth 2.0 프로토콜을 사용한 인증
    /// Google, GitHub, Microsoft 등 다양한 OAuth Provider 지원
    /// </summary>
    public class OAuthAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IConfiguration _configuration;
        private readonly IOAuthService _oauthService;
        
        public override string ProviderName => "OAuth";
        public override string ProviderType => "External";

        public OAuthAuthenticationProvider(
            ILogger<OAuthAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            IConfiguration configuration,
            IOAuthService oauthService)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _configuration = configuration;
            _oauthService = oauthService;
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request)
        {
            try
            {
                // OAuth 인증 코드 확인
                if (string.IsNullOrEmpty(request.Code))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("OAuth authorization code is required");
                }

                if (string.IsNullOrEmpty(request.Provider))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("OAuth provider is required");
                }

                // OAuth 토큰 교환
                // [FIX] RedirectUri가 null일 경우를 대비하여 명시적으로 확인하고 실패 처리합니다.
                var redirectUri = request.RedirectUri ?? _configuration[$"OAuth:{request.Provider}:RedirectUri"];
                if (string.IsNullOrEmpty(redirectUri))
                {
                    _logger.LogWarning("RedirectUri is not configured for OAuth provider {Provider}", request.Provider);
                    return ServiceResult<AuthenticationOutcome>.Failure($"RedirectUri is not configured for provider {request.Provider}");
                }
                
                var tokenResult = await _oauthService.ExchangeCodeForTokenAsync(
                    request.Provider,
                    request.Code,
                    redirectUri);

                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    _logger.LogWarning("Failed to exchange OAuth code for {Provider}", request.Provider);
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to exchange authorization code");
                }

                // 사용자 정보 가져오기
                var userInfoResult = await _oauthService.GetUserInfoAsync(
                    request.Provider,
                    tokenResult.Data.AccessToken);

                if (!userInfoResult.IsSuccess || userInfoResult.Data == null)
                {
                    _logger.LogWarning("Failed to get user info from {Provider}", request.Provider);
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to retrieve user information");
                }

                var oauthUser = userInfoResult.Data;
                
                // ConnectedId에서 OAuth 정보로 사용자 찾기
                var connectedId = await _context.ConnectedIds
                    .Include(ci => ci.User)
                    .FirstOrDefaultAsync(ci => 
                        ci.Provider == request.Provider &&
                        ci.ProviderUserId == oauthUser.Id);

                User? user = null;
                Guid connectedIdValue;
                
                if (connectedId != null)
                {
                    // 기존 사용자
                    user = connectedId.User;
                    connectedIdValue = connectedId.Id;
                    
                    // OAuth 토큰 업데이트
                    connectedId.AccessToken = tokenResult.Data.AccessToken;
                    connectedId.RefreshToken = tokenResult.Data.RefreshToken;
                    // [FIX] non-nullable 'int' 타입에 '??' 연산자를 사용할 수 없으므로 제거합니다.
                    connectedId.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenResult.Data.ExpiresIn);
                    await _context.SaveChangesAsync();
                }
                else
                {
                    // 이메일로 기존 사용자 찾기
                    if (!string.IsNullOrEmpty(oauthUser.Email))
                    {
                        user = await _context.Users
                            .FirstOrDefaultAsync(u => u.Email == oauthUser.Email);
                    }

                    // 사용자가 없으면 새로 생성
                    if (user == null)
                    {
                        // [FIX] 신규 사용자 생성 시 이메일이 없으면 실패 처리하여 Null 할당을 방지합니다.
                        if (string.IsNullOrEmpty(oauthUser.Email))
                        {
                            _logger.LogWarning("OAuth provider {Provider} did not return an email for a new user.", request.Provider);
                            return ServiceResult<AuthenticationOutcome>.Failure("An email is required for new user registration.");
                        }
                        
                        user = new User
                        {
                            Id = Guid.NewGuid(),
                            Username = oauthUser.Username ?? oauthUser.Email.Split('@')[0] ?? $"user_{Guid.NewGuid():N}",
                            // 위에서 null 체크를 통과했으므로 이 할당은 이제 안전합니다.
                            Email = oauthUser.Email, 
                            EmailVerified = oauthUser.EmailVerified
                        };

                        await _context.Users.AddAsync(user);
                    }

                    // 조직 결정
                    var organizationId = request.OrganizationId ??
                        _configuration.GetValue<Guid>("Auth:GlobalOrganizationId",
                            Guid.Parse("00000000-0000-0000-0000-000000000001"));

                    // ConnectedId 생성
                    var createRequest = new CreateConnectedIdRequest
                    {
                        UserId = user.Id,
                        OrganizationId = organizationId,
                        ApplicationId = request.ApplicationId
                    };

                    var createResult = await _connectedIdService.CreateAsync(createRequest);
                    if (!createResult.IsSuccess || createResult.Data == null)
                    {
                        return ServiceResult<AuthenticationOutcome>.Failure("Failed to create connected identity");
                    }

                    connectedIdValue = createResult.Data.Id;
                    
                    // OAuth 정보 저장
                    var createdConnectedId = await _context.ConnectedIds
                        .FirstOrDefaultAsync(ci => ci.Id == connectedIdValue);
                    
                    if (createdConnectedId != null)
                    {
                        createdConnectedId.Provider = request.Provider;
                        createdConnectedId.ProviderUserId = oauthUser.Id;
                        createdConnectedId.AccessToken = tokenResult.Data.AccessToken;
                        createdConnectedId.RefreshToken = tokenResult.Data.RefreshToken;
                        // [FIX] non-nullable 'int' 타입에 '??' 연산자를 사용할 수 없으므로 제거합니다.
                        createdConnectedId.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenResult.Data.ExpiresIn);
                        createdConnectedId.ProviderData = JsonSerializer.Serialize(oauthUser);
                        
                        // 프로필 정보 업데이트
                        createdConnectedId.FirstName = oauthUser.FirstName;
                        createdConnectedId.LastName = oauthUser.LastName;
                        createdConnectedId.ProfilePictureUrl = oauthUser.Picture;
                        // DisplayName 설정: OAuth에서 제공한 이름 > Username > Email prefix
                        createdConnectedId.ProfileDisplayName = oauthUser.Username ?? 
                                                                oauthUser.Email?.Split('@')[0] ?? 
                                                                "User";
                        
                        await _context.SaveChangesAsync();
                    }
                }

                var finalOrganizationId = connectedId?.OrganizationId ?? request.OrganizationId ??
                    _configuration.GetValue<Guid>("Auth:GlobalOrganizationId",
                        Guid.Parse("00000000-0000-0000-0000-000000000001"));

                // 세션 생성
                var sessionResult = await _sessionService.CreateSessionAsync(
                    new Core.Models.Auth.Session.Requests.CreateSessionRequest
                    {
                        ConnectedId = connectedIdValue,
                        OrganizationId = finalOrganizationId,
                        SessionType = SessionType.Web,
                        IpAddress = request.IpAddress,
                        UserAgent = request.UserAgent,
                        DeviceInfo = request.DeviceId,
                        OperatingSystem = request.DeviceInfo?.OperatingSystem,
                        Browser = request.DeviceInfo?.Browser,
                        Location = request.DeviceInfo?.Location,
                        ExpiresAt = DateTime.UtcNow.AddHours(24),
                        InitialStatus = SessionStatus.Active,
                        Metadata = JsonSerializer.Serialize(new
                        {
                            AuthenticationMethod = AuthenticationMethod.OAuth.ToString(),
                            Provider = request.Provider,
                            ApplicationId = request.ApplicationId
                        })
                    });

                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed");
                }

                // 토큰 생성
                var claims = new List<Claim>
                {
                    new Claim("user_id", user.Id.ToString()),
                    new Claim("connected_id", connectedIdValue.ToString()),
                    new Claim("org_id", finalOrganizationId.ToString()),
                    new Claim("auth_method", "oauth"),
                    new Claim("oauth_provider", request.Provider),
                    new Claim("session_id", sessionResult.Data?.SessionId.ToString() ?? "")
                };

                if (!string.IsNullOrEmpty(user.Email))
                {
                    claims.Add(new Claim("email", user.Email));
                }

                var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    user.Id,
                    connectedIdValue,
                    claims);

                if (!accessTokenResult.IsSuccess || accessTokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
                }

                var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedIdValue,
                    SessionId = sessionResult.Data?.SessionId ?? Guid.Empty,
                    AccessToken = accessTokenResult.Data?.AccessToken,
                    RefreshToken = refreshToken.Data,
                    ExpiresAt = accessTokenResult.Data?.ExpiresAt,
                    OrganizationId = finalOrganizationId,
                    ApplicationId = request.ApplicationId,
                    AuthenticationMethod = AuthenticationMethod.OAuth.ToString(),
                    IsFirstLogin = connectedId == null
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OAuth authentication failed");
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication failed");
            }
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
        {
            // OAuth는 코드 교환 후 사용자 정보를 가져오므로 이 메서드는 사용하지 않음
            return Task.FromResult<UserProfile?>(null);
        }

        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        public override async Task<ServiceResult> RevokeAsync(string tokenOrSessionId)
        {
            if (Guid.TryParse(tokenOrSessionId, out var sessionId))
            {
                var session = await _context.Sessions
                    .FirstOrDefaultAsync(s => s.Id == sessionId && s.Status == SessionStatus.Active);

                if (session != null)
                {
                    session.Status = SessionStatus.LoggedOut;
                    session.EndedAt = DateTime.UtcNow;
                    session.EndReason = SessionEndReason.UserLogout;
                    await _context.SaveChangesAsync();
                }
            }

            return ServiceResult.Success();
        }

        public override async Task<bool> IsEnabledAsync()
        {
            var isEnabled = _configuration.GetValue<bool>("OAuth:Enabled");
            return await Task.FromResult(isEnabled);
        }
    }
}