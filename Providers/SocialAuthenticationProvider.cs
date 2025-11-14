using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Providers
{
    public class SocialAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly ISocialAuthenticationService _socialAuthService;
        private readonly IConfiguration _configuration;

        public override string ProviderName => "Social";
        public override string ProviderType => "External";

        public SocialAuthenticationProvider(
            ILogger<SocialAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            ISocialAuthenticationService socialAuthService,
            IConfiguration configuration)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _socialAuthService = socialAuthService;
            _configuration = configuration;
        }
        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.SocialProvider))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Authorization code and provider are required.", "INVALID_REQUEST");
            }

            try
            {
                var socialResult = await _socialAuthService.HandleCallbackAsync(request.SocialProvider, request.Code, request.State);
                if (!socialResult.IsSuccess || socialResult.Data == null)
                {
                    _logger.LogWarning("Social authentication callback failed for provider {Provider}. Reason: {Reason}", request.SocialProvider, socialResult.ErrorMessage);
                    return ServiceResult<AuthenticationOutcome>.Failure(socialResult.ErrorMessage ?? "Social authentication failed.", socialResult.ErrorCode);
                }

                var socialData = socialResult.Data;

                // --- FIX 1: UserId가 null일 경우를 대비한 안전장치 추가 ---
                if (!socialData.UserId.HasValue)
                {
                    _logger.LogError("Social authentication succeeded, but the user ID from the provider was null.");
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to retrieve user ID from the social provider.");
                }

                var user = await _context.Users.FindAsync(socialData.UserId.Value);
                if (user == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("User not found after social login.", "USER_NOT_FOUND");
                }

                var sessionResult = await _sessionService.CreateSessionAsync(new CreateSessionRequest
                {
                    UserId = socialData.UserId.Value, // UserId.Value 사용
                    ConnectedId = socialData.ConnectedId,
                    // --- FIX 2: OrganizationId의 null 가능성 처리 ---
                    OrganizationId = request.OrganizationId.HasValue ? request.OrganizationId.Value : Guid.Empty,
                    ApplicationId = request.ApplicationId,
                    SessionType = SessionType.Web,
                    Level = request.OrganizationId.HasValue ? SessionLevel.Organization : SessionLevel.Global,
                    IpAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    DeviceInfo = request.DeviceInfo != null ? JsonSerializer.Serialize(request.DeviceInfo) : null,
                    Provider = "Social",
                    AuthenticationMethod = AuthenticationMethod.SocialLogin,
                    SecurityLevel = SessionSecurityLevel.Enhanced,
                    Metadata = JsonSerializer.Serialize(new { socialData.Provider, socialData.ProviderId })
                });

                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed after social login.", "SESSION_ERROR");
                }

                var claims = new List<Claim>
                {
                    new Claim("user_id", socialData.UserId.ToString() ?? string.Empty),
                    new Claim("connected_id", socialData.ConnectedId.ToString() ?? string.Empty),
                    new Claim("auth_method", "social"),
                    new Claim("social_provider", socialData.Provider ?? string.Empty),
                    new Claim("session_id", sessionResult.Data.SessionId?.ToString() ?? string.Empty)
                };

                if (request.OrganizationId.HasValue)
                {
                    claims.Add(new Claim("org_id", request.OrganizationId.Value.ToString()));
                }

                // --- FIX 3: ConnectedId의 null 가능성 처리 ---
                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, socialData.ConnectedId ?? Guid.Empty, claims);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed.", "TOKEN_ERROR");
                }

                var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = socialData.UserId,
                    ConnectedId = socialData.ConnectedId,
                    SessionId = sessionResult.Data.SessionId,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = refreshToken.Data,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = request.OrganizationId,
                    ApplicationId = request.ApplicationId,
                    AuthenticationMethod = AuthenticationMethod.SocialLogin.ToString(),
                    IsNewUser = socialData.IsNewUser,
                    AuthenticationStrength = AuthenticationStrength.Medium
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during social authentication.");
                return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred.", "SYSTEM_ERROR");
            }
        }

        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        public override async Task<ServiceResult> RevokeAsync(string token)
        {
            var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);
            if (!validationResult.IsSuccess || validationResult.Data == null) return ServiceResult.Failure("Invalid token.");

            var sessionIdClaim = validationResult.Data.FindFirst("session_id");
            if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
            {
                return ServiceResult.Failure("Session ID not found in token.");
            }
            return await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout);
        }

        public override Task<bool> IsEnabledAsync()
        {
            var isEnabled = _configuration.GetValue<bool>("Features:SocialLogin:Enabled");
            return Task.FromResult(isEnabled);
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request) => Task.FromResult<UserProfile?>(null);
    }
}