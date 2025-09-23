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
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;


namespace AuthHive.Auth.Providers
{
    public class SsoAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IOrganizationSSOService _ssoService;

        public override string ProviderName => "SSO";
        public override string ProviderType => "External";

        public SsoAuthenticationProvider(
            ILogger<SsoAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            IOrganizationSSOService ssoService)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _ssoService = ssoService;
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(AuthenticationRequest request)
        {
            if (!request.OrganizationId.HasValue || string.IsNullOrEmpty(request.SamlResponse))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Organization ID and SAML response are required.", "INVALID_REQUEST");
            }

            try
            {
                var ssoResult = await _ssoService.ProcessSsoResponseAsync(request.OrganizationId.Value, request.SamlResponse);
                if (!ssoResult.IsSuccess || ssoResult.Data == null)
                {
                    _logger.LogWarning("SSO authentication failed for organization {OrganizationId}. Reason: {Reason}", request.OrganizationId, ssoResult.ErrorMessage);
                    return ServiceResult<AuthenticationOutcome>.Failure(ssoResult.ErrorMessage ?? "SSO authentication failed.", ssoResult.ErrorCode);
                }

                var ssoData = ssoResult.Data;

                // --- FIX 1: UserId가 null일 경우를 대비한 안전장치 추가 ---
                if (!ssoData.UserId.HasValue)
                {
                    _logger.LogError("SSO authentication succeeded, but the user ID was null. SSO Provider: {Provider}", ssoData.Provider);
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to retrieve user ID from SSO provider.");
                }

                var user = await _context.Users.FindAsync(ssoData.UserId.Value);
                if (user == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("User not found after SSO processing.", "USER_NOT_FOUND");
                }

                var sessionResult = await _sessionService.CreateSessionAsync(new CreateSessionRequest
                {
                    UserId = ssoData.UserId.Value, // .Value를 사용하여 안전하게 할당
                                                   // --- FIX 2: ConnectedId의 Guid? -> Guid 타입 변환 오류 해결 ---
                    ConnectedId = ssoData.ConnectedId ?? Guid.Empty,
                    OrganizationId = request.OrganizationId,
                    ApplicationId = request.ApplicationId,
                    SessionType = SessionType.Web,
                    Level = SessionLevel.Organization,
                    IPAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    DeviceInfo = request.DeviceInfo != null ? JsonSerializer.Serialize(request.DeviceInfo) : null,
                    Provider = "SSO",
                    AuthenticationMethod = AuthenticationMethod.SSO,
                    SecurityLevel = SessionSecurityLevel.High,
                    Metadata = JsonSerializer.Serialize(new { ssoData.Provider, ssoData.ExternalId })
                });

                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed after SSO login.", "SESSION_ERROR");
                }

                var claims = new List<Claim>
                {
                    new Claim("user_id", ssoData.UserId.ToString() ?? string.Empty),
                    new Claim("connected_id", ssoData.ConnectedId.ToString() ?? string.Empty),
                    new Claim("org_id", request.OrganizationId.Value.ToString()),
                    new Claim("auth_method", "sso"),
                    new Claim("sso_provider", ssoData.Provider ?? string.Empty),
                    new Claim("session_id", sessionResult.Data.SessionId?.ToString() ?? string.Empty)
                };

                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, ssoData.ConnectedId ?? Guid.Empty, claims);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed.", "TOKEN_ERROR");
                }

                var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = ssoData.UserId,
                    ConnectedId = ssoData.ConnectedId,
                    SessionId = sessionResult.Data.SessionId,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = refreshToken.Data,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = request.OrganizationId,
                    ApplicationId = request.ApplicationId,
                    AuthenticationMethod = AuthenticationMethod.SSO.ToString(),
                    IsNewUser = ssoData.IsNewUser,
                    AuthenticationStrength = AuthenticationStrength.High
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during SSO authentication for organization {OrganizationId}", request.OrganizationId);
                return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred during SSO authentication.", "SYSTEM_ERROR");
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
            return Task.FromResult(true);
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request) => Task.FromResult<UserProfile?>(null);
    }
}