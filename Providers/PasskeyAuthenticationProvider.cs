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
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// 패스키(Passkey) 인증 제공자 - AuthHive v15
    /// FIDO2/WebAuthn 표준을 사용하여 암호 없는 인증(지문, 얼굴 인식 등)을 처리합니다.
    /// BiometricAuthenticationProvider의 현대적인 대체재이며, 핵심 로직은 IFidoService를 공유합니다.
    /// </summary>
    public class PasskeyAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IFidoService _fidoService;
        private readonly IConfiguration _configuration;

        public override string ProviderName => "Passkey";
        public override string ProviderType => "Internal";

        public PasskeyAuthenticationProvider(
            ILogger<PasskeyAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            IFidoService fidoService,
            IConfiguration configuration) // IConfiguration 주입 추가
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _fidoService = fidoService;
            _configuration = configuration;
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(AuthenticationRequest request)
        {
            try
            {
                if (request.PasskeyAction == "register")
                {
                    return await RegisterPasskeyAsync(request);
                }

                if (request.PasskeyAction == "verify")
                {
                    return await VerifyPasskeyAsync(request);
                }

                return ServiceResult<AuthenticationOutcome>.Failure("Invalid passkey action.", "INVALID_ACTION");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Passkey authentication failed.");
                return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred.", "SYSTEM_ERROR");
            }
        }

        private async Task<ServiceResult<AuthenticationOutcome>> RegisterPasskeyAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Username))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Username is required for registration.", "USERNAME_REQUIRED");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Username || u.Username == request.Username);
            if (user == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("User not found.", "USER_NOT_FOUND");
            }
            
            var enrollmentOptions = await _fidoService.GenerateEnrollmentOptionsAsync(
                user.Id,
                user.Username ?? user.Email ?? "user",
                BiometricType.WindowsHello); 

            if (!enrollmentOptions.IsSuccess || enrollmentOptions.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate passkey registration options.", "FIDO_ERROR");
            }

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = false,
                RequiresPasskeyRegistration = true,
                PasskeyChallenge = enrollmentOptions.Data.Challenge,
                PasskeyOptions = enrollmentOptions.Data.Options,
                Message = "Please use your device to create a passkey."
            });
        }

        private async Task<ServiceResult<AuthenticationOutcome>> VerifyPasskeyAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.PasskeyResponse))
            {
                if (string.IsNullOrEmpty(request.Username))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Username is required to get authentication options.", "USERNAME_REQUIRED");
                }
                
                var authOptions = await _fidoService.GenerateAuthenticationOptionsAsync(request.Username);
                if (!authOptions.IsSuccess || authOptions.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Could not retrieve passkeys for user.", "FIDO_ERROR");
                }

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = false,
                    RequiresPasskeyAuthentication = true,
                    PasskeyChallenge = authOptions.Data.Challenge,
                    PasskeyOptions = authOptions.Data.Options,
                    Message = "Please use your passkey to sign in."
                });
            }
            
            if (string.IsNullOrEmpty(request.BiometricCredentialId))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Credential ID is missing in passkey response.", "INVALID_RESPONSE");
            }
            
            var verificationResult = await _fidoService.VerifyAuthenticationResponseAsync(
                request.BiometricCredentialId,
                request.PasskeyResponse,
                request.PasskeyChallenge ?? "");

            if (!verificationResult.IsSuccess || verificationResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Passkey verification failed.", "VERIFICATION_FAILED");
            }

            var credentialResult = await _fidoService.GetCredentialByIdAsync(verificationResult.Data.CredentialId ?? "");
            if(!credentialResult.IsSuccess || credentialResult.Data == null)
            {
                 return ServiceResult<AuthenticationOutcome>.Failure("Passkey credential not found.", "CREDENTIAL_NOT_FOUND");
            }
            var credential = credentialResult.Data;
            
            var user = await _context.Users.FindAsync(credential.UserId);
            if (user == null)
            {
                 return ServiceResult<AuthenticationOutcome>.Failure("User associated with the passkey not found.", "USER_NOT_FOUND");
            }

            var connectedIdResult = await _connectedIdService.GetOrCreateAsync(user.Id, request.OrganizationId ?? Guid.Empty);
            var connectedId = connectedIdResult.IsSuccess ? connectedIdResult.Data : null;

            var sessionResult = await _sessionService.CreateSessionAsync(new CreateSessionRequest
            {
                UserId = user.Id,
                ConnectedId = connectedId?.Id,
                OrganizationId = request.OrganizationId,
                ApplicationId = request.ApplicationId,
                SessionType = SessionType.Web,
                Level = request.OrganizationId.HasValue ? SessionLevel.Organization : SessionLevel.Global,
                IpAddress = request.IpAddress,
                UserAgent = request.UserAgent,
                DeviceInfo = request.DeviceInfo != null ? JsonSerializer.Serialize(request.DeviceInfo) : null,
                Provider = "Passkey",
                AuthenticationMethod = AuthenticationMethod.Passkey,
                SecurityLevel = SessionSecurityLevel.Maximum
            });

            if (!sessionResult.IsSuccess || sessionResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed.", "SESSION_ERROR");
            }

            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString()),
                new Claim("auth_method", "passkey"),
                new Claim("credential_id", credential.Id.ToString()),
                new Claim("session_id", sessionResult.Data.SessionId.ToString()?? string.Empty)
            };
            
            if (connectedId != null) claims.Add(new Claim("connected_id", connectedId.Id.ToString()));
            
            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, connectedId?.Id ?? Guid.Empty, claims);
            if (!tokenResult.IsSuccess || tokenResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed.", "TOKEN_ERROR");
            }

            var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = true,
                UserId = user.Id,
                ConnectedId = connectedId?.Id,
                SessionId = sessionResult.Data.SessionId,
                AccessToken = tokenResult.Data.AccessToken,
                RefreshToken = refreshToken.Data,
                ExpiresAt = tokenResult.Data.ExpiresAt,
                OrganizationId = request.OrganizationId,
                ApplicationId = request.ApplicationId,
                AuthenticationMethod = AuthenticationMethod.Passkey.ToString(),
                AuthenticationStrength = AuthenticationStrength.VeryHigh
            });
        }
        
        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현
        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현
        public override async Task<ServiceResult> RevokeAsync(string token)
        {
            var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);
            if (!validationResult.IsSuccess || validationResult.Data == null) return ServiceResult.Failure("Invalid token.");

            var sessionIdClaim = validationResult.Data.FindFirst("session_id");
            if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
            {
                return ServiceResult.Failure("Session ID not found in token.");
            }
            
            // ISessionService에 세션 종료 위임
            return await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout);
        }

        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현
        public override Task<bool> IsEnabledAsync()
        {
            var isEnabled = _configuration.GetValue<bool>("Features:Passkey:Enabled");
            return Task.FromResult(isEnabled && _fidoService != null);
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request) => Task.FromResult<UserProfile?>(null);
    }
}

