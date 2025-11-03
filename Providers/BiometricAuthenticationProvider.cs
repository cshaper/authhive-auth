// Providers/Authentication/BiometricAuthenticationProvider.cs
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
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

namespace AuthHive.Auth.Providers.Authentication
{
    public class BiometricAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IConfiguration _configuration;
        private readonly IFidoService _fidoService;
        private readonly IDeviceTrustService _deviceTrustService;
        
        public override string ProviderName => "Biometric";
        public override string ProviderType => "Internal";

        public BiometricAuthenticationProvider(
            ILogger<BiometricAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            IConfiguration configuration,
            IFidoService fidoService,
            IDeviceTrustService deviceTrustService)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _configuration = configuration;
            _fidoService = fidoService;
            _deviceTrustService = deviceTrustService;
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request)
        {
            try
            {
                if (request.BiometricAction == "enroll")
                {
                    return await EnrollBiometricAsync(request);
                }

                if (request.BiometricAction == "verify")
                {
                    return await VerifyBiometricAsync(request);
                }

                return ServiceResult<AuthenticationOutcome>.Failure("Invalid biometric action");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Biometric authentication failed");
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication failed");
            }
        }

        private async Task<ServiceResult<AuthenticationOutcome>> EnrollBiometricAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Username))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Username is required for biometric enrollment");
            }

            if (!string.IsNullOrEmpty(request.DeviceId))
            {
                var deviceTrust = await _deviceTrustService.IsDeviceTrustedAsync(request.DeviceId);
                if (!deviceTrust.IsSuccess || !deviceTrust.Data)
                {
                    _logger.LogWarning("Biometric enrollment attempted from untrusted device: {DeviceId}", request.DeviceId);
                }
            }
            
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Username || u.Username == request.Username);

            if (user == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("User not found");
            }
            
            var biometricType = ParseBiometricType(request.BiometricType);

            var enrollmentOptions = await _fidoService.GenerateEnrollmentOptionsAsync(
                user.Id,
                user.Username ?? user.Email ?? "user",
                biometricType);

            if (!enrollmentOptions.IsSuccess || enrollmentOptions.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate enrollment options");
            }

            var challengeKey = $"biometric:challenge:{enrollmentOptions.Data.Challenge}";
            await _cache.SetStringAsync(challengeKey, user.Id.ToString(),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
                });

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = false,
                RequiresBiometricEnrollment = true,
                BiometricChallenge = enrollmentOptions.Data.Challenge,
                BiometricOptions = enrollmentOptions.Data.Options,
                Message = "Complete biometric enrollment on your device"
            });
        }

        private async Task<ServiceResult<AuthenticationOutcome>> VerifyBiometricAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.BiometricCredentialId) || 
                string.IsNullOrEmpty(request.BiometricResponse))
            {
                if (!string.IsNullOrEmpty(request.Username))
                {
                    var authOptions = await _fidoService.GenerateAuthenticationOptionsAsync(request.Username);
                    
                    if (!authOptions.IsSuccess || authOptions.Data == null)
                    {
                        return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate authentication options");
                    }

                    return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                    {
                        Success = false,
                        RequiresBiometricVerification = true,
                        BiometricChallenge = authOptions.Data.Challenge,
                        BiometricOptions = authOptions.Data.Options,
                        Message = "Use your biometric to authenticate"
                    });
                }
                return ServiceResult<AuthenticationOutcome>.Failure("Username or credential is required");
            }

            var verificationResult = await _fidoService.VerifyAuthenticationResultAsync(
                request.BiometricCredentialId,
                request.BiometricResponse,
                request.BiometricChallenge ?? "");

            if (!verificationResult.IsSuccess || verificationResult.Data == null)
            {
                _logger.LogWarning("Biometric verification failed for credential: {CredentialId}", request.BiometricCredentialId);
                return ServiceResult<AuthenticationOutcome>.Failure("Biometric verification failed");
            }
            
            var credentialResult = await _fidoService.GetCredentialByIdAsync(request.BiometricCredentialId);
            if (!credentialResult.IsSuccess || credentialResult.Data == null)
            {
                 return ServiceResult<AuthenticationOutcome>.Failure("Biometric credential not found");
            }
            var biometricCredential = credentialResult.Data;
            
            var user = await _context.Users.FindAsync(biometricCredential.UserId);
            if (user == null)
            {
                 return ServiceResult<AuthenticationOutcome>.Failure("User associated with biometric credential not found");
            }

            if (!string.IsNullOrEmpty(request.DeviceId))
            {
                await _deviceTrustService.UpdateDeviceTrustAsync(
                    request.DeviceId,
                    user.Id,
                    TrustLevel.High);
            }

            await _fidoService.UpdateCredentialUsageAsync(
                biometricCredential.CredentialId, 
                DateTime.UtcNow, 
                request.DeviceId);

            ConnectedId? connectedId = null;
            if (request.OrganizationId.HasValue)
            {
                var connectedIdResult = await _connectedIdService.GetOrCreateAsync(
                    user.Id,
                    request.OrganizationId.Value);
                
                if (connectedIdResult.IsSuccess && connectedIdResult.Data != null)
                {
                    connectedId = connectedIdResult.Data;
                }
            }

            var sessionResult = await _sessionService.CreateSessionAsync(
                new CreateSessionRequest
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
                    Provider = "Biometric",
                    AuthenticationMethod = AuthenticationMethod.Biometric,
                    IsBiometric = true,
                    BiometricType = biometricCredential.Type.ToString(),
                    SecurityLevel = SessionSecurityLevel.High
                });

            if (!sessionResult.IsSuccess || sessionResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed");
            }

            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString()),
                new Claim("auth_method", "biometric"),
                new Claim("biometric_type", biometricCredential.Type.ToString()),
                new Claim("credential_id", biometricCredential.Id.ToString()),
                new Claim("session_id", sessionResult.Data.SessionId.ToString() ?? "")
            };

            if (connectedId != null)
            {
                claims.Add(new Claim("connected_id", connectedId.Id.ToString()));
            }
            if (!string.IsNullOrEmpty(request.DeviceId))
            {
                claims.Add(new Claim("device_id", request.DeviceId));
            }

            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                user.Id,
                connectedId?.Id ?? Guid.Empty,
                claims);

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
            }

            var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

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
                AuthenticationMethod = AuthenticationMethod.Biometric.ToString(),
                IsBiometric = true,
                BiometricType = biometricCredential.Type.ToString(),
                // [수정 완료] Enum 값을 (Model.AuthenticationStrength)로 캐스팅하여 타입 불일치 오류를 해결합니다.
                AuthenticationStrength = AuthenticationStrength.VeryHigh
            });
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
        {
            return Task.FromResult<UserProfile?>(null);
        }

        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        public override async Task<ServiceResult> RevokeAsync(string token)
        {
            var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);
            if (!validationResult.IsSuccess || validationResult.Data == null)
            {
                return ServiceResult.Failure("Invalid token");
            }
            
            var sessionIdClaim = validationResult.Data.FindFirst("session_id");
            if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
            {
                return ServiceResult.Failure("Session ID not found in token");
            }
            
            var session = await _context.Sessions
                .FirstOrDefaultAsync(s => s.Id == sessionId && s.Status == SessionStatus.Active);

            if (session != null)
            {
                session.Status = SessionStatus.LoggedOut;
                session.EndedAt = DateTime.UtcNow;
                session.EndReason = SessionEndReason.UserLogout;
                await _context.SaveChangesAsync();
            }

            return ServiceResult.Success();
        }

        public override async Task<bool> IsEnabledAsync()
        {
            var isEnabled = _configuration.GetValue<bool>("Biometric:Enabled");
            var hasFidoService = _fidoService != null;
            return await Task.FromResult(isEnabled && hasFidoService);
        }

        private BiometricType ParseBiometricType(string? type)
        {
            if (string.IsNullOrEmpty(type))
            {
                return BiometricType.Fingerprint;
            }
            if (Enum.TryParse<BiometricType>(type, true, out var result))
            {
                return result;
            }
            return BiometricType.Fingerprint;
        }
    }
}