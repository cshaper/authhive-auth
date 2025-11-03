using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using System.Threading; // CancellationToken을 위해 추가
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base; // BaseApiController에 필요
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit; // IAuditService에 필요
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IPrincipalAccessor에 필요
using AuthHive.Core.Interfaces.Business.Platform; // IPlanRestrictionService에 필요
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider에 필요
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService에 필요
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore; // FindAsync 사용을 위해 필요
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// 패스키(Passkey) 인증 제공자 - AuthHive v16 최종본
    /// BaseAuthenticationProvider의 모든 공통 로직을 활용하며, FIDO2/WebAuthn 표준 인증을 수행합니다.
    /// </summary>
    public class PasskeyAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IFidoService _fidoService;
        private readonly IConfiguration _configuration;
        private readonly ISessionService _sessionService; // 세션 관리를 위해 유지
        private readonly IConnectedIdService _connectedIdService; // ConnectedId 생성을 위해 유지

        public override string ProviderName => "Passkey";
        public override string ProviderType => "Internal";

        public PasskeyAuthenticationProvider(
            ILogger<PasskeyAuthenticationProvider> logger,
            // 🚨 BaseAuthenticationProvider가 요구하는 9가지 필수 인자
            ICacheService cacheService, // ICacheService로 변경
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IAuditService auditService,
            IUserRepository userRepository,
            IConnectedIdRepository connectedIdRepository,
            IAccountSecurityService accountSecurityService,
            IPlanRestrictionService planRestrictionService, // ✅ IPlanRestrictionService 추가
            
            // PasskeyProvider에 특화된 서비스
            ITokenProvider tokenProvider,
            IFidoService fidoService,
            IConfiguration configuration,
            ISessionService sessionService, // 세션 서비스 유지
            IConnectedIdService connectedIdService) // ConnectedId 서비스 유지
            // 🚨 BaseAuthenticationProvider의 9가지 인자만 base()로 전달
            : base(logger, cacheService, unitOfWork, dateTimeProvider, auditService, userRepository, connectedIdRepository, accountSecurityService, planRestrictionService)
        {
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
            _fidoService = fidoService ?? throw new ArgumentNullException(nameof(fidoService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request, 
            CancellationToken cancellationToken) // ✅ CancellationToken 추가
        {
            try
            {
                if (request.PasskeyAction == "register")
                {
                    return await RegisterPasskeyAsync(request, cancellationToken);
                }

                if (request.PasskeyAction == "verify")
                {
                    return await VerifyPasskeyAsync(request, cancellationToken);
                }

                return ServiceResult<AuthenticationOutcome>.Failure("Invalid passkey action.", "INVALID_ACTION");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Passkey authentication failed.");
                return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred.", "SYSTEM_ERROR");
            }
        }

        private async Task<ServiceResult<AuthenticationOutcome>> RegisterPasskeyAsync(
            AuthenticationRequest request, 
            CancellationToken cancellationToken) // ✅ CancellationToken 추가
        {
            if (string.IsNullOrEmpty(request.Username))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Username is required for registration.", "USERNAME_REQUIRED");
            }

            // 🚨 DbContext 직접 접근 대신 Repository 사용
            var user = await _userRepository.GetByUsernameAsync(request.Username, cancellationToken: cancellationToken);
            if (user == null)
            {
                user = await _userRepository.GetByEmailAsync(request.Username, cancellationToken: cancellationToken);
                if (user == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("User not found.", "USER_NOT_FOUND");
                }
            }
            
            var enrollmentOptions = await _fidoService.GenerateEnrollmentOptionsAsync(
                user.Id,
                user.Username ?? user.Email ?? "user",
                BiometricType.WindowsHello,
                cancellationToken); // ✅ CancellationToken 전달

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

        private async Task<ServiceResult<AuthenticationOutcome>> VerifyPasskeyAsync(
            AuthenticationRequest request, 
            CancellationToken cancellationToken) // ✅ CancellationToken 추가
        {
            // 1. 인증 옵션 생성 (PasskeyResponse가 없을 경우)
            if (string.IsNullOrEmpty(request.PasskeyResponse))
            {
                if (string.IsNullOrEmpty(request.Username))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Username is required to get authentication options.", "USERNAME_REQUIRED");
                }
                
                var authOptions = await _fidoService.GenerateAuthenticationOptionsAsync(
                    request.Username,
                    cancellationToken); // ✅ CancellationToken 전달

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
            
            // 2. 인증 응답 검증 (PasskeyResponse가 있을 경우)
            if (string.IsNullOrEmpty(request.BiometricCredentialId))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Credential ID is missing in passkey response.", "INVALID_RESPONSE");
            }
            
            var verificationResult = await _fidoService.VerifyAuthenticationResultAsync(
                request.BiometricCredentialId,
                request.PasskeyResponse,
                request.PasskeyChallenge ?? "",
                cancellationToken); // ✅ CancellationToken 전달

            if (!verificationResult.IsSuccess || verificationResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Passkey verification failed.", "VERIFICATION_FAILED");
            }

            // 3. 자격 증명 및 사용자 조회
            var credentialResult = await _fidoService.GetCredentialByIdAsync(
                verificationResult.Data.CredentialId ?? "",
                cancellationToken); // ✅ CancellationToken 전달
                
            if(!credentialResult.IsSuccess || credentialResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Passkey credential not found.", "CREDENTIAL_NOT_FOUND");
            }
            var credential = credentialResult.Data;
            
            // 🚨 DbContext 직접 접근 대신 Repository 사용
            var user = await _userRepository.GetByIdAsync(credential.UserId, cancellationToken);
            if (user == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("User associated with the passkey not found.", "USER_NOT_FOUND");
            }

            // 4. ConnectedId 및 Session 생성
            var connectedIdResult = await _connectedIdService.GetOrCreateAsync(
                user.Id, 
                request.OrganizationId ?? Guid.Empty, 
                cancellationToken); // ✅ CancellationToken 전달
                
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
                Provider = ProviderName, // ProviderName 사용
                AuthenticationMethod = AuthenticationMethod.Passkey,
                SecurityLevel = SessionSecurityLevel.Maximum
            }, cancellationToken); // ✅ CancellationToken 전달

            if (!sessionResult.IsSuccess || sessionResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed.", "SESSION_ERROR");
            }

            // 5. Token 생성
            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString()),
                new Claim("auth_method", "passkey"),
                new Claim("credential_id", credential.Id.ToString()),
                // SessionId는 Nullable Guid이므로 null-coalescing을 사용
                new Claim("session_id", sessionResult.Data.SessionId.ToString() ?? string.Empty) 
            };
            
            if (connectedId != null) claims.Add(new Claim("connected_id", connectedId.Id.ToString()));
            
            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                user.Id, 
                connectedId?.Id ?? Guid.Empty, 
                claims,
                cancellationToken); // ✅ CancellationToken 전달

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed.", "TOKEN_ERROR");
            }

            var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(
                user.Id, 
                cancellationToken); // ✅ CancellationToken 전달

            // 6. 최종 AuthenticationOutcome 반환
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
        
        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현 (CancellationToken 추가)
        public override async Task<ServiceResult<bool>> ValidateAsync(string token, CancellationToken cancellationToken = default)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현 (CancellationToken 추가)
        public override async Task<ServiceResult> RevokeAsync(string token, CancellationToken cancellationToken = default)
        {
            var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);
            if (!validationResult.IsSuccess || validationResult.Data == null) return ServiceResult.Failure("Invalid token.");

            var sessionIdClaim = validationResult.Data.FindFirst("session_id");
            if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
            {
                return ServiceResult.Failure("Session ID not found in token.");
            }
            
            // ISessionService에 세션 종료 위임
            // NOTE: ISessionService.EndSessionAsync가 CancellationToken을 받도록 수정되어야 합니다.
            return await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout);
        }

        // [수정 완료] BaseAuthenticationProvider의 추상 메서드 구현 (CancellationToken 추가)
        public override Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
        {
            var isEnabled = _configuration.GetValue<bool>("Features:Passkey:Enabled");
            // FidoService 자체의 Health Check 로직은 복잡하므로, 여기서는 Null 체크만 수행합니다.
            return Task.FromResult(isEnabled && _fidoService != null);
        }
        
        // BaseAuthenticationProvider에 이미 FindUserAsync가 구현되었으므로, 이 메서드는 제거합니다.
        // protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request) => Task.FromResult<UserProfile?>(null);
    }
}