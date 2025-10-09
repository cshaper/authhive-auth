// Path: AuthHive.Auth/Services/Authentication/AuthenticationOrchestrationService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 오케스트레이션 서비스 - AuthHive v16 최종본
    /// 모든 인증 관련 서비스들을 조율하는 Facade 패턴 구현체입니다.
    /// v16 아키텍처 원칙에 따라 역할 분리, 캐시 추상화, ConnectedId 중심 설계를 준수합니다.
    /// </summary>
    public class AuthenticationOrchestrationService : IAuthenticationOrchestrationService
    {
        private readonly IPasswordService _passwordService;
        private readonly ISocialAuthenticationService _socialAuthService;
        private readonly IApiKeyAuthenticationService _apiKeyAuthService;
        private readonly IMfaAuthenticationService _mfaService;
        private readonly IAccountSecurityService _securityService;
        private readonly IAuthenticationAttemptService _attemptService;
        private readonly ITokenService _tokenService;
        private readonly ISessionService _sessionService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IAuthenticationCacheService _authCacheService;
        private readonly ILogger<AuthenticationOrchestrationService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public AuthenticationOrchestrationService(
            IPasswordService passwordService,
            ISocialAuthenticationService socialAuthService,
            IApiKeyAuthenticationService apiKeyAuthService,
            IMfaAuthenticationService mfaService,
            IAccountSecurityService securityService,
            IAuthenticationAttemptService attemptService,
            ITokenService tokenService,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            IAuthenticationCacheService authCacheService,
            ILogger<AuthenticationOrchestrationService> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _passwordService = passwordService;
            _socialAuthService = socialAuthService;
            _apiKeyAuthService = apiKeyAuthService;
            _mfaService = mfaService;
            _securityService = securityService;
            _attemptService = attemptService;
            _tokenService = tokenService;
            _sessionService = sessionService;
            _connectedIdService = connectedIdService;
            _authCacheService = authCacheService;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("AuthenticationOrchestrationService initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        #endregion


        #region Main Authentication Flow
        public async Task<ServiceResult<AuthenticationResponse>> AuthenticateAsync(AuthenticationRequest request)
        {
            try
            {
                _logger.LogInformation("Authentication attempt started for method {Method}", request.Method);

                var securityCheckResult = await PreAuthenticationSecurityCheckAsync(request);
                if (!securityCheckResult.IsSuccess)
                    return ServiceResult<AuthenticationResponse>.Failure(securityCheckResult.ErrorMessage ?? "Pre-authentication security check failed.");

                var primaryAuthResult = await PerformPrimaryAuthenticationAsync(request);
                if (!primaryAuthResult.IsSuccess || primaryAuthResult.Data == null)
                    // FINAL FIX: Provide a default message if ErrorMessage is null.
                    return ServiceResult<AuthenticationResponse>.Failure(primaryAuthResult.ErrorMessage ?? "Primary authentication failed.");

                var authResponse = primaryAuthResult.Data;

                var mfaHandledResult = await HandleMfaFlowAsync(request, authResponse);
                if (!mfaHandledResult.IsSuccess || mfaHandledResult.Data == null)
                    return ServiceResult<AuthenticationResponse>.Failure(mfaHandledResult.ErrorMessage ?? "MFA processing failed.");

                authResponse = mfaHandledResult.Data;

                if (authResponse.Success && !authResponse.RequiresMfa)
                {
                    return await PostAuthenticationProcessingAsync(request, authResponse);
                }

                _logger.LogInformation("Authentication process requires MFA for user {UserId}", authResponse.UserId);
                return ServiceResult<AuthenticationResponse>.Success(authResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during authentication orchestration for method {Method}", request.Method);
                return ServiceResult<AuthenticationResponse>.Failure("An unexpected server error occurred during authentication.");
            }
        }
        #endregion

        #region Private Authentication Steps
        private async Task<ServiceResult> PreAuthenticationSecurityCheckAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress)) return ServiceResult.Success();

            var riskResult = await _authCacheService.GetRiskAssessmentAsync(request.IpAddress);
            if (riskResult.IsSuccess && riskResult.Data is { IsBlocked: true })
            {
                _logger.LogWarning("High risk IP blocked: {IpAddress}, Risk Score: {RiskScore}", request.IpAddress, riskResult.Data.RiskScore);
                return ServiceResult.Failure("Access denied due to security policy.");
            }

            if (!string.IsNullOrEmpty(request.Username))
            {
                var bruteForceResult = await _attemptService.DetectBruteForceAttackAsync(request.Username, request.IpAddress);
                if (bruteForceResult.IsSuccess && bruteForceResult.Data)
                {
                    return ServiceResult.Failure("Too many failed attempts. Please try again later.");
                }
            }

            return ServiceResult.Success();
        }

        private Task<ServiceResult<AuthenticationResponse>> PerformPrimaryAuthenticationAsync(AuthenticationRequest request)
        {
            return request.Method switch
            {
                AuthenticationMethod.Password => HandlePasswordAuthenticationAsync(request),
                AuthenticationMethod.OAuth => HandleOAuthAuthenticationAsync(request),
                AuthenticationMethod.SocialLogin => HandleSocialAuthenticationAsync(request),
                AuthenticationMethod.ApiKey => HandleApiKeyAuthenticationAsync(request), // FIX: Call the new helper
                _ => Task.FromResult(ServiceResult<AuthenticationResponse>.Failure($"Unsupported authentication method: {request.Method}"))
            };
        }

        private Task<ServiceResult<AuthenticationResponse>> HandlePasswordAuthenticationAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Username and password are required."));
            }
            return _passwordService.AuthenticateWithPasswordAsync(request.Username, request.Password, request.OrganizationId);
        }

        private Task<ServiceResult<AuthenticationResponse>> HandleSocialAuthenticationAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.SocialToken) || string.IsNullOrEmpty(request.SocialProvider))
            {
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Social token and provider are required."));
            }
            return _socialAuthService.AuthenticateWithSocialAsync(request.SocialProvider, request.SocialToken, request.OrganizationId);
        }

        private Task<ServiceResult<AuthenticationResponse>> HandleOAuthAuthenticationAsync(AuthenticationRequest request)
        {
            // FIX 1: Add null check for RedirectUri
            if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.Provider) || string.IsNullOrEmpty(request.RedirectUri))
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("OAuth provider, authorization code, and redirect URI are required."));

            return _socialAuthService.AuthenticateWithOAuthAsync(request.Provider, request.Code, request.RedirectUri, request.State);
        }

        // FINAL FIX: Add the missing helper method for API Key authentication
        private Task<ServiceResult<AuthenticationResponse>> HandleApiKeyAuthenticationAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.ApiKey))
            {
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("API Key is required."));
            }
            return _apiKeyAuthService.AuthenticateWithApiKeyAsync(request.ApiKey, request.ApiSecret);
        }

        private async Task<ServiceResult<AuthenticationResponse>> HandleMfaFlowAsync(AuthenticationRequest request, AuthenticationResponse primaryResponse)
        {
            if (!primaryResponse.UserId.HasValue) return ServiceResult<AuthenticationResponse>.Success(primaryResponse);

            var mfaRequirementResult = await _authCacheService.GetMfaRequirementAsync(primaryResponse.UserId.Value, request.OrganizationId);
            if (!mfaRequirementResult.IsSuccess || mfaRequirementResult.Data?.IsRequired != true)
                return ServiceResult<AuthenticationResponse>.Success(primaryResponse);

            if (!string.IsNullOrEmpty(request.MfaCode))
            {
                // FIX 2: Provide a default MFA method if the request doesn't specify one.
                var mfaMethodToVerify = request.MfaMethod ?? "totp"; // Default to TOTP

                var mfaVerifyResult = await _mfaService.CompleteMfaAuthenticationAsync(primaryResponse.UserId.Value, request.MfaCode, mfaMethodToVerify);
                if (!mfaVerifyResult.IsSuccess)
                    return ServiceResult<AuthenticationResponse>.Failure(mfaVerifyResult.ErrorMessage ?? "MFA verification failed.");

                primaryResponse.MfaVerified = true;
            }
            else
            {
                primaryResponse.RequiresMfa = true;
                var availableMethodsResult = await _authCacheService.GetMfaSettingsAsync(primaryResponse.UserId.Value);
                if (availableMethodsResult.IsSuccess && availableMethodsResult.Data != null)
                {
                    primaryResponse.MfaMethods = availableMethodsResult.Data.EnabledMethods.ToList();
                }
            }
            return ServiceResult<AuthenticationResponse>.Success(primaryResponse);
        }

        private async Task<ServiceResult<AuthenticationResponse>> PostAuthenticationProcessingAsync(AuthenticationRequest request, AuthenticationResponse response)
        {
            if (!response.ConnectedId.HasValue)
                return ServiceResult<AuthenticationResponse>.Failure("ConnectedId is missing for session creation.");

            var sessionResult = await _sessionService.CreateSessionAsync(new CreateSessionRequest
            {
                ConnectedId = response.ConnectedId.Value,
                DeviceInfo = request.DeviceInfo,
                IpAddress = request.IpAddress
            });

            if (!sessionResult.IsSuccess || sessionResult.Data == null || !sessionResult.Data.SessionId.HasValue)
                return ServiceResult<AuthenticationResponse>.Failure(sessionResult.ErrorMessage ?? "Failed to create session.");

            var sessionId = sessionResult.Data.SessionId.Value;
            var tokenResult = await _tokenService.GenerateTokensAsync(sessionId);

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
                return ServiceResult<AuthenticationResponse>.Failure(tokenResult.ErrorMessage ?? "Failed to generate tokens.");

            response.AccessToken = tokenResult.Data.AccessToken;
            response.RefreshToken = tokenResult.Data.RefreshToken;
            response.SessionId = sessionId;
            response.ExpiresAt = tokenResult.Data.ExpiresAt;

            if (response.UserId.HasValue)
            {
                // Run post-authentication tasks like logging and device checks in the background
                // to avoid slowing down the user's login response time.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var ipAddressForLog = request.IpAddress ?? "0.0.0.0";

                        // Log the successful authentication attempt for auditing and statistics.
                        await _attemptService.LogSuccessfulAuthenticationAsync(
                            response.UserId.Value,
                            response.ConnectedId,
                            request.Method,
                            ipAddressForLog,
                            request.UserAgent);

                        // Update the user's last activity timestamp.
                        await _connectedIdService.UpdateLastActivityAsync(response.ConnectedId.Value);

                        // If device information is present, check if it's a new device and notify the user.
                        if (request.DeviceInfo != null)
                        {
                            var fingerprint = GenerateDeviceFingerprint(request.DeviceInfo);

                            // FINAL FIX: Pass all required arguments to the method.
                            await _securityService.CheckAndNotifyNewDeviceAsync(
                                response.UserId.Value,
                                request.DeviceInfo.DeviceId,
                                fingerprint,
                                request.DeviceInfo.Location,
                                request.IpAddress ?? "Unknown", // Pass the IP address
                                request.UserAgent              // Pass the User Agent
                            );
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log any errors from the background task, but don't let them crash the application.
                        _logger.LogError(ex, "An error occurred in the post-authentication background task for UserId {UserId}", response.UserId.Value);
                    }
                });
            }

            return ServiceResult<AuthenticationResponse>.Success(response);
        }
        #endregion

        #region Logout
        public async Task<ServiceResult> LogoutAsync(Guid sessionId, bool revokeAllTokens = false)
        {
            var sessionResult = await _sessionService.GetSessionAsync(sessionId);
            if (!sessionResult.IsSuccess || sessionResult.Data == null)
                return ServiceResult.Failure(sessionResult.ErrorMessage ?? "Session not found.");

            var session = sessionResult.Data;
            await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout);

            if (revokeAllTokens && session.UserId != Guid.Empty)
            {
                await LogoutAllSessionsAsync(session.UserId, sessionId);
            }

            await _authCacheService.ClearUserAndSessionCacheAsync(session.UserId, session.ConnectedId, sessionId);

            _logger.LogInformation("Logout completed for session {SessionId}", sessionId);
            return ServiceResult.Success("Logged out successfully.");
        }

        /// <summary>
        /// 특정 사용자의 모든 세션을 로그아웃 처리합니다.
        /// v16 원칙: UserId를 기반으로 모든 ConnectedId를 조회한 후, 각 ConnectedId의 세션을 종료합니다.
        /// </summary>
        public async Task<ServiceResult<int>> LogoutAllSessionsAsync(Guid userId, Guid? exceptSessionId = null)
        {
            int loggedOutCount = 0;
            var connectedIdsResult = await _connectedIdService.GetByUserAsync(userId);
            if (connectedIdsResult.IsSuccess && connectedIdsResult.Data != null)
            {
                foreach (var cid in connectedIdsResult.Data)
                {
                    var activeSessionsResult = await _sessionService.GetActiveSessionsAsync(cid.Id);
                    if (activeSessionsResult.IsSuccess && activeSessionsResult.Data != null)
                    {
                        foreach (var session in activeSessionsResult.Data)
                        {
                            if (exceptSessionId.HasValue && session.Id == exceptSessionId.Value) continue;

                            var endResult = await _sessionService.EndSessionAsync(session.Id, SessionEndReason.UserLogoutAll);
                            if (endResult.IsSuccess) loggedOutCount++;
                        }
                    }
                }
            }

            await _tokenService.RevokeAllTokensForUserAsync(userId);

            // FINAL FIX: Changed to the correct method name defined in the interface.
            await _authCacheService.ClearAuthenticationCacheAsync(userId);

            _logger.LogInformation("Logged out from {Count} sessions for user {UserId}", loggedOutCount, userId);
            return ServiceResult<int>.Success(loggedOutCount);
        }
        #endregion

        #region Delegated Methods
        public Task<ServiceResult<AuthenticationResponse>> RegisterAsync(string email, string password, string displayName, Guid? organizationId = null)
            => _passwordService.RegisterAsync(email, password, displayName, organizationId);

        public Task<ServiceResult<PasswordResetToken>> RequestPasswordResetAsync(string email, Guid? organizationId = null)
            => _passwordService.RequestPasswordResetAsync(email, organizationId);

        public Task<ServiceResult> ResetPasswordAsync(string token, string newPassword)
            => _passwordService.ResetPasswordAsync(token, newPassword);

        public Task<ServiceResult> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
            => _passwordService.ChangePasswordAsync(userId, currentPassword, newPassword);
        #endregion

        #region Helpers
        private string GenerateDeviceFingerprint(DeviceInfo deviceInfo)
        {
            if (deviceInfo == null) return string.Empty;
            var components = new List<string> {
                deviceInfo.DeviceId, deviceInfo.DeviceType, deviceInfo.OperatingSystem,
                deviceInfo.Browser, deviceInfo.BrowserVersion, deviceInfo.DeviceModel ?? "N/A"
            };
            var combinedString = string.Join("|", components.Where(c => !string.IsNullOrWhiteSpace(c)));
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(combinedString);
                var hashBytes = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
        #endregion
    }
}