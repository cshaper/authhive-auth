// Services/AuthenticationManager.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 인증 관리자 구현 - AuthHive v15
    /// 모든 인증 프로바이더를 통합 관리하고 적절한 프로바이더로 라우팅합니다.
    /// </summary>
    public class AuthenticationManager : IAuthenticationManager
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AuthenticationManager> _logger;
        private readonly ITokenProvider _tokenProvider;
        private readonly ISessionService _sessionService;
        private readonly Dictionary<AuthenticationMethod, Type> _providerMapping;

        public AuthenticationManager(
            IServiceProvider serviceProvider,
            ILogger<AuthenticationManager> logger,
            ITokenProvider tokenProvider,
            ISessionService sessionService)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _tokenProvider = tokenProvider;
            _sessionService = sessionService;
            
            // 인증 방법과 Provider 매핑
            _providerMapping = new Dictionary<AuthenticationMethod, Type>
            {
                [AuthenticationMethod.Password] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.ApiKey] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.OAuth] = typeof(OAuthAuthenticationProvider),
                [AuthenticationMethod.SocialLogin] = typeof(SocialAuthenticationProvider),
                [AuthenticationMethod.SSO] = typeof(SsoAuthenticationProvider),
                [AuthenticationMethod.JWT] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.MagicLink] = typeof(MagicLinkAuthenticationProvider),
                [AuthenticationMethod.Passkey] = typeof(PasskeyAuthenticationProvider),
                [AuthenticationMethod.Certificate] = typeof(CertificateAuthenticationProvider),
                [AuthenticationMethod.Biometric] = typeof(BiometricAuthenticationProvider)
            };
        }

        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request)
        {
            try
            {
                _logger.LogInformation(
                    "Processing authentication request for method: {Method}, Organization: {OrgId}",
                    request.Method, request.OrganizationId);

                // 적절한 Provider 선택
                var provider = GetProvider(request.Method);
                if (provider == null)
                {
                    _logger.LogWarning("No provider found for authentication method: {Method}", request.Method);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        $"Authentication method {request.Method} is not supported");
                }

                // Provider가 활성화되어 있는지 확인
                if (!await provider.IsEnabledAsync())
                {
                    _logger.LogWarning("Provider {Provider} is not enabled", provider.ProviderName);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        $"Authentication provider {provider.ProviderName} is not enabled");
                }

                // 인증 수행
                var result = await provider.AuthenticateAsync(request);
                
                if (result.IsSuccess && result.Data != null)
                {
                    _logger.LogInformation(
                        "Authentication successful for user {UserId} using {Method}",
                        result.Data.UserId, request.Method);
                    
                    // 인증 성공 이벤트 발행
                    await PublishAuthenticationSuccessEvent(result.Data);
                }
                else
                {
                    _logger.LogWarning(
                        "Authentication failed for method {Method}: {Error}",
                        request.Method, result.ErrorMessage);
                    
                    // 인증 실패 이벤트 발행
                    await PublishAuthenticationFailureEvent(request, result.ErrorMessage);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication error for method {Method}", request.Method);
                return ServiceResult<AuthenticationOutcome>.Failure(
                    "An error occurred during authentication");
            }
        }

        public async Task<ServiceResult<bool>> ValidateTokenAsync(string token)
        {
            try
            {
                // PASETO 토큰 검증
                var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);
                return ServiceResult<bool>.Success(validationResult.IsSuccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return ServiceResult<bool>.Failure("Token validation error");
            }
        }

        public async Task<ServiceResult> RevokeTokenAsync(string token)
        {
            try
            {
                // 세션 찾기 및 종료
                var sessionResult = await _sessionService.GetSessionByTokenAsync(token);
                if (sessionResult.IsSuccess && sessionResult.Data != null)
                {
                    await _sessionService.EndSessionAsync(
                        sessionResult.Data.SessionId,
                        SessionEnums.SessionEndReason.UserLogout);
                    
                    return ServiceResult.Success("Token revoked successfully");
                }
                
                return ServiceResult.Failure("Token not found or could not be revoked");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking token");
                return ServiceResult.Failure("Token revocation error");
            }
        }

        public async Task<ServiceResult<AuthenticationOutcome>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // Refresh Token으로 세션 찾기
                var sessionResult = await _sessionService.GetSessionByTokenAsync(refreshToken);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid refresh token");
                }

                var session = sessionResult.Data;

                // 세션 갱신
                var refreshResult = await _sessionService.RefreshSessionAsync(session.SessionId);
                if (!refreshResult.IsSuccess || refreshResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to refresh session");
                }

                // 새 토큰 생성
                var claims = new List<System.Security.Claims.Claim>
                {
                    new("user_id", session.UserId.ToString()),
                    new("session_id", session.SessionId.ToString())
                };

                if (session.ConnectedId.HasValue)
                {
                    claims.Add(new("connected_id", session.ConnectedId.Value.ToString()));
                }

                if (session.OrganizationId.HasValue)
                {
                    claims.Add(new("org_id", session.OrganizationId.Value.ToString()));
                }

                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    session.UserId,
                    session.ConnectedId ?? Guid.Empty,
                    claims);

                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate new token");
                }

                var newRefreshToken = await _tokenProvider.GenerateRefreshTokenAsync(session.UserId);

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = session.UserId,
                    ConnectedId = session.ConnectedId,
                    SessionId = session.SessionId,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = newRefreshToken.Data,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = session.OrganizationId,
                    ApplicationId = session.ApplicationId
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return ServiceResult<AuthenticationOutcome>.Failure("Token refresh error");
            }
        }

        public async Task<ServiceResult<List<AuthenticationMethod>>> GetAvailableMethodsAsync(
            Guid? organizationId = null)
        {
            try
            {
                var availableMethods = new List<AuthenticationMethod>();
                
                foreach (var mapping in _providerMapping)
                {
                    var provider = GetProvider(mapping.Key);
                    if (provider != null && await provider.IsEnabledAsync())
                    {
                        // 조직별 설정 확인 (필요한 경우)
                        if (organizationId.HasValue)
                        {
                            // TODO: 조직별 인증 방법 설정 확인
                        }
                        
                        availableMethods.Add(mapping.Key);
                    }
                }
                
                return ServiceResult<List<AuthenticationMethod>>.Success(availableMethods);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting available authentication methods");
                return ServiceResult<List<AuthenticationMethod>>.Failure(
                    "Failed to get available authentication methods");
            }
        }

        public async Task<ServiceResult<bool>> IsMethodEnabledAsync(
            AuthenticationMethod method,
            Guid? organizationId = null)
        {
            try
            {
                var provider = GetProvider(method);
                if (provider == null)
                {
                    return ServiceResult<bool>.Success(false);
                }

                var isEnabled = await provider.IsEnabledAsync();
                
                // 조직별 설정 확인
                if (isEnabled && organizationId.HasValue)
                {
                    // TODO: 조직별 인증 방법 설정 확인
                }
                
                return ServiceResult<bool>.Success(isEnabled);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if method {Method} is enabled", method);
                return ServiceResult<bool>.Failure("Failed to check method status");
            }
        }

        public async Task<ServiceResult<AuthenticationMethodSettings>> GetMethodSettingsAsync(
            AuthenticationMethod method,
            Guid? organizationId = null)
        {
            try
            {
                var settings = new AuthenticationMethodSettings
                {
                    Method = method,
                    IsEnabled = await IsMethodEnabledAsync(method, organizationId).ContinueWith(t => t.Result.Data),
                    Priority = GetMethodPriority(method),
                    RequiresMfa = ShouldRequireMfa(method),
                    MaxAttempts = 5,
                    LockoutMinutes = 30
                };

                // 조직별 설정 오버라이드
                if (organizationId.HasValue)
                {
                    // TODO: 조직별 설정 로드
                }

                return ServiceResult<AuthenticationMethodSettings>.Success(settings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting settings for method {Method}", method);
                return ServiceResult<AuthenticationMethodSettings>.Failure("Failed to get method settings");
            }
        }

        public async Task<ServiceResult<string>> GenerateExternalLoginUrlAsync(
            string provider,
            string redirectUri,
            string? state = null,
            List<string>? scopes = null)
        {
            try
            {
                // OAuth/Social Provider에게 위임
                // TODO: OAuthProviderFactory를 통해 URL 생성
                
                var loginUrl = $"https://auth.provider.com/oauth/authorize?client_id=xxx&redirect_uri={redirectUri}&state={state ?? Guid.NewGuid().ToString()}";
                
                return ServiceResult<string>.Success(loginUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating external login URL for {Provider}", provider);
                return ServiceResult<string>.Failure("Failed to generate login URL");
            }
        }

        public async Task<ServiceResult<bool>> VerifyMfaAsync(
            Guid userId,
            string code,
            MfaMethod method)
        {
            try
            {
                // TODO: MFA 서비스 구현
                await Task.CompletedTask;
                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying MFA for user {UserId}", userId);
                return ServiceResult<bool>.Failure("MFA verification failed");
            }
        }

        public async Task<ServiceResult<List<AuthenticationAttemptSummary>>> GetAuthenticationHistoryAsync(
            Guid? userId = null,
            Guid? organizationId = null,
            int limit = 10)
        {
            try
            {
                // TODO: 인증 이력 조회 구현
                var history = new List<AuthenticationAttemptSummary>();
                
                return ServiceResult<List<AuthenticationAttemptSummary>>.Success(history);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication history");
                return ServiceResult<List<AuthenticationAttemptSummary>>.Failure("Failed to get authentication history");
            }
        }

        public async Task<ServiceResult<List<SessionSummary>>> GetActiveSessionsAsync(
            Guid userId,
            Guid? organizationId = null)
        {
            try
            {
                // TODO: 활성 세션 조회 구현
                var sessions = new List<SessionSummary>();
                
                return ServiceResult<List<SessionSummary>>.Success(sessions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active sessions for user {UserId}", userId);
                return ServiceResult<List<SessionSummary>>.Failure("Failed to get active sessions");
            }
        }

        public async Task<ServiceResult<int>> RevokeAllSessionsAsync(
            Guid userId,
            string? exceptCurrentToken = null)
        {
            try
            {
                // TODO: 모든 세션 종료 구현
                var count = 0;
                
                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking all sessions for user {UserId}", userId);
                return ServiceResult<int>.Failure("Failed to revoke sessions");
            }
        }

        public async Task<ServiceResult<AuthenticationStatistics>> GetStatisticsAsync(
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                // TODO: 통계 조회 구현
                var statistics = new AuthenticationStatistics();
                
                return ServiceResult<AuthenticationStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication statistics");
                return ServiceResult<AuthenticationStatistics>.Failure("Failed to get statistics");
            }
        }

        private IAuthenticationProvider? GetProvider(AuthenticationMethod method)
        {
            if (_providerMapping.TryGetValue(method, out var providerType))
            {
                return _serviceProvider.GetService(providerType) as IAuthenticationProvider;
            }
            
            return null;
        }

        private int GetMethodPriority(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Passkey => 1,
                AuthenticationMethod.Biometric => 2,
                AuthenticationMethod.SSO => 3,
                AuthenticationMethod.OAuth => 4,
                AuthenticationMethod.SocialLogin => 5,
                AuthenticationMethod.Password => 6,
                AuthenticationMethod.MagicLink => 7,
                AuthenticationMethod.ApiKey => 8,
                _ => 99
            };
        }

        private bool ShouldRequireMfa(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Password => true,
                AuthenticationMethod.MagicLink => false,
                AuthenticationMethod.Passkey => false,
                AuthenticationMethod.Biometric => false,
                AuthenticationMethod.Certificate => false,
                _ => false
            };
        }

        private async Task PublishAuthenticationSuccessEvent(AuthenticationOutcome outcome)
        {
            // TODO: Platform 서비스로 이벤트 발행
            await Task.CompletedTask;
        }

        private async Task PublishAuthenticationFailureEvent(
            AuthenticationRequest request,
            string? errorMessage)
        {
            // TODO: Platform 서비스로 이벤트 발행
            await Task.CompletedTask;
        }
    }
}