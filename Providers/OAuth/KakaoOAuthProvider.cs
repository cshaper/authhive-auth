using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Common;

namespace AuthHive.Auth.Providers.OAuth
{
    /// <summary>
    /// Kakao OAuth 2.0 제공자 구현 - AuthHive v15
    /// 카카오 소셜 로그인 지원
    /// </summary>
    public class KakaoOAuthProvider : IOAuthProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<KakaoOAuthProvider> _logger;

        // Kakao OAuth 2.0 엔드포인트
        private const string AUTHORIZATION_ENDPOINT = "https://kauth.kakao.com/oauth/authorize";
        private const string TOKEN_ENDPOINT = "https://kauth.kakao.com/oauth/token";
        private const string USER_INFO_ENDPOINT = "https://kapi.kakao.com/v2/user/me";
        private const string LOGOUT_ENDPOINT = "https://kapi.kakao.com/v1/user/logout";
        private const string UNLINK_ENDPOINT = "https://kapi.kakao.com/v1/user/unlink";

        // 기본 스코프
        private static readonly List<string> DEFAULT_SCOPES = new()
        {
            "profile_nickname",
            "profile_image",
            "account_email"
        };

        public string ProviderName => "kakao";

        public KakaoOAuthProvider(
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            ILogger<KakaoOAuthProvider> logger)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc />
        public Task<ServiceResult<string>> GetAuthorizationUrlAsync(
            string redirectUri,
            string state,
            List<string>? scopes = null)
        {
            try
            {
                var clientId = _configuration[$"OAuth:Kakao:ClientId"];
                if (string.IsNullOrEmpty(clientId))
                {
                    return Task.FromResult(ServiceResult<string>.Failure("Kakao OAuth client ID not configured", "CONFIG_ERROR"));
                }

                var scopesToUse = scopes ?? DEFAULT_SCOPES;
                var scopeString = string.Join(",", scopesToUse);

                var queryParams = new Dictionary<string, string>
                {
                    ["client_id"] = clientId,
                    ["redirect_uri"] = redirectUri,
                    ["response_type"] = "code",
                    ["state"] = state
                };

                // Kakao는 scope를 optional로 처리
                if (scopesToUse.Any())
                {
                    queryParams["scope"] = scopeString;
                }

                var queryString = string.Join("&",
                    queryParams.Select(kvp =>
                        $"{kvp.Key}={HttpUtility.UrlEncode(kvp.Value)}"));

                var authorizationUrl = $"{AUTHORIZATION_ENDPOINT}?{queryString}";

                _logger.LogInformation("Generated Kakao OAuth authorization URL for redirect URI: {RedirectUri}", redirectUri);

                return Task.FromResult(ServiceResult<string>.Success(authorizationUrl));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate Kakao OAuth authorization URL");
                return Task.FromResult(ServiceResult<string>.Failure("Failed to generate authorization URL", "AUTH_URL_ERROR"));
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<OAuthTokenResult>> ExchangeCodeForTokenAsync(
            string code,
            string redirectUri)
        {
            try
            {
                var clientId = _configuration[$"OAuth:Kakao:ClientId"];
                var clientSecret = _configuration[$"OAuth:Kakao:ClientSecret"];

                if (string.IsNullOrEmpty(clientId))
                {
                    return ServiceResult<OAuthTokenResult>.Failure(
                        "Kakao OAuth client ID not configured", "CONFIG_ERROR");
                }

                using var httpClient = _httpClientFactory.CreateClient();

                var tokenRequestParams = new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["client_id"] = clientId,
                    ["redirect_uri"] = redirectUri,
                    ["code"] = code
                };

                // Kakao는 client_secret이 optional
                if (!string.IsNullOrEmpty(clientSecret))
                {
                    tokenRequestParams["client_secret"] = clientSecret;
                }

                var tokenRequest = new FormUrlEncodedContent(tokenRequestParams);

                var response = await httpClient.PostAsync(TOKEN_ENDPOINT, tokenRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Kakao token exchange failed: {StatusCode} - {Content}",
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthTokenResult>.Failure(
                        "Failed to exchange authorization code", "TOKEN_EXCHANGE_ERROR");
                }

                var tokenData = JsonSerializer.Deserialize<JsonElement>(responseContent);

                var tokenResponse = new OAuthTokenResult
                {
                    AccessToken = tokenData.GetProperty("access_token").GetString() ?? string.Empty,
                    RefreshToken = tokenData.TryGetProperty("refresh_token", out var refreshToken)
                        ? refreshToken.GetString() : null,
                    TokenType = tokenData.GetProperty("token_type").GetString() ?? "Bearer",
                    ExpiresIn = tokenData.GetProperty("expires_in").GetInt32(),
                    Scopes = tokenData.TryGetProperty("scope", out var scope)
                        ? scope.GetString()?.Split(' ').ToList() ?? new List<string>()
                        : new List<string>()
                };

                // Kakao specific: refresh_token_expires_in
                if (tokenData.TryGetProperty("refresh_token_expires_in", out var refreshExpiresIn))
                {
                    tokenResponse.AdditionalData["refresh_token_expires_in"] = refreshExpiresIn.GetInt32();
                }

                _logger.LogInformation("Successfully exchanged Kakao OAuth code for tokens");

                return ServiceResult<OAuthTokenResult>.Success(tokenResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to exchange Kakao OAuth code for token");
                return ServiceResult<OAuthTokenResult>.Failure(
                    "Failed to exchange authorization code", "TOKEN_EXCHANGE_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<OAuthUserInfo>> GetUserInfoAsync(string accessToken)
        {
            try
            {
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                // Kakao는 property_keys 파라미터로 필요한 정보를 지정할 수 있음
                var requestUrl = $"{USER_INFO_ENDPOINT}";

                var response = await httpClient.GetAsync(requestUrl);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to get Kakao user info: {StatusCode} - {Content}",
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthUserInfo>.Failure(
                        "Failed to get user information", "USER_INFO_ERROR");
                }

                var userData = JsonSerializer.Deserialize<JsonElement>(responseContent);

                var userInfo = new OAuthUserInfo
                {
                    Id = userData.GetProperty("id").GetInt64().ToString(),
                    RawData = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent)
                        ?? new Dictionary<string, object>()
                };

                // Kakao 사용자 정보는 중첩 구조
                if (userData.TryGetProperty("kakao_account", out var kakaoAccount))
                {
                    if (kakaoAccount.TryGetProperty("email", out var email))
                    {
                        userInfo.Email = email.GetString();
                    }

                    if (kakaoAccount.TryGetProperty("is_email_verified", out var emailVerified))
                    {
                        userInfo.EmailVerified = emailVerified.GetBoolean();
                    }

                    if (kakaoAccount.TryGetProperty("profile", out var profile))
                    {
                        if (profile.TryGetProperty("nickname", out var nickname))
                        {
                            userInfo.Username = nickname.GetString();
                        }

                        if (profile.TryGetProperty("profile_image_url", out var profileImage))
                        {
                            userInfo.Picture = profileImage.GetString();
                        }
                    }
                }

                _logger.LogInformation("Successfully retrieved Kakao user info for user ID: {UserId}", userInfo.Id);

                return ServiceResult<OAuthUserInfo>.Success(userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Kakao user info");
                return ServiceResult<OAuthUserInfo>.Failure(
                    "Failed to get user information", "USER_INFO_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<OAuthTokenResult>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var clientId = _configuration[$"OAuth:Kakao:ClientId"];
                var clientSecret = _configuration[$"OAuth:Kakao:ClientSecret"];

                if (string.IsNullOrEmpty(clientId))
                {
                    return ServiceResult<OAuthTokenResult>.Failure(
                        "Kakao OAuth client ID not configured", "CONFIG_ERROR");
                }

                using var httpClient = _httpClientFactory.CreateClient();

                var refreshRequestParams = new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = clientId,
                    ["refresh_token"] = refreshToken
                };

                // Kakao는 client_secret이 optional
                if (!string.IsNullOrEmpty(clientSecret))
                {
                    refreshRequestParams["client_secret"] = clientSecret;
                }

                var refreshRequest = new FormUrlEncodedContent(refreshRequestParams);

                var response = await httpClient.PostAsync(TOKEN_ENDPOINT, refreshRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Kakao token refresh failed: {StatusCode} - {Content}",
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthTokenResult>.Failure(
                        "Failed to refresh token", "TOKEN_REFRESH_ERROR");
                }

                var tokenData = JsonSerializer.Deserialize<JsonElement>(responseContent);

                var tokenResponse = new OAuthTokenResult
                {
                    AccessToken = tokenData.GetProperty("access_token").GetString() ?? string.Empty,
                    // Kakao는 refresh_token을 갱신할 수도, 안 할 수도 있음
                    RefreshToken = tokenData.TryGetProperty("refresh_token", out var newRefreshToken)
                        ? newRefreshToken.GetString()
                        : refreshToken,
                    TokenType = tokenData.GetProperty("token_type").GetString() ?? "Bearer",
                    ExpiresIn = tokenData.GetProperty("expires_in").GetInt32()
                };

                _logger.LogInformation("Successfully refreshed Kakao OAuth token");

                return ServiceResult<OAuthTokenResult>.Success(tokenResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh Kakao OAuth token");
                return ServiceResult<OAuthTokenResult>.Failure(
                    "Failed to refresh token", "TOKEN_REFRESH_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> RevokeTokenAsync(string token)
        {
            try
            {
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                // Kakao는 로그아웃과 연결 끊기를 구분
                // 여기서는 로그아웃만 수행 (토큰 무효화)
                var response = await httpClient.PostAsync(LOGOUT_ENDPOINT, null);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to revoke Kakao token: {StatusCode}", response.StatusCode);
                    return ServiceResult.Failure("Failed to revoke token", "REVOKE_ERROR");
                }

                _logger.LogInformation("Successfully revoked Kakao OAuth token");

                return ServiceResult.Success("Token revoked successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke Kakao OAuth token");
                return ServiceResult.Failure("Failed to revoke token", "REVOKE_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<bool>> ValidateConfigurationAsync()
        {
            try
            {
                var clientId = _configuration[$"OAuth:Kakao:ClientId"];

                if (string.IsNullOrEmpty(clientId))
                {
                    _logger.LogWarning("Kakao OAuth client ID not configured");
                    return ServiceResult<bool>.Success(false, "Client ID not configured");
                }

                // Kakao는 client_secret이 optional이므로 체크하지 않음

                // Test connectivity to Kakao OAuth endpoints
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                try
                {
                    var response = await httpClient.GetAsync($"{AUTHORIZATION_ENDPOINT}?client_id=test");
                    // We expect a 4xx error (invalid request), but it confirms the endpoint is reachable
                    if (response.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
                    {
                        return ServiceResult<bool>.Success(false, "Kakao OAuth service unavailable");
                    }
                }
                catch (HttpRequestException)
                {
                    return ServiceResult<bool>.Success(false, "Cannot reach Kakao OAuth endpoints");
                }
                catch (TaskCanceledException)
                {
                    return ServiceResult<bool>.Success(false, "Kakao OAuth endpoints timeout");
                }

                _logger.LogInformation("Kakao OAuth configuration validated successfully");
                return ServiceResult<bool>.Success(true, "Configuration is valid");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate Kakao OAuth configuration");
                return ServiceResult<bool>.Failure("Failed to validate configuration", "VALIDATION_ERROR");
            }
        }
    }
}