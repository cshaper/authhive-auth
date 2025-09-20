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
using AuthHive.Core.Enums.Auth;

namespace AuthHive.Auth.Providers.OAuth
{
    /// <summary>
    /// Google OAuth 2.0 제공자 구현 - AuthHive v15
    /// Google 소셜 로그인 지원
    /// </summary>
    public class GoogleOAuthProvider : IOAuthProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<GoogleOAuthProvider> _logger;

        // Google OAuth 2.0 엔드포인트
        private const string AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
        private const string TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
        private const string USER_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo";
        private const string REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke";

        // 기본 스코프
        private static readonly List<string> DEFAULT_SCOPES = new()
        {
            "openid",
            "email",
            "profile"
        };

        public string ProviderName => "google";

        public GoogleOAuthProvider(
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            ILogger<GoogleOAuthProvider> logger)
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
                var clientId = _configuration[$"OAuth:Google:ClientId"];
                if (string.IsNullOrEmpty(clientId))
                {
                    return Task.FromResult(ServiceResult<string>.Failure("Google OAuth client ID not configured", "CONFIG_ERROR"));
                }

                var scopesToUse = scopes ?? DEFAULT_SCOPES;
                var scopeString = string.Join(" ", scopesToUse);

                var queryParams = new Dictionary<string, string>
                {
                    ["client_id"] = clientId,
                    ["redirect_uri"] = redirectUri,
                    ["response_type"] = "code",
                    ["scope"] = scopeString,
                    ["state"] = state,
                    ["access_type"] = "offline", // Request refresh token
                    ["prompt"] = "consent" // Force consent screen to get refresh token
                };

                var queryString = string.Join("&", 
                    queryParams.Select(kvp => 
                        $"{kvp.Key}={HttpUtility.UrlEncode(kvp.Value)}"));

                var authorizationUrl = $"{AUTHORIZATION_ENDPOINT}?{queryString}";

                _logger.LogInformation("Generated Google OAuth authorization URL for redirect URI: {RedirectUri}", redirectUri);
                
                return Task.FromResult(ServiceResult<string>.Success(authorizationUrl));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate Google OAuth authorization URL");
                return Task.FromResult(ServiceResult<string>.Failure("Failed to generate authorization URL", "AUTH_URL_ERROR"));
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<OAuthTokenResponse>> ExchangeCodeForTokenAsync(
            string code,
            string redirectUri)
        {
            try
            {
                var clientId = _configuration[$"OAuth:Google:ClientId"];
                var clientSecret = _configuration[$"OAuth:Google:ClientSecret"];

                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                {
                    return ServiceResult<OAuthTokenResponse>.Failure(
                        "Google OAuth client credentials not configured", "CONFIG_ERROR");
                }

                using var httpClient = _httpClientFactory.CreateClient();
                
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                });

                var response = await httpClient.PostAsync(TOKEN_ENDPOINT, tokenRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Google token exchange failed: {StatusCode} - {Content}", 
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthTokenResponse>.Failure(
                        "Failed to exchange authorization code", "TOKEN_EXCHANGE_ERROR");
                }

                var tokenData = JsonSerializer.Deserialize<JsonElement>(responseContent);
                
                var tokenResponse = new OAuthTokenResponse
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

                _logger.LogInformation("Successfully exchanged Google OAuth code for tokens");
                
                return ServiceResult<OAuthTokenResponse>.Success(tokenResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to exchange Google OAuth code for token");
                return ServiceResult<OAuthTokenResponse>.Failure(
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

                var response = await httpClient.GetAsync(USER_INFO_ENDPOINT);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to get Google user info: {StatusCode} - {Content}", 
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthUserInfo>.Failure(
                        "Failed to get user information", "USER_INFO_ERROR");
                }

                var userData = JsonSerializer.Deserialize<JsonElement>(responseContent);
                
                var userInfo = new OAuthUserInfo
                {
                    Id = userData.GetProperty("id").GetString() ?? string.Empty,
                    Email = userData.TryGetProperty("email", out var email) 
                        ? email.GetString() : null,
                    Name = userData.TryGetProperty("name", out var name) 
                        ? name.GetString() : null,
                    Picture = userData.TryGetProperty("picture", out var picture) 
                        ? picture.GetString() : null,
                    EmailVerified = userData.TryGetProperty("verified_email", out var verified) 
                        && verified.GetBoolean(),
                    RawData = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent) 
                        ?? new Dictionary<string, object>()
                };

                _logger.LogInformation("Successfully retrieved Google user info for user ID: {UserId}", userInfo.Id);
                
                return ServiceResult<OAuthUserInfo>.Success(userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Google user info");
                return ServiceResult<OAuthUserInfo>.Failure(
                    "Failed to get user information", "USER_INFO_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<OAuthTokenResponse>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var clientId = _configuration[$"OAuth:Google:ClientId"];
                var clientSecret = _configuration[$"OAuth:Google:ClientSecret"];

                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                {
                    return ServiceResult<OAuthTokenResponse>.Failure(
                        "Google OAuth client credentials not configured", "CONFIG_ERROR");
                }

                using var httpClient = _httpClientFactory.CreateClient();
                
                var refreshRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("grant_type", "refresh_token")
                });

                var response = await httpClient.PostAsync(TOKEN_ENDPOINT, refreshRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Google token refresh failed: {StatusCode} - {Content}", 
                        response.StatusCode, responseContent);
                    return ServiceResult<OAuthTokenResponse>.Failure(
                        "Failed to refresh token", "TOKEN_REFRESH_ERROR");
                }

                var tokenData = JsonSerializer.Deserialize<JsonElement>(responseContent);
                
                var tokenResponse = new OAuthTokenResponse
                {
                    AccessToken = tokenData.GetProperty("access_token").GetString() ?? string.Empty,
                    RefreshToken = refreshToken, // Google doesn't return new refresh token
                    TokenType = tokenData.GetProperty("token_type").GetString() ?? "Bearer",
                    ExpiresIn = tokenData.GetProperty("expires_in").GetInt32(),
                    Scopes = tokenData.TryGetProperty("scope", out var scope)
                        ? scope.GetString()?.Split(' ').ToList() ?? new List<string>()
                        : new List<string>()
                };

                _logger.LogInformation("Successfully refreshed Google OAuth token");
                
                return ServiceResult<OAuthTokenResponse>.Success(tokenResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh Google OAuth token");
                return ServiceResult<OAuthTokenResponse>.Failure(
                    "Failed to refresh token", "TOKEN_REFRESH_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> RevokeTokenAsync(string token)
        {
            try
            {
                using var httpClient = _httpClientFactory.CreateClient();
                
                var revokeRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("token", token)
                });

                var response = await httpClient.PostAsync(REVOKE_ENDPOINT, revokeRequest);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to revoke Google token: {StatusCode}", response.StatusCode);
                    return ServiceResult.Failure("Failed to revoke token", "REVOKE_ERROR");
                }

                _logger.LogInformation("Successfully revoked Google OAuth token");
                
                return ServiceResult.Success("Token revoked successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke Google OAuth token");
                return ServiceResult.Failure("Failed to revoke token", "REVOKE_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<bool>> ValidateConfigurationAsync()
        {
            try
            {
                var clientId = _configuration[$"OAuth:Google:ClientId"];
                var clientSecret = _configuration[$"OAuth:Google:ClientSecret"];

                if (string.IsNullOrEmpty(clientId))
                {
                    _logger.LogWarning("Google OAuth client ID not configured");
                    return ServiceResult<bool>.Success(false, "Client ID not configured");
                }

                if (string.IsNullOrEmpty(clientSecret))
                {
                    _logger.LogWarning("Google OAuth client secret not configured");
                    return ServiceResult<bool>.Success(false, "Client secret not configured");
                }

                // Test connectivity to Google OAuth endpoints
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                try
                {
                    var response = await httpClient.GetAsync($"{AUTHORIZATION_ENDPOINT}?client_id=test");
                    // We expect a 4xx error (invalid request), but it confirms the endpoint is reachable
                    if (response.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
                    {
                        return ServiceResult<bool>.Success(false, "Google OAuth service unavailable");
                    }
                }
                catch (HttpRequestException)
                {
                    return ServiceResult<bool>.Success(false, "Cannot reach Google OAuth endpoints");
                }
                catch (TaskCanceledException)
                {
                    return ServiceResult<bool>.Success(false, "Google OAuth endpoints timeout");
                }

                _logger.LogInformation("Google OAuth configuration validated successfully");
                return ServiceResult<bool>.Success(true, "Configuration is valid");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate Google OAuth configuration");
                return ServiceResult<bool>.Failure("Failed to validate configuration", "VALIDATION_ERROR");
            }
        }
    }
}