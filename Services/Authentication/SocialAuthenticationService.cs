// Path: AuthHive.Auth/Services/Authentication/SocialAuthenticationService.cs
using Microsoft.EntityFrameworkCore;
using Google.Apis.Auth;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User;
using static AuthHive.Core.Enums.Core.UserEnums;
using System.Text.Json;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Services.Authentication
{
    public class SocialAuthenticationService : ISocialAuthenticationService
    {
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SocialAuthenticationService> _logger;
        private readonly HttpClient _httpClient;

        public SocialAuthenticationService(
            AuthDbContext context,
            IConfiguration configuration,
            ILogger<SocialAuthenticationService> logger,
            IHttpClientFactory httpClientFactory)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient();
        }


        /// <summary>
        /// ISocialAuthenticationService.AuthenticateWithSocialAsync 구현
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> AuthenticateWithSocialAsync(
    string provider,
    string token,
    Guid? organizationId = null)
        {
            try
            {
                _logger.LogInformation(
                    "Social authentication attempt for provider: {Provider}, Organization: {OrganizationId}",
                    provider,
                    organizationId);

                // 기존 AuthenticateSocialAsync 로직을 여기에 직접 구현
                var validationResult = await ValidateSocialTokenAsync(provider, token);

                if (!validationResult.isValid || string.IsNullOrEmpty(validationResult.email))
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Invalid social token.");
                }

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == validationResult.email);

                bool isNewUser = false;

                if (user == null)
                {
                    user = new UserEntity
                    {
                        Email = validationResult.email,
                        DisplayName = validationResult.name ?? validationResult.email,
                        Status = UserStatus.Active,
                        EmailVerified = true
                    };

                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                    isNewUser = true;
                }

                // AuthenticationResponse 생성
                var response = new AuthenticationResponse
                {
                    Success = true,
                    UserId = user.Id,
                    AuthenticationMethod = provider,
                    IsFirstLogin = isNewUser,
                    OrganizationId = organizationId
                };

                return ServiceResult<AuthenticationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during social authentication");
                return ServiceResult<AuthenticationResponse>.Failure("Social authentication failed");
            }
        }

        /// <summary>
        /// OAuth 인증 구현
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> AuthenticateWithOAuthAsync(
            string provider,
            string code,
            string redirectUri,
            string? state = null)
        {
            try
            {
                _logger.LogInformation(
                    "OAuth authentication attempt for provider: {Provider}",
                    provider);

                // OAuth 프로바이더별 토큰 교환 로직
                var tokenResult = await ExchangeCodeForTokenAsync(provider, code, redirectUri);

                if (!tokenResult.success)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to exchange code for token");
                }

                // 획득한 토큰으로 소셜 인증 진행
                return await AuthenticateWithSocialAsync(provider, tokenResult.token!, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during OAuth authentication");
                return ServiceResult<AuthenticationResponse>.Failure("OAuth authentication failed");
            }
        }

        /// <summary>
        /// 소셜 토큰 검증
        /// </summary>
        public async Task<(bool isValid, string? email, string? name, string? providerUserId)>
            ValidateSocialTokenAsync(string provider, string token)
        {
            try
            {
                switch (provider.ToLower())
                {
                    case "google":
                        return await ValidateGoogleTokenAsync(token);

                    case "facebook":
                        return await ValidateFacebookTokenAsync(token);

                    case "github":
                        return await ValidateGithubTokenAsync(token);

                    case "microsoft":
                        return await ValidateMicrosoftTokenAsync(token);

                    default:
                        _logger.LogWarning("Unsupported provider: {Provider}", provider);
                        return (false, null, null, null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating social token for provider: {Provider}", provider);
                return (false, null, null, null);
            }
        }

        /// <summary>
        /// 지원되는 소셜 프로바이더 목록
        /// </summary>
        public async Task<ServiceResult<IEnumerable<string>>> GetSupportedProvidersAsync()
        {
            try
            {
                var providers = new List<string>();

                // 설정에서 활성화된 프로바이더 확인
                if (_configuration.GetValue<bool>("Authentication:Google:Enabled"))
                    providers.Add("google");

                if (_configuration.GetValue<bool>("Authentication:Facebook:Enabled"))
                    providers.Add("facebook");

                if (_configuration.GetValue<bool>("Authentication:Github:Enabled"))
                    providers.Add("github");

                if (_configuration.GetValue<bool>("Authentication:Microsoft:Enabled"))
                    providers.Add("microsoft");

                return await Task.FromResult(
                    ServiceResult<IEnumerable<string>>.Success(providers));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting supported providers");
                return ServiceResult<IEnumerable<string>>.Failure("Failed to get supported providers");
            }
        }

        /// <summary>
        /// IService.InitializeAsync 구현
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing Social Authentication Service");

                // 각 프로바이더 설정 확인
                var providers = await GetSupportedProvidersAsync();

                if (providers.IsSuccess == false || providers.Data?.Any() != true)
                {
                    _logger.LogWarning("No social authentication providers are configured");
                }
                else
                {
                    _logger.LogInformation(
                        "Social authentication initialized with providers: {Providers}",
                        string.Join(", ", providers.Data!));
                }

                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize Social Authentication Service");
                throw;
            }
        }

        /// <summary>
        /// IService.IsHealthyAsync 구현
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 데이터베이스 연결 확인
                var canConnect = await _context.Database.CanConnectAsync();

                if (!canConnect)
                {
                    _logger.LogWarning("Social Authentication Service: Database connection failed");
                    return false;
                }

                // 최소 하나의 프로바이더가 활성화되어 있는지 확인
                var providers = await GetSupportedProvidersAsync();
                var hasProviders = providers.IsSuccess && providers.Data != null && providers.Data.Any();

                return canConnect && hasProviders;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check failed for Social Authentication Service");
                return false;
            }
        }
        #region Private Helper Methods

        private async Task<(bool success, string? token)> ExchangeCodeForTokenAsync(
            string provider,
            string code,
            string redirectUri)
        {
            try
            {
                var clientId = _configuration[$"Authentication:{provider}:ClientId"] ?? string.Empty;
                var clientSecret = _configuration[$"Authentication:{provider}:ClientSecret"] ?? string.Empty;
                var tokenEndpoint = GetTokenEndpoint(provider);

                var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["code"] = code,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                    ["redirect_uri"] = redirectUri,
                    ["grant_type"] = "authorization_code"
                });

                var response = await _httpClient.PostAsync(tokenEndpoint, tokenRequest);

                if (!response.IsSuccessStatusCode)
                {
                    return (false, null);
                }

                var content = await response.Content.ReadAsStringAsync();
                var tokenData = JsonSerializer.Deserialize<JsonElement>(content);

                var accessToken = tokenData.GetProperty("access_token").GetString();
                return (true, accessToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to exchange code for token");
                return (false, null);
            }
        }

        private string GetTokenEndpoint(string provider)
        {
            return provider.ToLower() switch
            {
                "google" => "https://oauth2.googleapis.com/token",
                "facebook" => "https://graph.facebook.com/v12.0/oauth/access_token",
                "github" => "https://github.com/login/oauth/access_token",
                "microsoft" => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                _ => throw new NotSupportedException($"Provider {provider} is not supported")
            };
        }

        private async Task<(bool isValid, string? email, string? name, string? providerUserId)>
            ValidateGoogleTokenAsync(string token)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { _configuration["Authentication:Google:ClientId"] }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(token, settings);
                return (true, payload.Email, payload.Name, payload.Subject);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Google token validation failed");
                return (false, null, null, null);
            }
        }

        private async Task<(bool isValid, string? email, string? name, string? providerUserId)>
            ValidateFacebookTokenAsync(string token)
        {
            try
            {
                var appId = _configuration["Authentication:Facebook:AppId"];
                var appSecret = _configuration["Authentication:Facebook:AppSecret"];

                // Facebook token 검증 API 호출
                var response = await _httpClient.GetAsync(
                    $"https://graph.facebook.com/debug_token?input_token={token}&access_token={appId}|{appSecret}");

                if (!response.IsSuccessStatusCode)
                    return (false, null, null, null);

                var content = await response.Content.ReadAsStringAsync();
                var data = JsonSerializer.Deserialize<JsonElement>(content);

                if (!data.GetProperty("data").GetProperty("is_valid").GetBoolean())
                    return (false, null, null, null);

                // 사용자 정보 가져오기
                var userResponse = await _httpClient.GetAsync(
                    $"https://graph.facebook.com/me?fields=id,name,email&access_token={token}");

                if (userResponse.IsSuccessStatusCode)
                {
                    var userData = JsonSerializer.Deserialize<JsonElement>(
                        await userResponse.Content.ReadAsStringAsync());

                    return (true,
                        userData.TryGetProperty("email", out var email) ? email.GetString() : null,
                        userData.TryGetProperty("name", out var name) ? name.GetString() : null,
                        userData.TryGetProperty("id", out var id) ? id.GetString() : null);
                }

                return (false, null, null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Facebook token validation failed");
                return (false, null, null, null);
            }
        }

        private async Task<(bool isValid, string? email, string? name, string? providerUserId)>
            ValidateGithubTokenAsync(string token)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("token", token);

                var response = await _httpClient.GetAsync("https://api.github.com/user");

                if (!response.IsSuccessStatusCode)
                    return (false, null, null, null);

                var userData = JsonSerializer.Deserialize<JsonElement>(
                    await response.Content.ReadAsStringAsync());

                return (true,
                    userData.TryGetProperty("email", out var email) ? email.GetString() : null,
                    userData.TryGetProperty("name", out var name) ? name.GetString() : null,
                    userData.TryGetProperty("id", out var id) ? id.GetInt64().ToString() : null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Github token validation failed");
                return (false, null, null, null);
            }
        }

        private async Task<(bool isValid, string? email, string? name, string? providerUserId)>
            ValidateMicrosoftTokenAsync(string token)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");

                if (!response.IsSuccessStatusCode)
                    return (false, null, null, null);

                var userData = JsonSerializer.Deserialize<JsonElement>(
                    await response.Content.ReadAsStringAsync());

                return (true,
                    userData.TryGetProperty("mail", out var mail) ? mail.GetString() :
                        userData.TryGetProperty("userPrincipalName", out var upn) ? upn.GetString() : null,
                    userData.TryGetProperty("displayName", out var name) ? name.GetString() : null,
                    userData.TryGetProperty("id", out var id) ? id.GetString() : null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Microsoft token validation failed");
                return (false, null, null, null);
            }
        }

        #endregion
    }
}