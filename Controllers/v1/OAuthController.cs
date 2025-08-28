using Microsoft.AspNetCore.Mvc;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Auth.Services.Authentication;
using System.Text;
using Newtonsoft.Json;
using AuthHive.Core.Interfaces.Auth.Service;

namespace AuthHive.Auth.Controllers
{
    [ApiController]
    [Route("auth")]
    public class OAuthController : ControllerBase
    {

        private readonly IConfiguration _configuration;
        private readonly ILogger<OAuthController> _logger;
        private readonly HttpClient _httpClient;

        public OAuthController(
            IConfiguration configuration,
            ILogger<OAuthController> logger,
            IHttpClientFactory httpClientFactory)
        {
            _authService = authService;
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient();
        }

        /// <summary>
        /// OAuth 로그인 시작 - 제공자의 로그인 페이지로 리디렉션
        /// </summary>
        [HttpGet("login/{provider}")]
        public IActionResult Login(string provider)
        {
            var redirectUrl = provider.ToLower() switch
            {
                "google" => $"https://accounts.google.com/o/oauth2/v2/auth?" +
                    $"client_id={_configuration["OAuth:Google:ClientId"]}&" +
                    $"redirect_uri={_configuration["OAuth:Google:RedirectUri"]}&" +
                    $"response_type=code&" +
                    $"scope=openid email profile",

                "github" => $"https://github.com/login/oauth/authorize?" +
                    $"client_id={_configuration["OAuth:GitHub:ClientId"]}&" +
                    $"redirect_uri={_configuration["OAuth:GitHub:RedirectUri"]}&" +
                    $"scope=read:user user:email",

                "kakao" => $"https://kauth.kakao.com/oauth/authorize?" +
                    $"client_id={_configuration["OAuth:Kakao:ClientId"]}&" +
                    $"redirect_uri={_configuration["OAuth:Kakao:RedirectUri"]}&" +
                    $"response_type=code",

                "naver" => $"https://nid.naver.com/oauth2.0/authorize?" +
                    $"client_id={_configuration["OAuth:Naver:ClientId"]}&" +
                    $"redirect_uri={_configuration["OAuth:Naver:RedirectUri"]}&" +
                    $"response_type=code&" +
                    $"state=RANDOM_STATE",

                "line" => $"https://access.line.me/oauth2/v2.1/authorize?" +
                    $"client_id={_configuration["OAuth:Line:ClientId"]}&" +
                    $"redirect_uri={_configuration["OAuth:Line:RedirectUri"]}&" +
                    $"response_type=code&" +
                    $"scope=openid profile email&" +
                    $"state=RANDOM_STATE",

                _ => throw new NotSupportedException($"Provider {provider} is not supported")
            };

            _logger.LogInformation("Redirecting to {Provider} OAuth login", provider);
            return Redirect(redirectUrl);
        }

        /// <summary>
        /// OAuth 콜백 처리 - 인증 코드를 액세스 토큰으로 교환
        /// </summary>
        [HttpGet("callback/{provider}")]
        public async Task<IActionResult> Callback(string provider, string code, string? state = null)
        {
            try
            {
                _logger.LogInformation("OAuth callback received for {Provider} with code", provider);

                // 1. Authorization code를 Access token으로 교환
                var accessToken = await ExchangeCodeForToken(provider, code);

                if (string.IsNullOrEmpty(accessToken))
                {
                    _logger.LogWarning("Failed to exchange code for token for provider {Provider}", provider);
                    return BadRequest(new { error = "Failed to obtain access token" });
                }

                // 2. AuthenticationService를 통해 로그인 처리
                var result = await _authService.AuthenticateWithSocialAsync(provider, accessToken, null);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("OAuth authentication successful for provider {Provider}", provider);

                    // 프론트엔드가 있다면 토큰과 함께 리디렉션
                    // return Redirect($"http://localhost:3000/auth/success?token={result.Data.AccessToken}");

                    // API 응답으로 반환
                    return Ok(result.Data);
                }

                return Unauthorized(new { error = result.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OAuth callback failed for provider {Provider}", provider);
                return StatusCode(500, new { error = "OAuth authentication failed" });
            }
        }
        private async Task<string?> ExchangeCodeForToken(string provider, string code)
        {
            try
            {
                var tokenEndpoint = provider.ToLower() switch
                {
                    "google" => "https://oauth2.googleapis.com/token",
                    "github" => "https://github.com/login/oauth/access_token",
                    "kakao" => "https://kauth.kakao.com/oauth/token",
                    "naver" => "https://nid.naver.com/oauth2.0/token",
                    "line" => "https://api.line.me/oauth2/v2.1/token",
                    _ => throw new NotSupportedException($"Provider {provider} is not supported")
                };

                var tokenRequest = new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["client_id"] = _configuration[$"OAuth:{GetProviderConfigName(provider)}:ClientId"] ?? "",
                    ["client_secret"] = _configuration[$"OAuth:{GetProviderConfigName(provider)}:ClientSecret"] ?? "",
                    ["redirect_uri"] = _configuration[$"OAuth:{GetProviderConfigName(provider)}:RedirectUri"] ?? ""
                };

                // Naver는 state 파라미터 필요
                if (provider.ToLower() == "naver")
                {
                    tokenRequest["state"] = "RANDOM_STATE";
                }

                var content = new FormUrlEncodedContent(tokenRequest);

                // GitHub는 Accept 헤더 필요
                if (provider.ToLower() == "github")
                {
                    _httpClient.DefaultRequestHeaders.Accept.Clear();
                    _httpClient.DefaultRequestHeaders.Accept.Add(
                        new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                }

                var response = await _httpClient.PostAsync(tokenEndpoint, content);
                var responseContent = await response.Content.ReadAsStringAsync();

                _logger.LogInformation("Token exchange response for {Provider}: {Response}", provider, responseContent);

                if (response.IsSuccessStatusCode)
                {
                    dynamic? tokenResponse = JsonConvert.DeserializeObject(responseContent);

                    // Google의 경우 id_token을 사용
                    if (provider.ToLower() == "google")
                    {
                        string? idToken = tokenResponse?.id_token;
                        _logger.LogInformation("Using Google ID token for validation");
                        return idToken;
                    }

                    // 다른 제공자는 access_token 사용
                    string? accessToken = tokenResponse?.access_token ?? tokenResponse?.accessToken;

                    _logger.LogInformation("Successfully obtained access token for {Provider}", provider);
                    return accessToken;
                }

                _logger.LogError("Failed to exchange code for token. Status: {Status}, Response: {Response}",
                    response.StatusCode, responseContent);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exchanging code for token for provider {Provider}", provider);
                return null;
            }
        }
        private string GetProviderConfigName(string provider)
        {
            return provider.ToLower() switch
            {
                "google" => "Google",
                "github" => "GitHub",
                "kakao" => "Kakao",
                "naver" => "Naver",
                "line" => "Line",
                _ => provider
            };
        }
    }
}