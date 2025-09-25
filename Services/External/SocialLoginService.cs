using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.External;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Models.User.Requests;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.External
{
    /// <summary>
    /// 소셜 로그인 서비스 - SaaS 최적화
    /// 동적 프로바이더 처리와 멀티테넌시 지원
    /// </summary>
    public class SocialLoginService : ISocialLoginService, IService
    {
        private readonly ILogger<SocialLoginService> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUserService _userService;
        private readonly HttpClient _httpClient;

        private const string CACHE_PREFIX = "social";
        private const int TOKEN_CACHE_MINUTES = 30;
        private const int PROFILE_CACHE_MINUTES = 15;

        #region IExternalService Properties
        public string ServiceName => "Social";
        public string Provider => "OAuth2";
        public string? ApiVersion => "2.0";
        public RetryPolicy RetryPolicy { get; set; } = new() { MaxRetries = 1, InitialDelayMs = 200 };
        public int TimeoutSeconds { get; set; } = 10;
        public bool EnableCircuitBreaker { get; set; } = true;
        public IExternalService? FallbackService { get; set; }

        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;
        #endregion

        public SocialLoginService(
            ILogger<SocialLoginService> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IUserService userService,
            HttpClient httpClient)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _userService = userService;
            _httpClient = httpClient;
            _httpClient.Timeout = TimeSpan.FromSeconds(TimeoutSeconds);
        }

        #region IService Implementation
        public async Task InitializeAsync()
        {
            _logger.LogInformation("Social Login Service initialized");
            await Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync();
        }
        #endregion

        #region Core Authentication - Dynamic Provider Handling

        /// <summary>
        /// 통합 소셜 인증 - 모든 프로바이더 동적 처리
        /// </summary>
        public async Task<ServiceResult<SocialAuthResult>> AuthenticateAsync(
            SocialProvider provider,
            SocialAuthRequest request)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 동적 토큰 검증
                var profile = await ValidateDynamicTokenAsync(provider, request.Token);
                if (profile == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<SocialAuthResult>.Failure("Invalid token");
                }

                // 사용자 조회/생성
                var userResult = await GetOrCreateUserAsync(provider, profile);
                // 수정 후
                if (!userResult.IsSuccess || userResult.Data == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<SocialAuthResult>.Failure(userResult.Message ?? "User creation failed");
                }

                // 토큰 캐싱
                await CacheTokensAsync(userResult.Data!.ConnectedId, provider, request.Token);

                await _unitOfWork.CommitTransactionAsync();

                ServiceCalled?.Invoke(this, new() { ServiceName = ServiceName, Operation = "Authenticate" });
                return ServiceResult<SocialAuthResult>.Success(userResult.Data);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Social auth failed for {Provider}", provider);
                ServiceFailed?.Invoke(this, new() { ServiceName = ServiceName, Error = ex.Message });
                return ServiceResult<SocialAuthResult>.Failure("Authentication failed");
            }
        }

        /// <summary>
        /// Google 로그인 - 간소화
        /// </summary>
        public Task<ServiceResult<SocialAuthResult>> LoginWithGoogleAsync(
            string idToken,
            GoogleAuthOptions? options = null)
        {
            var request = new SocialAuthRequest
            {
                Token = idToken,
                AdditionalData = options != null ? SerializeOptions(options) : null
            };
            return AuthenticateAsync(SocialProvider.Google, request);
        }

        /// <summary>
        /// Kakao 로그인 - 간소화
        /// </summary>
        public Task<ServiceResult<SocialAuthResult>> LoginWithKakaoAsync(
            string accessToken,
            KakaoAuthOptions? options = null)
        {
            var request = new SocialAuthRequest
            {
                Token = accessToken,
                AdditionalData = options != null ? SerializeOptions(options) : null
            };
            return AuthenticateAsync(SocialProvider.Kakao, request);
        }

        /// <summary>
        /// Naver 로그인 - 간소화
        /// </summary>
        public Task<ServiceResult<SocialAuthResult>> LoginWithNaverAsync(
            string accessToken,
            NaverAuthOptions? options = null)
        {
            var request = new SocialAuthRequest
            {
                Token = accessToken,
                AdditionalData = options != null ? SerializeOptions(options) : null
            };
            return AuthenticateAsync(SocialProvider.Naver, request);
        }

        /// <summary>
        /// Apple 로그인 - 간소화
        /// </summary>
        public Task<ServiceResult<SocialAuthResult>> LoginWithAppleAsync(
            string identityToken,
            string authorizationCode,
            AppleAuthOptions? options = null)
        {
            var request = new SocialAuthRequest
            {
                Token = identityToken,
                AuthorizationCode = authorizationCode,
                AdditionalData = options != null ? SerializeOptions(options) : null
            };
            return AuthenticateAsync(SocialProvider.Apple, request);
        }

        /// <summary>
        /// Microsoft 로그인 - 간소화
        /// </summary>
        public Task<ServiceResult<SocialAuthResult>> LoginWithMicrosoftAsync(
            string accessToken,
            MicrosoftAuthOptions? options = null)
        {
            var request = new SocialAuthRequest
            {
                Token = accessToken,
                AdditionalData = options != null ? SerializeOptions(options) : null
            };
            return AuthenticateAsync(SocialProvider.Microsoft, request);
        }

        #endregion

        #region Account Linking

        /// <summary>
        /// 소셜 계정 연결 - 동적 처리
        /// </summary>
        public async Task<ServiceResult<SocialLinkResult>> LinkSocialAccountAsync(
            Guid connectedId,
            SocialProvider provider,
            SocialLinkRequest request)
        {
            try
            {
                // 중복 연결 체크
                var existingLink = await GetLinkedAccountAsync(connectedId, provider);
                if (existingLink != null)
                    return ServiceResult<SocialLinkResult>.Failure("Already linked");

                // 동적 토큰 검증
                var profile = await ValidateDynamicTokenAsync(provider, request.AccessToken);
                if (profile == null)
                    return ServiceResult<SocialLinkResult>.Failure("Invalid token");

                // 연결 정보 저장
                var linkKey = GetCacheKey($"link:{connectedId}:{provider}");
                var linkData = new LinkedSocialAccount
                {
                    Provider = provider,
                    ProviderId = profile.CustomAttributes?["id"]?.ToString() ?? "",
                    Email = profile.Email,
                    DisplayName = profile.DisplayName,
                    ProfilePictureUrl = profile.ProfilePictureUrl,
                    LinkedAt = _dateTimeProvider.UtcNow,
                    IsActive = true
                };

                await _cacheService.SetAsync(linkKey, linkData, TimeSpan.FromDays(30));

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Create,
                    "SOCIAL_LINK",
                    connectedId,
                    metadata: new Dictionary<string, object> { ["provider"] = provider.ToString() });

                return ServiceResult<SocialLinkResult>.Success(new SocialLinkResult
                {
                    Success = true,
                    Provider = provider.ToString(),
                    ProviderId = linkData.ProviderId,
                    LinkedAt = linkData.LinkedAt,
                    UpdatedProfile = request.OverwriteProfile ? profile : null
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to link social account");
                return ServiceResult<SocialLinkResult>.Failure("Link failed");
            }
        }

        /// <summary>
        /// 소셜 계정 연결 해제
        /// </summary>
        public async Task<ServiceResult> UnlinkSocialAccountAsync(
            Guid connectedId,
            SocialProvider provider,
            UnlinkOptions? options = null)
        {
            try
            {
                var linkKey = GetCacheKey($"link:{connectedId}:{provider}");
                await _cacheService.RemoveAsync(linkKey);

                if (options?.RevokeTokens == true)
                {
                    var tokenKey = GetCacheKey($"token:{connectedId}:{provider}");
                    await _cacheService.RemoveAsync(tokenKey);
                }

                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Delete,
                    "SOCIAL_UNLINK",
                    connectedId,
                    metadata: new Dictionary<string, object>
                    {
                        ["provider"] = provider.ToString(),
                        ["reason"] = options?.Reason ?? "user_requested"
                    });

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unlink social account");
                return ServiceResult.Failure("Unlink failed");
            }
        }

        /// <summary>
        /// 연결된 계정 목록 조회
        /// </summary>
        public async Task<ServiceResult<List<LinkedSocialAccount>>> GetLinkedAccountsAsync(Guid connectedId)
        {
            try
            {
                var accounts = new List<LinkedSocialAccount>();

                foreach (SocialProvider provider in Enum.GetValues<SocialProvider>())
                {
                    var linkKey = GetCacheKey($"link:{connectedId}:{provider}");
                    var account = await _cacheService.GetAsync<LinkedSocialAccount>(linkKey);
                    if (account != null)
                        accounts.Add(account);
                }

                return ServiceResult<List<LinkedSocialAccount>>.Success(accounts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get linked accounts");
                return ServiceResult<List<LinkedSocialAccount>>.Failure("Failed to retrieve accounts");
            }
        }

        /// <summary>
        /// 계정 병합 - 간소화
        /// </summary>
        public async Task<ServiceResult<AccountMergeResult>> MergeSocialAccountsAsync(
            Guid primaryConnectedId,
            Guid secondaryConnectedId,
            MergeOptions options)
        {
            // 실제 구현은 비즈니스 요구사항에 따라 달라짐
            // 여기서는 간단한 구조만 제공
            await Task.CompletedTask;
            return ServiceResult<AccountMergeResult>.Success(new AccountMergeResult
            {
                MergedUserId = primaryConnectedId,
                MergedConnectedId = primaryConnectedId,
                MergedAccountsCount = 2,
                MergedAt = _dateTimeProvider.UtcNow
            });
        }

        #endregion

        #region Profile Sync

        /// <summary>
        /// 프로필 갱신 - 동적 처리
        /// </summary>
        public async Task<ServiceResult<SocialProfile>> RefreshSocialProfileAsync(
            Guid connectedId,
            SocialProvider provider,
            bool autoUpdate = false)
        {
            try
            {
                // 토큰 가져오기
                var tokenKey = GetCacheKey($"token:{connectedId}:{provider}");
                var token = await _cacheService.GetAsync<string>(tokenKey);
                if (string.IsNullOrEmpty(token))
                    return ServiceResult<SocialProfile>.Failure("No token available");

                // 프로필 갱신
                var profile = await ValidateDynamicTokenAsync(provider, token);
                if (profile == null)
                    return ServiceResult<SocialProfile>.Failure("Failed to refresh profile");

                // 캐시 업데이트
                var profileKey = GetCacheKey($"profile:{connectedId}:{provider}");
                await _cacheService.SetAsync(profileKey, profile, TimeSpan.FromMinutes(PROFILE_CACHE_MINUTES));

                return ServiceResult<SocialProfile>.Success(profile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh social profile");
                return ServiceResult<SocialProfile>.Failure("Refresh failed");
            }
        }

        /// <summary>
        /// 프로필 동기화 설정
        /// </summary>
        public async Task<ServiceResult> ConfigureProfileSyncAsync(
            Guid connectedId,
            SocialProvider provider,
            ProfileSyncSettings settings)
        {
            var key = GetCacheKey($"sync:{connectedId}:{provider}");
            await _cacheService.SetAsync(key, settings, TimeSpan.FromDays(90));
            return ServiceResult.Success();
        }

        /// <summary>
        /// 프로필 사진 업데이트
        /// </summary>
        public async Task<ServiceResult<string>> UpdateProfilePictureFromSocialAsync(
            Guid connectedId,
            SocialProvider provider)
        {
            var profileResult = await RefreshSocialProfileAsync(connectedId, provider);
            if (!profileResult.IsSuccess || string.IsNullOrEmpty(profileResult.Data?.ProfilePictureUrl))
                return ServiceResult<string>.Failure("No profile picture available");

            return ServiceResult<string>.Success(profileResult.Data.ProfilePictureUrl);
        }

        #endregion

        #region Token Management

        /// <summary>
        /// 토큰 갱신
        /// </summary>
        public async Task<ServiceResult<SocialTokens>> RefreshSocialTokensAsync(
            Guid connectedId,
            SocialProvider provider)
        {
            // 프로바이더별 토큰 갱신 로직
            // 실제 구현은 각 프로바이더 API에 따라 다름
            await Task.CompletedTask;
            return ServiceResult<SocialTokens>.Failure("Not implemented");
        }

        /// <summary>
        /// 토큰 검증
        /// </summary>
        public async Task<ServiceResult<TokenValidation>> ValidateSocialTokenAsync(
            string accessToken,
            SocialProvider provider)
        {
            var profile = await ValidateDynamicTokenAsync(provider, accessToken);
            return ServiceResult<TokenValidation>.Success(new TokenValidation
            {
                IsValid = profile != null,
                ExpiresAt = _dateTimeProvider.UtcNow.AddMinutes(TOKEN_CACHE_MINUTES)
            });
        }

        /// <summary>
        /// 토큰 폐기
        /// </summary>
        public async Task<ServiceResult> RevokeSocialTokenAsync(
            Guid connectedId,
            SocialProvider provider)
        {
            var tokenKey = GetCacheKey($"token:{connectedId}:{provider}");
            await _cacheService.RemoveAsync(tokenKey);
            return ServiceResult.Success();
        }

        #endregion

        #region Organization Integration

        /// <summary>
        /// 도메인 기반 조직 연결
        /// </summary>
        public async Task<ServiceResult<OrganizationLinkResult>> LinkToOrganizationByDomainAsync(
            string email,
            SocialProvider provider,
            DomainLinkOptions? options = null)
        {
            // 도메인 추출 및 조직 매칭 로직
            var domain = email.Split('@').LastOrDefault();
            if (string.IsNullOrEmpty(domain))
                return ServiceResult<OrganizationLinkResult>.Failure("Invalid email");

            // 실제 구현에서는 도메인-조직 매핑 테이블 조회
            await Task.CompletedTask;
            return ServiceResult<OrganizationLinkResult>.Success(new OrganizationLinkResult
            {
                OrganizationId = Guid.NewGuid(),
                OrganizationName = $"Organization for {domain}",
                AutoLinked = true,
                JoinedAt = _dateTimeProvider.UtcNow
            });
        }

        /// <summary>
        /// 조직 멤버 동기화
        /// </summary>
        public async Task<ServiceResult> SyncOrganizationMembersAsync(
            Guid organizationId,
            SocialProvider provider,
            OrganizationSyncOptions options)
        {
            // 실제 구현은 비즈니스 로직에 따름
            await Task.CompletedTask;
            return ServiceResult.Success();
        }

        #endregion

        #region Permissions & Scopes

        /// <summary>
        /// 추가 스코프 요청
        /// </summary>
        public async Task<ServiceResult<ScopeRequestResult>> RequestAdditionalScopesAsync(
            Guid connectedId,
            SocialProvider provider,
            List<string> scopes)
        {
            // OAuth 재인증 플로우 트리거
            await Task.CompletedTask;
            return ServiceResult<ScopeRequestResult>.Success(new ScopeRequestResult
            {
                Success = true,
                GrantedScopes = scopes,
                ConsentUrl = $"https://auth.{provider.ToString().ToLower()}.com/consent"
            });
        }

        /// <summary>
        /// 허용된 스코프 조회
        /// </summary>
        public async Task<ServiceResult<List<string>>> GetGrantedScopesAsync(
            Guid connectedId,
            SocialProvider provider)
        {
            var linkData = await GetLinkedAccountAsync(connectedId, provider);
            return ServiceResult<List<string>>.Success(linkData?.GrantedScopes ?? new List<string>());
        }

        #endregion

        #region Social Features (Minimal Implementation)

        /// <summary>
        /// 친구 목록 - 최소 구현
        /// </summary>
        public async Task<ServiceResult<SocialFriendsList>> GetSocialFriendsAsync(
            Guid connectedId,
            SocialProvider provider,
            FriendsQueryOptions? options = null)
        {
            await Task.CompletedTask;
            return ServiceResult<SocialFriendsList>.Success(new SocialFriendsList());
        }

        /// <summary>
        /// 소셜 공유 - 최소 구현
        /// </summary>
        public async Task<ServiceResult<ShareResult>> ShareToSocialAsync(
            Guid connectedId,
            SocialProvider provider,
            ShareContent content)
        {
            await Task.CompletedTask;
            return ServiceResult<ShareResult>.Success(new ShareResult { Success = true });
        }

        #endregion

        #region Additional Providers (Stub Implementations)

        public Task<ServiceResult<SocialAuthResult>> LoginWithLineAsync(string accessToken, LineAuthOptions? options = null)
            => AuthenticateAsync(SocialProvider.Line, new SocialAuthRequest { Token = accessToken });

        public Task<ServiceResult<SocialAuthResult>> LoginWithGitHubAsync(string accessToken, GitHubAuthOptions? options = null)
            => AuthenticateAsync(SocialProvider.GitHub, new SocialAuthRequest { Token = accessToken });

        public Task<ServiceResult<SocialAuthResult>> LoginWithGitLabAsync(string accessToken, GitLabAuthOptions? options = null)
            => AuthenticateAsync(SocialProvider.GitLab, new SocialAuthRequest { Token = accessToken });

        public Task<ServiceResult<SocialAuthResult>> LoginWithLinkedInAsync(string accessToken, LinkedInAuthOptions? options = null)
            => AuthenticateAsync(SocialProvider.LinkedIn, new SocialAuthRequest { Token = accessToken });

        #endregion

        #region Helper Methods

        private async Task<SocialProfile?> ValidateDynamicTokenAsync(SocialProvider provider, string token)
        {
            try
            {
                // 캐시 확인
                var cacheKey = GetCacheKey($"validate:{provider}:{token.GetHashCode()}");
                var cached = await _cacheService.GetAsync<SocialProfile>(cacheKey);
                if (cached != null) return cached;

                // 프로바이더별 엔드포인트 (동적 설정 가능)
                var endpoint = provider switch
                {
                    SocialProvider.Google => "https://oauth2.googleapis.com/tokeninfo",
                    SocialProvider.Kakao => "https://kapi.kakao.com/v2/user/me",
                    SocialProvider.Naver => "https://openapi.naver.com/v1/nid/me",
                    _ => null
                };

                if (endpoint == null) return null;

                // API 호출 (동적 헤더/파라미터)
                var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode) return null;

                var json = await response.Content.ReadAsStringAsync();
                var data = JsonSerializer.Deserialize<Dictionary<string, object>>(json);

                // 동적 프로필 매핑
                var profile = new SocialProfile
                {
                    Email = data?.GetValueOrDefault("email")?.ToString(),
                    Name = data?.GetValueOrDefault("name")?.ToString(),
                    ProfilePictureUrl = data?.GetValueOrDefault("picture")?.ToString(),
                    CustomAttributes = data,
                    LastUpdated = _dateTimeProvider.UtcNow
                };

                // 캐싱
                await _cacheService.SetAsync(cacheKey, profile, TimeSpan.FromMinutes(PROFILE_CACHE_MINUTES));
                return profile;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation failed for {Provider}", provider);
                return null;
            }
        }

        private async Task<ServiceResult<SocialAuthResult>> GetOrCreateUserAsync(SocialProvider provider, SocialProfile profile)
        {
            // 사용자 조회/생성 로직
            var email = profile.Email ?? $"{Guid.NewGuid()}@social.local";
            var userResult = await _userService.GetByEmailAsync(email);

            Guid userId;
            bool isNewUser = false;

            if (!userResult.IsSuccess)
            {
                // 새 사용자 생성
                var createResult = await _userService.CreateAsync(new CreateUserRequest
                {
                    Email = email,
                    DisplayName = profile.DisplayName ?? profile.Name,
                    ExternalUserId = profile.CustomAttributes?["id"]?.ToString(),
                    ExternalSystemType = provider.ToString()
                });

                if (!createResult.IsSuccess)
                    return ServiceResult<SocialAuthResult>.Failure("User creation failed");

                userId = createResult.Data!.Id;
                isNewUser = true;
            }
            else
            {
                userId = userResult.Data!.Id;
            }

            return ServiceResult<SocialAuthResult>.Success(new SocialAuthResult
            {
                Success = true,
                IsNewUser = isNewUser,
                UserId = userId,
                ConnectedId = userId, // 간소화
                Provider = provider.ToString(),
                ProviderId = profile.CustomAttributes?["id"]?.ToString() ?? "",
                Profile = profile,
                AuthMethod = AuthenticationMethod.SocialLogin
            });
        }

        private async Task CacheTokensAsync(Guid connectedId, SocialProvider provider, string token)
        {
            var key = GetCacheKey($"token:{connectedId}:{provider}");
            await _cacheService.SetAsync(key, token, TimeSpan.FromMinutes(TOKEN_CACHE_MINUTES));
        }

        private async Task<LinkedSocialAccount?> GetLinkedAccountAsync(Guid connectedId, SocialProvider provider)
        {
            var linkKey = GetCacheKey($"link:{connectedId}:{provider}");
            return await _cacheService.GetAsync<LinkedSocialAccount>(linkKey);
        }

        private async Task<Dictionary<string, object>?> GetProviderConfigAsync(SocialProvider provider)
        {
            var key = GetCacheKey($"config:{provider}");
            return await _cacheService.GetAsync<Dictionary<string, object>>(key);
        }

        private Dictionary<string, string> SerializeOptions<T>(T options) where T : class
        {
            var json = JsonSerializer.Serialize(options);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
        }

        private string GetCacheKey(string suffix)
            => $"{CACHE_PREFIX}:{suffix}";

        #endregion

        #region IExternalService Implementation

        public async Task<ServiceHealthStatus> CheckHealthAsync()
        {
            var isHealthy = await IsHealthyAsync();
            return new ServiceHealthStatus
            {
                IsHealthy = isHealthy,
                ErrorMessage = isHealthy ? "Operational" : "Degraded",
                CheckedAt = _dateTimeProvider.UtcNow
            };
        }

        public Task<ServiceResult> TestConnectionAsync()
            => Task.FromResult(_httpClient != null ? ServiceResult.Success() : ServiceResult.Failure("HTTP client not available"));

        public Task<ServiceResult> ValidateConfigurationAsync()
            => Task.FromResult(ServiceResult.Success());

        public Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(DateTime startDate, DateTime endDate, Guid? organizationId = null)
            => Task.FromResult(ServiceResult<ExternalServiceUsage>.Success(new ExternalServiceUsage
            {
                ServiceName = ServiceName,
                PeriodStart = startDate,
                PeriodEnd = endDate
            }));

        public Task RecordMetricsAsync(ExternalServiceMetrics metrics)
        {
            _logger.LogDebug("Metrics: {ServiceName} - {Method}", metrics.ServiceName, metrics.Operation);
            return Task.CompletedTask;
        }

        #endregion
    }
}