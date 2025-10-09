using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.External;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Auth.Providers.OAuth.Factory;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Infra.Cache;
namespace AuthHive.Auth.Services.Providers
{
    /// <summary>
    /// 소셜 인증 제공자 구현 - AuthHive v15
    /// 여러 OAuth 제공자를 통합 관리하고 소셜 로그인 기능을 제공합니다.
    /// </summary>
    public class SocialAuthProvider : ISocialAuthProvider
    {
        private readonly IOAuthProviderFactory _providerFactory;
        private readonly IUserSocialAccountRepository _socialAccountRepository;
        private readonly IUserRepository _userRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly ICacheService _cacheService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SocialAuthProvider> _logger;

        // Provider 매핑
        private static readonly Dictionary<string, SocialProvider> ProviderMapping = new()
        {
            ["google"] = SocialProvider.Google,
            ["kakao"] = SocialProvider.Kakao,
            ["naver"] = SocialProvider.Naver,
            ["github"] = SocialProvider.GitHub,
            ["microsoft"] = SocialProvider.Microsoft,
            ["facebook"] = SocialProvider.Facebook,
            ["line"] = SocialProvider.Line,
            ["apple"] = SocialProvider.Apple,
            ["twitter"] = SocialProvider.Twitter,
            ["gitlab"] = SocialProvider.GitLab,
            ["linkedin"] = SocialProvider.LinkedIn
        };

        // 역매핑
        private static readonly Dictionary<SocialProvider, string> ReverseProviderMapping =
            ProviderMapping.ToDictionary(x => x.Value, x => x.Key);

        // State 캐시 키 접두사
        private const string STATE_CACHE_PREFIX = "oauth:state:";
        private const int STATE_EXPIRY_MINUTES = 10;

        public SocialAuthProvider(
            IOAuthProviderFactory providerFactory,
            IUserSocialAccountRepository socialAccountRepository,
            IUserRepository userRepository,
            IConnectedIdRepository connectedIdRepository,
            ICacheService cacheService,
            IConfiguration configuration,
            ILogger<SocialAuthProvider> logger)
        {
            _providerFactory = providerFactory;
            _socialAccountRepository = socialAccountRepository;
            _userRepository = userRepository;
            _connectedIdRepository = connectedIdRepository;
            _cacheService = cacheService;
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<ServiceResult<List<SocialProvider>>> GetSupportedProvidersAsync()
        {
            try
            {
                var availableProviders = _providerFactory.GetAvailableProviders();
                var supportedProviders = new List<SocialProvider>();

                foreach (var provider in availableProviders)
                {
                    if (ProviderMapping.TryGetValue(provider.ToLower(), out var socialProvider))
                    {
                        // 설정 확인
                        var oauthProvider = _providerFactory.GetProvider(provider);
                        var configResult = await oauthProvider.ValidateConfigurationAsync();

                        if (configResult.IsSuccess && configResult.Data)
                        {
                            supportedProviders.Add(socialProvider);
                        }
                    }
                }

                _logger.LogInformation("Found {Count} supported social providers", supportedProviders.Count);
                return ServiceResult<List<SocialProvider>>.Success(supportedProviders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get supported providers");
                return ServiceResult<List<SocialProvider>>.Failure("Failed to get supported providers", "PROVIDER_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<string>> GetLoginUrlAsync(
            string provider,
            string redirectUri,
            string? state = null)
        {
            try
            {
                // OAuth Provider 가져오기
                var oauthProvider = _providerFactory.GetProvider(provider.ToLower());

                // State 생성 (CSRF 방지)
                var stateValue = state ?? Guid.NewGuid().ToString("N");

                // State를 캐시에 저장
                var stateData = new Dictionary<string, string>
                {
                    ["provider"] = provider,
                    ["redirect_uri"] = redirectUri,
                    ["created_at"] = DateTime.UtcNow.ToString("O")
                };

                await _cacheService.SetAsync(
                    $"{STATE_CACHE_PREFIX}{stateValue}",
                    System.Text.Json.JsonSerializer.Serialize(stateData),
                    TimeSpan.FromMinutes(STATE_EXPIRY_MINUTES));

                // Authorization URL 생성
                var urlResult = await oauthProvider.GetAuthorizationUrlAsync(redirectUri, stateValue);

                if (!urlResult.IsSuccess)
                {
                    return ServiceResult<string>.Failure(urlResult.ErrorMessage ?? "Failed to generate login URL", urlResult.ErrorCode);
                }

                _logger.LogInformation("Generated login URL for {Provider}", provider);
                return ServiceResult<string>.Success(urlResult.Data!);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate login URL for {Provider}", provider);
                return ServiceResult<string>.Failure("Failed to generate login URL", "URL_GENERATION_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<SocialAuthResult>> HandleCallbackAsync(
            string provider,
            string code,
            string? state = null,
            CancellationToken cancellationToken=default)
        {
            try
            {
                // State 검증 (CSRF 방지)
                if (!string.IsNullOrEmpty(state))
                {
                    var stateKey = $"{STATE_CACHE_PREFIX}{state}";
                    var cachedStateJson = await _cacheService.GetAsync<string>(stateKey);

                    if (string.IsNullOrEmpty(cachedStateJson))
                    {
                        return ServiceResult<SocialAuthResult>.Failure("Invalid or expired state", "INVALID_STATE");
                    }

                    // State 캐시에서 제거 (일회용)
                    await _cacheService.RemoveAsync(stateKey);
                }

                // OAuth Provider 가져오기
                var oauthProvider = _providerFactory.GetProvider(provider.ToLower());

                // Code를 Token으로 교환
                var redirectUri = _configuration[$"OAuth:{provider}:RedirectUri"] ?? "";
                var tokenResult = await oauthProvider.ExchangeCodeForTokenAsync(code, redirectUri);

                if (!tokenResult.IsSuccess)
                {
                    return ServiceResult<SocialAuthResult>.Failure(
                        tokenResult.ErrorMessage ?? "Failed to exchange code for token",
                        tokenResult.ErrorCode);
                }

                var tokens = tokenResult.Data!;

                // 사용자 정보 조회
                var userInfoResult = await oauthProvider.GetUserInfoAsync(tokens.AccessToken);

                if (!userInfoResult.IsSuccess)
                {
                    return ServiceResult<SocialAuthResult>.Failure(
                        userInfoResult.ErrorMessage ?? "Failed to get user info",
                        userInfoResult.ErrorCode);
                }

                var userInfo = userInfoResult.Data!;

                // 소셜 계정 조회 또는 생성
                var socialAccount = await _socialAccountRepository.GetByProviderIdAsync(
                    GetSocialProvider(provider),
                    userInfo.Id);

                bool isNewUser = socialAccount == null;
                Guid userId;
                Guid connectedId;

                if (isNewUser)
                {
                    // 새 사용자 생성
                    var createUserResult = await CreateUserFromSocialProfile(provider, userInfo);
                    if (!createUserResult.IsSuccess)
                    {
                        return ServiceResult<SocialAuthResult>.Failure(
                            createUserResult.ErrorMessage ?? "Failed to create user",
                            createUserResult.ErrorCode);
                    }

                    var newUser = createUserResult.Data!;
                    userId = newUser.Id;

                    // ConnectedId 조회 (User의 ConnectedIds 컬렉션에서 첫 번째)
                    var userConnectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                    connectedId = userConnectedIds.FirstOrDefault()?.Id ?? Guid.Empty;
                    
                    var fullName = $"{userInfo.FirstName} {userInfo.LastName}".Trim();

                    // 소셜 계정 정보 저장
                    var newSocialAccount = new UserSocialAccount
                    {
                        Id = Guid.NewGuid(),
                        UserId = userId,
                        Provider = GetSocialProvider(provider),
                        ProviderId = userInfo.Id,
                        Email = userInfo.Email,
                        DisplayName = fullName,
                        ProfilePictureUrl = userInfo.Picture,
                        AccessToken = tokens.AccessToken,
                        RefreshToken = tokens.RefreshToken,
                        TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn),
                        LinkedAt = DateTime.UtcNow,
                        IsActive = true,
                        Metadata = System.Text.Json.JsonSerializer.Serialize(userInfo.RawData)
                    };

                    await _socialAccountRepository.AddAsync(newSocialAccount);
                }
                else
                {
                    // socialAccount가 null이 아님을 보장
                    if (socialAccount == null)
                    {
                        return ServiceResult<SocialAuthResult>.Failure(
                            "Social account not found",
                            "ACCOUNT_NOT_FOUND");
                    }

                    // 기존 사용자
                    var user = await _userRepository.GetByIdAsync(socialAccount.UserId);
                    if (user == null)
                    {
                        return ServiceResult<SocialAuthResult>.Failure("User not found", "USER_NOT_FOUND");
                    }

                    userId = user.Id;

                    // ConnectedId 조회
                    var userConnectedIds = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                    connectedId = userConnectedIds.FirstOrDefault()?.Id ?? Guid.Empty;

                    // 토큰 업데이트
                    socialAccount.AccessToken = tokens.AccessToken;
                    socialAccount.RefreshToken = tokens.RefreshToken;
                    socialAccount.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn);
                    socialAccount.LastUsedAt = DateTime.UtcNow;

                    await _socialAccountRepository.UpdateAsync(socialAccount);

                    // 마지막 로그인 정보 업데이트
                    user.LastLoginAt = DateTime.UtcNow;
                    user.LoginCount = (user.LoginCount ?? 0) + 1;
                    if (user.FirstLoginAt == null)
                    {
                        user.FirstLoginAt = DateTime.UtcNow;
                    }
                    await _userRepository.UpdateAsync(user);
                }
                
                var profileFullName = $"{userInfo.FirstName} {userInfo.LastName}".Trim();

                // 결과 생성
                var authResult = new SocialAuthResult
                {
                    Success = true,
                    IsNewUser = isNewUser,
                    UserId = userId,
                    ConnectedId = connectedId,
                    Provider = provider,
                    ProviderId = userInfo.Id,
                    Profile = new SocialProfile
                    {
                        Email = userInfo.Email,
                        EmailVerified = userInfo.EmailVerified,
                        Name = profileFullName,
                        DisplayName = profileFullName,
                        ProfilePictureUrl = userInfo.Picture,
                        LastUpdated = DateTime.UtcNow
                    },
                    Tokens = new SocialTokens
                    {
                        AccessToken = tokens.AccessToken,
                        RefreshToken = tokens.RefreshToken,
                        ExpiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn),
                        Scopes = tokens.Scopes
                    },
                    AuthMethod = AuthenticationMethod.SocialLogin
                };

                _logger.LogInformation(
                    "Social authentication successful for {Provider}, User: {UserId}, New: {IsNew}",
                    provider, userId, isNewUser);

                return ServiceResult<SocialAuthResult>.Success(authResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle callback for {Provider}", provider);
                return ServiceResult<SocialAuthResult>.Failure("Authentication failed", "AUTH_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> LinkSocialAccountAsync(
            Guid userId,
            string provider,
            string providerUserId)
        {
            try
            {
                // 사용자 존재 확인
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found");
                }

                // 기존 연결 확인
                var existingAccount = await _socialAccountRepository.GetByProviderIdAsync(
                    GetSocialProvider(provider),
                    providerUserId);

                if (existingAccount != null)
                {
                    if (existingAccount.UserId == userId)
                    {
                        return ServiceResult.Success("Account already linked");
                    }

                    return ServiceResult.Failure("This social account is already linked to another user", "ALREADY_LINKED");
                }

                // 새 연결 생성
                var socialAccount = new UserSocialAccount
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    Provider = GetSocialProvider(provider),
                    ProviderId = providerUserId,
                    LinkedAt = DateTime.UtcNow,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                await _socialAccountRepository.AddAsync(socialAccount);

                _logger.LogInformation(
                    "Linked {Provider} account {ProviderId} to user {UserId}",
                    provider, providerUserId, userId);

                return ServiceResult.Success("Social account linked successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to link social account");
                return ServiceResult.Failure("Failed to link social account", "LINK_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> UnlinkSocialAccountAsync(
            Guid userId,
            string provider)
        {
            try
            {
                var socialProvider = GetSocialProvider(provider);
                var socialAccounts = await _socialAccountRepository.GetByUserIdAsync(userId);
                var accountToUnlink = socialAccounts.FirstOrDefault(a => a.Provider == socialProvider);

                if (accountToUnlink == null)
                {
                    return ServiceResult.NotFound("Social account not found");
                }

                // 최소 하나의 로그인 방법 확인
                if (socialAccounts.Count == 1)
                {
                    var user = await _userRepository.GetByIdAsync(userId);
                    if (user != null && string.IsNullOrEmpty(user.PasswordHash))
                    {
                        return ServiceResult.Failure(
                            "Cannot unlink the only login method. Please set a password first.",
                            "LAST_LOGIN_METHOD");
                    }
                }

                // Token 취소 (가능한 경우)
                if (!string.IsNullOrEmpty(accountToUnlink.AccessToken))
                {
                    try
                    {
                        var oauthProvider = _providerFactory.GetProvider(provider.ToLower());
                        await oauthProvider.RevokeTokenAsync(accountToUnlink.AccessToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to revoke token for {Provider}", provider);
                    }
                }

                // 연결 삭제
                await _socialAccountRepository.DeleteAsync(accountToUnlink);

                _logger.LogInformation(
                    "Unlinked {Provider} account from user {UserId}",
                    provider, userId);

                return ServiceResult.Success("Social account unlinked successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unlink social account");
                return ServiceResult.Failure("Failed to unlink social account", "UNLINK_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<List<LinkedSocialAccount>>> GetLinkedAccountsAsync(Guid userId)
        {
            try
            {
                var socialAccounts = await _socialAccountRepository.GetByUserIdAsync(userId);

                var linkedAccounts = socialAccounts.Select(a => new LinkedSocialAccount
                {
                    Provider = a.Provider,
                    ProviderId = a.ProviderId,
                    Email = a.Email,
                    DisplayName = a.DisplayName,
                    ProfilePictureUrl = a.ProfilePictureUrl,
                    LinkedAt = a.LinkedAt,
                    LastUsedAt = a.LastUsedAt,
                    GrantedScopes = ParseScopes(a.Scopes),
                    IsActive = a.IsActive
                }).ToList();

                _logger.LogInformation("Found {Count} linked accounts for user {UserId}", linkedAccounts.Count, userId);

                return ServiceResult<List<LinkedSocialAccount>>.Success(linkedAccounts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get linked accounts");
                return ServiceResult<List<LinkedSocialAccount>>.Failure("Failed to get linked accounts", "QUERY_ERROR");
            }
        }

        #region Private Helper Methods

        private SocialProvider GetSocialProvider(string provider)
        {
            if (ProviderMapping.TryGetValue(provider.ToLower(), out var socialProvider))
            {
                return socialProvider;
            }

            throw new ArgumentException($"Unknown provider: {provider}");
        }

        private string GetProviderName(SocialProvider provider)
        {
            if (ReverseProviderMapping.TryGetValue(provider, out var providerName))
            {
                return providerName;
            }

            throw new ArgumentException($"Unknown provider: {provider}");
        }

        private async Task<ServiceResult<UserEntity>> CreateUserFromSocialProfile(
            string provider,
            OAuthUserInfo userInfo)
        {
            try
            {
                // Email 기반으로 기존 사용자 확인
                UserEntity? existingUser = null;
                if (!string.IsNullOrEmpty(userInfo.Email))
                {
                    existingUser = await _userRepository.GetByEmailAsync(userInfo.Email);
                }

                if (existingUser != null)
                {
                    // 기존 사용자에 소셜 계정 연결
                    return ServiceResult<UserEntity>.Success(existingUser);
                }
                
                var fullName = $"{userInfo.FirstName} {userInfo.LastName}".Trim();

                // 새 사용자 생성
                var newUser = new UserEntity
                {
                    Id = Guid.NewGuid(),
                    Email = userInfo.Email ?? $"{userInfo.Id}@{provider.ToLower()}.local",
                    Username = GenerateUsername(userInfo, provider),
                    DisplayName = fullName,
                    IsEmailVerified = userInfo.EmailVerified,
                    EmailVerified = userInfo.EmailVerified,
                    EmailVerifiedAt = userInfo.EmailVerified ? DateTime.UtcNow : null,
                    Status = Core.Enums.Core.UserEnums.UserStatus.Active,
                    IsTwoFactorEnabled = false,
                    TwoFactorEnabled = false,
                    IsAccountLocked = false,
                    RequiresPasswordChange = false,
                    FirstLoginAt = DateTime.UtcNow,
                    LastLoginAt = DateTime.UtcNow,
                    LoginCount = 1,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                // User 저장
                await _userRepository.AddAsync(newUser);

                // ConnectedId 생성
                var connectedId = new ConnectedId
                {
                    Id = Guid.NewGuid(),
                    UserId = newUser.Id,
                    OrganizationId = newUser.OrganizationId ?? Guid.Empty,
                    Provider = provider.ToLower(), // required 속성
                    ProviderUserId = userInfo.Id,
                    Status = ConnectedIdEnums.ConnectedIdStatus.Active,
                    MembershipType = ConnectedIdEnums.MembershipType.Member,
                    JoinedAt = DateTime.UtcNow,
                    LastActiveAt = DateTime.UtcNow,
                    // IsActive = true, // 제거 - read-only 속성
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                await _connectedIdRepository.AddAsync(connectedId);

                // 프로필 생성 (선택적)
                if (!string.IsNullOrEmpty(userInfo.Picture))
                {
                    var profile = new UserProfile
                    {
                        Id = Guid.NewGuid(),
                        UserId = newUser.Id,
                        ProfileImageUrl = userInfo.Picture,
                        TimeZone = "UTC",
                        PreferredLanguage = "en",
                        PreferredCurrency = "USD",
                        IsPublic = false,
                        EmailNotificationsEnabled = true,
                        SmsNotificationsEnabled = false,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    // UserProfileRepository를 통해 저장 (구현 필요)
                }

                _logger.LogInformation(
                    "Created new user {UserId} from {Provider} profile {ProviderId}",
                    newUser.Id, provider, userInfo.Id);

                return ServiceResult<UserEntity>.Success(newUser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create user from social profile");
                return ServiceResult<UserEntity>.Failure("Failed to create user", "USER_CREATE_ERROR");
            }
        }

        private string GenerateUsername(OAuthUserInfo userInfo, string provider)
        {
            if (!string.IsNullOrEmpty(userInfo.Email))
            {
                var emailPrefix = userInfo.Email.Split('@')[0];
                // 특수문자 제거 및 소문자 변환
                return System.Text.RegularExpressions.Regex.Replace(emailPrefix, @"[^a-zA-Z0-9]", "").ToLower();
            }

            var fullName = $"{userInfo.FirstName} {userInfo.LastName}".Trim();
            if (!string.IsNullOrEmpty(fullName))
            {
                return fullName.Replace(" ", ".").ToLower();
            }

            return $"{provider.ToLower()}.{userInfo.Id}";
        }

        private List<string> ParseScopes(string? scopesString)
        {
            if (string.IsNullOrEmpty(scopesString))
                return new List<string>();

            return scopesString.Split(' ', ',').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        }

        #endregion
    }
}