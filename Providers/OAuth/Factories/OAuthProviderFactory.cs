
using AuthHive.Auth.Providers.OAuth.Factory;
using AuthHive.Core.Interfaces.Auth.Provider;

namespace AuthHive.Auth.Providers.OAuth.Factory;
public class OAuthProviderFactory : IOAuthProviderFactory
{
    private readonly Dictionary<string, IOAuthProvider> _providers;
    private readonly ILogger<OAuthProviderFactory> _logger;

    public OAuthProviderFactory(
        IServiceProvider serviceProvider,
        IConfiguration configuration,
        ILogger<OAuthProviderFactory> logger)
    {
        _logger = logger;
        _providers = new Dictionary<string, IOAuthProvider>(StringComparer.OrdinalIgnoreCase);

        // 설정에서 활성화된 제공자만 등록
        var oauthConfig = configuration.GetSection("OAuth");

        if (oauthConfig.GetSection("Google").Exists())
        {
            _providers["google"] = serviceProvider.GetRequiredService<GoogleOAuthProvider>();
        }

        if (oauthConfig.GetSection("Kakao").Exists())
        {
            _providers["kakao"] = serviceProvider.GetRequiredService<AuthHive.Auth.Providers.OAuth.KakaoOAuthProvider>();
        }

        // 필요한 다른 제공자들도 추가

        _logger.LogInformation("Registered {Count} OAuth providers", _providers.Count);
    }

    public IOAuthProvider GetProvider(string providerName)
    {
        if (_providers.TryGetValue(providerName, out var provider))
        {
            return provider;
        }

        throw new NotSupportedException($"OAuth provider '{providerName}' is not supported");
    }

    public IEnumerable<string> GetAvailableProviders()
    {
        return _providers.Keys;
    }
}