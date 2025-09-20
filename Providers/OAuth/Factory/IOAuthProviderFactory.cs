using AuthHive.Core.Interfaces.Auth.Provider;
namespace AuthHive.Auth.Providers.OAuth.Factory;
public interface IOAuthProviderFactory
{
    IOAuthProvider GetProvider(string providerName);
    IEnumerable<string> GetAvailableProviders();
}