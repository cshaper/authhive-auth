// // Path: AuthHive.Auth/Factories/PasswordHashProviderFactory.cs
// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.Infra.Security;
// using AuthHive.Core.Interfaces.Security;

// namespace AuthHive.Auth.Providers.OAuth.Factories
// {
//     public class PasswordHashProviderFactory : IPasswordHashProviderFactory
//     {
//         private readonly IEnumerable<IPasswordHashProvider> _providers;
//         private readonly IAccountSecurityService _accountSecurityService;

//         public PasswordHashProviderFactory(
//             IEnumerable<IPasswordHashProvider> providers, 
//             IAccountSecurityService accountSecurityService)
//         {
//             _providers = providers;
//             _accountSecurityService = accountSecurityService;
//         }

//         public async Task<IPasswordHashProvider> GetProviderAsync(Guid? organizationId, CancellationToken cancellationToken = default)
//         {
//             string desiredAlgorithm = "argon2id"; // ✨ 시스템 기본값은 Argon2

//             if (organizationId.HasValue)
//             {
//                 // 조직의 보안 설정을 조회하여 어떤 알고리즘을 사용할지 결정합니다.
//                 // 예: AccountSecuritySettings에 'PasswordHashAlgorithm' 속성이 있다고 가정
//                 var settingsResult = await _accountSecurityService.GetSecuritySettingsAsync(organizationId.Value, cancellationToken);
//                 if (settingsResult.IsSuccess && !string.IsNullOrEmpty(settingsResult.Data?.PasswordHashAlgorithm))
//                 {
//                     desiredAlgorithm = settingsResult.Data.PasswordHashAlgorithm;
//                 }
//             }

//             // 등록된 모든 Provider 중에서 원하는 알고리즘 이름을 가진 것을 찾습니다.
//             var provider = _providers.FirstOrDefault(p => 
//                 p.AlgorithmName.Equals(desiredAlgorithm, StringComparison.OrdinalIgnoreCase));

//             // 만약 설정된 Provider가 없다면, 기본 Provider(Argon2)를 반환합니다.
//             return provider ?? _providers.First(p => p.AlgorithmName.Equals("argon2id", StringComparison.OrdinalIgnoreCase));
//         }
//     }
// }
