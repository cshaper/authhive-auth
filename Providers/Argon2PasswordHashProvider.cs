using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Security;
using Isopoh.Cryptography.Argon2;
using System.Threading.Tasks;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// Implements IPasswordHashProvider using the modern and secure Argon2id algorithm.
    /// This class is a self-contained provider with no external business logic dependencies.
    /// It relies on the 'Isopoh.Cryptography.Argon2' NuGet package.
    /// </summary>
    public class Argon2PasswordHashProvider : IPasswordHashProvider
    {

        public string AlgorithmName => AuthConstants.PasswordHashingAlgorithms.Argon2id;
        /// <summary>
        /// Hashes a password using the Argon2id algorithm.
        /// The configuration (time cost, memory cost, parallelism) is handled by the library's defaults,
        /// which are generally secure.
        /// </summary>
        /// <param name="password">The plain-text password to hash.</param>
        /// <returns>A Task that resolves to the Argon2 hash string.</returns>

        public Task<string> HashPasswordAsync(string password)
        {
            // Argon2.Hash는 CPU 집약적이므로 Task.Run으로 백그라운드 스레드에서 실행하는 것이 좋습니다.
            return Task.Run(() => Argon2.Hash(password));
        }
        /// <summary>
        /// Verifies a plain-text password against a stored Argon2 hash.
        /// </summary>
        /// <param name="password">The plain-text password to verify.</param>
        /// <param name="storedHash">The stored hash string to verify against.</param>
        /// <returns>A Task that resolves to true if the password is valid, otherwise false.</returns>
        public Task<bool> VerifyPasswordAsync(string password, string hash)
        {
            return Task.Run(() => Argon2.Verify(hash, password));
        }
    }
}

