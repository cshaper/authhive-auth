using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Security;

namespace AuthHive.Core.Providers.Security
{
    /// <summary>
    /// Implements IPasswordHashProvider using the industry-standard PBKDF2 algorithm.
    /// This version correctly implements the async interface methods.
    /// </summary>
    public class Pbkdf2PasswordHashProvider : IPasswordHashProvider
    {
        private const int SaltSize = 16; // 128 bit
        private const int KeySize = 32; // 256 bit
        private const int Iterations = 10000;
        private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private const char Delimiter = ';';

        /// <summary>
        /// Hashes a password using PBKDF2 (RFC 2898).
        /// ✨ 수정된 부분: Task<string>을 반환합니다.
        /// </summary>
        public Task<string> HashPasswordAsync(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, _hashAlgorithm, KeySize);

            var result = string.Join(Delimiter, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
            
            // PBKDF2는 CPU-bound 작업이므로 Task.FromResult로 래핑하여 비동기 시그니처를 맞춥니다.
            return Task.FromResult(result);
        }

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash.
        /// ✨ 수정된 부분: Task<bool>을 반환하며 인터페이스를 올바르게 구현합니다.
        /// </summary>
        public Task<bool> VerifyPasswordAsync(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash))
            {
                return Task.FromResult(false);
            }

            var parts = storedHash.Split(Delimiter);
            if (parts.Length != 2)
            {
                // 잘못된 형식의 해시 문자열
                return Task.FromResult(false);
            }

            try
            {
                var salt = Convert.FromBase64String(parts[0]);
                var hash = Convert.FromBase64String(parts[1]);

                var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, _hashAlgorithm, KeySize);

                var areEqual = CryptographicOperations.FixedTimeEquals(hash, hashToCompare);
                return Task.FromResult(areEqual);
            }
            catch (FormatException)
            {
                // Base64 디코딩 실패 시
                return Task.FromResult(false);
            }
        }
    }
}

