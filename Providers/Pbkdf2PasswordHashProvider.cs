using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Constants.Auth; 

namespace AuthHive.Core.Providers.Security // (네임스페이스가 Core.Providers.Security로 되어있으나, auth.auth/Providers로 가정)
{
    /// <summary>
    /// [v17 수정] IPasswordHashProvider의 PBKDF2 구현체입니다.
    /// v17 인터페이스(AlgorithmName)를 구현하도록 수정되었습니다.
    /// </summary>
    public class Pbkdf2PasswordHashProvider : IPasswordHashProvider
    {
        private const int SaltSize = 16; // 128 bit
        private const int KeySize = 32; // 256 bit
        private const int Iterations = 10000;
        private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private const char Delimiter = ';';

        /// <summary>
        /// [v17 수정] CS0535 오류 해결: IPasswordHashProvider.AlgorithmName 구현
        /// </summary>
        public string AlgorithmName => AuthConstants.PasswordHashingAlgorithms.Pbkdf2;

        /// <summary>
        /// Hashes a password using PBKDF2 (RFC 2898).
        /// </summary>
        public Task<string> HashPasswordAsync(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, _hashAlgorithm, KeySize);

            var result = string.Join(Delimiter, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
            
            return Task.FromResult(result);
        }

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash.
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
                return Task.FromResult(false);
            }
        }
    }
}