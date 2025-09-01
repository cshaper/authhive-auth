using AuthHive.Core.Interfaces.Infra.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthHive.Auth.Services.Security
{
    /// <summary>
    /// Implements IEncryptionService using AES-256 (CBC with PKCS7 padding) for strong encryption.
    /// The encryption key and IV must be configured in appsettings.json.
    /// </summary>
    public class EncryptionService : IEncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;
        private readonly ILogger<EncryptionService> _logger;

        public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
        {
            _logger = logger;

            var keyBase64 = configuration["Encryption:Key"];
            var ivBase64 = configuration["Encryption:IV"];

            if (string.IsNullOrEmpty(keyBase64) || string.IsNullOrEmpty(ivBase64))
            {
                _logger.LogCritical("Encryption Key or IV is not configured in appsettings.json. Please provide a Base64 encoded 32-byte key and 16-byte IV under the 'Encryption' section.");
                throw new InvalidOperationException("Encryption keys are not configured. This is a fatal configuration error.");
            }

            try
            {
                _key = Convert.FromBase64String(keyBase64);
                _iv = Convert.FromBase64String(ivBase64);

                if (_key.Length != 32) throw new ArgumentException("The configured encryption key must be 32 bytes (256-bit).");
                if (_iv.Length != 16) throw new ArgumentException("The configured encryption IV must be 16 bytes (128-bit).");
            }
            catch (FormatException ex)
            {
                _logger.LogCritical(ex, "The configured Encryption Key or IV is not a valid Base64 string.");
                throw;
            }
        }

        public async Task<string> EncryptAsync(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            await using var memoryStream = new MemoryStream();
            await using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                await using (var streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8))
                {
                    await streamWriter.WriteAsync(plainText);
                }
            }

            return Convert.ToBase64String(memoryStream.ToArray());
        }

        public async Task<string> DecryptAsync(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;
            
            try
            {
                var buffer = Convert.FromBase64String(cipherText);

                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                await using var memoryStream = new MemoryStream(buffer);
                await using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                using var streamReader = new StreamReader(cryptoStream, Encoding.UTF8);

                return await streamReader.ReadToEndAsync();
            }
            catch (FormatException ex)
            {
                _logger.LogError(ex, "Failed to decrypt data. The input is not a valid Base64 string.");
                // For security, don't reveal details about the error to the caller.
                throw new CryptographicException("Invalid encrypted data format.");
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "Cryptographic error during decryption. This may indicate incorrect key/IV or corrupted data.");
                throw; // Re-throw the original exception
            }
        }
    }
}
