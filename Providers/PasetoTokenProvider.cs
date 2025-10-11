using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Configuration;
using System.Text;
using Paseto;
using Paseto.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// ITokenProvider의 PASETO v4.local 구현체입니다.
    /// appsettings.json의 Paseto 섹션에서 설정을 읽어 토큰을 생성하고 검증합니다.
    /// </summary>
    public class PasetoTokenProvider : ITokenProvider
    {
        // ⚠️ 변경: PasetoSymmetricKey 대신 원시 키 바이트 배열을 저장합니다.
        private readonly byte[] _keyBytes; 
        private readonly string _issuer;
        private readonly string _audience;
        private readonly TimeSpan _accessTokenLifetime;

        public PasetoTokenProvider(IConfiguration configuration)
        {
            var keyString = configuration["Paseto:Key"] ?? throw new ArgumentNullException("Paseto:Key", "PASETO Key is not configured.");
            _issuer = configuration["Paseto:Issuer"] ?? throw new ArgumentNullException("Paseto:Issuer", "PASETO Issuer is not configured.");
            _audience = configuration["Paseto:Audience"] ?? throw new ArgumentNullException("Paseto:Audience", "PASETO Audience is not configured.");

            var keyBytes = Convert.FromBase64String(keyString);
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("PASETO key must be 32 bytes (256 bits) for v4 protocol.", "Paseto:Key");
            }

            // ⚠️ 수정: 키 객체 대신 바이트 배열을 저장합니다.
            _keyBytes = keyBytes; 
            
            // ⚠️ 원시 키 객체 생성 로직 제거: _pasetoKey = new PasetoSymmetricKey(keyBytes, new Version4());

            _accessTokenLifetime = TimeSpan.FromHours(configuration.GetValue<double>("Paseto:ExpiryInHours", 24));
        }

        /// <inheritdoc />
        public Task<ServiceResult<TokenInfo>> GenerateAccessTokenAsync(Guid userId, Guid connectedId, IEnumerable<Claim>? additionalClaims = null)
        {
            try
            {
                var issuedAt = DateTime.UtcNow;
                var expiresAt = issuedAt.Add(_accessTokenLifetime);

                var builder = new PasetoBuilder()
                    // ⚠️ 수정: UseV4(Purpose.Local) 사용 (PasetoBuilder에 존재하는 Fluent API)
                    .UseV4(Paseto.Purpose.Local)
                    // ⚠️ 수정: WithKey(_pasetoKey) 대신 WithSharedKey(_keyBytes) 사용
                    .WithSharedKey(_keyBytes) 
                    .Issuer(_issuer)
                    .Audience(_audience)
                    .Expiration(expiresAt)
                    .IssuedAt(issuedAt)
                    // Core claims that are essential for the system
                    .Subject(userId.ToString()) // 'sub' is the standard claim for user identifier
                    .AddClaim(ClaimTypes.NameIdentifier, userId.ToString())
                    .AddClaim("connected_id", connectedId.ToString());

                // Add any extra claims if they are provided
                if (additionalClaims != null)
                {
                    foreach (var claim in additionalClaims)
                    {
                        // Ensure we don't overwrite the essential claims
                        if (claim.Type != "sub" && claim.Type != ClaimTypes.NameIdentifier && claim.Type != "connected_id")
                        {
                            builder.AddClaim(claim.Type, claim.Value);
                        }
                    }
                }

                var token = builder.Encode();

                var tokenInfo = new TokenInfo 
                { 
                    AccessToken = token, 
                    ExpiresAt = expiresAt,
                    IssuedAt = issuedAt,
                    ExpiresIn = (int)_accessTokenLifetime.TotalSeconds
                };
                return Task.FromResult(ServiceResult<TokenInfo>.Success(tokenInfo));
            }
            catch (Exception ex)
            {
                // In a real application, you should log this exception.
                return Task.FromResult(ServiceResult<TokenInfo>.Failure($"Token generation failed: {ex.Message}"));
            }
        }

        /// <inheritdoc />
        public Task<ServiceResult<ClaimsPrincipal>> ValidateAccessTokenAsync(string accessToken)
        {
            try
            {
                var validationResult = new PasetoBuilder()
                    // ⚠️ 수정: UseV4(Purpose.Local) 사용 (PasetoBuilder에 존재하는 Fluent API)
                    .UseV4(Paseto.Purpose.Local)
                    // ⚠️ 수정: WithKey(_pasetoKey) 대신 WithSharedKey(_keyBytes) 사용
                    .WithSharedKey(_keyBytes) 
                    .Audience(_audience)
                    .Issuer(_issuer)
                    .Decode(accessToken);

                // Convert the Paseto payload dictionary to a standard .NET Claims list.
                var pasetoClaims = validationResult.Paseto.Payload
                    .Select(p => new Claim(p.Key, p.Value?.ToString() ?? string.Empty))
                    .ToList();
                
                // Ensure the subject claim is correctly mapped to NameIdentifier if not present
                if (!pasetoClaims.Any(c => c.Type == ClaimTypes.NameIdentifier) && validationResult.Paseto.Payload.ContainsKey("sub"))
                {
                    pasetoClaims.Add(new Claim(ClaimTypes.NameIdentifier, validationResult.Paseto.Payload["sub"]?.ToString() ?? string.Empty));
                }

                var identity = new ClaimsIdentity(pasetoClaims, "PASETO");
                var principal = new ClaimsPrincipal(identity);

                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Success(principal));
            }
            catch (Exception ex)
            {
                // In a real application, you should log this exception.
                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Failure($"Token validation failed: {ex.Message}"));
            }
        }

        /// <inheritdoc />
        public Task<ServiceResult<string>> GenerateRefreshTokenAsync(Guid userId)
        {
            // A refresh token should be a cryptographically secure random string.
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            var refreshToken = Convert.ToBase64String(randomNumber);
            
            return Task.FromResult(ServiceResult<string>.Success(refreshToken));
        }
    }
}