using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Configuration;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Paseto.Protocol;
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
        private readonly PasetoSymmetricKey _pasetoKey;
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

            _pasetoKey = new PasetoSymmetricKey(keyBytes, new Version4());
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
                    .UseV4(Purpose.Local)
                    .WithKey(_pasetoKey)
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
                    .UseV4(Purpose.Local)
                    .WithKey(_pasetoKey)
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

