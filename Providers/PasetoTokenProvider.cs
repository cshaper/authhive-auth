using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Configuration;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Linq;
using Paseto.Protocol;

namespace AuthHive.Auth.Providers
{
    public class PasetoTokenProvider : ITokenProvider
    {
        private readonly PasetoKey _pasetoKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly TimeSpan _accessTokenLifetime;

        public PasetoTokenProvider(IConfiguration configuration)
        {
            var keyString = configuration["Paseto:Key"];
            if (string.IsNullOrEmpty(keyString)) throw new ArgumentNullException(nameof(keyString), "PASETO Key is not configured.");

            _issuer = configuration["Paseto:Issuer"] ?? throw new ArgumentNullException("PASETO Issuer is not configured.");
            _audience = configuration["Paseto:Audience"] ?? throw new ArgumentNullException("PASETO Audience is not configured.");

            var keyBytes = Convert.FromBase64String(keyString);
            if (keyBytes.Length != 32) throw new ArgumentException("PASETO v4 key must be 32 bytes long.");

            // For Paseto.Core v1.0.7, create symmetric key with protocol version
            _pasetoKey = new PasetoSymmetricKey(keyBytes, new Version4());

            _accessTokenLifetime = TimeSpan.FromHours(configuration.GetValue<double>("Paseto:ExpiryInHours", 24));
        }

        public Task<ServiceResult<TokenInfo>> GenerateAccessTokenAsync(Guid userId, Guid? connectedId, Dictionary<string, object>? claims)
        {
            var expiresAt = DateTime.UtcNow.Add(_accessTokenLifetime);

            var builder = new PasetoBuilder()
                .UseV4(Purpose.Local)
                .WithKey(_pasetoKey)
                .Issuer(_issuer)
                .Audience(_audience)
                .Subject(userId.ToString())
                .Expiration(expiresAt)
                .IssuedAt(DateTime.UtcNow)
                .AddClaim("connected_id", connectedId?.ToString() ?? string.Empty);

            if (claims != null)
            {
                foreach (var claim in claims)
                {
                    builder.AddClaim(claim.Key, claim.Value);
                }
            }

            var token = builder.Encode();

            var result = new TokenInfo { AccessToken = token, ExpiresAt = expiresAt };
            return Task.FromResult(ServiceResult<TokenInfo>.Success(result));
        }

        public Task<ServiceResult<ClaimsPrincipal>> ValidateTokenAsync(string token)
        {
            try
            {
                var validationResult = new PasetoBuilder()
                    .UseV4(Purpose.Local)
                    .WithKey(_pasetoKey)
                    .Audience(_audience)
                    .Issuer(_issuer)
                    .Decode(token);

                // PasetoToken in v1.0.7 uses Payload property which is a dictionary
                var pasetoClaims = validationResult.Paseto.Payload.Select(p => new Claim(p.Key, p.Value?.ToString() ?? string.Empty));
                var identity = new ClaimsIdentity(pasetoClaims, "PASETO");
                var principal = new ClaimsPrincipal(identity);

                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Success(principal));
            }
            catch (Exception ex)
            {
                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Failure($"Token validation failed: {ex.Message}"));
            }
        }

        public Task<ServiceResult<string>> GenerateRefreshTokenAsync(Guid userId)
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Task.FromResult(ServiceResult<string>.Success(Convert.ToBase64String(randomNumber)));
        }

        public Task<ServiceResult<Dictionary<string, object>>> GetClaimsAsync(string token)
        {
            try
            {
                var validationResult = new PasetoBuilder()
                    .UseV4(Purpose.Local)
                    .WithKey(_pasetoKey)
                    .Decode(token);

                // Use Payload property for v1.0.7
                var claimsDictionary = validationResult.Paseto.Payload.ToDictionary(k => k.Key, v => v.Value ?? new object());
                return Task.FromResult(ServiceResult<Dictionary<string, object>>.Success(claimsDictionary));
            }
            catch (Exception ex)
            {
                return Task.FromResult(ServiceResult<Dictionary<string, object>>.Failure($"Failed to get claims: {ex.Message}"));
            }
        }

        public Task<ServiceResult<DateTime?>> GetExpirationAsync(string token)
        {
            try
            {
                var validationResult = new PasetoBuilder()
                    .UseV4(Purpose.Local)
                    .WithKey(_pasetoKey)
                    .Decode(token);

                // For v1.0.7, check for "exp" claim in Payload
                if (validationResult.Paseto.Payload.TryGetValue("exp", out var expValue))
                {
                    if (expValue is DateTime expDateTime)
                    {
                        return Task.FromResult(ServiceResult<DateTime?>.Success(expDateTime));
                    }
                    else if (DateTime.TryParse(expValue?.ToString(), out var parsedDate))
                    {
                        return Task.FromResult(ServiceResult<DateTime?>.Success(parsedDate));
                    }
                }

                return Task.FromResult(ServiceResult<DateTime?>.Success(null));
            }
            catch (Exception ex)
            {
                return Task.FromResult(ServiceResult<DateTime?>.Failure($"Failed to get expiration: {ex.Message}"));
            }
        }

        public Task<ServiceResult<TokenInfo>> RefreshTokenAsync(string refreshToken)
        {
            throw new NotImplementedException("RefreshTokenAsync logic belongs in a stateful service, not the stateless token provider.");
        }

        public Task<ServiceResult> RevokeTokenAsync(string token)
        {
            throw new NotImplementedException("RevokeTokenAsync logic belongs in a stateful service, not the stateless token provider.");
        }
            #region 새로 추가해야 할 메서드들

    public async Task<ServiceResult<TokenInfo>> GenerateAccessTokenAsync(Guid userId, Guid connectedId, Dictionary<string, object>? claims = null)
    {
        // 기존 GenerateAccessTokenAsync(userId, connectedId?, claims) 메서드의 로직을 여기로 이동
        // connectedId가 이제 필수 파라미터가 되었음
        return await GenerateAccessTokenAsync(userId, (Guid?)connectedId, claims);
    }

    public async Task<ServiceResult<ClaimsPrincipal>> ValidateAccessTokenAsync(string accessToken)
    {
        // 기존 ValidateTokenAsync의 로직을 여기로 복사
        return await ValidateTokenAsync(accessToken);
    }

    public async Task<ServiceResult<Dictionary<string, object>>> ExtractClaimsAsync(string accessToken)
    {
        // 기존 GetClaimsAsync의 로직을 여기로 복사
        return await GetClaimsAsync(accessToken);
    }

    public async Task<ServiceResult<DateTime?>> GetTokenExpirationAsync(string accessToken)
    {
        // 기존 GetExpirationAsync의 로직을 여기로 복사
        return await GetExpirationAsync(accessToken);
    }

    #endregion
    }
}