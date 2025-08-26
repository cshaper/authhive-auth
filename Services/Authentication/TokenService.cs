using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Entities.Auth;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Paseto.Protocol;

namespace AuthHive.Auth.Services.Authentication
{
    public interface ITokenService
    {
        string GenerateToken(ConnectedId connectedId, Session session);
        Task<TokenValidationResult> ValidateToken(string token);
    }

    public class TokenService : ITokenService
    {
        private readonly PasetoSymmetricKey _pasetoKey;
        private readonly ILogger<TokenService> _logger;

        public TokenService(IConfiguration configuration, ILogger<TokenService> logger)
        {
            _logger = logger;
            var keyString = configuration["Paseto:Key"] ?? GenerateDefaultKey();
            var keyBytes = Convert.FromBase64String(keyString);

            if (keyBytes.Length != 32)
            {
                throw new InvalidOperationException("PASETO v4.local requires exactly a 32-byte key.");
            }
            
            // Version4 인스턴스 생성 후 PasetoSymmetricKey에 전달
            var protocolVersion = new Paseto.Protocol.Version4();
            _pasetoKey = new PasetoSymmetricKey(
                new ReadOnlyMemory<byte>(keyBytes), 
                protocolVersion
            );
        }

        public string GenerateToken(ConnectedId connectedId, Session session)
        {
            try
            {
                var token = new PasetoBuilder()
                    .Use(ProtocolVersion.V4, Purpose.Local)  // 여기서는 enum 사용
                    .WithKey(_pasetoKey)
                    .AddClaim("cid", connectedId.Id.ToString())
                    .AddClaim("uid", connectedId.UserId.ToString())
                    .AddClaim("oid", connectedId.OrganizationId.ToString())
                    .AddClaim("sid", session.Id.ToString())
                    .AddClaim("provider", connectedId.Provider ?? "local")
                    .Issuer("AuthHive")
                    .Audience("AuthHive")
                    .Expiration(session.ExpiresAt)
                    .Encode();
                return token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate PASETO token for ConnectedId {ConnectedId}", connectedId.Id);
                throw;
            }
        }

        public Task<TokenValidationResult> ValidateToken(string token)
        {
            try
            {
                var validationParameters = new PasetoTokenValidationParameters
                {
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidAudience = "AuthHive",
                    ValidIssuer = "AuthHive"
                };

                var result = new PasetoBuilder()
                    .Use(ProtocolVersion.V4, Purpose.Local)  // 여기서는 enum 사용
                    .WithKey(_pasetoKey)
                    .Decode(token, validationParameters);
                
                var payload = result.Paseto.Payload;
                    
                return Task.FromResult(new TokenValidationResult
                {
                    IsValid = true,
                    ConnectedId = Guid.Parse(payload["cid"].ToString()!),
                    UserId = Guid.Parse(payload["uid"].ToString()!),
                    OrganizationId = Guid.Parse(payload["oid"].ToString()!),
                    SessionId = Guid.Parse(payload["sid"].ToString()!),
                    Provider = payload.ContainsKey("provider") ? payload["provider"].ToString()! : "local"
                });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PASETO token validation failed with an exception.");
                return Task.FromResult(new TokenValidationResult { IsValid = false });
            }
        }

        private static string GenerateDefaultKey()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }
    }

    public class TokenValidationResult
    {
        public bool IsValid { get; set; }
        public Guid ConnectedId { get; set; }
        public Guid UserId { get; set; }
        public Guid OrganizationId { get; set; }
        public Guid SessionId { get; set; }
        public string Provider { get; set; } = "local";
    }
}