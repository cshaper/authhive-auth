using AuthHive.Core.Interfaces.Auth.Provider;
// using AuthHive.Core.Models.Auth.Authentication; // [v17 수정] TokenInfo 네임스페이스 변경
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
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth;
// [v17 수정] CS0246 오류 해결: v17 불변 DTO의 네임스페이스를 'using'
using AuthHive.Core.Models.Auth.Authentication.Common; 

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// [v17 수정] ITokenProvider의 PASETO v4.local 구현체입니다.
    /// v17의 불변 DTO(TokenInfo)를 사용하도록 수정되었습니다.
    /// </summary>
    public class PasetoTokenProvider : ITokenProvider
    {
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
            _keyBytes = keyBytes;

            _accessTokenLifetime = TimeSpan.FromHours(configuration.GetValue<double>("Paseto:ExpiryInHours", 24));
        }

        /// <inheritdoc />
        public Task<ServiceResult<TokenInfo>> GenerateAccessTokenAsync(Guid userId, Guid connectedId, IEnumerable<Claim>? additionalClaims = null, CancellationToken cancellationToken = default)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested(); // 작업 취소 확인

                var now = DateTime.UtcNow;
                var expiresAt = now.Add(_accessTokenLifetime);

                var builder = new PasetoBuilder()
                    .UseV4(Purpose.Local)
                    .WithSharedKey(_keyBytes)
                    .Issuer(_issuer)
                    .Audience(_audience)
                    .Expiration(expiresAt)
                    .IssuedAt(now)
                    .Subject(userId.ToString()) // 'sub' 클레임은 UserId를 사용
                    .AddClaim(AuthConstants.ClaimTypes.ConnectedId, connectedId.ToString());

                if (additionalClaims != null)
                {
                    var standardClaims = new HashSet<string>
                    {
                        AuthConstants.ClaimTypes.Subject,
                        AuthConstants.ClaimTypes.ConnectedId,
                        System.Security.Claims.ClaimTypes.NameIdentifier
                    };

                    foreach (var claim in additionalClaims)
                    {
                        if (!standardClaims.Contains(claim.Type))
                        {
                            builder.AddClaim(claim.Type, claim.Value);
                        }
                    }
                }

                var token = builder.Encode();

                // [v17 수정] CS7036/CS0200 오류 해결:
                // v16의 기본 생성자 및 속성 할당 방식 대신,
                // v17 불변 DTO의 '생성자'를 사용하여 객체 생성
                var tokenInfo = new TokenInfo(
                    accessToken: token,
                    refreshToken: "", // [v17 정합성] 이 메서드는 AccessToken만 생성 (Refresh 토큰은 별도)
                    expiresIn: (int)_accessTokenLifetime.TotalSeconds,
                    issuedAt: now,
                    expiresAt: expiresAt
                    // TokenType은 TokenInfo 생성자에서 기본값("Bearer")으로 처리됨
                );
                
                return Task.FromResult(ServiceResult<TokenInfo>.Success(tokenInfo));
            }
            catch (OperationCanceledException)
            {
                return Task.FromResult(ServiceResult<TokenInfo>.Failure("Token generation was canceled."));
            }
            catch (Exception ex)
            {
                return Task.FromResult(ServiceResult<TokenInfo>.Failure($"Token generation failed: {ex.Message}"));
            }
        }

        /// <inheritdoc />
        public Task<ServiceResult<ClaimsPrincipal>> ValidateAccessTokenAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                var validationResult = new PasetoBuilder()
                    .UseV4(Purpose.Local)
                    .WithSharedKey(_keyBytes)
                    .Audience(_audience)
                    .Issuer(_issuer)
                    .Decode(accessToken);

                var pasetoClaims = validationResult.Paseto.Payload
                    .Select(p => new Claim(p.Key, p.Value?.ToString() ?? string.Empty))
                    .ToList();
                
                var subjectClaim = pasetoClaims.FirstOrDefault(c => c.Type == AuthConstants.ClaimTypes.Subject);
                if (subjectClaim != null && !pasetoClaims.Any(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier))
                {
                    pasetoClaims.Add(new Claim(System.Security.Claims.ClaimTypes.NameIdentifier, subjectClaim.Value));
                }

                var identity = new ClaimsIdentity(pasetoClaims, "PASETO");
                var principal = new ClaimsPrincipal(identity);

                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Success(principal));
            }
            catch (OperationCanceledException)
            {
                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Failure("Token validation was canceled."));
            }
            catch (Exception ex)
            {
                return Task.FromResult(ServiceResult<ClaimsPrincipal>.Failure($"Token validation failed: {ex.Message}"));
            }
        }

        /// <inheritdoc />
        public Task<ServiceResult<string>> GenerateRefreshTokenAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            var refreshToken = Convert.ToBase64String(randomNumber);

            return Task.FromResult(ServiceResult<string>.Success(refreshToken));
        }
    }
}