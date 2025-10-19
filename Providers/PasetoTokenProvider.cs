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
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth; // AuthConstants 사용을 위해 추가

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// ITokenProvider의 PASETO v4.local 구현체입니다. - v16 Refactored
    /// appsettings.json에서 설정을 읽고, AuthConstants.ClaimTypes를 준수하여 토큰을 생성/검증합니다.
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
                    .AddClaim(AuthConstants.ClaimTypes.ConnectedId, connectedId.ToString()); // 수정: "cid" 상수 사용

                if (additionalClaims != null)
                {
                    // 중복될 수 있는 표준 클레임 목록
                    var standardClaims = new HashSet<string>
                    {
                        AuthConstants.ClaimTypes.Subject,
                        AuthConstants.ClaimTypes.ConnectedId,
                        System.Security.Claims.ClaimTypes.NameIdentifier // "sub"와 동일하게 취급될 수 있음
                    };

                    foreach (var claim in additionalClaims)
                    {
                        // 표준 클레임과 중복되지 않는 경우에만 추가
                        if (!standardClaims.Contains(claim.Type))
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
                    IssuedAt = now,
                    ExpiresIn = (int)_accessTokenLifetime.TotalSeconds
                };
                return Task.FromResult(ServiceResult<TokenInfo>.Success(tokenInfo));
            }
            catch (OperationCanceledException)
            {
                return Task.FromResult(ServiceResult<TokenInfo>.Failure("Token generation was canceled."));
            }
            catch (Exception ex)
            {
                // TODO: 프로덕션 환경에서는 민감한 예외 메시지를 로그에만 기록하고, 사용자에게는 일반적인 에러 메시지를 반환해야 합니다.
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
                
                // 'sub' 클레임이 있는데 NameIdentifier 클레임이 없다면, 표준 호환성을 위해 추가해줍니다.
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
