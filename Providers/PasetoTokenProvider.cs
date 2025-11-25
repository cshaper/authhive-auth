using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Paseto;
using Paseto.Builder;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Constants.Auth;

namespace AuthHive.Auth.Providers;

/// <summary>
/// [Infra] PASETO v4.local 토큰 생성기 (Implementation)
/// ITokenProvider를 구현하여 실제 암호화 토큰을 생성하고 검증합니다.
/// </summary>
public class PasetoTokenProvider : ITokenProvider
{
    private readonly byte[] _keyBytes;
    private readonly string _issuer;
    private readonly string _audience;

    public PasetoTokenProvider(IConfiguration configuration)
    {
        var keyString = configuration["Paseto:Key"] ?? throw new ArgumentNullException("Paseto:Key");
        _issuer = configuration["Paseto:Issuer"] ?? throw new ArgumentNullException("Paseto:Issuer");
        _audience = configuration["Paseto:Audience"] ?? throw new ArgumentNullException("Paseto:Audience");

        var keyBytes = Convert.FromBase64String(keyString);
        if (keyBytes.Length != 32)
        {
            throw new ArgumentException("PASETO key must be 32 bytes (256 bits).", "Paseto:Key");
        }
        _keyBytes = keyBytes;
    }

    /// <summary>
    /// 클레임 목록을 받아 PASETO 토큰 문자열을 생성합니다.
    /// </summary>
    public Task<string> GenerateTokenAsync(
        IEnumerable<Claim> claims,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var builder = new PasetoBuilder()
            .UseV4(Purpose.Local)
            .WithSharedKey(_keyBytes)
            .Issuer(_issuer)
            .Audience(_audience)
            .Expiration(expiresAt)
            .IssuedAt(DateTime.UtcNow);

        foreach (var claim in claims)
        {
            // PasetoBuilder는 중복 키 처리를 위해 커스텀 로직이 필요할 수 있으나,
            // 기본적으로 AddClaim을 사용합니다.
            builder.AddClaim(claim.Type, claim.Value);
        }

        var token = builder.Encode();
        return Task.FromResult(token);
    }

    /// <summary>
    /// 토큰을 검증하고 ClaimsPrincipal을 반환합니다.
    /// </summary>
    public Task<ClaimsPrincipal?> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var validationResult = new PasetoBuilder()
                .UseV4(Purpose.Local)
                .WithSharedKey(_keyBytes)
                .Audience(_audience)
                .Issuer(_issuer)
                .Decode(token); // 유효하지 않으면 예외 발생

            if (validationResult.Paseto.Payload == null)
                return Task.FromResult<ClaimsPrincipal?>(null);

            // Payload를 Claim으로 변환
            var claims = validationResult.Paseto.Payload
                .Select(kvp => new Claim(kvp.Key, kvp.Value?.ToString() ?? string.Empty))
                .ToList();

            var identity = new ClaimsIdentity(claims, "PASETO");
            return Task.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(identity));
        }
        catch (Exception)
        {
            // 서명 불일치, 만료 등으로 검증 실패 시 null 반환
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
    }

    /// <summary>
    /// 리프레시 토큰용 랜덤 문자열 생성
    /// </summary>
    public Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        
        // URL-safe Base64 권장하지만, 여기서는 표준 Base64 사용 (필요시 변경)
        var token = Convert.ToBase64String(randomNumber);
        return Task.FromResult(token);
    }
}