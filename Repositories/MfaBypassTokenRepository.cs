using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// MFA 바이패스 토큰 Repository 구현체 - AuthHive v15
    /// MFA 바이패스 토큰의 생성, 조회, 무효화를 담당합니다.
    /// </summary>
    public class MfaBypassTokenRepository : BaseRepository<MfaBypassToken>, IMfaBypassTokenRepository
    {
        private const string CACHE_KEY_PREFIX = "mfa_bypass_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public MfaBypassTokenRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        /// <summary>
        /// 해시되지 않은 원본 토큰 값으로 바이패스 토큰 정보를 조회합니다.
        /// </summary>
        public async Task<MfaBypassToken?> FindByTokenValueAsync(
            string tokenValue,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(tokenValue))
                return null;

            // 토큰 값을 해시로 변환
            var tokenHash = HashToken(tokenValue);

            // 캐시 확인
            var cacheKey = $"{CACHE_KEY_PREFIX}token_{tokenHash}";
            if (_cache != null && _cache.TryGetValue<MfaBypassToken>(cacheKey, out var cached) && cached != null)
            {
                // 만료 및 사용 여부 재확인
                if (!cached.IsUsed && cached.ExpiresAt > DateTime.UtcNow)
                    return cached;
                else
                {
                    _cache.Remove(cacheKey);
                    return null;
                }
            }
            // 데이터베이스에서 조회
            var token = await Query()
                .Include(t => t.User)
                .FirstOrDefaultAsync(t =>
                    t.TokenHash == tokenHash &&
                    !t.IsUsed &&
                    t.ExpiresAt > DateTime.UtcNow,
                    cancellationToken);

            // 캐시에 저장
            if (token != null && _cache != null)
            {
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = token.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(1)
                };
                _cache.Set(cacheKey, token, cacheOptions);
            }

            return token;
        }

        /// <summary>
        /// 특정 사용자의 활성 바이패스 토큰 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<MfaBypassToken>> GetActiveTokensByUserIdAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await Query()
                .Include(t => t.User)
                .Where(t =>
                    t.UserId == userId &&
                    !t.IsUsed &&
                    t.ExpiresAt > now)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자의 모든 바이패스 토큰을 무효화합니다.
        /// </summary>
        public async Task<int> VoidAllTokensForUserAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // 활성 토큰들 조회
            var activeTokens = await Query()
                .Where(t =>
                    t.UserId == userId &&
                    !t.IsUsed &&
                    t.ExpiresAt > now)
                .ToListAsync(cancellationToken);

            if (!activeTokens.Any())
                return 0;

            // 모든 토큰을 사용됨으로 표시
            foreach (var token in activeTokens)
            {
                token.IsUsed = true;
                token.UsedAt = now;
                token.UpdatedAt = now;

                // 캐시에서 제거
                if (_cache != null)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}token_{token.TokenHash}";
                    _cache.Remove(cacheKey);
                }
            }

            await UpdateRangeAsync(activeTokens);
            await _context.SaveChangesAsync(cancellationToken);

            return activeTokens.Count;
        }

        #region 추가 메서드

        /// <summary>
        /// 새 바이패스 토큰을 생성합니다.
        /// </summary>
        public async Task<(MfaBypassToken token, string tokenValue)> CreateTokenAsync(
            Guid userId,
            string reason,
            int validityHours = 24,
            CancellationToken cancellationToken = default)
        {
            // 랜덤 토큰 생성
            var tokenValue = GenerateSecureToken();
            var tokenHash = HashToken(tokenValue);

            var token = new MfaBypassToken
            {
                TokenHash = tokenHash,
                UserId = userId,
                Reason = reason,
                ExpiresAt = DateTime.UtcNow.AddHours(validityHours),
                IsUsed = false,
                User = await _context.Set<Core.Entities.User.User>()
                    .FirstAsync(u => u.Id == userId, cancellationToken)
            };

            await AddAsync(token);
            await _context.SaveChangesAsync(cancellationToken);

            return (token, tokenValue);
        }

        /// <summary>
        /// 토큰을 사용됨으로 표시합니다.
        /// </summary>
        public async Task<bool> MarkTokenAsUsedAsync(
            Guid tokenId,
            CancellationToken cancellationToken = default)
        {
            var token = await GetByIdAsync(tokenId);

            if (token == null || token.IsUsed)
                return false;

            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
            token.UpdatedAt = DateTime.UtcNow;

            // 캐시에서 제거
            if (_cache != null)
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}token_{token.TokenHash}";
                _cache.Remove(cacheKey);
            }

            await UpdateAsync(token);
            await _context.SaveChangesAsync(cancellationToken);

            return true;
        }

        /// <summary>
        /// 만료된 토큰들을 정리합니다.
        /// </summary>
        public async Task<int> CleanupExpiredTokensAsync(
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var cutoffDate = now.AddDays(-30); // 30일 이상 지난 토큰 삭제

            var expiredTokens = await Query()
                .Where(t => t.ExpiresAt < cutoffDate ||
                           (t.IsUsed && t.UsedAt < cutoffDate))
                .ToListAsync(cancellationToken);

            if (expiredTokens.Any())
            {
                await DeleteRangeAsync(expiredTokens);
                await _context.SaveChangesAsync(cancellationToken);
            }

            return expiredTokens.Count;
        }

        /// <summary>
        /// 사용자의 토큰 사용 통계를 조회합니다.
        /// </summary>
        public async Task<TokenUsageStatistics> GetUserTokenStatisticsAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var thirtyDaysAgo = now.AddDays(-30);

            var tokens = await Query()
                .Where(t => t.UserId == userId && t.CreatedAt >= thirtyDaysAgo)
                .ToListAsync(cancellationToken);

            return new TokenUsageStatistics
            {
                UserId = userId,
                TotalTokensIssued = tokens.Count,
                ActiveTokens = tokens.Count(t => !t.IsUsed && t.ExpiresAt > now),
                UsedTokens = tokens.Count(t => t.IsUsed),
                ExpiredTokens = tokens.Count(t => !t.IsUsed && t.ExpiresAt <= now),
                LastTokenIssuedAt = tokens.OrderByDescending(t => t.CreatedAt).FirstOrDefault()?.CreatedAt,
                LastTokenUsedAt = tokens.Where(t => t.IsUsed).OrderByDescending(t => t.UsedAt).FirstOrDefault()?.UsedAt
            };
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 토큰 값을 SHA256으로 해시합니다.
        /// </summary>
        private string HashToken(string tokenValue)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(tokenValue);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// 암호학적으로 안전한 랜덤 토큰을 생성합니다.
        /// </summary>
        private string GenerateSecureToken(int length = 32)
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);

            // URL-safe Base64 인코딩
            return Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
        }

        #endregion
    }

    /// <summary>
    /// 토큰 사용 통계
    /// </summary>
    public class TokenUsageStatistics
    {
        public Guid UserId { get; set; }
        public int TotalTokensIssued { get; set; }
        public int ActiveTokens { get; set; }
        public int UsedTokens { get; set; }
        public int ExpiredTokens { get; set; }
        public DateTime? LastTokenIssuedAt { get; set; }
        public DateTime? LastTokenUsedAt { get; set; }
    }
}