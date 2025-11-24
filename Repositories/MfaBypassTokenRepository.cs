using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Entities.Auth.Authentication;
// 💡 1. ICacheService (v17 표준 캐시) 네임스페이스 추가
using AuthHive.Core.Interfaces.Infra.Cache;
// 💡 IMemoryCache 제거

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// MFA 바이패스 토큰 Repository 구현체 - AuthHive v17
    /// 💡 v17: ICacheService를 사용하도록 수정
    /// </summary>
    public class MfaBypassTokenRepository : BaseRepository<MfaBypassToken>, IMfaBypassTokenRepository
    {
        private const string CACHE_KEY_PREFIX = "mfa_bypass_";
        private readonly IOrganizationContext _organizationContext; // 💡 organizationContext는 로컬에서 사용 (Base로 전달 X)

        // 💡 2. [CS1729 해결] 생성자 시그니처를 v17 표준으로 수정
        public MfaBypassTokenRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ICacheService? cacheService = null) // 💡 IMemoryCache -> ICacheService
            : base(context, cacheService) // 💡 v17 BaseRepository 생성자 호출 (2-args)
        {
            _organizationContext = organizationContext;
        }

        // 💡 3. [CS0534 해결] v17 BaseRepository의 추상 메서드 구현
        protected override bool IsOrganizationBaseEntity()
        {
            // MfaBypassToken은 조직이 아닌 사용자(User) 범위에 속합니다.
            return false; 
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

            var tokenHash = HashToken(tokenValue);
            var cacheKey = $"{CACHE_KEY_PREFIX}token_{tokenHash}";

            // 💡 4. [CS0103 해결] _cache -> _cacheService (v17 캐시)로 변경
            if (_cacheService != null)
            {
                // 💡 TryGetValue -> GetAsync
                var cached = await _cacheService.GetAsync<MfaBypassToken>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    if (!cached.IsUsed && cached.ExpiresAt > DateTime.UtcNow)
                        return cached;
                    else
                    {
                        // 💡 Remove -> RemoveAsync
                        await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                        return null;
                    }
                }
            }
            
            // IsOrganizationBaseEntity()가 false이므로 Query()는 조직 필터링을 하지 않습니다.
            var token = await Query() 
                .Include(t => t.User)
                .FirstOrDefaultAsync(t =>
                    t.TokenHash == tokenHash &&
                    !t.IsUsed &&
                    t.ExpiresAt > DateTime.UtcNow,
                    cancellationToken);

            // 💡 5. [CS0103 해결] _cache -> _cacheService (v17 캐시)로 변경
            if (token != null && _cacheService != null)
            {
                // 💡 Set(key, value, options) -> SetAsync(key, value, expiry, token)
                // ICacheService는 절대 만료가 아닌 상대 만료(TimeSpan)를 사용합니다.
                var relativeExpiry = token.ExpiresAt - DateTime.UtcNow;
                if (relativeExpiry <= TimeSpan.Zero) 
                {
                    relativeExpiry = TimeSpan.FromMinutes(1); // 만료되었지만 안전을 위해 1분 캐시
                }
                
                await _cacheService.SetAsync(cacheKey, token, relativeExpiry, cancellationToken);
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

            var activeTokens = await Query()
                .Where(t =>
                    t.UserId == userId &&
                    !t.IsUsed &&
                    t.ExpiresAt > now)
                .ToListAsync(cancellationToken);

            if (!activeTokens.Any())
                return 0;

            foreach (var token in activeTokens)
            {
                token.IsUsed = true;
                token.UsedAt = now;
                token.UpdatedAt = now;

                // 💡 6. [CS0103 해결] _cache -> _cacheService (v17 캐시)로 변경
                if (_cacheService != null)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}token_{token.TokenHash}";
                    // 💡 Remove -> RemoveAsync
                    await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                }
            }

            await UpdateRangeAsync(activeTokens, cancellationToken); // 💡 CancellationToken 전달
            // 💡 SaveChangesAsync는 BaseRepository의 UpdateRangeAsync에서 호출되므로 중복 호출 제거
            // await _context.SaveChangesAsync(cancellationToken); 

            return activeTokens.Count;
        }

        #region 추가 메서드 (인터페이스에 없음)

        /// <summary>
        /// 새 바이패스 토큰을 생성합니다.
        /// </summary>
        public async Task<(MfaBypassToken token, string tokenValue)> CreateTokenAsync(
            Guid userId,
            string reason,
            int validityHours = 24,
            CancellationToken cancellationToken = default)
        {
            var tokenValue = GenerateSecureToken();
            var tokenHash = HashToken(tokenValue);

            var token = new MfaBypassToken
            {
                TokenHash = tokenHash,
                UserId = userId,
                Reason = reason,
                ExpiresAt = DateTime.UtcNow.AddHours(validityHours),
                IsUsed = false,
                // 💡 User 엔티티를 여기서 직접 로드하는 것은 Repository의 책임이 아닐 수 있으나,
                // 💡 기존 로직을 유지합니다.
                User = await _context.Set<Core.Entities.User.User>()
                    .FirstAsync(u => u.Id == userId, cancellationToken)
            };

            await AddAsync(token, cancellationToken); // 💡 CancellationToken 전달
            // 💡 SaveChangesAsync는 AddAsync에서 호출되므로 중복 호출 제거
            // await _context.SaveChangesAsync(cancellationToken);

            return (token, tokenValue);
        }

        /// <summary>
        /// 토큰을 사용됨으로 표시합니다.
        /// </summary>
        public async Task<bool> MarkTokenAsUsedAsync(
            Guid tokenId,
            CancellationToken cancellationToken = default)
        {
            var token = await GetByIdAsync(tokenId, cancellationToken); // 💡 CancellationToken 전달

            if (token == null || token.IsUsed)
                return false;

            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
            token.UpdatedAt = DateTime.UtcNow;

            // 💡 7. [CS0103 해결] _cache -> _cacheService (v17 캐시)로 변경
            if (_cacheService != null)
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}token_{token.TokenHash}";
                // 💡 Remove -> RemoveAsync
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            await UpdateAsync(token, cancellationToken); // 💡 CancellationToken 전달
            // 💡 SaveChangesAsync는 UpdateAsync에서 호출되므로 중복 호출 제거
            // await _context.SaveChangesAsync(cancellationToken);

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
                await DeleteRangeAsync(expiredTokens, cancellationToken); // 💡 CancellationToken 전달
                // 💡 SaveChangesAsync는 DeleteRangeAsync에서 호출되므로 중복 호출 제거
                // await _context.SaveChangesAsync(cancellationToken);
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