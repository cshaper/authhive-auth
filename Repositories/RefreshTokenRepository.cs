using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Refresh Token 저장소 구현 - AuthHive v15
    /// BaseRepository를 상속받아 Refresh Token 전용 기능 구현
    /// </summary>
    public class RefreshTokenRepository : 
        BaseRepository<RefreshToken>, 
        IRefreshTokenRepository
    {
        private readonly ILogger<RefreshTokenRepository> _logger;

        public RefreshTokenRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<RefreshTokenRepository> logger,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IRefreshTokenRepository 특정 메서드

        /// <summary>
        /// 토큰 해시로 Refresh Token 조회
        /// </summary>
        public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            return await Query()
                .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
        }

        /// <summary>
        /// 토큰 값으로 Refresh Token 조회
        /// </summary>
        public async Task<RefreshToken?> GetByTokenValueAsync(string tokenValue)
        {
            if (string.IsNullOrWhiteSpace(tokenValue))
                throw new ArgumentException("Token value cannot be empty", nameof(tokenValue));

            return await Query()
                .FirstOrDefaultAsync(rt => rt.TokenValue == tokenValue);
        }

        /// <summary>
        /// 특정 사용자의 모든 Refresh Token 폐기
        /// </summary>
        public async Task<int> RevokeAllForUserAsync(Guid userId)
        {
            var tokens = await Query()
                .Where(rt => rt.ConnectedId == userId && !rt.IsRevoked)
                .ToListAsync();

            if (!tokens.Any())
            {
                _logger.LogInformation("No active tokens found for user {UserId}", userId);
                return 0;
            }

            var revokedAt = DateTime.UtcNow;
            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = revokedAt;
                token.RevokedReason = "User requested revocation";
            }

            // BaseRepository의 UpdateRangeAsync 사용
            await UpdateRangeAsync(tokens);
            
            _logger.LogInformation("Revoked {Count} tokens for user {UserId}", tokens.Count, userId);
            return tokens.Count;
        }

        /// <summary>
        /// 특정 세션의 모든 Refresh Token 폐기
        /// </summary>
        public async Task<int> RevokeAllForSessionAsync(Guid sessionId)
        {
            var tokens = await Query()
                .Where(rt => rt.SessionId == sessionId && !rt.IsRevoked)
                .ToListAsync();

            if (!tokens.Any())
            {
                _logger.LogInformation("No active tokens found for session {SessionId}", sessionId);
                return 0;
            }

            var revokedAt = DateTime.UtcNow;
            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = revokedAt;
                token.RevokedReason = "Session terminated";
            }

            // BaseRepository의 UpdateRangeAsync 사용
            await UpdateRangeAsync(tokens);
            
            _logger.LogInformation("Revoked {Count} tokens for session {SessionId}", tokens.Count, sessionId);
            return tokens.Count;
        }

        /// <summary>
        /// 특정 사용자의 활성 Refresh Token 목록 조회
        /// </summary>
        public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(Guid userId)
        {
            return await Query()
                .Where(rt => rt.ConnectedId == userId && rt.IsActive && !rt.IsRevoked)
                .OrderByDescending(rt => rt.CreatedAt)
                .ToListAsync();
        }

        #endregion

        #region Override BaseRepository Methods with Logging

        /// <summary>
        /// Refresh Token 생성 - 로깅 추가
        /// </summary>
        public override async Task<RefreshToken> AddAsync(RefreshToken token)
        {
            var result = await base.AddAsync(token);
            _logger.LogInformation("Created refresh token {TokenId} for user {UserId}", 
                token.Id, token.ConnectedId);
            return result;
        }

        /// <summary>
        /// Refresh Token 삭제 - 로깅 추가
        /// </summary>
        public override async Task DeleteAsync(RefreshToken token)
        {
            await base.DeleteAsync(token);
            _logger.LogWarning("Deleted refresh token {TokenId}", token.Id);
        }

        #endregion

        #region Additional Helper Methods

        /// <summary>
        /// 만료된 토큰 정리
        /// </summary>
        public async Task<int> CleanupExpiredTokensAsync()
        {
            var expiredTokens = await Query()
                .Where(rt => rt.ExpiresAt < DateTime.UtcNow && !rt.IsRevoked)
                .ToListAsync();

            if (!expiredTokens.Any())
                return 0;

            foreach (var token in expiredTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedReason = "Token expired";
            }

            await UpdateRangeAsync(expiredTokens);
            
            _logger.LogInformation("Cleaned up {Count} expired tokens", expiredTokens.Count);
            return expiredTokens.Count;
        }

        /// <summary>
        /// 특정 기간 이상 사용되지 않은 토큰 정리
        /// </summary>
        public async Task<int> CleanupInactiveTokensAsync(int daysInactive = 30)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysInactive);
            
            var inactiveTokens = await Query()
                .Where(rt => rt.LastUsedAt < cutoffDate && !rt.IsRevoked)
                .ToListAsync();

            if (!inactiveTokens.Any())
                return 0;

            foreach (var token in inactiveTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedReason = $"Inactive for {daysInactive} days";
            }

            await UpdateRangeAsync(inactiveTokens);
            
            _logger.LogInformation("Cleaned up {Count} inactive tokens", inactiveTokens.Count);
            return inactiveTokens.Count;
        }

        #endregion

        #region Unit of Work

        /// <summary>
        /// 변경사항 저장
        /// </summary>
        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }

        #endregion
    }
}