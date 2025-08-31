using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using Microsoft.EntityFrameworkCore;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 액세스 토큰 저장소 구현 - AuthHive v15
    /// AccessToken 전용 Repository (RefreshToken 제거됨)
    /// </summary>
    public class AccessTokenRepository : OrganizationScopedRepository<AccessToken>, IAccessTokenRepository
    {
        private readonly ILogger<AccessTokenRepository> _logger;

        public AccessTokenRepository(
            AuthDbContext context,
            ILogger<AccessTokenRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region Access Token Operations

        public async Task<AccessToken?> GetAccessTokenByHashAsync(string tokenHash)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            return await Query()
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .FirstOrDefaultAsync(t => t.TokenHash == tokenHash &&
                                          t.IsActive &&
                                          !t.IsRevoked);
        }

        public async Task<IEnumerable<AccessToken>> GetActiveAccessTokensAsync(Guid connectedId)
        {
            var now = DateTime.UtcNow;

            return await Query()
                .Include(t => t.Client)
                .Include(t => t.Session)
                .Where(t => t.ConnectedId == connectedId &&
                           t.IsActive &&
                           !t.IsRevoked &&
                           t.ExpiresAt > now)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<AccessToken>> GetAccessTokensBySessionAsync(Guid sessionId)
        {
            return await Query()
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.SessionId == sessionId)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<AccessToken>> GetExpiredAccessTokensAsync(DateTime? since = null)
        {
            var cutoffDate = since ?? DateTime.UtcNow.AddDays(-30);
            var now = DateTime.UtcNow;

            return await Query()
                .Where(t => t.ExpiresAt < now &&
                           t.ExpiresAt >= cutoffDate &&
                           !t.IsRevoked)
                .OrderBy(t => t.ExpiresAt)
                .ToListAsync();
        }

        public async Task IncrementAccessTokenUsageAsync(Guid tokenId)
        {
            var token = await GetByIdAsync(tokenId);
            if (token == null)
            {
                _logger.LogWarning("Attempted to increment usage for non-existent token {TokenId}", tokenId);
                return;
            }

            token.UsageCount++;
            token.LastUsedAt = DateTime.UtcNow;
            token.LastUsedIP = GetClientIpAddress();

            await UpdateAsync(token);
        }

        public async Task RevokeAccessTokenAsync(Guid tokenId, string reason, DateTime? revokedAt = null)
        {
            var token = await GetByIdAsync(tokenId);
            if (token == null)
            {
                _logger.LogWarning("Attempted to revoke non-existent token {TokenId}", tokenId);
                return;
            }

            if (token.IsRevoked)
            {
                _logger.LogInformation("Token {TokenId} is already revoked", tokenId);
                return;
            }

            token.IsRevoked = true;
            token.IsActive = false;
            token.RevokedAt = revokedAt ?? DateTime.UtcNow;
            token.RevokedReason = reason;

            await UpdateAsync(token);

            _logger.LogInformation("Revoked access token {TokenId} for reason: {Reason}", tokenId, reason);
        }

        public async Task<int> RevokeAllAccessTokensForConnectedIdAsync(Guid connectedId, string reason)
        {
            var accessTokens = await Query()
                .Where(t => t.ConnectedId == connectedId && !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            
            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
            }

            if (accessTokens.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} access tokens for ConnectedId {ConnectedId}. Reason: {Reason}",
                    accessTokens.Count, connectedId, reason);
            }

            return accessTokens.Count;
        }

        public async Task<int> RevokeAllAccessTokensForSessionAsync(Guid sessionId, string reason)
        {
            var accessTokens = await Query()
                .Where(t => t.SessionId == sessionId && !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            
            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
            }

            if (accessTokens.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} access tokens for Session {SessionId}. Reason: {Reason}",
                    accessTokens.Count, sessionId, reason);
            }

            return accessTokens.Count;
        }

        public async Task<int> RevokeAllAccessTokensForClientAsync(Guid clientId, string reason)
        {
            var accessTokens = await Query()
                .Where(t => t.ClientId == clientId && !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            
            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
            }

            if (accessTokens.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} access tokens for Client {ClientId}. Reason: {Reason}",
                    accessTokens.Count, clientId, reason);
            }

            return accessTokens.Count;
        }

        #endregion

        #region Helper Methods

        private string? GetClientIpAddress()
        {
            return null;
        }

        #endregion
    }
}