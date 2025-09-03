using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 액세스 토큰 저장소 구현 - AuthHive v15
    /// AccessToken 전용 Repository (RefreshToken 제거됨)
    /// </summary>
    public class AccessTokenRepository : BaseRepository<AccessToken>, IAccessTokenRepository
    {
        private readonly ILogger<AccessTokenRepository> _logger;

        public AccessTokenRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AccessTokenRepository> logger,
            IMemoryCache? cache = null) : base(context, organizationContext, cache)
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
            var now = DateTime.UtcNow;

            // ExecuteUpdateAsync를 사용하여 DB에서 직접 업데이트 실행
            var affectedRows = await Query()
                .Where(t => t.ConnectedId == connectedId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    // AuditableEntity의 UpdatedAt도 수동으로 갱신해주는 것이 좋습니다.
                    .SetProperty(t => t.UpdatedAt, now)
                );

            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for ConnectedId {ConnectedId}. Reason: {Reason}",
                    affectedRows, connectedId, reason);
            }

            return affectedRows;
        }

        public async Task<int> RevokeAllAccessTokensForSessionAsync(Guid sessionId, string reason)
        {
            var now = DateTime.UtcNow;

            // ExecuteUpdateAsync를 사용하여 DB에서 직접 일괄 업데이트를 실행합니다.
            // 불필요한 데이터 조회가 없고, DB 왕복이 단 한 번만 발생합니다.
            var affectedRows = await Query()
                .Where(t => t.SessionId == sessionId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    .SetProperty(t => t.UpdatedAt, now) // AuditableEntity 속성 갱신
                );

            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for Session {SessionId}. Reason: {Reason}",
                    affectedRows, sessionId, reason);
            }

            return affectedRows;
        }

        public async Task<int> RevokeAllAccessTokensForClientAsync(Guid clientId, string reason)
        {
            var now = DateTime.UtcNow;

            // 위와 동일한 패턴으로, 조건만 ClientId로 변경합니다.
            var affectedRows = await Query()
                .Where(t => t.ClientId == clientId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    .SetProperty(t => t.UpdatedAt, now) // AuditableEntity 속성 갱신
                );

            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for Client {ClientId}. Reason: {Reason}",
                    affectedRows, clientId, reason);
            }

            return affectedRows;
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