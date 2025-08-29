using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Base;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OAuth 토큰 저장소 구현 - AuthHive v15
    /// OAuthAccessToken과 RefreshToken 관리
    /// OrganizationScopedEntity를 상속받아 조직별 격리 보장
    /// </summary>
    public class OAuthTokenRepository : IOAuthTokenRepository
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<OAuthTokenRepository> _logger;
        private readonly Guid _currentOrganizationId;
        private readonly Guid? _currentConnectedId;

        public OAuthTokenRepository(
            AuthDbContext context,
            ILogger<OAuthTokenRepository> logger,
            IOrganizationContext organizationContext,
            IConnectedIdContext connectedIdContext)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _currentOrganizationId = organizationContext?.OrganizationId ?? throw new ArgumentNullException(nameof(organizationContext));
            _currentConnectedId = connectedIdContext?.ConnectedId;
        }

        #region IRepository<OAuthAccessToken> Implementation

        public async Task<OAuthAccessToken?> GetByIdAsync(Guid id)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .Where(t => t.OrganizationId == _currentOrganizationId)
                .FirstOrDefaultAsync(t => t.Id == id && !t.IsDeleted);
        }

        public async Task<IEnumerable<OAuthAccessToken>> GetAllAsync()
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<OAuthAccessToken>> FindAsync(Expression<Func<OAuthAccessToken, bool>> predicate)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<OAuthAccessToken?> FirstOrDefaultAsync(Expression<Func<OAuthAccessToken, bool>> predicate)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted)
                .Where(predicate)
                .FirstOrDefaultAsync();
        }

        public async Task<bool> AnyAsync(Expression<Func<OAuthAccessToken, bool>> predicate)
        {
            return await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted)
                .AnyAsync(predicate);
        }

        public async Task<int> CountAsync(Expression<Func<OAuthAccessToken, bool>>? predicate = null)
        {
            var query = _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync();
        }

        public async Task<(IEnumerable<OAuthAccessToken> Items, int TotalCount)> GetPagedAsync(
            int pageNumber, 
            int pageSize, 
            Expression<Func<OAuthAccessToken, bool>>? predicate = null,
            Expression<Func<OAuthAccessToken, object>>? orderBy = null,
            bool isDescending = false)
        {
            var query = _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending 
                    ? query.OrderByDescending(orderBy) 
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(t => t.CreatedAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<OAuthAccessToken> AddAsync(OAuthAccessToken entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            entity.OrganizationId = _currentOrganizationId;
            entity.CreatedByConnectedId = _currentConnectedId;
            entity.CreatedAt = DateTime.UtcNow;

            var existingToken = await _context.OAuthAccessTokens
                .Where(t => t.TokenHash == entity.TokenHash && !t.IsDeleted)
                .FirstOrDefaultAsync();

            if (existingToken != null)
            {
                _logger.LogWarning("Duplicate token hash detected for organization {OrganizationId}", _currentOrganizationId);
                throw new InvalidOperationException("Token with the same hash already exists");
            }

            _context.OAuthAccessTokens.Add(entity);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new OAuth access token {TokenId} for ConnectedId {ConnectedId} in Organization {OrganizationId}",
                entity.Id, entity.ConnectedId, entity.OrganizationId);

            return entity;
        }

        public async Task AddRangeAsync(IEnumerable<OAuthAccessToken> entities)
        {
            var tokenList = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var entity in tokenList)
            {
                entity.OrganizationId = _currentOrganizationId;
                entity.CreatedByConnectedId = _currentConnectedId;
                entity.CreatedAt = now;
            }

            _context.OAuthAccessTokens.AddRange(tokenList);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(OAuthAccessToken entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            if (entity.OrganizationId != _currentOrganizationId)
            {
                _logger.LogWarning("Attempted to update token from different organization. Current: {Current}, Token: {Token}",
                    _currentOrganizationId, entity.OrganizationId);
                throw new UnauthorizedAccessException("Cannot update token from different organization");
            }

            entity.UpdatedAt = DateTime.UtcNow;
            entity.UpdatedByConnectedId = _currentConnectedId;

            _context.Entry(entity).State = EntityState.Modified;
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRangeAsync(IEnumerable<OAuthAccessToken> entities)
        {
            var tokenList = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var entity in tokenList)
            {
                if (entity.OrganizationId != _currentOrganizationId)
                {
                    throw new UnauthorizedAccessException($"Cannot update token {entity.Id} from different organization");
                }

                entity.UpdatedAt = now;
                entity.UpdatedByConnectedId = _currentConnectedId;
                _context.Entry(entity).State = EntityState.Modified;
            }

            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var token = await GetByIdAsync(id);
            if (token == null)
                return;

            await DeleteAsync(token);
        }

        public async Task DeleteAsync(OAuthAccessToken entity)
        {
            if (entity == null)
                throw new ArgumentNullException(nameof(entity));

            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            entity.DeletedByConnectedId = _currentConnectedId;

            await UpdateAsync(entity);

            _logger.LogInformation("Soft deleted OAuth access token {TokenId}", entity.Id);
        }

        public async Task DeleteRangeAsync(IEnumerable<OAuthAccessToken> entities)
        {
            var tokenList = entities.ToList();
            var now = DateTime.UtcNow;

            foreach (var entity in tokenList)
            {
                if (entity.OrganizationId == _currentOrganizationId)
                {
                    entity.IsDeleted = true;
                    entity.DeletedAt = now;
                    entity.DeletedByConnectedId = _currentConnectedId;
                    _context.Entry(entity).State = EntityState.Modified;
                }
            }

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteAsync(Guid id)
        {
            await DeleteAsync(id);
        }

        public async Task<bool> ExistsAsync(Guid id)
        {
            return await _context.OAuthAccessTokens
                .AnyAsync(t => t.OrganizationId == _currentOrganizationId && 
                              t.Id == id && 
                              !t.IsDeleted);
        }

        public async Task<bool> ExistsAsync(Expression<Func<OAuthAccessToken, bool>> predicate)
        {
            return await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId && !t.IsDeleted)
                .AnyAsync(predicate);
        }

        #endregion

        #region IOrganizationScopedRepository<OAuthAccessToken> Implementation

        public async Task<IEnumerable<OAuthAccessToken>> GetByOrganizationIdAsync(Guid organizationId)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .Where(t => t.OrganizationId == organizationId && !t.IsDeleted)
                .ToListAsync();
        }

        public async Task<OAuthAccessToken?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .Where(t => t.OrganizationId == organizationId)
                .FirstOrDefaultAsync(t => t.Id == id && !t.IsDeleted);
        }

        public async Task<IEnumerable<OAuthAccessToken>> FindByOrganizationAsync(
            Guid organizationId, 
            Expression<Func<OAuthAccessToken, bool>> predicate)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.OrganizationId == organizationId && !t.IsDeleted)
                .Where(predicate)
                .ToListAsync();
        }

        public async Task<(IEnumerable<OAuthAccessToken> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber,
            int pageSize,
            Expression<Func<OAuthAccessToken, bool>>? additionalPredicate = null,
            Expression<Func<OAuthAccessToken, object>>? orderBy = null,
            bool isDescending = false)
        {
            var query = _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.OrganizationId == organizationId && !t.IsDeleted);

            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }

            var totalCount = await query.CountAsync();

            if (orderBy != null)
            {
                query = isDescending 
                    ? query.OrderByDescending(orderBy) 
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderByDescending(t => t.CreatedAt);
            }

            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return (items, totalCount);
        }

        public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
        {
            return await _context.OAuthAccessTokens
                .AnyAsync(t => t.OrganizationId == organizationId && t.Id == id && !t.IsDeleted);
        }

        public async Task<int> CountByOrganizationAsync(
            Guid organizationId, 
            Expression<Func<OAuthAccessToken, bool>>? predicate = null)
        {
            var query = _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == organizationId && !t.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync();
        }

        public async Task DeleteAllByOrganizationAsync(Guid organizationId)
        {
            var tokens = await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == organizationId && !t.IsDeleted)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsDeleted = true;
                token.DeletedAt = DateTime.UtcNow;
                token.DeletedByConnectedId = _currentConnectedId;
            }

            if (tokens.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Soft deleted {Count} OAuth access tokens for organization {OrganizationId}", 
                    tokens.Count, organizationId);
            }
        }

        #endregion

        #region IOAuthTokenRepository Specific Methods

        public async Task<OAuthAccessToken?> GetAccessTokenByHashAsync(string tokenHash)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .Where(t => t.OrganizationId == _currentOrganizationId)
                .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && 
                                          !t.IsDeleted && 
                                          t.IsActive &&
                                          !t.IsRevoked);
        }

        public async Task<IEnumerable<OAuthAccessToken>> GetActiveAccessTokensAsync(Guid connectedId)
        {
            var now = DateTime.UtcNow;
            
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.Session)
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ConnectedId == connectedId &&
                           !t.IsDeleted &&
                           t.IsActive &&
                           !t.IsRevoked &&
                           t.ExpiresAt > now)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<OAuthAccessToken>> GetAccessTokensBySessionAsync(Guid sessionId)
        {
            return await _context.OAuthAccessTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.SessionId == sessionId &&
                           !t.IsDeleted)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<OAuthAccessToken>> GetExpiredAccessTokensAsync(DateTime? since = null)
        {
            var cutoffDate = since ?? DateTime.UtcNow.AddDays(-30);
            var now = DateTime.UtcNow;

            return await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ExpiresAt < now &&
                           t.ExpiresAt >= cutoffDate &&
                           !t.IsDeleted &&
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
            token.UpdatedAt = DateTime.UtcNow;
            token.UpdatedByConnectedId = _currentConnectedId;

            await UpdateAsync(token);

            // Revoke all child tokens if this is a parent token
            if (token.ChildTokens?.Any() == true)
            {
                foreach (var childToken in token.ChildTokens.Where(ct => !ct.IsRevoked))
                {
                    await RevokeAccessTokenAsync(childToken.Id, $"Parent token revoked: {reason}");
                }
            }

            _logger.LogInformation("Revoked OAuth access token {TokenId} for reason: {Reason}", tokenId, reason);
        }

        #endregion

        #region Refresh Token Operations

        public async Task<RefreshToken?> GetRefreshTokenAsync(Guid id)
        {
            return await _context.RefreshTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.AccessToken)
                .Where(t => t.OrganizationId == _currentOrganizationId)
                .FirstOrDefaultAsync(t => t.Id == id && !t.IsDeleted);
        }

        public async Task<RefreshToken?> GetRefreshTokenByHashAsync(string tokenHash)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            return await _context.RefreshTokens
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.AccessToken)
                .Where(t => t.OrganizationId == _currentOrganizationId)
                .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && 
                                          !t.IsDeleted && 
                                          t.IsActive &&
                                          !t.IsRevoked);
        }

        public async Task<IEnumerable<RefreshToken>> GetActiveRefreshTokensAsync(Guid connectedId)
        {
            var now = DateTime.UtcNow;
            
            return await _context.RefreshTokens
                .Include(t => t.Client)
                .Include(t => t.Session)
                .Include(t => t.AccessToken)
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ConnectedId == connectedId &&
                           !t.IsDeleted &&
                           t.IsActive &&
                           !t.IsRevoked &&
                           t.ExpiresAt > now)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync();
        }

        public async Task IncrementRefreshTokenUsageAsync(Guid tokenId)
        {
            var token = await GetRefreshTokenAsync(tokenId);
            if (token == null)
            {
                _logger.LogWarning("Attempted to increment usage for non-existent refresh token {TokenId}", tokenId);
                return;
            }

            token.UsageCount++;
            token.LastUsedAt = DateTime.UtcNow;
            token.LastUsedIP = GetClientIpAddress();
            token.UpdatedAt = DateTime.UtcNow;
            token.UpdatedByConnectedId = _currentConnectedId;

            _context.Entry(token).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            // Check if max usage count is exceeded
            if (token.MaxUsageCount > 0 && token.UsageCount > token.MaxUsageCount)
            {
                await RevokeRefreshTokenAsync(tokenId, $"Max usage count ({token.MaxUsageCount}) exceeded");
            }
        }

        public async Task RevokeRefreshTokenAsync(Guid tokenId, string reason, DateTime? revokedAt = null)
        {
            var token = await GetRefreshTokenAsync(tokenId);
            if (token == null)
            {
                _logger.LogWarning("Attempted to revoke non-existent refresh token {TokenId}", tokenId);
                return;
            }

            if (token.IsRevoked)
            {
                _logger.LogInformation("Refresh token {TokenId} is already revoked", tokenId);
                return;
            }

            token.IsRevoked = true;
            token.IsActive = false;
            token.RevokedAt = revokedAt ?? DateTime.UtcNow;
            token.RevokedReason = reason;
            token.UpdatedAt = DateTime.UtcNow;
            token.UpdatedByConnectedId = _currentConnectedId;

            _context.Entry(token).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked OAuth refresh token {TokenId} for reason: {Reason}", tokenId, reason);
        }

        public async Task<int> CleanupExpiredRefreshTokensAsync(DateTime before)
        {
            var tokensToDelete = await _context.RefreshTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ExpiresAt < before &&
                           !t.IsDeleted)
                .ToListAsync();

            foreach (var token in tokensToDelete)
            {
                token.IsDeleted = true;
                token.DeletedAt = DateTime.UtcNow;
                token.DeletedByConnectedId = _currentConnectedId;
            }

            var count = tokensToDelete.Count;
            if (count > 0)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Cleaned up {Count} expired refresh tokens for organization {OrganizationId}", 
                    count, _currentOrganizationId);
            }

            return count;
        }

        #endregion

        #region Bulk Operations

        public async Task<int> RevokeAllTokensForConnectedIdAsync(Guid connectedId, string reason)
        {
            var accessTokens = await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ConnectedId == connectedId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var refreshTokens = await _context.RefreshTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ConnectedId == connectedId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            var totalRevoked = 0;

            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            if (totalRevoked > 0)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} tokens for ConnectedId {ConnectedId} in organization {OrganizationId}. Reason: {Reason}",
                    totalRevoked, connectedId, _currentOrganizationId, reason);
            }

            return totalRevoked;
        }

        public async Task<int> RevokeAllTokensForSessionAsync(Guid sessionId, string reason)
        {
            var accessTokens = await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.SessionId == sessionId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var refreshTokens = await _context.RefreshTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.SessionId == sessionId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            var totalRevoked = 0;

            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            if (totalRevoked > 0)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} tokens for Session {SessionId} in organization {OrganizationId}. Reason: {Reason}",
                    totalRevoked, sessionId, _currentOrganizationId, reason);
            }

            return totalRevoked;
        }

        public async Task<int> RevokeAllTokensForClientAsync(Guid clientId, string reason)
        {
            var accessTokens = await _context.OAuthAccessTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ClientId == clientId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var refreshTokens = await _context.RefreshTokens
                .Where(t => t.OrganizationId == _currentOrganizationId &&
                           t.ClientId == clientId &&
                           !t.IsDeleted &&
                           !t.IsRevoked)
                .ToListAsync();

            var now = DateTime.UtcNow;
            var totalRevoked = 0;

            foreach (var token in accessTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                token.IsActive = false;
                token.RevokedAt = now;
                token.RevokedReason = reason;
                token.UpdatedAt = now;
                token.UpdatedByConnectedId = _currentConnectedId;
                totalRevoked++;
            }

            if (totalRevoked > 0)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} tokens for Client {ClientId} in organization {OrganizationId}. Reason: {Reason}",
                    totalRevoked, clientId, _currentOrganizationId, reason);
            }

            return totalRevoked;
        }

        #endregion

        #region Helper Methods

        private string? GetClientIpAddress()
        {
            // This would need to be injected from the HTTP context
            // For now, returning null
            return null;
        }

        #endregion
    }


}