using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    public class RefreshTokenRepository : OrganizationScopedRepository<RefreshToken>, IRefreshTokenRepository
    {
        private readonly ILogger<RefreshTokenRepository> _logger;

        public RefreshTokenRepository(AuthDbContext context, ILogger<RefreshTokenRepository> logger) 
            : base(context) // ✅ base constructor 호출
        {
            _logger = logger;
        }

        #region IRefreshTokenRepository 특정 메서드

        public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash)
        {
            return await Query() // ✅ 자동 조직 격리
                .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
        }

        public async Task<RefreshToken?> GetByTokenValueAsync(string tokenValue)
        {
            return await Query() // ✅ 자동 조직 격리
                .FirstOrDefaultAsync(rt => rt.TokenValue == tokenValue);
        }

        public async Task<int> RevokeAllForUserAsync(Guid userId)
        {
            var tokens = await Query() // ✅ 자동 조직 격리
                .Where(rt => rt.ConnectedId == userId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedReason = "User requested revocation";
            }

            if (tokens.Any())
            {
                await _context.SaveChangesAsync();
            }

            return tokens.Count;
        }

        public async Task<int> RevokeAllForSessionAsync(Guid sessionId)
        {
            var tokens = await Query() // ✅ 자동 조직 격리
                .Where(rt => rt.SessionId == sessionId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedReason = "Session terminated";
            }

            if (tokens.Any())
            {
                await _context.SaveChangesAsync();
            }

            return tokens.Count;
        }

        public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(Guid userId)
        {
            return await Query() // ✅ 자동 조직 격리
                .Where(rt => rt.ConnectedId == userId && rt.IsActive && !rt.IsRevoked)
                .ToListAsync();
        }

        #endregion
    }
}