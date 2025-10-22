using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Memory; // IMemoryCache 제거
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationContext 제거
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// Refresh Token 저장소 구현 - AuthHive v16
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용, 서비스 로직 제거
    /// </summary>
    public class RefreshTokenRepository :
        BaseRepository<RefreshToken>,
        IRefreshTokenRepository
    {
        private readonly ILogger<RefreshTokenRepository> _logger;

        public RefreshTokenRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ILogger<RefreshTokenRepository> logger,
            ICacheService? cacheService = null) // IMemoryCache -> ICacheService?
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. RefreshToken은 사용자 범위 (ConnectedId)이며,
        /// 조직 범위 필터링은 필요 없음 (false).
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;


        #region IRefreshTokenRepository 특정 메서드 (CancellationToken 추가)

        /// <summary>
        /// 토큰 해시로 유효한 Refresh Token 조회 (Cache-Aside 적용)
        /// </summary>
        public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            string cacheKey = GetCacheKey($"TokenHash:{tokenHash}"); // BaseRepository GetCacheKey 사용
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<RefreshToken>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            // Query() 사용 (IsDeleted=false 포함), 만료되지 않고 폐기되지 않은 토큰만 조회
            var token = await Query()
            // [FIXED] ConnectedUser -> ConnectedIdNavigation 으로 수정
                            .Include(rt => rt.ConnectedIdNavigation) // <-- 올바른 탐색 속성 사용
                            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash &&
                                rt.ExpiresAt > DateTime.UtcNow &&
                                !rt.IsRevoked,
                           cancellationToken);
            if (token != null && _cacheService != null)
            {
                // 토큰 만료 시간에 맞춰 TTL 설정
                var ttl = token.ExpiresAt - DateTime.UtcNow;
                if (ttl > TimeSpan.Zero)
                {
                    await _cacheService.SetAsync(cacheKey, token, ttl, cancellationToken);
                }
            }
            return token;
        }

        /// <summary>
                /// 토큰 값으로 유효한 Refresh Token 조회 (보안상 주의)
                /// </summary>
        public async Task<RefreshToken?> GetByTokenValueAsync(string tokenValue, CancellationToken cancellationToken = default)
        {
            // 실제 배포 환경에서는 토큰 값 직접 저장을 피하고 해시값만 사용해야 함
            _logger.LogWarning("Attempting to find refresh token by its actual value. This is insecure and should only be used in specific scenarios like initial migration or debugging.");
            if (string.IsNullOrWhiteSpace(tokenValue))
                throw new ArgumentException("Token value cannot be empty", nameof(tokenValue));

            return await Query()
                      .Include(rt => rt.ConnectedIdNavigation) 
                      .FirstOrDefaultAsync(rt => rt.TokenValue == tokenValue &&
                            rt.ExpiresAt > DateTime.UtcNow &&
                            !rt.IsRevoked,
                     cancellationToken);
        }

        /// <summary>
        /// 특정 사용자의 활성 Refresh Token 목록 조회
        /// </summary>
        public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(
            Guid connectedId, // userId -> connectedId
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(rt => rt.ConnectedId == connectedId &&
                             rt.ExpiresAt > DateTime.UtcNow && // IsActive 대신 만료 시간 체크
                             !rt.IsRevoked)
                .OrderByDescending(rt => rt.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자의 모든 Refresh Token 폐기 (ExecuteUpdateAsync 사용 최적화)
        /// </summary>
        public async Task<int> RevokeAllForUserAsync(
            Guid connectedId, // userId -> connectedId
            string reason = "User requested revocation",
            CancellationToken cancellationToken = default)
        {
            var revokedAt = DateTime.UtcNow;
            // EF Core 7+ ExecuteUpdateAsync 사용
            int revokedCount = await Query()
                .Where(rt => rt.ConnectedId == connectedId &&
                             !rt.IsRevoked &&
                             rt.ExpiresAt > revokedAt) // 이미 만료된 토큰 제외
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, revokedAt)
                    .SetProperty(rt => rt.RevokedReason, reason),
                    cancellationToken);

            if (revokedCount > 0)
            {
                // 관련 캐시 무효화 (예: 해시값 기반 캐시 등)
                // 토큰 목록을 먼저 조회하지 않으므로, 더 넓은 범위의 캐시 무효화 필요 가능성
                _logger.LogInformation("Revoked {Count} tokens for user {ConnectedId}", revokedCount, connectedId);
                // TODO: Invalidate relevant caches (e.g., all tokens for the user, specific token hashes if known)
            }
            else
            {
                _logger.LogInformation("No active tokens found to revoke for user {ConnectedId}", connectedId);
            }
            return revokedCount;
        }

        /// <summary>
        /// 특정 세션의 모든 Refresh Token 폐기 (ExecuteUpdateAsync 사용 최적화)
        /// </summary>
        public async Task<int> RevokeAllForSessionAsync(
            Guid sessionId,
            string reason = "Session terminated",
            CancellationToken cancellationToken = default)
        {
            var revokedAt = DateTime.UtcNow;
            // EF Core 7+ ExecuteUpdateAsync 사용
            int revokedCount = await Query()
                .Where(rt => rt.SessionId == sessionId &&
                             !rt.IsRevoked &&
                             rt.ExpiresAt > revokedAt)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, revokedAt)
                    .SetProperty(rt => rt.RevokedReason, reason),
                    cancellationToken);

            if (revokedCount > 0)
            {
                _logger.LogInformation("Revoked {Count} tokens for session {SessionId}", revokedCount, sessionId);
                // TODO: Invalidate relevant caches
            }
            else
            {
                _logger.LogInformation("No active tokens found to revoke for session {SessionId}", sessionId);
            }
            return revokedCount;
        }

        #endregion

        #region Override BaseRepository Methods with Logging & Caching (CancellationToken 추가)

        /// <summary>
        /// Refresh Token 생성 - 로깅 추가
        /// </summary>
        public override async Task<RefreshToken> AddAsync(RefreshToken token, CancellationToken cancellationToken = default)
        {
            // ID, CreatedAt 등은 BaseRepository 또는 Interceptor 처리
            var result = await base.AddAsync(token, cancellationToken);
            _logger.LogInformation("Created refresh token {TokenId} for connected user {ConnectedId}",
                result.Id, result.ConnectedId);
            // Add는 캐시 무효화 안 함 (새 데이터이므로)
            return result;
        }

        /// <summary>
        /// Refresh Token 업데이트 - 캐시 무효화 추가
        /// </summary>
        public override async Task UpdateAsync(RefreshToken entity, CancellationToken cancellationToken = default)
        {
            await base.UpdateAsync(entity, cancellationToken); // ID 기반 캐시 무효화 포함
            // 해시값 기반 캐시 무효화 추가
            if (!string.IsNullOrEmpty(entity.TokenHash))
            {
                await InvalidateTokenHashCacheAsync(entity.TokenHash, cancellationToken);
            }
            _logger.LogInformation("Updated refresh token {TokenId}", entity.Id);
        }


        /// <summary>
        /// Refresh Token 삭제 (Soft Delete) - 로깅 및 캐시 무효화 추가
        /// </summary>
        public override async Task DeleteAsync(RefreshToken token, CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(token, cancellationToken); // ID 기반 캐시 무효화 포함
            // 해시값 기반 캐시 무효화 추가
            if (!string.IsNullOrEmpty(token.TokenHash))
            {
                await InvalidateTokenHashCacheAsync(token.TokenHash, cancellationToken);
            }
            _logger.LogWarning("Soft Deleted refresh token {TokenId}", token.Id);
        }

        // TokenHash 캐시 무효화 헬퍼
        private async Task InvalidateTokenHashCacheAsync(string tokenHash, CancellationToken cancellationToken)
        {
            if (_cacheService != null && !string.IsNullOrWhiteSpace(tokenHash))
            {
                string cacheKey = GetCacheKey($"TokenHash:{tokenHash}");
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogDebug("Invalidated TokenHash cache for hash: {TokenHash}", tokenHash); // 로그 레벨 Debug로 변경
            }
        }

        #endregion

        #region Cleanup Operations (CancellationToken 추가, 최적화)

        /// <summary>
        /// 만료된 토큰 정리 (폐기 상태로 변경, ExecuteUpdateAsync 사용)
        /// </summary>
        public async Task<int> CleanupExpiredTokensAsync(CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            int cleanedCount = await Query()
                .Where(rt => rt.ExpiresAt < now && !rt.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, now)
                    .SetProperty(rt => rt.RevokedReason, "Token expired"),
                    cancellationToken);

            if (cleanedCount > 0)
            {
                _logger.LogInformation("Cleaned up {Count} expired tokens", cleanedCount);
                // TODO: Invalidate relevant caches if needed (potentially broad invalidation)
            }
            return cleanedCount;
        }

        /// <summary>
        /// 특정 기간 이상 사용되지 않은 토큰 정리 (폐기 상태로 변경, ExecuteUpdateAsync 사용)
        /// </summary>
        public async Task<int> CleanupInactiveTokensAsync(int daysInactive = 30, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysInactive);
            var now = DateTime.UtcNow;
            int cleanedCount = await Query()
                .Where(rt => rt.LastUsedAt < cutoffDate && !rt.IsRevoked && rt.ExpiresAt > now) // 만료되지 않은 토큰 중 비활성
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(rt => rt.IsRevoked, true)
                    .SetProperty(rt => rt.RevokedAt, now)
                    .SetProperty(rt => rt.RevokedReason, $"Inactive for {daysInactive} days"),
                    cancellationToken);

            if (cleanedCount > 0)
            {
                _logger.LogInformation("Cleaned up {Count} inactive tokens (inactive for >{Days} days)", cleanedCount, daysInactive);
                // TODO: Invalidate relevant caches
            }
            return cleanedCount;
        }

        #endregion

        // [FIXED] SaveChangesAsync 제거 (Unit of Work 패턴 사용)
    }
}