using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Events;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
// [수정] TokenRevokedEvent의 네임스페이스 변경을 반영
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Entities.Auth.Authentication;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 액세스 토큰 저장소 구현 - AuthHive v16
    /// AccessToken 엔티티에 대한 데이터베이스 작업을 처리합니다.
    /// </summary>
    public class AccessTokenRepository : BaseRepository<AccessToken>, IAccessTokenRepository
    {
        private readonly ILogger<AccessTokenRepository> _logger;
        private readonly IEventBus _eventBus;

        /// <summary>
        /// AccessTokenRepository의 생성자. 최신 아키텍처에 따라 의존성을 주입받습니다.
        /// </summary>
        public AccessTokenRepository(
            AuthDbContext context,
            ILogger<AccessTokenRepository> logger,
            IEventBus eventBus,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티(AccessToken)가 조직 범위인지 여부를 결정합니다.
        /// AccessToken은 OrganizationScopedEntity를 상속하므로 true를 반환하여 멀티테넌시 필터링을 강제합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region Access Token Operations

        /// <summary>
        /// 토큰의 해시(Hash) 값으로 AccessToken과 관련 엔티티들을 조회합니다.
        /// 사용: API 요청 헤더에 담긴 토큰을 검증하는 미들웨어에서 주로 사용됩니다.
        /// </summary>
        public async Task<AccessToken?> GetAccessTokenByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                throw new ArgumentException("Token hash cannot be empty", nameof(tokenHash));

            return await Query()
                .Include(t => t.OAuthProvider)
                .Include(t => t.ConnectedIdNavigation)
                .Include(t => t.Session)
                .Include(t => t.PlatformApplication)
                .FirstOrDefaultAsync(t => t.TokenHash == tokenHash &&
                                          t.IsActive &&
                                          !t.IsRevoked, cancellationToken);
        }

        /// <summary>
        /// 특정 사용자(ConnectedId)에게 발급된 모든 활성 토큰 목록을 조회합니다.
        /// 사용: "내 기기 관리" 페이지에서 현재 로그인된 세션 목록을 보여주거나, 보안상 특정 사용자의 모든 세션을 확인할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AccessToken>> GetActiveAccessTokensAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Include(t => t.OAuthProvider)
                .Include(t => t.Session)
                .Where(t => t.ConnectedId == connectedId &&
                            t.IsActive &&
                            !t.IsRevoked &&
                            t.ExpiresAt > now)
                .OrderByDescending(t => t.IssuedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 세션 ID에 속한 모든 토큰(활성/비활성 포함)을 조회합니다.
        /// 사용: 특정 세션의 전체 토큰 발급 이력을 확인하는 등 감사(Audit) 목적으로 사용될 수 있습니다.
        /// </summary>
        public async Task<IEnumerable<AccessToken>> GetAccessTokensBySessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(t => t.OAuthProvider)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.SessionId == sessionId)
                .OrderByDescending(t => t.IssuedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료되었지만 아직 정리되지 않은 토큰 목록을 조회합니다.
        /// 사용: 주기적으로 실행되는 백그라운드 클린업 작업(Cleanup Job)에서 삭제할 토큰 대상을 식별하기 위해 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AccessToken>> GetExpiredAccessTokensAsync(DateTime? since = null, CancellationToken cancellationToken = default)
        {
            var cutoffDate = since ?? DateTime.UtcNow.AddDays(-30);
            var now = DateTime.UtcNow;
            return await Query()
                .Where(t => t.ExpiresAt < now &&
                            t.ExpiresAt >= cutoffDate &&
                            !t.IsRevoked)
                .OrderBy(t => t.ExpiresAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 토큰의 사용 횟수를 1 증가시키고 마지막 사용 정보를 기록합니다.
        /// 사용: 토큰 검증이 성공한 직후 호출되어, 토큰 사용 통계 및 보안 감사 데이터를 업데이트합니다.
        /// </summary>
        public async Task IncrementAccessTokenUsageAsync(Guid tokenId, string? clientIp, CancellationToken cancellationToken = default)
        {
            var token = await GetByIdAsync(tokenId, cancellationToken);
            if (token == null)
            {
                _logger.LogWarning("Attempted to increment usage for non-existent token {TokenId}", tokenId);
                return;
            }

            token.UsageCount++;
            token.LastUsedAt = DateTime.UtcNow;
            token.LastUsedIP = clientIp;

            await UpdateAsync(token, cancellationToken);
        }

        /// <summary>
        /// 특정 토큰을 명시적으로 폐기(Revoke) 상태로 변경합니다.
        /// 사용: 사용자가 '로그아웃'하거나 관리자가 특정 세션을 '강제 종료'할 때 호출됩니다.
        /// </summary>
        public async Task RevokeAccessTokenAsync(Guid tokenId, string reason, DateTime? revokedAt = null, CancellationToken cancellationToken = default)
        {
            var token = await GetByIdAsync(tokenId, cancellationToken);
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

            await UpdateAsync(token, cancellationToken);
            _logger.LogInformation("Revoked access token {TokenId} for reason: {Reason}", tokenId, reason);
        }

        /// <summary>
        /// 특정 사용자(ConnectedId)의 모든 활성 토큰을 일괄 폐기합니다.
        /// 사용: '모든 기기에서 로그아웃', 사용자 계정 비활성화, 비밀번호 변경 시 보안을 위해 호출됩니다.
        /// </summary>
        public async Task<int> RevokeAllAccessTokensForConnectedIdAsync(Guid connectedId, string reason, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var affectedRows = await Query()
                .Where(t => t.ConnectedId == connectedId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    .SetProperty(t => t.UpdatedAt, now),
                    cancellationToken);
            
            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for ConnectedId {ConnectedId}. Reason: {Reason}", affectedRows, connectedId, reason);
            }
            return affectedRows;
        }

        /// <summary>
        /// 특정 세션(SessionId)에 속한 모든 활성 토큰을 일괄 폐기하고, 이벤트를 발행합니다.
        /// 사용: 특정 디바이스/브라우저에서의 로그아웃(세션 종료) 시 호출됩니다.
        /// </summary>
        public async Task<int> RevokeAllAccessTokensForSessionAsync(Guid sessionId, string reason, CancellationToken cancellationToken = default)
        {
            var tokenInfo = await Query()
                .Where(t => t.SessionId == sessionId && !t.IsRevoked)
                .Select(t => new { t.ConnectedId, t.OrganizationId })
                .FirstOrDefaultAsync(cancellationToken);

            if (tokenInfo == null)
            {
                _logger.LogInformation("No active tokens found for Session {SessionId} to revoke.", sessionId);
                return 0;
            }

            var now = DateTime.UtcNow;
            var affectedRows = await Query()
                .Where(t => t.SessionId == sessionId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    .SetProperty(t => t.UpdatedAt, now),
                    cancellationToken);
            
            if (affectedRows > 0)
            {
                string eventReason = $"Bulk revocation for session {sessionId}. Count: {affectedRows}. Reason: {reason}";
                await _eventBus.PublishAsync(new TokenRevokedEvent(
                        sessionId.ToString(),
                        tokenInfo.ConnectedId,
                        tokenInfo.OrganizationId,
                        eventReason
                    ), cancellationToken); 

                _logger.LogInformation("Revoked {Count} access tokens for Session {SessionId}. Reason: {Reason}", affectedRows, sessionId, reason);
            }
            return affectedRows;
        }

        /// <summary>
        /// 특정 OAuth Provider(OAuthProviderId)가 발급한 모든 활성 토큰을 일괄 폐기합니다.
        /// 사용: 연동된 서드파티 앱의 보안이 침해되었거나, 앱 연동을 해제할 때 해당 앱이 발급한 모든 토큰을 무효화하기 위해 사용됩니다.
        /// </summary>
        public async Task<int> RevokeAllAccessTokensForProviderAsync(Guid providerId, string reason, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var affectedRows = await Query()
                .Where(t => t.OAuthProviderId == providerId && !t.IsRevoked)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.IsActive, false)
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.RevokedReason, reason)
                    .SetProperty(t => t.UpdatedAt, now),
                    cancellationToken);

            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for Provider {ProviderId}. Reason: {Reason}", affectedRows, providerId, reason);
            }
            return affectedRows;
        }

        #endregion
    }
}

