using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Auth.Events;


// using AuthHive.Core.Interfaces.Organization.Service; // 다른 곳에서 사용하지 않는다면, 이 줄을 삭제하거나 주석 처리하는 것이 좋습니다.
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
        private readonly IEventBus _eventBus;

        /// <summary>
        /// AccessTokenRepository의 생성자. 의존성 주입(DI)을 통해 필수 객체들을 주입받습니다.
        /// BaseRepository는 멀티테넌시와 캐싱 처리를 위해 Context와 CacheService만 요구합니다.
        /// IOrganizationContext는 BaseRepository의 쿼리 필터링에 사용된다고 가정합니다.
        /// </summary>
        public AccessTokenRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AccessTokenRepository> logger, // 1. 필수
            IEventBus eventBus,                   // 2. 필수
            ICacheService? cacheService = null) //
            : base(context, cacheService)
        {
            // BaseRepository가 ILogger를 받지 않으므로 여기서 할당
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
        }

        #region Access Token Operations
        /// <summary>
        /// BaseRepository<TEntity>의 추상 멤버를 구현합니다.
        /// 이 메서드는 BaseRepository가 쿼리를 실행할 때, 해당 엔티티가 조직 스코프(Scope)를 가져야 하는지 결정합니다.
        /// </summary>
        /// <returns>AccessToken은 ConnectedId를 통해 조직에 종속되므로 true를 반환하여 멀티테넌시 필터링을 강제합니다.</returns>
        protected override bool IsOrganizationScopedEntity()
        {
            // AccessToken은 ConnectedId를 통해 조직에 종속되므로 true를 반환합니다.
            return true;
        }

        /// <summary>
        /// 토큰의 해시(Hash) 값을 사용하여 AccessToken 엔티티와 관련 종속 항목(Client, Session 등)을 조회합니다.
        /// 이 메서드는 주로 토큰 검증(Validation) 플로우에서 사용됩니다.
        /// </summary>
        public async Task<AccessToken?> GetAccessTokenByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
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
                                            !t.IsRevoked, cancellationToken);
        }

        /// <summary>
        /// 특정 연결 ID(ConnectedId)를 가진 사용자에게 발급된 현재 활성화된(만료되지 않고 폐기되지 않은) 모든 AccessToken 목록을 조회합니다.
        /// </summary>
        /// <remarks>
        /// **사용 플로우:** 보안 검사 (예: 동시 로그인 제한, 특정 디바이스의 토큰 목록 제공) 시 사용됩니다.
        /// 토큰의 Client 및 Session 정보를 함께 포함(Include)하여 추가적인 DB 조회 없이 관련 정보를 제공합니다.
        /// </remarks>
        /// <param name="connectedId">토큰을 발급받은 사용자 또는 서비스의 고유 식별자.</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰. 장기 실행 쿼리 시 리소스 낭비를 방지합니다.</param>
        /// <returns>활성화된 AccessToken 엔티티 목록.</returns>
        public async Task<IEnumerable<AccessToken>> GetActiveAccessTokensAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await Query()
              .Include(t => t.Client)
              .Include(t => t.Session)
                      // 1. ConnectedId로 필터링 (BaseRepository에서 조직 스코프 필터링이 추가됨)
                      .Where(t => t.ConnectedId == connectedId &&
                     t.IsActive &&         // 활성화 상태여야 함
                                    !t.IsRevoked &&      // 명시적으로 폐기되지 않았어야 함
                                    t.ExpiresAt > now)   // 만료 시간이 현재 시각보다 미래여야 함
                      .OrderByDescending(t => t.IssuedAt) // 최신 발급 토큰 순으로 정렬
                      .ToListAsync(cancellationToken); // 
        }

        public async Task<IEnumerable<AccessToken>> GetAccessTokensBySessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(t => t.Client)
                .Include(t => t.ConnectedIdNavigation)
                .Where(t => t.SessionId == sessionId)
                .OrderByDescending(t => t.IssuedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료되었지만 아직 폐기되지 않은 AccessToken 목록을 조회합니다.
        /// 이 메서드는 주로 백그라운드 작업(Cleanup Job)이나 보안 감사 목적으로 사용됩니다.
        /// </summary>
        /// <remarks>
        /// **사용 플로우:** 데이터베이스 클렌징 작업에서 호출됩니다. 
        /// 반환된 토큰들은 이후 물리적인 삭제(Cleanup) 대상이 됩니다.
        /// </remarks>
        /// <param name="since">만료 시각(ExpiresAt)이 이 시점 이후인 토큰들만 조회합니다. (기본값: 30일 전)</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
        /// <returns>만료된 AccessToken 엔티티 목록.</returns>
        public async Task<IEnumerable<AccessToken>> GetExpiredAccessTokensAsync(DateTime? since = null, CancellationToken cancellationToken = default)
        {
            // 쿼리 시작 시점을 설정합니다. since가 없으면 기본값으로 지난 30일 동안 만료된 토큰을 대상으로 합니다.
            var cutoffDate = since ?? DateTime.UtcNow.AddDays(-30);
            var now = DateTime.UtcNow;

            return await Query()
              .Where(t => t.ExpiresAt < now &&     // 1. 이미 만료 시각이 지난 토큰
                                    t.ExpiresAt >= cutoffDate && // 2. (since 조건) 특정 시점 이후에 만료된 토큰 (너무 오래된 토큰은 이미 삭제되었을 수 있음)
                                    !t.IsRevoked)        // 3. (Revoked와 구분) 명시적 폐기(Revoked)가 아닌 '시간 만료'로 상태가 종료된 토큰
                      .OrderBy(t => t.ExpiresAt)
              .ToListAsync(cancellationToken);
        }

        /// <summary>
                /// 특정 AccessToken의 사용 횟수를 증가시키고 마지막 사용 시각 및 IP를 갱신합니다.
                /// </summary>
                /// <remarks>
                /// **사용 플로우:** 토큰 검증(Validation)이 성공한 직후 호출되어, 해당 토큰이 실제로 사용되었음을 기록합니다. 
                /// 이 정보는 보안 감사 및 Rate Limit, 비정상적인 사용 패턴 감지(Fraud Detection)의 기초 데이터로 활용됩니다.
                /// 💡 **아키텍처 개선:** 클라이언트 IP는 Repository 외부(Service 계층)에서 HttpContext를 통해 받아 전달됩니다.
                /// </remarks>
                /// <param name="tokenId">사용량을 증가시킬 AccessToken의 ID.</param>
                /// <param name="clientIp">요청을 보낸 클라이언트의 IP 주소.</param>
                /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
        public async Task IncrementAccessTokenUsageAsync(Guid tokenId, string? clientIp, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetByIdAsync에도 CancellationToken을 전달합니다.
            var token = await GetByIdAsync(tokenId, cancellationToken);
            if (token == null)
            {
                _logger.LogWarning("Attempted to increment usage for non-existent token {TokenId}", tokenId);
                return;
            }

            token.UsageCount++;
            token.LastUsedAt = DateTime.UtcNow;
            // 💡 GetClientIpAddress() 호출 대신, 서비스 레이어에서 받은 clientIp 인자를 사용합니다.
            token.LastUsedIP = clientIp;

            // BaseRepository의 UpdateAsync에도 CancellationToken을 전달합니다.
            await UpdateAsync(token, cancellationToken);
        }

        /// <summary>
        /// 특정 AccessToken을 명시적으로 폐기(Revoke) 상태로 변경합니다.
        /// </summary>
        /// <remarks>
        /// **사용 플로우:** 사용자 스스로 로그아웃하거나, 관리자가 특정 세션을 강제 종료할 때, 또는 보안 침해 감지 시스템에 의해 호출됩니다.
        /// IsRevoked 플래그를 true로 변경하고, IsActive를 false로 설정하여 즉시 토큰 사용을 불가능하게 합니다.
        /// </remarks>
        /// <param name="tokenId">폐기할 AccessToken의 ID.</param>
        /// <param name="reason">토큰이 폐기된 이유(보안 감사 기록용).</param>
        /// <param name="revokedAt">폐기 시각 (미지정 시 현재 UTC 시각 사용).</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
        public async Task RevokeAccessTokenAsync(Guid tokenId, string reason, DateTime? revokedAt = null, CancellationToken cancellationToken = default)
        {
            var token = await GetByIdAsync(tokenId, cancellationToken); // CancellationToken 전달
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

            await UpdateAsync(token, cancellationToken); // CancellationToken 전달
            _logger.LogInformation("Revoked access token {TokenId} for reason: {Reason}", tokenId, reason);
        }
        /// <summary>
                /// 특정 사용자(ConnectedId)와 연결된 모든 활성 토큰을 데이터베이스에서 직접 대량 폐기(Revoke)합니다.
                /// </summary>
                /// <remarks>
                /// **사용 플로우:** 사용자 비밀번호 변경, 계정 비활성화 또는 관리자에 의한 강제 로그아웃 등 계정 레벨의 보안 이벤트 발생 시 사용됩니다.
                /// ExecuteUpdateAsync를 사용하여 DB에서 단일 쿼리로 처리하므로 성능이 뛰어납니다.
                /// </remarks>
                /// <param name="connectedId">토큰을 소유한 사용자의 ID.</param>
                /// <param name="reason">폐기 이유.</param>
                /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
                /// <returns>폐기된 토큰의 수.</returns>
        public async Task<int> RevokeAllAccessTokensForConnectedIdAsync(Guid connectedId, string reason, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // ExecuteUpdateAsync를 사용하여 DB에서 직접 업데이트 실행 (성능 최적화)
            var affectedRows = await Query()
        .Where(t => t.ConnectedId == connectedId && !t.IsRevoked)
        .ExecuteUpdateAsync(updates => updates
          .SetProperty(t => t.IsRevoked, true)
          .SetProperty(t => t.IsActive, false)
          .SetProperty(t => t.RevokedAt, now)
          .SetProperty(t => t.RevokedReason, reason)
                    // AuditableEntity의 UpdatedAt도 수동으로 갱신해주는 것이 좋습니다.
                    .SetProperty(t => t.UpdatedAt, now)
        , cancellationToken); // 👈 CancellationToken 전달
        
            if (affectedRows > 0)
            {
                _logger.LogInformation("Revoked {Count} access tokens for ConnectedId {ConnectedId}. Reason: {Reason}",
                  affectedRows, connectedId, reason);
            }

            return affectedRows;
        }

        /// <summary>
                /// 특정 세션(SessionId)과 연결된 모든 활성 토큰을 데이터베이스에서 대량 폐기하고 이벤트를 발행합니다.
                /// </summary>
                /// <remarks>
                /// **사용 플로우:** 세션 만료 또는 세션 강제 종료 시 사용됩니다. ConnectedId 조회는 이벤트 발행 시 AggregateId로 사용됩니다.
                /// </remarks>
                /// <param name="sessionId">토큰들이 속한 세션의 ID.</param>
                /// <param name="reason">폐기 이유.</param>
                /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
                /// <returns>폐기된 토큰의 수.</returns>
        public async Task<int> RevokeAllAccessTokensForSessionAsync(Guid sessionId, string reason, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // 1. 이벤트 발행에 사용할 ConnectedId를 찾습니다. (이벤트의 Aggregate Root ID로 사용)
            var connectedId = await Query()
        .Where(t => t.SessionId == sessionId && !t.IsRevoked)
        .Select(t => (Guid?)t.ConnectedId)
        .FirstOrDefaultAsync(cancellationToken); 

            // 2. ExecuteUpdateAsync를 사용하여 DB에서 직접 대량 업데이트를 실행합니다 (비용 최적화).
            var affectedRows = await Query()
        .Where(t => t.SessionId == sessionId && !t.IsRevoked)
        .ExecuteUpdateAsync(updates => updates
          .SetProperty(t => t.IsRevoked, true)
          .SetProperty(t => t.IsActive, false)
          .SetProperty(t => t.RevokedAt, now)
          .SetProperty(t => t.RevokedReason, reason)
          .SetProperty(t => t.UpdatedAt, now)
        , cancellationToken);
            if (affectedRows > 0)
            {
                // ⭐️ IEventBus 발행: 세션별 토큰 폐기 이벤트.
                // 연결된 시스템(예: 캐시 서비스)에 폐기 사실을 알려 캐시를 무효화하는 등의 후속 조치를 취하도록 합니다.
                await _eventBus.PublishAsync(new TokenRevokedEvent(
          connectedId.GetValueOrDefault(Guid.Empty), // ConnectedId를 AggregateId로 사용
          Guid.Empty,
          $"Bulk revocation for session {sessionId}. Count: {affectedRows}. Reason: {reason}"),
                    cancellationToken); 
                _logger.LogInformation("Revoked {Count} access tokens for Session {SessionId}. Reason: {Reason}",
          affectedRows, sessionId, reason);
            }

            return affectedRows;
        }

        /// <summary>
        /// 특정 클라이언트 애플리케이션(ClientId)에 의해 발급된 모든 활성 토큰을 데이터베이스에서 대량 폐기합니다.
        /// </summary>
        /// <remarks>
        /// **사용 플로우:** 클라이언트(예: 모바일 앱, 웹 서비스)의 보안이 손상되었거나, 해당 클라이언트 ID를 비활성화할 때 사용됩니다.
        /// 해당 클라이언트가 발급한 모든 토큰을 한 번에 무효화하는 강력한 보안 조치입니다.
        /// </remarks>
        /// <param name="clientId">토큰을 발급한 클라이언트 애플리케이션의 ID.</param>
        /// <param name="reason">폐기 이유.</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
        /// <returns>폐기된 토큰의 수.</returns>
        public async Task<int> RevokeAllAccessTokensForClientAsync(Guid clientId, string reason, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            var affectedRows = await Query()
              .Where(t => t.ClientId == clientId && !t.IsRevoked)
              .ExecuteUpdateAsync(updates => updates
                .SetProperty(t => t.IsRevoked, true)
                .SetProperty(t => t.IsActive, false)
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.RevokedReason, reason)
                .SetProperty(t => t.UpdatedAt, now) // AuditableEntity 속성 갱신
                      , cancellationToken); // 👈 CancellationToken 전달

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