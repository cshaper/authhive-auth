// File: authhive.auth/services/handlers/User/Features/UpdateRateLimitCacheHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - ❗️ 오류 해결 최종본]
// ❗️ IPlanRestrictionService가 IHealthCheckable을 구현함을 전제로 합니다.
// ❗️ GetRateLimitsForUserAsync 대신 GetNumericLimitAsync를 사용합니다.
// ❗️ IConnectedIdService를 사용하여 OrganizationId를 조회합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Auth.Service; // IPlanRestrictionService, IConnectedIdService
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService, IHealthCheckable
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Features;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// API 접근 권한 변경 시, IPlanRestrictionService에서 Rate Limit을 다시 조회하여
    /// 캐시를 업데이트합니다.
    /// </summary>
    public class UpdateRateLimitCacheHandler :
        IDomainEventHandler<ApiAccessChangedEvent>,
        IService // (IService는 IHealthCheckable을 포함)
    {
        private readonly ICacheService _cacheService;
        private readonly IPlanRestrictionService _planRestrictionService; // (IHealthCheckable을 구현)
        private readonly IConnectedIdService _connectedIdService; // (IService를 구현 가정)
        private readonly ILogger<UpdateRateLimitCacheHandler> _logger;
        private const string CACHE_KEY_PREFIX = "feature";

        // --- IDomainEventHandler 구현 ---
        public int Priority => 11; // 권한 캐시가 업데이트된 후 실행
        public bool IsEnabled => true;

        public UpdateRateLimitCacheHandler(
            ICacheService cacheService,
            IPlanRestrictionService planRestrictionService,
            IConnectedIdService connectedIdService,
            ILogger<UpdateRateLimitCacheHandler> logger)
        {
            _cacheService = cacheService;
            _planRestrictionService = planRestrictionService;
            _connectedIdService = connectedIdService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 권한 변경 시, 플랜 서비스에서 새 Rate Limit 규칙을 가져와 캐시를 갱신합니다.
        /// </summary>
        public async Task HandleAsync(ApiAccessChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                Guid organizationId = Guid.Empty;

                // (한글 주석) ❗️ 오류 수정 지점 1: OrganizationId를 행위자(ConnectedId)로부터 조회합니다.
                if (@event.ChangedByConnectedId.HasValue)
                {
                    // (가정) IConnectedIdService는 GetByIdAsync를 제공합니다.
                    var result = await _connectedIdService.GetByIdAsync(@event.ChangedByConnectedId.Value, cancellationToken);
                    if (result.IsSuccess && result.Data != null)
                    {
                        organizationId = result.Data.OrganizationId;
                    }
                }

                if (organizationId == Guid.Empty)
                {
                    // (한글 주석) ❗️ {UserId} 플레이스홀더를 추가하여 로깅 오류(CA2017)를 수정합니다.
                    _logger.LogWarning("Could not resolve OrganizationId from ChangedByConnectedId ({ConnectedId}) for UserId {UserId}. Rate limit cache NOT updated.",
            @event.ChangedByConnectedId, @event.UserId);
                    return;
                }

                // (한글 주석) ❗️ 오류 수정 지점 2: GetRateLimitsForUserAsync 대신 GetNumericLimitAsync를 사용합니다.
                var rateLimits = new Dictionary<string, int>();

                rateLimits["requests_per_minute"] = await _planRestrictionService.GetNumericLimitAsync(
                    organizationId, "requests_per_minute", 60, cancellationToken);

                rateLimits["requests_per_hour"] = await _planRestrictionService.GetNumericLimitAsync(
                    organizationId, "requests_per_hour", 1000, cancellationToken);

                // (한글 주석) Rate Limit은 'UserId'를 기준으로 적용되므로 캐시 키는 UserId를 사용합니다.
                var rateLimitKey = $"{CACHE_KEY_PREFIX}:ratelimit:{@event.UserId:N}";
                await _cacheService.SetAsync(rateLimitKey, rateLimits, TimeSpan.FromHours(1), cancellationToken);

                _logger.LogDebug("Rate limit cache updated for user {UserId} (Org: {OrganizationId}) via PlanService.", @event.UserId, organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update Rate Limit cache for user {UserId}.", @event.UserId);
            }
        }

        #region IService Implementation

        /// <summary>
        /// (한글 주석) 서비스 초기화 로직 (IService 구현)
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        /// <summary>
        /// (한글 주석) ❗️ 오류 수정 지점 3:
        /// IPlanRestrictionService가 IHealthCheckable을 구현하므로, 헬스 체크가 유효합니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // (가정) _cacheService와 _connectedIdService는 IService(IHealthCheckable 상속)를 구현.
            // (수정) _planRestrictionService는 IHealthCheckable을 구현.
            return IsEnabled &&
                   await _cacheService.IsHealthyAsync(cancellationToken) &&
                   await _connectedIdService.IsHealthyAsync(cancellationToken) &&
                   await _planRestrictionService.IsHealthyAsync(cancellationToken); // ❗️ 오류 해결
        }
        #endregion
    }
}