// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/UpdateApiKeyUsageMetricsHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Interfaces.Infra.Monitoring; // IMetricsService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyUsedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Application API 키 사용 이벤트(Hot Path)를 처리하여 사용량 메트릭을 증가시킵니다.
    /// (감사 로그를 기록하지 않습니다 - 성능)
    /// </summary>
    public class UpdateApiKeyUsageMetricsHandler :
        IDomainEventHandler<ApplicationApiKeyUsedEvent>, // ❗️ 이름 변경된 이벤트
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IMetricsService _metricsService;
        private readonly ILogger<UpdateApiKeyUsageMetricsHandler> _logger;
        
        // 캐시 키 (예: "apikeys:usage:apiKeyId")
        private const string APIKEY_USAGE_KEY_FORMAT = "apikeys:usage:{0}";

        public int Priority => 1; // ❗️ 가장 빠르게 처리되어야 하는 Hot Path
        public bool IsEnabled => true;

        public UpdateApiKeyUsageMetricsHandler(
            ICacheService cacheService,
            IMetricsService metricsService,
            ILogger<UpdateApiKeyUsageMetricsHandler> logger)
        {
            _cacheService = cacheService;
            _metricsService = metricsService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyUsedEvent @event, CancellationToken cancellationToken = default)
        {
            var apiKeyId = @event.AggregateId;
            var cacheKey = string.Format(APIKEY_USAGE_KEY_FORMAT, apiKeyId);
            
            try
            {
                // 1. 캐시(Redis 등)를 사용하여 원자적(Atomic)으로 카운터 증가
                // ❗️ 지침 4 (ICacheService) 사용
                long newCount = await _cacheService.IncrementAsync(cacheKey, 1, cancellationToken);
                
                // 2. 메트릭 서비스(Prometheus/Datadog 등)에 카운터 보고
                // ❗️ 지침 6 (RateLimiterService 등) 관련: 이 메트릭을 기반으로 속도 제한 수행
                await _metricsService.IncrementAsync("auth.apikey.usage.total", 1, cancellationToken);
                await _metricsService.IncrementAsync($"auth.apikey.usage.endpoint.{SanitizeMetricLabel(@event.Endpoint)}", 1, cancellationToken);

                // (선택적) 특정 횟수마다 DB에 저장
                if (newCount % 100 == 0) // 예: 100번 호출마다
                {
                     _logger.LogInformation("API Key {ApiKeyId} usage reached {Count}. (DB flush point)", apiKeyId, newCount);
                     // TODO: IUnitOfWork와 Repository를 사용하여 DB에 사용량 업데이트 (배치 작업 권장)
                }
            }
            catch (Exception ex)
            {
                // Hot Path 이벤트 핸들러는 절대 실패(throw)하면 안 됨.
                _logger.LogError(ex, "Failed to update API key usage metrics for ApiKeyId: {ApiKeyId}", apiKeyId);
            }
        }

        private string SanitizeMetricLabel(string label)
        {
            // Prometheus 등 메트릭 시스템에 맞게 레이블 정규화
            return string.IsNullOrEmpty(label) ? "unknown" : System.Text.RegularExpressions.Regex.Replace(label.ToLowerInvariant(), @"[^a-z0-9_:]+", "_");
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}