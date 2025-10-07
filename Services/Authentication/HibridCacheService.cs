// Path: AuthHive.Auth.Services/HybridCacheService.cs (or similar infrastructure path)
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common.Cache;

// 사용자가 지정한 네임스페이스
namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 하이브리드 캐시 서비스 구현체 (로컬 인-메모리 + 분산 캐시)
    /// ICacheService의 저수준 기술 구현을 담당합니다.
    /// Cache-Aside 패턴을 사용하여 로컬 캐시의 성능과 분산 캐시의 일관성을 모두 확보합니다.
    /// </summary>
    public class HybridCacheService : ICacheService
    {
        private readonly IMemoryCache _memoryCache;
        private readonly IDistributedCache _distributedCache;
        private readonly ILogger<HybridCacheService> _logger;
        private readonly JsonSerializerOptions _jsonSerializerOptions = new() { PropertyNameCaseInsensitive = true };

        public HybridCacheService(
            IMemoryCache memoryCache,
            IDistributedCache distributedCache,
            ILogger<HybridCacheService> logger)
        {
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation (건강 상태 확인 및 초기화)

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 메모리 캐시 테스트
                var testKey = $"health_check_mem_{Guid.NewGuid()}";
                _memoryCache.Set(testKey, "test", TimeSpan.FromSeconds(1));
                _memoryCache.Remove(testKey);

                // 분산 캐시 테스트 (Read/Write)
                var distributedTestKey = $"health_check_dist_{Guid.NewGuid()}";
                await _distributedCache.SetStringAsync(distributedTestKey, "test",
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(1) });
                await _distributedCache.RemoveAsync(distributedTestKey);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Hybrid cache health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("HybridCacheService initialized and ready.");
            return Task.CompletedTask;
        }

        #endregion

        #region 기본 캐시 작업

        /// <summary>
        /// 캐시 조회 (Hybrid Strategy: MemoryCache -> DistributedCache)
        /// </summary>
        public async Task<T?> GetAsync<T>(string key) where T : class
        {
            // 1. Memory Cache에서 조회 시도 (가장 빠름)
            if (_memoryCache.TryGetValue<T>(key, out var value) && value != null)
            {
                return value;
            }

            // 2. Memory Cache Miss. Distributed Cache에서 조회 시도
            try
            {
                var json = await _distributedCache.GetStringAsync(key);
                if (!string.IsNullOrEmpty(json))
                {
                    var distributedValue = JsonSerializer.Deserialize<T>(json, _jsonSerializerOptions);

                    if (distributedValue != null)
                    {
                        // 3. Distributed Cache Hit. Memory Cache에 다시 채워넣음 (Cache-Aside)
                        // DistributedCache는 TTL 정보가 없으므로, 기본 TTL 또는 적절한 TTL로 설정
                        // 실제 운영 환경에서는 TTL 관리가 필요
                        _memoryCache.Set(key, distributedValue, TimeSpan.FromMinutes(5));
                        return distributedValue;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get value from Distributed Cache for key: {Key}", key);
                // 분산 캐시 조회 실패 시 null 반환하여 DB로 폴백 유도
            }

            return null;
        }

        /// <summary>
        /// 캐시 저장 (Write-Through Strategy: MemoryCache + DistributedCache)
        /// </summary>
        public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null) where T : class
        {
            if (value == null) return;

            // 기본 TTL 설정
            var ttl = expiration ?? TimeSpan.FromMinutes(5);

            // 1. Memory Cache에 저장
            _memoryCache.Set(key, value, ttl);

            // 2. Distributed Cache에 저장
            try
            {
                var json = JsonSerializer.Serialize(value, _jsonSerializerOptions);
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                };
                await _distributedCache.SetStringAsync(key, json, options);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set value to Distributed Cache for key: {Key}", key);
            }
        }

        /// <summary>
        /// 캐시 키 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(string key)
        {
            if (_memoryCache.TryGetValue(key, out _))
            {
                return true;
            }

            try
            {
                // 분산 캐시는 GetStringAsync의 오버헤드를 줄이기 위해 GetAsync를 사용해 존재 여부만 확인
                var result = await _distributedCache.GetAsync(key);
                return result != null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check existence in Distributed Cache for key: {Key}", key);
                return false;
            }
        }

        /// <summary>
        /// 캐시 제거 (Both Caches)
        /// </summary>
        public async Task RemoveAsync(string key)
        {
            _memoryCache.Remove(key);
            try
            {
                await _distributedCache.RemoveAsync(key);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove key from Distributed Cache: {Key}", key);
            }
        }

        /// <summary>
        /// 패턴 기반 캐시 제거 (Distributed Cache만 지원 가능)
        /// Memory Cache는 패턴 제거가 불가능하며, 분산 캐시에 의존합니다.
        /// </summary>
        public Task RemoveByPatternAsync(string pattern)
        {
            // 경고: IDistributedCache 인터페이스는 패턴 기반 삭제를 지원하지 않습니다. 
            // 실제 구현 시 Redis/Memcached 전용 클라이언트(예: StackExchange.Redis)를 사용해야 합니다.
            // 여기서는 경고 로그만 남깁니다.
            _logger.LogWarning("RemoveByPatternAsync called. This operation is not natively supported by IDistributedCache. Requires underlying client implementation for pattern: {Pattern}", pattern);
            return Task.CompletedTask;
        }

        #endregion

        #region 원자적 작업 (Distributed Cache 의존)

        public async Task<T> GetOrSetAsync<T>(string key, Func<Task<T>> factory, TimeSpan? expiration = null) where T : class
        {
            // Hybrid Get 시도
            var cachedValue = await GetAsync<T>(key);
            if (cachedValue != null)
            {
                return cachedValue;
            }

            // 캐시 미스: factory 실행
            var newValue = await factory();
            await SetAsync(key, newValue, expiration);
            return newValue;
        }

        /// <summary>
        /// 증가 (분산 캐시 의존)
        /// </summary>
        public async Task<long> IncrementAsync(string key, long value = 1)
        {
            // IDistributedCache는 Increment를 지원하지 않으므로, 
            // Redis/Memcached 전용 클라이언트를 사용해야 합니다.
            _logger.LogWarning("IncrementAsync requires direct access to distributed cache client (e.g., Redis). Defaulting to a simplified, non-atomic operation (DANGEROUS).");

            // 비원자적(non-atomic) 구현 예시 (운영 환경에서는 절대 비추천)
            var currentBytes = await _distributedCache.GetAsync(key);
            long currentValue = 0;
            if (currentBytes != null && currentBytes.Length > 0)
            {
                if (long.TryParse(Encoding.UTF8.GetString(currentBytes), out var parsed))
                {
                    currentValue = parsed;
                }
            }
            long newValue = currentValue + value;
            await _distributedCache.SetStringAsync(key, newValue.ToString());

            // MemoryCache에서 제거하여 다음 조회 시 분산 캐시에서 읽어오도록 강제
            _memoryCache.Remove(key);

            return newValue;
        }

        /// <summary>
        /// 감소 (IncrementAsync와 동일)
        /// </summary>
        public Task<long> DecrementAsync(string key, long value = 1) => IncrementAsync(key, -value);

        #endregion

        #region 분산 락, 벌크 작업, 캐시 관리 (분산 캐시 의존)

        // 분산 락: IDistributedCache는 분산 락을 직접 제공하지 않습니다.
        // StackExchange.Redis의 RedisLock 같은 전용 클라이언트를 사용해야 합니다.
        public Task<bool> AcquireLockAsync(string key, string value, TimeSpan expiration)
        {
            _logger.LogWarning("AcquireLockAsync requires direct access to distributed cache client (e.g., Redis SET NX). Returning false (not acquired) as a safe fallback.");
            return Task.FromResult(false);
        }
        public Task<bool> ReleaseLockAsync(string key, string value) => Task.FromResult(true);
        public Task<bool> ExtendLockAsync(string key, string value, TimeSpan expiration) => Task.FromResult(true);

        // 벌크 작업
        public async Task<IDictionary<string, T?>> GetMultipleAsync<T>(IEnumerable<string> keys) where T : class
        {
            // GetAsync를 병렬로 실행하는 것으로 대체 (최적화는 전용 클라이언트에서)
            var results = await Task.WhenAll(keys.Select(key => GetAsync<T>(key)));
            return keys.Zip(results, (k, v) => new { Key = k, Value = v })
                       .ToDictionary(x => x.Key, x => x.Value);
        }
        public async Task SetMultipleAsync<T>(IDictionary<string, T> items, TimeSpan? expiration = null) where T : class
        {
            await Task.WhenAll(items.Select(kvp => SetAsync(kvp.Key, kvp.Value, expiration)));
        }
        public async Task RemoveMultipleAsync(IEnumerable<string> keys)
        {
            await Task.WhenAll(keys.Select(key => RemoveAsync(key)));
        }

        // 캐시 관리
        public Task FlushAsync()
        {
            // 경고: IDistributedCache 인터페이스는 FLUSHALL 명령을 제공하지 않습니다.
            // Memory Cache도 강제 초기화가 불가능합니다.
            _logger.LogWarning("FlushAsync called. This operation is not safely supported by IDistributedCache. Requires underlying client (e.g., Redis FLUSHALL) or a custom MemoryCache hack.");

            // Memory Cache는 .NET 6+ 버전에서 캐시 엔트리를 저장하는 내부 필드를 리플렉션으로 접근해야
            // 초기화가 가능하지만, 이는 권장되지 않습니다. 분산 캐시만 플러시 가능하도록 안내합니다.
            return Task.CompletedTask;
        }

        public Task<CacheStatistics> GetStatisticsAsync()
        {
            // IDistributedCache는 통계를 제공하지 않으므로, 더미 데이터 반환
            var stats = new CacheStatistics
            {
                ServiceName = "HybridCache",
                CacheType = "Hybrid (InMemory + Distributed)",
                StatsPeriodStart = DateTime.MinValue,
                StatsPeriodEnd = DateTime.UtcNow,
                TotalHits = 0, // 실제 통계 로깅 시스템(e.g., Prometheus) 필요
                TotalMisses = 0,
                HitRate = 0.0,
                TotalEntries = 0 // 정확한 카운트는 분산 캐시 클라이언트에 종속됨
            };
            _logger.LogInformation("GetStatisticsAsync provides dummy data. Real statistics require dedicated client integration (e.g., Redis STATS).");
            return Task.FromResult(stats);
        }

        #endregion
        #region String-specific cache operations

        /// <summary>
        /// 캐시에서 문자열 값을 가져옵니다.
        /// </summary>
        public async Task<string?> GetStringAsync(string key)
        {
            // 1. Memory Cache에서 조회 시도
            if (_memoryCache.TryGetValue<string>(key, out var value) && value != null)
            {
                return value;
            }

            // 2. Distributed Cache에서 조회 시도
            try
            {
                var distributedValue = await _distributedCache.GetStringAsync(key);
                if (!string.IsNullOrEmpty(distributedValue))
                {
                    // 3. Memory Cache에 다시 채워넣음 (Cache-Aside)
                    _memoryCache.Set(key, distributedValue, TimeSpan.FromMinutes(5));
                    return distributedValue;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get string value from Distributed Cache for key: {Key}", key);
            }

            return null;
        }

        /// <summary>
        /// 문자열 값을 캐시에 저장합니다. (값 타입 저장용)
        /// </summary>
        public async Task SetStringAsync(string key, string value, TimeSpan? expiration = null)
        {
            if (string.IsNullOrEmpty(value)) return;

            // 기본 TTL 설정
            var ttl = expiration ?? TimeSpan.FromMinutes(5);

            // 1. Memory Cache에 저장
            _memoryCache.Set(key, value, ttl);

            // 2. Distributed Cache에 저장
            try
            {
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                };
                await _distributedCache.SetStringAsync(key, value, options);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set string value to Distributed Cache for key: {Key}", key);
            }
        }

        #endregion
    }
}