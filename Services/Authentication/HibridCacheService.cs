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

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Memory Cache 테스트는 동기이므로 CancellationToken 사용 안 함
                var testKey = $"health_check_mem_{Guid.NewGuid()}";
                _memoryCache.Set(testKey, "test", TimeSpan.FromSeconds(1));
                _memoryCache.Remove(testKey);

                // 분산 캐시 테스트 (Read/Write)
                var distributedTestKey = $"health_check_dist_{Guid.NewGuid()}";
                var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(1) };

                // ✅ DistributedCache 메서드에 CancellationToken 전달
                await _distributedCache.SetStringAsync(distributedTestKey, "test", options, cancellationToken);
                await _distributedCache.RemoveAsync(distributedTestKey, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Hybrid cache health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) // ✅ CancellationToken 추가
        {
            _logger.LogInformation("HybridCacheService initialized and ready.");
            return Task.CompletedTask;
        }
        #endregion

        #region 기본 캐시 작업

        /// <summary>
        /// 캐시 조회 (Hybrid Strategy: MemoryCache -> DistributedCache)
        /// </summary>
        public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class
        {
            // 1. Memory Cache에서 조회 시도 (가장 빠름)
            if (_memoryCache.TryGetValue<T>(key, out var value) && value != null)
            {
                return value;
            }

            // 2. Memory Cache Miss. Distributed Cache에서 조회 시도
            try
            {
                var json = await _distributedCache.GetStringAsync(key, cancellationToken);
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
        public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
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
                // ✅ CancellationToken 전달
                await _distributedCache.SetStringAsync(key, json, options, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set value to Distributed Cache for key: {Key}", key);
            }
        }

        /// <summary>
        /// 캐시 키 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(string key, CancellationToken cancellationToken = default)
        {
            if (_memoryCache.TryGetValue(key, out _))
            {
                return true;
            }

            try
            {
                // 분산 캐시는 GetStringAsync의 오버헤드를 줄이기 위해 GetAsync를 사용해 존재 여부만 확인
                var result = await _distributedCache.GetAsync(key, cancellationToken);
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
        public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            _memoryCache.Remove(key);
            try
            {    // 2. Distributed Cache에서 제거
                await _distributedCache.RemoveAsync(key, cancellationToken);
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
        public async Task RemoveByPatternAsync(string pattern, CancellationToken cancellationToken = default)
        {
            // 경고: IDistributedCache 인터페이스는 패턴 기반 삭제를 지원하지 않습니다. 
            // 실제 구현 시 Redis/Memcached 전용 클라이언트(예: StackExchange.Redis)를 사용해야 합니다.
            // 여기서는 경고 로그만 남깁니다.
            //// TODO [SaaS 품질 개선]: ICacheService 인터페이스를 구현하는 Redis 전용 클라이언트(예: StackExchange.Redis)를 도입하여 PATTERN 기반 삭제 기능을 구현해야 합니다. 
            ///현재 IDistributedCache는 이를 지원하지 않아 분산 캐시에서 키가 남아있을 수 있습니다.
            _logger.LogWarning("RemoveByPatternAsync called. This operation is not natively supported by IDistributedCache. Requires underlying client implementation for pattern: {Pattern}", pattern);
            await Task.CompletedTask;
        }

        #endregion

        #region 원자적 작업 (Distributed Cache 의존)

        public async Task<T> GetOrSetAsync<T>(string key, Func<Task<T>> factory, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
        {
            // Hybrid Get 시도
            var cachedValue = await GetAsync<T>(key, cancellationToken);
            if (cachedValue != null)
            {
                return cachedValue;
            }

            // 캐시 미스: factory 실행
            var newValue = await factory();
            await SetAsync(key, newValue, expiration, cancellationToken); // ✅ CancellationToken 전달
            return newValue;

        }

        /// <summary>
        /// 증가 (분산 캐시 의존)
        /// </summary>
        public async Task<long> IncrementAsync(string key, long value = 1, CancellationToken cancellationToken = default)
        {
            // IDistributedCache는 Increment를 지원하지 않으므로, 
            // Redis/Memcached 전용 클라이언트를 사용해야 합니다.
            // TODO [SaaS 품질 개선]: 이 로직은 두 번의 I/O를 수행하여 원자적이지 않습니다. Redis의 INCRBY와 같은 원자적 명령을 직접 지원하는 분산 캐시 클라이언트로 대체해야 합니다. 현재는 데이터 정합성 문제가 발생할 수 있습니다.

            _logger.LogWarning("IncrementAsync requires direct access to distributed cache client (e.g., Redis). Defaulting to a simplified, non-atomic operation (DANGEROUS).");

            // 비원자적(non-atomic) 구현 예시 (운영 환경에서는 절대 비추천)
            var currentBytes = await _distributedCache.GetAsync(key, cancellationToken);
            long currentValue = 0; // 1. 초기값 선언
            if (currentBytes != null && currentBytes.Length > 0)
            {
                // 2. 바이트 배열을 문자열로 변환 (분산 캐시는 보통 문자열로 저장)
                var currentString = System.Text.Encoding.UTF8.GetString(currentBytes);

                // 3. 문자열을 long 타입 숫자로 파싱 (파싱 실패 방지를 위해 TryParse 사용 권장)
                if (long.TryParse(currentString, out long parsedValue))
                {
                    currentValue = parsedValue;
                }
            }
            long newValue = currentValue + value;
            await _distributedCache.SetStringAsync(key, newValue.ToString(), cancellationToken);

            // MemoryCache에서 제거하여 다음 조회 시 분산 캐시에서 읽어오도록 강제
            _memoryCache.Remove(key);

            return newValue;
        }

        /// <summary>
        /// 감소 (IncrementAsync와 동일)
        /// </summary>
        public Task<long> DecrementAsync(string key, long value = 1, CancellationToken cancellationToken = default) => IncrementAsync(key, -value, cancellationToken);

        #endregion

        #region 분산 락, 벌크 작업, 캐시 관리 (분산 캐시 의존)

        // 분산 락: IDistributedCache는 분산 락을 직접 제공하지 않습니다.
        // StackExchange.Redis의 RedisLock 같은 전용 클라이언트를 사용해야 합니다.
        public async Task<bool> AcquireLockAsync(
              string key,
              string value, // 락 소유자 식별자 (예: GUID)
              TimeSpan expiry, // 락 유지 시간
              CancellationToken cancellationToken = default)
        {
            // ------------------------------------------------------------
            // [TODO] 
            //경고: IDistributedCache는 분산 잠금을 직접 지원하지 않습니다.
            // 분산 잠금(Distributed Lock)의 원자성을 보장하려면 Redis의 
            // SET NX EX(SETNX)와 같은 원자적 명령을 직접 사용해야 합니다.
            // ------------------------------------------------------------

            _logger.LogWarning("AcquireLockAsync is not natively atomic with IDistributedCache. Consider using a dedicated distributed locking library (e.g., RedLock.net) or direct Redis client access for production.");

            // 분산 잠금을 흉내내는 비원자적 로직 예시 (운영 환경 비추천)
            // 1. 해당 키가 존재하는지 확인
            var existingValue = await _distributedCache.GetAsync(key, cancellationToken);

            if (existingValue == null)
            {
                // 2. 키가 없으면 (락이 없으면) 락을 설정
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = expiry // 만료 시간 설정
                };

                // value를 바이트 배열로 변환
                var valueBytes = System.Text.Encoding.UTF8.GetBytes(value);

                // SetAsync는 이미 존재하는 키를 덮어씁니다. (비원자적 문제 발생 가능성 있음)
                await _distributedCache.SetAsync(key, valueBytes, options, cancellationToken);

                // 🌟 Redis의 SETNX 명령이 아니므로, 동시성 문제가 발생할 수 있습니다.
                return true;
            }

            // 락을 획득하지 못함 (다른 곳에서 이미 락을 소유)
            return false;
        }
        public Task<bool> ReleaseLockAsync(string key, string value, CancellationToken cancellationToken = default) => Task.FromResult(true); // ✅ CancellationToken 추가
        public Task<bool> ExtendLockAsync(string key, string value, TimeSpan expiration, CancellationToken cancellationToken = default) => Task.FromResult(true); // ✅ CancellationToken 추가

        // 벌크 작업
        public async Task<IDictionary<string, T?>> GetMultipleAsync<T>(IEnumerable<string> keys, CancellationToken cancellationToken = default) where T : class
        {
            // GetAsync를 병렬로 실행하는 것으로 대체 (최적화는 전용 클라이언트에서)
            var tasks = keys.Select(key => GetAsync<T>(key, cancellationToken));
            var results = await Task.WhenAll(tasks);
            return keys.Zip(results, (k, v) => new { Key = k, Value = v })
                       .ToDictionary(x => x.Key, x => x.Value);
        }
        public async Task SetMultipleAsync<T>(IDictionary<string, T> items, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class // ✅ CancellationToken 추가
        {
            // ✅ 모든 병렬 작업에 CancellationToken 전달
            await Task.WhenAll(items.Select(kvp => SetAsync(kvp.Key, kvp.Value, expiration, cancellationToken)));
        }
        public async Task RemoveMultipleAsync(IEnumerable<string> keys, CancellationToken cancellationToken = default) // ✅ CancellationToken 추가
        {
            // ✅ 모든 병렬 작업에 CancellationToken 전달
            await Task.WhenAll(keys.Select(key => RemoveAsync(key, cancellationToken)));
        }

        // 캐시 관리
        public Task FlushAsync(CancellationToken cancellationToken = default) // ✅ CancellationToken 추가
        {
            // ... (경고 로그 유지) ...
            // TODO [SaaS 품질 개선]: FlushAsync는 FLUSHALL 명령을 직접 지원하는 분산 캐시 클라이언트에서만 안전하게 실행해야 합니다. Memory Cache 초기화는 .NET에서 지원되지 않습니다.
            return Task.CompletedTask;
        }

        public Task<CacheStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
        {
            // IDistributedCache는 통계를 제공하지 않으므로, 현재는 더미 데이터만 반환합니다.
            // 참고: CancellationToken은 비동기 작업 취소를 위해 받지만, 이 메서드에서는 즉시 Task.FromResult로 반환되므로 사용되지 않습니다.

            var stats = new CacheStatistics
            {
                ServiceName = "HybridCache",
                CacheType = "Hybrid (InMemory + Distributed)",
                // 통계 기간은 실제 시스템에서 로깅 시작 시점과 현재 시간으로 설정해야 합니다.
                StatsPeriodStart = DateTime.MinValue,
                StatsPeriodEnd = DateTime.UtcNow,

                // IDistributedCache 인터페이스만으로는 정확한 통계를 얻을 수 없습니다.
                // 실제 통계 (Hit/Miss/Entry Count)를 위해서는
                // [TODO] Redis/Memcached 전용 클라이언트의 모니터링 명령(예: Redis의 INFO)을 사용해야 합니다.
                TotalHits = 0,
                TotalMisses = 0,
                HitRate = 0.0,
                TotalEntries = 0
            };

            // 만약 로그를 남기고자 한다면:
            _logger.LogInformation("GetStatisticsAsync provides dummy data. Real statistics require dedicated client integration (e.g., Redis INFO/STATS) and a custom logging/metrics system.");

            // 비동기 메서드지만 동기적으로 결과를 반환 (더미 데이터이므로 I/O 없음)
            return Task.FromResult(stats);
        }

        #endregion
        #region String-specific cache operations

        /// <summary>
        /// 캐시에서 문자열 값을 가져옵니다.
        /// </summary>
        public async Task<string?> GetStringAsync(string key, CancellationToken cancellationToken = default) // ✅ CancellationToken 추가
        {
            // 1. Memory Cache에서 조회 시도
            if (_memoryCache.TryGetValue<string>(key, out var value) && value != null)
            {
                return value;
            }

            // 2. Distributed Cache에서 조회 시도
            try
            {
                var distributedValue = await _distributedCache.GetStringAsync(key, cancellationToken);
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
        public async Task SetStringAsync(string key, string value, TimeSpan? expiration = null, CancellationToken cancellationToken = default) // ✅ CancellationToken 추가
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
                // ✅ CancellationToken 전달
                await _distributedCache.SetStringAsync(key, value, options, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set string value to Distributed Cache for key: {Key}", key);
            }
        }

        #endregion
    }
}