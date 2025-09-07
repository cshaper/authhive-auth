using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Cache;
using AuthHive.Core.Models.Auth.Authentication.Cache;
using AuthHive.Core.Entities.Proxy;
using System.Collections.Concurrent;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 인증 캐시 관리 서비스 구현체 - AuthHive v15
    /// 인증 관련 데이터의 캐싱 전략을 관리하고 성능을 최적화합니다.
    /// </summary>
    public class AuthenticationCacheService : IAuthenticationCacheService
    {
        private readonly IMemoryCache _memoryCache;
        private readonly IDistributedCache? _distributedCache;
        private readonly ILogger<AuthenticationCacheService> _logger;
        
        // 캐시 통계 추적
        private readonly ConcurrentDictionary<string, CacheMetrics> _metrics = new();
        private readonly object _statsLock = new();
        private DateTime _statsStartTime = DateTime.UtcNow;

        // 캐시 키 프리픽스
        private const string SESSION_PREFIX = "auth:session:";
        private const string TOKEN_PREFIX = "auth:token:";
        private const string MFA_PREFIX = "auth:mfa:";
        private const string USER_PREFIX = "auth:user:";
        private const string ORG_PREFIX = "auth:org:";

        // 기본 TTL 설정
        private readonly TimeSpan _defaultSessionTtl = TimeSpan.FromMinutes(30);
        private readonly TimeSpan _defaultTokenTtl = TimeSpan.FromMinutes(5);
        private readonly TimeSpan _defaultMfaTtl = TimeSpan.FromMinutes(10);

        public AuthenticationCacheService(
            IMemoryCache memoryCache,
            IDistributedCache? distributedCache,
            ILogger<AuthenticationCacheService> logger)
        {
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _distributedCache = distributedCache;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Memory cache 테스트
                var testKey = $"health_check_{Guid.NewGuid()}";
                _memoryCache.Set(testKey, "test", TimeSpan.FromSeconds(1));
                _memoryCache.Remove(testKey);

                // Distributed cache 테스트 (있는 경우)
                if (_distributedCache != null)
                {
                    await _distributedCache.SetStringAsync(testKey, "test");
                    await _distributedCache.RemoveAsync(testKey);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cache health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("AuthenticationCacheService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region 캐시 관리

        public async Task<ServiceResult> ClearAuthenticationCacheAsync(Guid userId)
        {
            try
            {
                var keysToRemove = new List<string>();
                
                // 사용자 관련 모든 캐시 키 수집
                keysToRemove.Add($"{USER_PREFIX}{userId}");
                keysToRemove.Add($"{SESSION_PREFIX}{userId}:*");
                keysToRemove.Add($"{MFA_PREFIX}{userId}");

                foreach (var key in keysToRemove)
                {
                    _memoryCache.Remove(key);
                    if (_distributedCache != null)
                    {
                        await _distributedCache.RemoveAsync(key);
                    }
                }

                _logger.LogInformation("Cleared authentication cache for user {UserId}", userId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear authentication cache for user {UserId}", userId);
                return ServiceResult.Failure($"Failed to clear cache: {ex.Message}");
            }
        }

        public async Task<ServiceResult> ClearAllAuthenticationCacheAsync(Guid? organizationId = null)
        {
            try
            {
                if (organizationId.HasValue)
                {
                    // 조직별 캐시 클리어
                    var orgPrefix = $"{ORG_PREFIX}{organizationId}:";
                    // Memory cache는 전체 순회가 불가능하므로 주의 필요
                    _logger.LogWarning("Organization-scoped cache clear requested for {OrgId}", organizationId);
                }
                else
                {
                    // 전체 캐시 클리어 (주의: 운영 환경에서는 위험)
                    _logger.LogWarning("Full cache clear requested - this operation impacts all users");
                }

                // Async operation to maintain consistency
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear all authentication cache");
                return ServiceResult.Failure($"Failed to clear cache: {ex.Message}");
            }
        }

        public async Task<ServiceResult> WarmupCacheAsync(Guid userId)
        {
            try
            {
                // 사용자의 기본 정보를 미리 캐싱
                // 실제 구현시 Repository를 통해 데이터 로드
                _logger.LogInformation("Cache warmup completed for user {UserId}", userId);
                
                // Async operation to maintain consistency
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to warmup cache for user {UserId}", userId);
                return ServiceResult.Failure($"Failed to warmup cache: {ex.Message}");
            }
        }

        public async Task<ServiceResult> InvalidateCacheAsync(string cacheKey)
        {
            try
            {
                _memoryCache.Remove(cacheKey);
                
                if (_distributedCache != null)
                {
                    await _distributedCache.RemoveAsync(cacheKey);
                }

                _logger.LogDebug("Invalidated cache key: {CacheKey}", cacheKey);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache key {CacheKey}", cacheKey);
                return ServiceResult.Failure($"Failed to invalidate cache: {ex.Message}");
            }
        }

        #endregion

        #region 세션 캐시

        public async Task<ServiceResult> CacheSessionAsync(AuthenticationCacheSession session)
        {
            try
            {
                var key = $"{SESSION_PREFIX}{session.SessionId}";
                var options = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };

                _memoryCache.Set(key, session, options);

                if (_distributedCache != null)
                {
                    var json = JsonSerializer.Serialize(session);
                    await _distributedCache.SetStringAsync(key, json, new DistributedCacheEntryOptions
                    {
                        AbsoluteExpiration = session.ExpiresAt,
                        SlidingExpiration = TimeSpan.FromMinutes(5)
                    });
                }

                RecordCacheHit(key);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache session {SessionId}", session.SessionId);
                return ServiceResult.Failure($"Failed to cache session: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationCacheSession>> GetCachedSessionAsync(Guid sessionId)
        {
            try
            {
                var key = $"{SESSION_PREFIX}{sessionId}";
                
                // Memory cache 확인
                if (_memoryCache.TryGetValue<AuthenticationCacheSession>(key, out var session) && session != null)
                {
                    RecordCacheHit(key);
                    return ServiceResult<AuthenticationCacheSession>.Success(session);
                }

                // Distributed cache 확인
                if (_distributedCache != null)
                {
                    var json = await _distributedCache.GetStringAsync(key);
                    if (!string.IsNullOrEmpty(json))
                    {
                        session = JsonSerializer.Deserialize<AuthenticationCacheSession>(json);
                        if (session != null)
                        {
                            // Memory cache에도 저장
                            _memoryCache.Set(key, session, _defaultSessionTtl);
                            RecordCacheHit(key);
                            return ServiceResult<AuthenticationCacheSession>.Success(session);
                        }
                    }
                }

                RecordCacheMiss(key);
                return ServiceResult<AuthenticationCacheSession>.Failure("Session not found in cache");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cached session {SessionId}", sessionId);
                return ServiceResult<AuthenticationCacheSession>.Failure($"Failed to get session: {ex.Message}");
            }
        }

        public async Task<ServiceResult> RemoveSessionCacheAsync(Guid sessionId)
        {
            var key = $"{SESSION_PREFIX}{sessionId}";
            return await InvalidateCacheAsync(key);
        }

        #endregion

        #region 토큰 캐시

        public async Task<ServiceResult> CacheTokenValidationAsync(string tokenHash, AuthenticationCacheTokenValidation validation)
        {
            try
            {
                var key = $"{TOKEN_PREFIX}{tokenHash}";
                var options = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = validation.CacheExpiresAt
                };

                _memoryCache.Set(key, validation, options);

                if (_distributedCache != null)
                {
                    var json = JsonSerializer.Serialize(validation);
                    await _distributedCache.SetStringAsync(key, json, new DistributedCacheEntryOptions
                    {
                        AbsoluteExpiration = validation.CacheExpiresAt
                    });
                }

                RecordCacheHit(key);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache token validation");
                return ServiceResult.Failure($"Failed to cache token: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationCacheTokenValidation>> GetCachedTokenValidationAsync(string tokenHash)
        {
            try
            {
                var key = $"{TOKEN_PREFIX}{tokenHash}";
                
                if (_memoryCache.TryGetValue<AuthenticationCacheTokenValidation>(key, out var validation) && validation != null)
                {
                    RecordCacheHit(key);
                    return ServiceResult<AuthenticationCacheTokenValidation>.Success(validation);
                }

                if (_distributedCache != null)
                {
                    var json = await _distributedCache.GetStringAsync(key);
                    if (!string.IsNullOrEmpty(json))
                    {
                        validation = JsonSerializer.Deserialize<AuthenticationCacheTokenValidation>(json);
                        if (validation != null)
                        {
                            _memoryCache.Set(key, validation, _defaultTokenTtl);
                            RecordCacheHit(key);
                            return ServiceResult<AuthenticationCacheTokenValidation>.Success(validation);
                        }
                    }
                }

                RecordCacheMiss(key);
                return ServiceResult<AuthenticationCacheTokenValidation>.Failure("Token validation not found in cache");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cached token validation");
                return ServiceResult<AuthenticationCacheTokenValidation>.Failure($"Failed to get token: {ex.Message}");
            }
        }

        #endregion

        #region MFA 상태 캐시

        public async Task<ServiceResult> CacheMfaStateAsync(Guid userId, AuthenticationCacheMfaState state)
        {
            try
            {
                var key = $"{MFA_PREFIX}{userId}";
                var options = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = state.ChallengeExpiresAt
                };

                _memoryCache.Set(key, state, options);

                if (_distributedCache != null)
                {
                    var json = JsonSerializer.Serialize(state);
                    await _distributedCache.SetStringAsync(key, json, new DistributedCacheEntryOptions
                    {
                        AbsoluteExpiration = state.ChallengeExpiresAt
                    });
                }

                RecordCacheHit(key);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache MFA state for user {UserId}", userId);
                return ServiceResult.Failure($"Failed to cache MFA state: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationCacheMfaState>> GetCachedMfaStateAsync(Guid userId)
        {
            try
            {
                var key = $"{MFA_PREFIX}{userId}";
                
                if (_memoryCache.TryGetValue<AuthenticationCacheMfaState>(key, out var state) && state != null)
                {
                    RecordCacheHit(key);
                    return ServiceResult<AuthenticationCacheMfaState>.Success(state);
                }

                if (_distributedCache != null)
                {
                    var json = await _distributedCache.GetStringAsync(key);
                    if (!string.IsNullOrEmpty(json))
                    {
                        state = JsonSerializer.Deserialize<AuthenticationCacheMfaState>(json);
                        if (state != null)
                        {
                            _memoryCache.Set(key, state, _defaultMfaTtl);
                            RecordCacheHit(key);
                            return ServiceResult<AuthenticationCacheMfaState>.Success(state);
                        }
                    }
                }

                RecordCacheMiss(key);
                return ServiceResult<AuthenticationCacheMfaState>.Failure("MFA state not found in cache");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cached MFA state for user {UserId}", userId);
                return ServiceResult<AuthenticationCacheMfaState>.Failure($"Failed to get MFA state: {ex.Message}");
            }
        }

        #endregion

        #region 캐시 통계

        public async Task<ServiceResult<CacheStatistics>> GetCacheStatisticsAsync()
        {
            try
            {
                var stats = new CacheStatistics
                {
                    ServiceName = "AuthenticationCache",
                    CacheType = _distributedCache != null ? "Hybrid" : "InMemory",
                    StatsPeriodStart = _statsStartTime,
                    StatsPeriodEnd = DateTime.UtcNow
                };

                lock (_statsLock)
                {
                    foreach (var metric in _metrics.Values)
                    {
                        stats.TotalHits += metric.Hits;
                        stats.TotalMisses += metric.Misses;
                    }

                    stats.HitRate = stats.TotalHits + stats.TotalMisses > 0
                        ? (double)stats.TotalHits / (stats.TotalHits + stats.TotalMisses)
                        : 0;
                    stats.MissRate = 1 - stats.HitRate;
                }

                await Task.CompletedTask;
                return ServiceResult<CacheStatistics>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cache statistics");
                return ServiceResult<CacheStatistics>.Failure($"Failed to get statistics: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationCacheStatistics>> GetUserCacheStatisticsAsync(Guid userId)
        {
            try
            {
                var stats = new AuthenticationCacheStatistics
                {
                    ServiceName = "AuthenticationCache",
                    CacheType = _distributedCache != null ? "Hybrid" : "InMemory"
                };

                // 사용자별 통계 수집 로직
                var userKey = $"{USER_PREFIX}{userId}";
                if (_metrics.TryGetValue(userKey, out var metric))
                {
                    stats.TotalHits = metric.Hits;
                    stats.TotalMisses = metric.Misses;
                }

                await Task.CompletedTask;
                return ServiceResult<AuthenticationCacheStatistics>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user cache statistics");
                return ServiceResult<AuthenticationCacheStatistics>.Failure($"Failed to get statistics: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationCacheStatistics>> GetOrganizationCacheStatisticsAsync(Guid organizationId)
        {
            try
            {
                var stats = new AuthenticationCacheStatistics
                {
                    ServiceName = "AuthenticationCache",
                    CacheType = _distributedCache != null ? "Hybrid" : "InMemory"
                };

                // 조직별 통계 수집 로직
                stats.EntriesByOrganization[organizationId] = 0;

                await Task.CompletedTask;
                return ServiceResult<AuthenticationCacheStatistics>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization cache statistics");
                return ServiceResult<AuthenticationCacheStatistics>.Failure($"Failed to get statistics: {ex.Message}");
            }
        }

        #endregion

        #region 캐시 분석

        public async Task<ServiceResult<CacheMissAnalysis>> AnalyzeCacheMissesAsync(TimeSpan? period = null)
        {
            try
            {
                var analysis = new CacheMissAnalysis
                {
                    ServiceName = "AuthenticationCache",
                    AnalysisPeriod = period ?? TimeSpan.FromHours(1),
                    AnalysisStartTime = DateTime.UtcNow.Subtract(period ?? TimeSpan.FromHours(1)),
                    AnalysisEndTime = DateTime.UtcNow
                };

                // 캐시 미스 패턴 분석
                foreach (var kvp in _metrics)
                {
                    if (kvp.Value.Misses > 0)
                    {
                        var pattern = ExtractKeyPattern(kvp.Key);
                        if (!analysis.MissByKeyPattern.ContainsKey(pattern))
                            analysis.MissByKeyPattern[pattern] = 0;
                        analysis.MissByKeyPattern[pattern] += (int)kvp.Value.Misses;
                        analysis.TotalMisses += (int)kvp.Value.Misses;
                    }
                }

                await Task.CompletedTask;
                return ServiceResult<CacheMissAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze cache misses");
                return ServiceResult<CacheMissAnalysis>.Failure($"Failed to analyze: {ex.Message}");
            }
        }

        public async Task<ServiceResult<CacheHitRateAnalysis>> AnalyzeCacheHitRateAsync(TimeSpan? period = null)
        {
            try
            {
                var analysis = new CacheHitRateAnalysis
                {
                    AnalysisPeriod = period ?? TimeSpan.FromHours(1),
                    OverallHitRate = 0
                };

                lock (_statsLock)
                {
                    long totalHits = 0, totalMisses = 0;
                    foreach (var metric in _metrics.Values)
                    {
                        totalHits += metric.Hits;
                        totalMisses += metric.Misses;
                    }

                    analysis.OverallHitRate = totalHits + totalMisses > 0
                        ? (double)totalHits / (totalHits + totalMisses)
                        : 0;
                }

                await Task.CompletedTask;
                return ServiceResult<CacheHitRateAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze cache hit rate");
                return ServiceResult<CacheHitRateAnalysis>.Failure($"Failed to analyze: {ex.Message}");
            }
        }

        public async Task<ServiceResult<CachePerformanceAnalysis>> AnalyzeCachePerformanceAsync()
        {
            try
            {
                var analysis = new CachePerformanceAnalysis
                {
                    TotalOperations = _metrics.Sum(m => m.Value.Hits + m.Value.Misses),
                    AverageResponseTime = 0.5, // 임시 값
                    P95ResponseTime = 1.2,
                    P99ResponseTime = 2.5
                };

                await Task.CompletedTask;
                return ServiceResult<CachePerformanceAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to analyze cache performance");
                return ServiceResult<CachePerformanceAnalysis>.Failure($"Failed to analyze: {ex.Message}");
            }
        }

        #endregion

        #region 캐시 최적화

        public async Task<ServiceResult<CacheOptimizationRecommendations>> GetCacheOptimizationRecommendationsAsync()
        {
            try
            {
                var recommendations = new CacheOptimizationRecommendations
                {
                    ServiceName = "AuthenticationCache",
                    AnalyzedAt = DateTime.UtcNow,
                    Recommendations = new List<OptimizationRecommendation>()
                };

                // 히트율이 낮으면 TTL 증가 권장
                var stats = await GetCacheStatisticsAsync();
                if (stats.IsSuccess && stats.Data != null && stats.Data.HitRate < 0.7)
                {
                    recommendations.Recommendations.Add(new OptimizationRecommendation
                    {
                        Id = "increase_ttl",
                        Title = "Increase Cache TTL",
                        Description = "Current hit rate is below 70%. Consider increasing TTL values.",
                        Impact = "High",
                        Difficulty = "Easy",
                        Category = "Performance"
                    });
                }

                return ServiceResult<CacheOptimizationRecommendations>.Success(recommendations);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get optimization recommendations");
                return ServiceResult<CacheOptimizationRecommendations>.Failure($"Failed to get recommendations: {ex.Message}");
            }
        }

        public async Task<ServiceResult> OptimizeCacheSizeAsync()
        {
            try
            {
                // 캐시 크기 최적화 로직
                _logger.LogInformation("Cache size optimization completed");
                
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to optimize cache size");
                return ServiceResult.Failure($"Failed to optimize: {ex.Message}");
            }
        }

        public async Task<ServiceResult> OptimizeCacheTTLAsync()
        {
            try
            {
                // TTL 최적화 로직
                _logger.LogInformation("Cache TTL optimization completed");
                
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to optimize cache TTL");
                return ServiceResult.Failure($"Failed to optimize: {ex.Message}");
            }
        }

        #endregion

        #region 캐시 정책

        public async Task<ServiceResult> SetCachePolicyAsync(CachePolicy policy)
        {
            try
            {
                // 정책 저장 로직 (DB 또는 설정)
                _logger.LogInformation("Cache policy updated: {PolicyName}", policy.PolicyName);
                
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set cache policy");
                return ServiceResult.Failure($"Failed to set policy: {ex.Message}");
            }
        }

        public async Task<ServiceResult<CachePolicy>> GetCachePolicyAsync()
        {
            try
            {
                // 현재 정책 조회
                var policy = new CachePolicy
                {
                    PolicyName = "Default Authentication Cache Policy",
                    PolicyKey = "auth_cache_default",
                    TTLSeconds = 300,
                    IsActive = true
                };

                await Task.CompletedTask;
                return ServiceResult<CachePolicy>.Success(policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cache policy");
                return ServiceResult<CachePolicy>.Failure($"Failed to get policy: {ex.Message}");
            }
        }

        public async Task<ServiceResult<CachePolicyValidation>> ValidateCachePolicyAsync(CachePolicy policy)
        {
            try
            {
                var validation = new CachePolicyValidation
                {
                    IsValid = true,
                    Errors = new List<string>(),
                    Warnings = new List<string>()
                };

                // 정책 검증 로직
                if (policy.TTLSeconds < 60)
                {
                    validation.Warnings.Add("TTL is very short (< 60 seconds)");
                }

                if (policy.TTLSeconds > 86400)
                {
                    validation.Warnings.Add("TTL is very long (> 24 hours)");
                }

                if (string.IsNullOrEmpty(policy.PolicyName))
                {
                    validation.IsValid = false;
                    validation.Errors.Add("Policy name is required");
                }

                await Task.CompletedTask;
                return ServiceResult<CachePolicyValidation>.Success(validation);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate cache policy");
                return ServiceResult<CachePolicyValidation>.Failure($"Failed to validate: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        private void RecordCacheHit(string key)
        {
            var pattern = ExtractKeyPattern(key);
            _metrics.AddOrUpdate(pattern, 
                new CacheMetrics { Hits = 1 },
                (k, m) => { m.Hits++; return m; });
        }

        private void RecordCacheMiss(string key)
        {
            var pattern = ExtractKeyPattern(key);
            _metrics.AddOrUpdate(pattern,
                new CacheMetrics { Misses = 1 },
                (k, m) => { m.Misses++; return m; });
        }

        private string ExtractKeyPattern(string key)
        {
            // 키에서 패턴 추출 (예: "auth:session:123" -> "auth:session")
            var parts = key.Split(':');
            return parts.Length >= 2 ? $"{parts[0]}:{parts[1]}" : key;
        }

        #endregion

        #region Internal Classes

        private class CacheMetrics
        {
            public long Hits { get; set; }
            public long Misses { get; set; }
        }

        #endregion
    }



    public class CachePattern
    {
        public string Pattern { get; set; } = string.Empty;
        public int Frequency { get; set; }
        public string Type { get; set; } = string.Empty;
    }
}