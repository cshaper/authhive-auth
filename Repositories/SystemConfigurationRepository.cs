using AuthHive.Core.Entities.System;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.System;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Linq.Expressions;
using System.Text.Json;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 시스템 설정 리포지토리 구현체
    /// AuthHive 플랫폼 전반에 걸친 모든 설정을 데이터베이스에서 관리합니다.
    /// </summary>
    public class SystemConfigurationRepository : BaseRepository<SystemConfiguration>, ISystemConfigurationRepository
    {
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<SystemConfigurationRepository> _logger;
        
        // 캐시 키 prefix
        private const string CACHE_PREFIX = "SysConfig";
        
        // JSON 직렬화 옵션 (재사용)
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        public SystemConfigurationRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<SystemConfigurationRepository> logger,
            IEncryptionService encryptionService,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회 (캐시 최적화)

        /// <summary>
        /// 설정 키(Key)를 사용해 특정 설정 항목 하나를 조회합니다.
        /// </summary>
        public async Task<SystemConfiguration?> GetByKeyAsync(
            string configurationKey, 
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인
            if (_cache != null && !includeInactive)
            {
                var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);
                if (_cache.TryGetValue(cacheKey, out SystemConfiguration? cached))
                {
                    return cached;
                }
            }

            var query = _dbSet.AsNoTracking();
            
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            
            var result = await query.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            // 캐시 저장
            if (_cache != null && result != null && !includeInactive)
            {
                var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);
                _cache.Set(cacheKey, result, GetCacheOptions(result));
            }
            
            return result;
        }

        /// <summary>
        /// 여러 개의 설정 키를 목록으로 전달하여 한 번의 쿼리로 모두 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetByKeysAsync(
            IEnumerable<string> configurationKeys,
            CancellationToken cancellationToken = default)
        {
            var keyList = configurationKeys.ToList();
            if (!keyList.Any())
                return Enumerable.Empty<SystemConfiguration>();

            // 캐시에서 먼저 찾기
            var cached = new List<SystemConfiguration>();
            var notCached = new List<string>();
            
            if (_cache != null)
            {
                foreach (var key in keyList)
                {
                    var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), key);
                    if (_cache.TryGetValue(cacheKey, out SystemConfiguration? item) && item != null)
                    {
                        cached.Add(item);
                    }
                    else
                    {
                        notCached.Add(key);
                    }
                }
                
                if (!notCached.Any())
                    return cached;
            }
            else
            {
                notCached = keyList;
            }

            // DB에서 나머지 조회
            var fromDb = await _dbSet
                .AsNoTracking()
                .Where(c => notCached.Contains(c.ConfigurationKey))
                .ToListAsync(cancellationToken);
            
            // 캐시에 저장
            if (_cache != null)
            {
                foreach (var config in fromDb)
                {
                    var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), config.ConfigurationKey);
                    _cache.Set(cacheKey, config, GetCacheOptions(config));
                }
            }
            
            return cached.Concat(fromDb);
        }

        /// <summary>
        /// 설정 타입(Type)으로 관련된 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetByTypeAsync(
            SystemConfigurationType configurationType, 
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                .Where(c => c.ConfigurationType == configurationType);
            
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            
            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 카테고리(Category)로 관련된 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetByCategoryAsync(
            SystemConfigurationCategory category, 
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking()
                .Where(c => c.Category == category);
            
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            
            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 설정 키가 존재하는지 확인합니다.
        /// </summary>
        public async Task<bool> ExistsAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인
            if (_cache != null)
            {
                var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);
                if (_cache.TryGetValue(cacheKey, out _))
                    return true;
            }
            
            return await _dbSet.AnyAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
        }

        #endregion

        #region 값 조회 및 타입 변환 (최적화)

        /// <summary>
        /// 설정 값을 문자열(string)로 간편하게 조회합니다.
        /// </summary>
        public async Task<string?> GetStringValueAsync(
            string configurationKey, 
            string? defaultValue = null,
            CancellationToken cancellationToken = default)
        {
            var config = await GetByKeyAsync(configurationKey, false, cancellationToken);
            return config?.ConfigurationValue ?? defaultValue;
        }

        /// <summary>
        /// 설정 값을 정수(int)로 간편하게 조회합니다.
        /// </summary>
        public async Task<int> GetIntValueAsync(
            string configurationKey, 
            int defaultValue = 0,
            CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return int.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값을 불리언(bool)으로 간편하게 조회합니다.
        /// </summary>
        public async Task<bool> GetBoolValueAsync(
            string configurationKey, 
            bool defaultValue = false,
            CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return bool.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값을 Decimal로 조회합니다.
        /// </summary>
        public async Task<decimal> GetDecimalValueAsync(
            string configurationKey,
            decimal defaultValue = 0m,
            CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return decimal.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값을 DateTime으로 조회합니다.
        /// </summary>
        public async Task<DateTime?> GetDateTimeValueAsync(
            string configurationKey,
            DateTime? defaultValue = null,
            CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            if (string.IsNullOrEmpty(configValue))
                return defaultValue;
            
            return DateTime.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값을 TimeSpan으로 조회합니다.
        /// </summary>
        public async Task<TimeSpan?> GetTimeSpanValueAsync(
            string configurationKey,
            TimeSpan? defaultValue = null,
            CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            if (string.IsNullOrEmpty(configValue))
                return defaultValue;
            
            return TimeSpan.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값이 JSON 형식일 때, 지정된 클래스 객체(T)로 자동 역직렬화하여 조회합니다.
        /// </summary>
        public async Task<T?> GetJsonValueAsync<T>(
            string configurationKey,
            CancellationToken cancellationToken = default) where T : class
        {
            var jsonValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            if (string.IsNullOrEmpty(jsonValue)) 
                return null;

            try
            {
                return JsonSerializer.Deserialize<T>(jsonValue, _jsonOptions);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to deserialize JSON for key {Key}", configurationKey);
                return null;
            }
        }

        /// <summary>
        /// 암호화된 설정 값을 자동으로 복호화하여 평문으로 조회합니다.
        /// </summary>
        public async Task<string?> GetDecryptedValueAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            var config = await GetByKeyAsync(configurationKey, false, cancellationToken);
            if (config == null || string.IsNullOrEmpty(config.ConfigurationValue))
                return null;

            if (!config.IsEncrypted)
            {
                _logger.LogWarning("Attempted to decrypt non-encrypted value for key {Key}", configurationKey);
                return config.ConfigurationValue;
            }

            try
            {
                return await _encryptionService.DecryptAsync(config.ConfigurationValue);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decrypt value for key {Key}", configurationKey);
                return null;
            }
        }

        #endregion

        #region 설정 생성 및 업데이트 (트랜잭션 최적화)

        /// <summary>
        /// 설정이 존재하면 업데이트하고, 없으면 새로 생성(Upsert)합니다.
        /// </summary>
        public async Task<SystemConfiguration> UpsertAsync(
            string configurationKey, 
            string value, 
            SystemConfigurationType configurationType, 
            SystemConfigurationCategory? category = null, 
            string? description = null,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var existingConfig = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (existingConfig != null)
            {
                existingConfig.ConfigurationValue = value;
                existingConfig.ConfigurationType = configurationType;
                existingConfig.Category = category ?? existingConfig.Category;
                existingConfig.Description = description ?? existingConfig.Description;
                existingConfig.UpdatedAt = DateTime.UtcNow;
                
                _dbSet.Update(existingConfig);
                return existingConfig;
            }
            
            var newConfig = new SystemConfiguration
            {
                ConfigurationKey = configurationKey,
                ConfigurationValue = value,
                ConfigurationType = configurationType,
                Category = category,
                Description = description,
                CreatedAt = DateTime.UtcNow
            };
            
            await _dbSet.AddAsync(newConfig, cancellationToken);
            return newConfig;
        }
        
        /// <summary>
        /// 특정 설정의 값(Value)만 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateValueAsync(
            string configurationKey, 
            string newValue, 
            bool recordHistory = true,
            string? changedBy = null,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;
            
            if (config.IsReadOnly)
            {
                _logger.LogWarning("Attempted to update read-only configuration {Key}", configurationKey);
                return false;
            }

            var oldValue = config.ConfigurationValue;
            
            if (recordHistory && oldValue != newValue)
            {
                await RecordChangeHistoryInternalAsync(config, oldValue, newValue, changedBy ?? "SYSTEM");
            }
            
            config.ConfigurationValue = newValue;
            config.UpdatedAt = DateTime.UtcNow;
            _dbSet.Update(config);
            
            return true;
        }

        /// <summary>
        /// 전달된 평문 값을 자동으로 암호화하여 저장합니다.
        /// </summary>
        public async Task<bool> UpdateEncryptedValueAsync(
            string configurationKey, 
            string plainValue,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;
            
            var encryptedValue = await _encryptionService.EncryptAsync(plainValue);
            config.ConfigurationValue = encryptedValue;
            config.IsEncrypted = true;
            config.UpdatedAt = DateTime.UtcNow;
            
            _dbSet.Update(config);
            return true;
        }

        /// <summary>
        /// 전달된 객체를 JSON 문자열로 직렬화하여 저장합니다.
        /// </summary>
        public async Task<bool> UpdateJsonValueAsync<T>(
            string configurationKey, 
            T value,
            CancellationToken cancellationToken = default) where T : class
        {
            var jsonValue = JsonSerializer.Serialize(value, _jsonOptions);
            return await UpdateValueAsync(configurationKey, jsonValue, true, null, cancellationToken);
        }
        
        #endregion

        #region 유효 기간 관리
        
        /// <summary>
        /// 현재 시점에서 유효한 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetEffectiveConfigurationsAsync(
            DateTime? asOfDate = null,
            CancellationToken cancellationToken = default)
        {
            var now = asOfDate ?? DateTime.UtcNow;
            return await _dbSet
                .AsNoTracking()
                .Where(c =>
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now))
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 설정의 유효 기간을 설정합니다.
        /// </summary>
        public async Task<bool> SetEffectivePeriodAsync(
            string configurationKey, 
            DateTime? effectiveFrom, 
            DateTime? effectiveUntil,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;

            config.EffectiveFrom = effectiveFrom;
            config.EffectiveUntil = effectiveUntil;
            config.UpdatedAt = DateTime.UtcNow;
            
            _dbSet.Update(config);
            return true;
        }
        
        /// <summary>
        /// 유효 기간이 만료된 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetExpiredConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.EffectiveUntil.HasValue && c.EffectiveUntil.Value < now)
                .ToListAsync(cancellationToken);
        }
        
        /// <summary>
        /// 특정 기간 동안만 유효한 임시 설정을 생성합니다.
        /// </summary>
        public async Task<SystemConfiguration> CreateTemporaryConfigurationAsync(
            string configurationKey, 
            string value, 
            TimeSpan duration,
            SystemConfigurationType configurationType = SystemConfigurationType.Maintenance,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var newConfig = new SystemConfiguration
            {
                ConfigurationKey = configurationKey,
                ConfigurationValue = value,
                EffectiveFrom = now,
                EffectiveUntil = now.Add(duration),
                ConfigurationType = configurationType,
                CreatedAt = now
            };
            
            await _dbSet.AddAsync(newConfig, cancellationToken);
            return newConfig;
        }
        
        #endregion

        #region 변경 이력 관리 (최적화)
        
        /// <summary>
        /// 특정 설정의 값 변경 이력을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<ConfigurationChangeHistory>> GetChangeHistoryAsync(
            string configurationKey, 
            int limit = 10,
            CancellationToken cancellationToken = default)
        {
            var config = await _dbSet
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null || string.IsNullOrEmpty(config.ChangeHistory))
                return Enumerable.Empty<ConfigurationChangeHistory>();

            try
            {
                var history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(
                    config.ChangeHistory, _jsonOptions) ?? new List<ConfigurationChangeHistory>();
                
                return history
                    .OrderByDescending(h => h.ChangedAt)
                    .Take(limit);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse change history for key {Key}", configurationKey);
                return Enumerable.Empty<ConfigurationChangeHistory>();
            }
        }
        
        /// <summary>
        /// 설정 값 변경 내역을 JSON 필드에 기록합니다. (외부 호출용)
        /// </summary>
        public async Task<bool> RecordChangeHistoryAsync(
            string configurationKey, 
            string? oldValue, 
            string newValue, 
            string changedBy,
            CancellationToken cancellationToken = default)
        {
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;
            
            await RecordChangeHistoryInternalAsync(config, oldValue, newValue, changedBy);
            _dbSet.Update(config);
            
            return true;
        }
        
        /// <summary>
        /// 과거 특정 시점의 설정 값을 조회합니다.
        /// </summary>
        public async Task<string?> GetValueAsOfDateAsync(
            string configurationKey, 
            DateTime asOfDate,
            CancellationToken cancellationToken = default)
        {
            var history = await GetChangeHistoryAsync(configurationKey, 100, cancellationToken);
            var record = history
                .Where(h => h.ChangedAt <= asOfDate)
                .OrderByDescending(h => h.ChangedAt)
                .FirstOrDefault();

            return record?.NewValue;
        }

        /// <summary>
        /// 변경 이력 삭제 (오래된 이력 정리)
        /// </summary>
        public async Task<int> PurgeChangeHistoryAsync(
            string configurationKey,
            int keepRecentCount = 10,
            CancellationToken cancellationToken = default)
        {
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null || string.IsNullOrEmpty(config.ChangeHistory))
                return 0;

            try
            {
                var history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(
                    config.ChangeHistory, _jsonOptions) ?? new List<ConfigurationChangeHistory>();
                
                var originalCount = history.Count;
                
                if (originalCount <= keepRecentCount)
                    return 0;
                
                var trimmedHistory = history
                    .OrderByDescending(h => h.ChangedAt)
                    .Take(keepRecentCount)
                    .ToList();
                
                config.ChangeHistory = JsonSerializer.Serialize(trimmedHistory, _jsonOptions);
                _dbSet.Update(config);
                
                return originalCount - keepRecentCount;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to purge change history for key {Key}", configurationKey);
                return 0;
            }
        }

        #endregion
        
        #region 읽기 전용 및 보안

        public async Task<IEnumerable<SystemConfiguration>> GetReadOnlyConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.IsReadOnly)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> SetReadOnlyAsync(
            string configurationKey, 
            bool isReadOnly,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;
            
            config.IsReadOnly = isReadOnly;
            config.UpdatedAt = DateTime.UtcNow;
            _dbSet.Update(config);
            
            return true;
        }

        public async Task<IEnumerable<SystemConfiguration>> GetEncryptedConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.IsEncrypted)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<SystemConfiguration>> GetSystemManagedConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.IsSystemManaged)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 민감한 설정 마스킹 조회
        /// </summary>
        public async Task<string?> GetMaskedValueAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            var config = await GetByKeyAsync(configurationKey, false, cancellationToken);
            if (config == null || string.IsNullOrEmpty(config.ConfigurationValue))
                return null;

            var value = config.ConfigurationValue;
            
            // API Key, Password 등 민감한 값 마스킹
            if (configurationKey.Contains("Key", StringComparison.OrdinalIgnoreCase) ||
                configurationKey.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
                configurationKey.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
                configurationKey.Contains("Token", StringComparison.OrdinalIgnoreCase))
            {
                if (value.Length <= 4)
                    return "****";
                
                // 처음 2자와 마지막 2자만 보여주고 나머지는 마스킹
                var prefix = value.Substring(0, Math.Min(2, value.Length / 4));
                var suffix = value.Substring(Math.Max(value.Length - 2, value.Length * 3 / 4));
                return $"{prefix}****{suffix}";
            }
            
            return value;
        }

        #endregion

        #region 재시작 요구 사항

        public async Task<IEnumerable<SystemConfiguration>> GetRestartRequiredConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.RequiresRestart)
                .ToListAsync(cancellationToken);
        }
        
        public async Task<IEnumerable<SystemConfiguration>> GetPendingRestartConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            // RequiresRestart 플래그가 설정된 항목을 반환
            return await GetRestartRequiredConfigurationsAsync(cancellationToken);
        }

        public async Task<bool> SetRestartRequiredAsync(
            string configurationKey, 
            bool requiresRestart,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            
            var config = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null) 
                return false;
            
            config.RequiresRestart = requiresRestart;
            config.UpdatedAt = DateTime.UtcNow;
            _dbSet.Update(config);
            
            return true;
        }
        
        #endregion

        #region 일괄 작업 (트랜잭션 최적화)

        /// <summary>
        /// 여러 설정 값을 Dictionary 형태로 받아 한 번에 업데이트합니다.
        /// </summary>
        public async Task<int> BulkUpdateAsync(
            Dictionary<string, string> configurations,
            bool validateBeforeUpdate = false,
            CancellationToken cancellationToken = default)
        {
            if (!configurations.Any())
                return 0;
            
            // 검증 수행
            if (validateBeforeUpdate)
            {
                foreach (var kvp in configurations)
                {
                    var (isValid, errorMessage) = await ValidateValueAsync(kvp.Key, kvp.Value, cancellationToken);
                    if (!isValid)
                    {
                        _logger.LogWarning("Validation failed for {Key}: {Error}", kvp.Key, errorMessage);
                        throw new InvalidOperationException($"Validation failed for {kvp.Key}: {errorMessage}");
                    }
                }
            }
            
            var keys = configurations.Keys.ToList();
            var existingConfigs = await _dbSet
                .Where(c => keys.Contains(c.ConfigurationKey))
                .ToListAsync(cancellationToken);
            
            var updatedCount = 0;
            var now = DateTime.UtcNow;
            
            foreach (var config in existingConfigs)
            {
                if (configurations.TryGetValue(config.ConfigurationKey, out var newValue))
                {
                    config.ConfigurationValue = newValue;
                    config.UpdatedAt = now;
                    updatedCount++;
                    
                    InvalidateCacheForKey(config.ConfigurationKey);
                }
            }
            
            if (updatedCount > 0)
            {
                _dbSet.UpdateRange(existingConfigs);
            }
            
            return updatedCount;
        }

        /// <summary>
        /// 특정 카테고리에 속한 모든 설정을 일괄 삭제합니다.
        /// </summary>
        public async Task<int> DeleteByCategoryAsync(
            SystemConfigurationCategory category, 
            bool excludeSystemManaged = true,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(c => c.Category == category);
            
            if (excludeSystemManaged)
            {
                query = query.Where(c => !c.IsSystemManaged);
            }
            
            var toDelete = await query.ToListAsync(cancellationToken);
            
            if (!toDelete.Any())
                return 0;
            
            // 캐시 무효화
            foreach (var config in toDelete)
            {
                InvalidateCacheForKey(config.ConfigurationKey);
            }
            
            _dbSet.RemoveRange(toDelete);
            return toDelete.Count;
        }
        
        /// <summary>
        /// DB에 저장된 설정들을 파일로 내보내기 위해 Dictionary로 변환합니다.
        /// </summary>
        public async Task<Dictionary<string, object>> ExportConfigurationsAsync(
            IEnumerable<SystemConfigurationCategory>? categories = null,
            bool includeEncrypted = false,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking();
            
            if (categories?.Any() == true)
            {
                query = query.Where(c => c.Category.HasValue && categories.Contains(c.Category.Value));
            }
            
            // 암호화된 설정 제외
            if (!includeEncrypted)
            {
                query = query.Where(c => !c.IsEncrypted);
            }

            var configurations = await query
                .Where(c => c.ConfigurationValue != null)
                .Select(c => new { c.ConfigurationKey, c.ConfigurationValue, c.IsEncrypted })
                .ToListAsync(cancellationToken);

            var result = new Dictionary<string, object>();
            
            foreach (var config in configurations)
            {
                if (config.IsEncrypted && includeEncrypted)
                {
                    // 암호화된 값도 포함하는 경우, 복호화하여 내보내기
                    try
                    {
                        var decryptedValue = await _encryptionService.DecryptAsync(config.ConfigurationValue!);
                        result[config.ConfigurationKey] = decryptedValue;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to decrypt value for export: {Key}", config.ConfigurationKey);
                        result[config.ConfigurationKey] = "[DECRYPTION_FAILED]";
                    }
                }
                else
                {
                    result[config.ConfigurationKey] = config.ConfigurationValue!;
                }
            }
            
            return result;
        }

        /// <summary>
        /// 파일로부터 읽어온 설정들을 DB로 가져옵니다.
        /// </summary>
        public async Task<int> ImportConfigurationsAsync(
            Dictionary<string, object> configurations, 
            bool overwriteExisting = false,
            bool validateBeforeImport = true,
            CancellationToken cancellationToken = default)
        {
            if (!configurations.Any())
                return 0;
            
            // 가져오기 전 검증
            if (validateBeforeImport)
            {
                foreach (var kvp in configurations)
                {
                    var value = kvp.Value?.ToString();
                    if (!string.IsNullOrEmpty(value))
                    {
                        var (isValid, errorMessage) = await ValidateValueAsync(kvp.Key, value, cancellationToken);
                        if (!isValid)
                        {
                            _logger.LogWarning("Import validation failed for {Key}: {Error}", kvp.Key, errorMessage);
                            continue; // Skip invalid configurations
                        }
                    }
                }
            }
            
            var keys = configurations.Keys.ToList();
            var existingConfigs = await _dbSet
                .Where(c => keys.Contains(c.ConfigurationKey))
                .ToDictionaryAsync(c => c.ConfigurationKey, cancellationToken);
            
            var toAdd = new List<SystemConfiguration>();
            var toUpdate = new List<SystemConfiguration>();
            var now = DateTime.UtcNow;
            
            foreach (var kvp in configurations)
            {
                var value = kvp.Value?.ToString();
                if (string.IsNullOrEmpty(value))
                    continue;
                
                if (existingConfigs.TryGetValue(kvp.Key, out var existing))
                {
                    if (overwriteExisting && !existing.IsReadOnly)
                    {
                        existing.ConfigurationValue = value;
                        existing.UpdatedAt = now;
                        toUpdate.Add(existing);
                        InvalidateCacheForKey(kvp.Key);
                    }
                }
                else
                {
                    toAdd.Add(new SystemConfiguration
                    {
                        ConfigurationKey = kvp.Key,
                        ConfigurationValue = value,
                        ConfigurationType = SystemConfigurationType.General,
                        CreatedAt = now
                    });
                }
            }
            
            if (toAdd.Any())
                await _dbSet.AddRangeAsync(toAdd, cancellationToken);
            
            if (toUpdate.Any())
                _dbSet.UpdateRange(toUpdate);
            
            return toAdd.Count + toUpdate.Count;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 키워드를 사용하여 설정 키 또는 설명에서 검색합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> SearchAsync(
            string keyword, 
            bool searchInDescription = true,
            bool searchInValue = false,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(keyword))
                return Enumerable.Empty<SystemConfiguration>();
            
            var lowerKeyword = keyword.ToLower();
            IQueryable<SystemConfiguration> query = _dbSet.AsNoTracking();
            
            // 기본: 키에서 검색
            Expression<Func<SystemConfiguration, bool>> predicate = 
                c => c.ConfigurationKey.ToLower().Contains(lowerKeyword);
            
            // 설명에서도 검색
            if (searchInDescription)
            {
                predicate = c => c.ConfigurationKey.ToLower().Contains(lowerKeyword) ||
                                (c.Description != null && c.Description.ToLower().Contains(lowerKeyword));
            }
            
            // 값에서도 검색 (주의: 암호화된 값 제외)
            if (searchInValue)
            {
                predicate = c => c.ConfigurationKey.ToLower().Contains(lowerKeyword) ||
                                (searchInDescription && c.Description != null && c.Description.ToLower().Contains(lowerKeyword)) ||
                                (!c.IsEncrypted && c.ConfigurationValue != null && c.ConfigurationValue.ToLower().Contains(lowerKeyword));
            }
            
            return await query.Where(predicate).ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 복잡한 조건을 사용하여 설정을 검색하고 페이징합니다.
        /// </summary>
        public async Task<PagedResult<SystemConfiguration>> AdvancedSearchAsync(
            Expression<Func<SystemConfiguration, bool>> criteria, 
            int pageNumber = 1, 
            int pageSize = 50,
            Expression<Func<SystemConfiguration, object>>? orderBy = null,
            bool isDescending = false,
            CancellationToken cancellationToken = default)
        {
            // 페이지 파라미터 검증
            pageNumber = Math.Max(1, pageNumber);
            pageSize = Math.Clamp(pageSize, 1, 100);
            
            var query = _dbSet.AsNoTracking().Where(criteria);
            var totalCount = await query.CountAsync(cancellationToken);
            
            // 정렬 적용
            if (orderBy != null)
            {
                query = isDescending 
                    ? query.OrderByDescending(orderBy) 
                    : query.OrderBy(orderBy);
            }
            else
            {
                query = query.OrderBy(c => c.ConfigurationKey);
            }
            
            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);
             
            return PagedResult<SystemConfiguration>.Create(items, totalCount, pageNumber, pageSize);
        }

        #endregion
        
        #region 캐싱 지원
        
        /// <summary>
        /// 자주 조회되는 캐시 가능한 설정들을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetCacheableConfigurationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.ConfigurationType == SystemConfigurationType.FeatureFlag || 
                           c.ConfigurationType == SystemConfigurationType.Performance)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 캐시 키를 생성합니다.
        /// </summary>
        public string GenerateCacheKey(string configurationKey)
        {
            return BuildCacheKey("config", configurationKey);
        }

        /// <summary>
        /// 캐시 무효화 알림을 보냅니다.
        /// </summary>
        public async Task<bool> NotifyCacheInvalidationAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            InvalidateCacheForKey(configurationKey);
            _logger.LogInformation("Cache invalidation notification for {Key}", configurationKey);
            
            // TODO: Redis Pub/Sub 또는 메시징 시스템을 통한 분산 캐시 무효화
            await Task.CompletedTask;
            
            return true;
        }

        /// <summary>
        /// 모든 캐시 무효화
        /// </summary>
        public async Task<int> InvalidateAllCacheAsync(
            CancellationToken cancellationToken = default)
        {
            if (_cache == null)
                return 0;
            
            // 모든 설정 키 조회
            var allKeys = await _dbSet
                .Select(c => c.ConfigurationKey)
                .ToListAsync(cancellationToken);
            
            foreach (var key in allKeys)
            {
                InvalidateCacheForKey(key);
            }
            
            _logger.LogInformation("Invalidated cache for {Count} configuration keys", allKeys.Count);
            
            return allKeys.Count;
        }
        
        #endregion

        #region 검증 및 기본값
        
        public async Task<(bool IsValid, string? ErrorMessage)> ValidateValueAsync(
            string configurationKey, 
            string value,
            CancellationToken cancellationToken = default)
        {
            // 빈 값 체크
            if (string.IsNullOrWhiteSpace(value))
            {
                return (false, "Value cannot be empty");
            }
            
            // 설정별 특별 검증 규칙
            if (configurationKey.Contains("Port", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(value, out var port) || port < 1 || port > 65535)
                {
                    return (false, "Port must be between 1 and 65535");
                }
            }
            
            if (configurationKey.Contains("Email", StringComparison.OrdinalIgnoreCase))
            {
                // 간단한 이메일 검증
                if (!value.Contains('@') || !value.Contains('.'))
                {
                    return (false, "Invalid email format");
                }
            }
            
            if (configurationKey.Contains("Url", StringComparison.OrdinalIgnoreCase) ||
                configurationKey.Contains("Endpoint", StringComparison.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(value, UriKind.Absolute, out _))
                {
                    return (false, "Invalid URL format");
                }
            }
            
            if (configurationKey.Contains("Timeout", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(value, out var timeout) || timeout < 0)
                {
                    return (false, "Timeout must be a positive number");
                }
            }
            
            await Task.CompletedTask;
            return (true, null);
        }

        public async Task<int> InitializeDefaultConfigurationsAsync(
            bool overwriteExisting = false,
            CancellationToken cancellationToken = default)
        {
            var defaults = GetDefaultConfigurations();
            
            if (overwriteExisting)
            {
                // 기존 설정 덮어쓰기
                foreach (var defaultConfig in defaults)
                {
                    var existing = await _dbSet
                        .FirstOrDefaultAsync(c => c.ConfigurationKey == defaultConfig.ConfigurationKey, cancellationToken);
                    
                    if (existing != null)
                    {
                        if (!existing.IsReadOnly && !existing.IsSystemManaged)
                        {
                            existing.ConfigurationValue = defaultConfig.ConfigurationValue;
                            existing.UpdatedAt = DateTime.UtcNow;
                            _dbSet.Update(existing);
                        }
                    }
                    else
                    {
                        await _dbSet.AddAsync(defaultConfig, cancellationToken);
                    }
                }
                
                return defaults.Count;
            }
            else
            {
                // 존재하지 않는 설정만 추가
                var existingKeys = await _dbSet
                    .Select(c => c.ConfigurationKey)
                    .ToListAsync(cancellationToken);
                
                var toAdd = defaults
                    .Where(d => !existingKeys.Contains(d.ConfigurationKey))
                    .ToList();
                
                if (toAdd.Any())
                {
                    await _dbSet.AddRangeAsync(toAdd, cancellationToken);
                    return toAdd.Count;
                }
            }
            
            return 0;
        }

        public async Task<bool> ResetToDefaultAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            var defaults = GetDefaultConfigurations();
            var defaultConfig = defaults.FirstOrDefault(c => c.ConfigurationKey == configurationKey);
            
            if (defaultConfig == null)
                return false;
            
            var existing = await _dbSet
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (existing == null)
                return false;
            
            existing.ConfigurationValue = defaultConfig.ConfigurationValue;
            existing.UpdatedAt = DateTime.UtcNow;
            
            InvalidateCacheForKey(configurationKey);
            _dbSet.Update(existing);
            
            return true;
        }

        public async Task<string?> GetDefaultValueAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            var defaults = GetDefaultConfigurations();
            var defaultConfig = defaults.FirstOrDefault(c => c.ConfigurationKey == configurationKey);
            
            await Task.CompletedTask;
            return defaultConfig?.ConfigurationValue;
        }
        
        #endregion
        
        #region 통계 및 모니터링

        public async Task<ConfigurationUsageStatistics?> GetUsageStatisticsAsync(
            string configurationKey,
            CancellationToken cancellationToken = default)
        {
            var config = await _dbSet
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            
            if (config == null)
                return null;
            
            // 변경 이력에서 통계 추출
            var changeCount = 0;
            if (!string.IsNullOrEmpty(config.ChangeHistory))
            {
                try
                {
                    var history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(
                        config.ChangeHistory, _jsonOptions);
                    changeCount = history?.Count ?? 0;
                }
                catch { }
            }
            
            return new ConfigurationUsageStatistics
            {
                ConfigurationKey = configurationKey,
                TotalAccessCount = 0, // 실제 구현 시 access logging 필요
                LastAccessedAt = null, // 실제 구현 시 access logging 필요
                LastModifiedAt = config.UpdatedAt,
                LastModifiedBy = null, // 변경 이력에서 추출 가능
                ChangeCount = changeCount
            };
        }

        public async Task<IEnumerable<(SystemConfiguration Configuration, int AccessCount)>> GetMostUsedConfigurationsAsync(
            int topCount = 10,
            CancellationToken cancellationToken = default)
        {
            // 실제 구현에서는 access logging 테이블과 조인 필요
            // 현재는 모든 FeatureFlag를 반환하는 것으로 대체
            var configs = await _dbSet
                .AsNoTracking()
                .Where(c => c.ConfigurationType == SystemConfigurationType.FeatureFlag)
                .Take(topCount)
                .ToListAsync(cancellationToken);
            
            return configs.Select(c => (c, AccessCount: 0));
        }

        public async Task<IEnumerable<SystemConfiguration>> GetUnusedConfigurationsAsync(
            int unusedSinceDays = 90,
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-unusedSinceDays);
            
            return await _dbSet
                .AsNoTracking()
                .Where(c => c.UpdatedAt == null || c.UpdatedAt < cutoffDate)
                .Where(c => !c.IsSystemManaged) // 시스템 관리 설정 제외
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Private Helper Methods
        
        /// <summary>
        /// 캐시 키 생성 헬퍼
        /// </summary>
        private string BuildCacheKey(string operation, params object[] parameters)
        {
            var paramStr = string.Join(":", parameters);
            return $"{CACHE_PREFIX}:{operation}:{paramStr}";
        }
        
        /// <summary>
        /// 특정 설정 키의 캐시 무효화
        /// </summary>
        private void InvalidateCacheForKey(string configurationKey)
        {
            if (_cache == null) 
                return;
            
            // 여러 작업의 캐시 키를 모두 제거
            _cache.Remove(BuildCacheKey(nameof(GetByKeyAsync), configurationKey));
            _cache.Remove(BuildCacheKey("config", configurationKey));
        }
        
        /// <summary>
        /// 설정별 캐시 옵션 결정
        /// </summary>
        private MemoryCacheEntryOptions GetCacheOptions(SystemConfiguration config)
        {
            // 설정 타입별로 다른 캐시 정책 적용
            return config.ConfigurationType switch
            {
                SystemConfigurationType.FeatureFlag => new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5),
                    Priority = CacheItemPriority.High
                },
                SystemConfigurationType.Performance => new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
                    SlidingExpiration = TimeSpan.FromMinutes(10),
                    Priority = CacheItemPriority.Normal
                },
                _ => new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
                    SlidingExpiration = TimeSpan.FromMinutes(5),
                    Priority = CacheItemPriority.Normal
                }
            };
        }

        /// <summary>
        /// 내부용 변경 이력 기록 (SaveChanges 호출 없음)
        /// </summary>
        private async Task RecordChangeHistoryInternalAsync(
            SystemConfiguration config,
            string? oldValue,
            string newValue,
            string changedBy)
        {
            var history = new List<ConfigurationChangeHistory>();
            
            if (!string.IsNullOrEmpty(config.ChangeHistory))
            {
                try
                {
                    history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(
                        config.ChangeHistory, _jsonOptions) ?? new List<ConfigurationChangeHistory>();
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "Could not deserialize existing change history for key {Key}", 
                        config.ConfigurationKey);
                }
            }
            
            history.Add(new ConfigurationChangeHistory
            {
                OldValue = oldValue,
                NewValue = newValue,
                ChangedBy = changedBy,
                ChangedAt = DateTime.UtcNow
            });

            // 최근 10개의 이력만 유지
            var trimmedHistory = history
                .OrderByDescending(h => h.ChangedAt)
                .Take(10)
                .ToList();
            
            config.ChangeHistory = JsonSerializer.Serialize(trimmedHistory, _jsonOptions);
            
            await Task.CompletedTask; // 비동기 시그니처 유지
        }
        
        /// <summary>
        /// 시스템 기본 설정 정의 (예시)
        /// </summary>
        private List<SystemConfiguration> GetDefaultConfigurations()
        {
            return new List<SystemConfiguration>
            {
                new() 
                {
                    ConfigurationKey = "SessionTimeoutMinutes",
                    ConfigurationValue = "30",
                    ConfigurationType = SystemConfigurationType.Security,
                    Category = SystemConfigurationCategory.Authentication,
                    Description = "사용자 세션 타임아웃 시간 (분)",
                    IsSystemManaged = true,
                    CreatedAt = DateTime.UtcNow
                },
                new()
                {
                    ConfigurationKey = "MaxLoginAttempts",
                    ConfigurationValue = "5",
                    ConfigurationType = SystemConfigurationType.Security,
                    Category = SystemConfigurationCategory.Authentication,
                    Description = "최대 로그인 시도 횟수",
                    IsSystemManaged = true,
                    CreatedAt = DateTime.UtcNow
                },
                new()
                {
                    ConfigurationKey = "EnableAuditLog",
                    ConfigurationValue = "true",
                    ConfigurationType = SystemConfigurationType.Monitoring,
                    Category = SystemConfigurationCategory.Logging,
                    Description = "감사 로그 활성화 여부",
                    IsSystemManaged = true,
                    CreatedAt = DateTime.UtcNow
                }
            };
        }
        
        #endregion
    }
}