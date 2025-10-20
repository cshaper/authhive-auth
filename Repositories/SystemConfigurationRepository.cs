using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.System;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 시스템 설정 리포지토리 구현체 (v17 - 리팩토링)
    /// AuthHive 플랫폼 전반에 걸친 모든 설정을 데이터베이스에서 관리합니다.
    /// </summary>
    public class SystemConfigurationRepository : BaseRepository<SystemConfiguration>, ISystemConfigurationRepository
    {
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<SystemConfigurationRepository> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        private const string CACHE_PREFIX = "SysConfig";

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        // [수정] ICacheService, IDateTimeProvider 주입, IOrganizationContext 제거
        public SystemConfigurationRepository(
            AuthDbContext context,
            ILogger<SystemConfigurationRepository> logger,
            IEncryptionService encryptionService,
            IDateTimeProvider dateTimeProvider,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
        }

        // [추가] 시스템 설정은 조직에 종속되지 않으므로 false 반환
        protected override bool IsOrganizationScopedEntity() => false;

        #region 기본 조회 (캐시 최적화)

        public async Task<SystemConfiguration?> GetByKeyAsync(
            string configurationKey,
            bool includeInactive = false,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);

            if (_cacheService != null && !includeInactive)
            {
                var cached = await _cacheService.GetAsync<SystemConfiguration>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var query = Query().AsNoTracking();

            if (!includeInactive)
            {
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(c =>
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }

            var result = await query.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);

            if (_cacheService != null && result != null && !includeInactive)
            {
                await _cacheService.SetAsync(cacheKey, result, GetCacheExpiration(result), cancellationToken);
            }

            return result;
        }

        public async Task<IEnumerable<SystemConfiguration>> GetByKeysAsync(
            IEnumerable<string> configurationKeys,
            CancellationToken cancellationToken = default)
        {
            var keyList = configurationKeys.ToList();
            if (!keyList.Any())
                return Enumerable.Empty<SystemConfiguration>();

            var results = new List<SystemConfiguration>();
            var keysToFetch = new List<string>();

            if (_cacheService != null)
            {
                var cacheKeys = keyList.ToDictionary(key => BuildCacheKey(nameof(GetByKeyAsync), key), key => key);
                var cachedItems = await _cacheService.GetMultipleAsync<SystemConfiguration>(cacheKeys.Keys, cancellationToken);

                foreach (var kvp in cachedItems)
                {
                    if (kvp.Value != null)
                    {
                        results.Add(kvp.Value);
                    }
                }
                var cachedKeys = results.Select(r => r.ConfigurationKey).ToHashSet();
                keysToFetch = keyList.Where(k => !cachedKeys.Contains(k)).ToList();
            }
            else
            {
                keysToFetch = keyList;
            }

            if (!keysToFetch.Any())
            {
                return results;
            }

            var fromDb = await Query()
                .AsNoTracking()
                .Where(c => keysToFetch.Contains(c.ConfigurationKey))
                .ToListAsync(cancellationToken);

            if (_cacheService != null)
            {
                var itemsToCache = new Dictionary<string, SystemConfiguration>();
                foreach (var config in fromDb)
                {
                    var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), config.ConfigurationKey);
                    itemsToCache[cacheKey] = config;
                }
                if (itemsToCache.Any())
                {
                    // TODO: 개별 만료 시간 설정이 필요하다면 SetMultiple을 수정하거나 개별 SetAsync 호출
                    await _cacheService.SetMultipleAsync(itemsToCache, TimeSpan.FromMinutes(15), cancellationToken);
                }
            }

            return results.Concat(fromDb);
        }

        public async Task<IEnumerable<SystemConfiguration>> GetByTypeAsync(SystemConfigurationType configurationType, bool includeInactive = false, CancellationToken cancellationToken = default)
        {
            var query = Query().AsNoTracking().Where(c => c.ConfigurationType == configurationType);

            if (!includeInactive)
            {
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(c =>
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }

            return await query.ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<SystemConfiguration>> GetByCategoryAsync(SystemConfigurationCategory category, bool includeInactive = false, CancellationToken cancellationToken = default)
        {
            var query = Query().AsNoTracking().Where(c => c.Category == category);

            if (!includeInactive)
            {
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(c =>
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }

            return await query.ToListAsync(cancellationToken);
        }


        public async Task<bool> ExistsAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            var cacheKey = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);
            if (_cacheService != null && await _cacheService.ExistsAsync(cacheKey, cancellationToken))
            {
                return true;
            }

            return await Query().AnyAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
        }

        #endregion

        #region 값 조회 및 타입 변환

        public async Task<string?> GetStringValueAsync(
            string configurationKey,
            string? defaultValue = null,
            CancellationToken cancellationToken = default)
        {
            var config = await GetByKeyAsync(configurationKey, false, cancellationToken);
            return config?.ConfigurationValue ?? defaultValue;
        }

        public async Task<int> GetIntValueAsync(string configurationKey, int defaultValue = 0, CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return int.TryParse(configValue, out var result) ? result : defaultValue;
        }

        public async Task<bool> GetBoolValueAsync(string configurationKey, bool defaultValue = false, CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return bool.TryParse(configValue, out var result) ? result : defaultValue;
        }

        public async Task<decimal> GetDecimalValueAsync(string configurationKey, decimal defaultValue = 0, CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return decimal.TryParse(configValue, out var result) ? result : defaultValue;
        }

        public async Task<DateTime?> GetDateTimeValueAsync(string configurationKey, DateTime? defaultValue = null, CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return DateTime.TryParse(configValue, out var result) ? result : defaultValue;
        }

        public async Task<TimeSpan?> GetTimeSpanValueAsync(string configurationKey, TimeSpan? defaultValue = null, CancellationToken cancellationToken = default)
        {
            var configValue = await GetStringValueAsync(configurationKey, null, cancellationToken);
            return TimeSpan.TryParse(configValue, out var result) ? result : defaultValue;
        }

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
                return await _encryptionService.DecryptAsync(config.ConfigurationValue, cancellationToken);
            }

            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decrypt value for key {Key}", configurationKey);
                return null;
            }
        }

        #endregion

        #region 설정 생성 및 업데이트

        public async Task<SystemConfiguration> UpsertAsync(
            string configurationKey, string value, SystemConfigurationType configurationType,
            SystemConfigurationCategory? category = null, string? description = null,
            CancellationToken cancellationToken = default)
        {
            var existingConfig = await Query()
                .FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);

            if (existingConfig != null)
            {
                existingConfig.ConfigurationValue = value;
                existingConfig.ConfigurationType = configurationType;
                existingConfig.Category = category ?? existingConfig.Category;
                existingConfig.Description = description ?? existingConfig.Description;
                existingConfig.UpdatedAt = _dateTimeProvider.UtcNow;

                await UpdateAsync(existingConfig, cancellationToken);
                return existingConfig;
            }

            var newConfig = new SystemConfiguration
            {
                ConfigurationKey = configurationKey,
                ConfigurationValue = value,
                ConfigurationType = configurationType,
                Category = category,
                Description = description,
                CreatedAt = _dateTimeProvider.UtcNow
            };

            return await AddAsync(newConfig, cancellationToken);
        }

        public async Task<bool> UpdateValueAsync(
            string configurationKey, string newValue, bool recordHistory = true,
            string? changedBy = null, CancellationToken cancellationToken = default)
        {
            var config = await Query()
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
            config.UpdatedAt = _dateTimeProvider.UtcNow;
            await UpdateAsync(config, cancellationToken);

            return true;
        }

        public async Task<bool> UpdateEncryptedValueAsync(string configurationKey, string plainValue, CancellationToken cancellationToken = default)
        {
            var config = await Query().FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey, cancellationToken);
            if (config == null) return false;

            var encryptedValue = await _encryptionService.EncryptAsync(plainValue, cancellationToken);
            config.ConfigurationValue = encryptedValue;
            config.IsEncrypted = true;
            config.UpdatedAt = _dateTimeProvider.UtcNow;

            await UpdateAsync(config, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateJsonValueAsync<T>(string configurationKey, T value, CancellationToken cancellationToken = default) where T : class
        {
            var jsonValue = JsonSerializer.Serialize(value, _jsonOptions);
            return await UpdateValueAsync(configurationKey, jsonValue, true, null, cancellationToken);
        }

        #endregion

        // ... 다른 인터페이스 메서드 구현 ...

        #region Private Helper Methods

        private string BuildCacheKey(string operation, params object[] parameters)
        {
            var paramStr = string.Join(":", parameters);
            return $"{CACHE_PREFIX}:{operation}:{paramStr}";
        }

        private async Task InvalidateCacheForKeyAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null)
                return;

            var cacheKey1 = BuildCacheKey(nameof(GetByKeyAsync), configurationKey);
            var cacheKey2 = BuildCacheKey("config", configurationKey);

            await _cacheService.RemoveAsync(cacheKey1, cancellationToken);
            await _cacheService.RemoveAsync(cacheKey2, cancellationToken);
        }

        private TimeSpan GetCacheExpiration(SystemConfiguration config)
        {
            // EffectiveUntil이 설정되어 있으면, 만료 시간 이전에 캐시가 만료되도록 설정
            if (config.EffectiveUntil.HasValue)
            {
                var remaining = config.EffectiveUntil.Value - _dateTimeProvider.UtcNow;
                if (remaining > TimeSpan.Zero)
                {
                    return remaining;
                }
            }

            return config.ConfigurationType switch
            {
                SystemConfigurationType.FeatureFlag => TimeSpan.FromMinutes(5),
                SystemConfigurationType.Performance => TimeSpan.FromMinutes(30),
                _ => TimeSpan.FromMinutes(15),
            };
        }

        private async Task RecordChangeHistoryInternalAsync(
            SystemConfiguration config, string? oldValue, string newValue, string changedBy)
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
                ChangedAt = _dateTimeProvider.UtcNow
            });

            var trimmedHistory = history.OrderByDescending(h => h.ChangedAt).Take(10).ToList();
            config.ChangeHistory = JsonSerializer.Serialize(trimmedHistory, _jsonOptions);

            await Task.CompletedTask;
        }

        // ... GetDefaultConfigurations 메서드는 별도 파일/서비스로 분리하는 것을 권장 ...

        #endregion

        // ... ISystemConfigurationRepository의 나머지 메서드들을 여기에 모두 구현해야 합니다 ...
        #region 유효 기간 관리
        public Task<IEnumerable<SystemConfiguration>> GetEffectiveConfigurationsAsync(DateTime? asOfDate = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SetEffectivePeriodAsync(string configurationKey, DateTime? effectiveFrom, DateTime? effectiveUntil, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SystemConfiguration>> GetExpiredConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<SystemConfiguration> CreateTemporaryConfigurationAsync(string configurationKey, string value, TimeSpan duration, SystemConfigurationType configurationType = SystemConfigurationType.Maintenance, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 변경 이력 관리
        public Task<IEnumerable<ConfigurationChangeHistory>> GetChangeHistoryAsync(string configurationKey, int limit = 10, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> RecordChangeHistoryAsync(string configurationKey, string? oldValue, string newValue, string changedBy, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetValueAsOfDateAsync(string configurationKey, DateTime asOfDate, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> PurgeChangeHistoryAsync(string configurationKey, int keepRecentCount = 10, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 읽기 전용 및 보안
        public Task<IEnumerable<SystemConfiguration>> GetReadOnlyConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SetReadOnlyAsync(string configurationKey, bool isReadOnly, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SystemConfiguration>> GetEncryptedConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SystemConfiguration>> GetSystemManagedConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetMaskedValueAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 재시작 요구 사항
        public Task<IEnumerable<SystemConfiguration>> GetRestartRequiredConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SystemConfiguration>> GetPendingRestartConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SetRestartRequiredAsync(string configurationKey, bool requiresRestart, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 일괄 작업
        public Task<int> BulkUpdateAsync(Dictionary<string, string> configurations, bool validateBeforeUpdate = false, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> DeleteByCategoryAsync(SystemConfigurationCategory category, bool excludeSystemManaged = true, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<Dictionary<string, object>> ExportConfigurationsAsync(IEnumerable<SystemConfigurationCategory>? categories = null, bool includeEncrypted = false, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> ImportConfigurationsAsync(Dictionary<string, object> configurations, bool overwriteExisting = false, bool validateBeforeImport = true, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 검색 및 필터링
        public Task<IEnumerable<SystemConfiguration>> SearchAsync(string keyword, bool searchInDescription = true, bool searchInValue = false, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<PagedResult<SystemConfiguration>> AdvancedSearchAsync(Expression<Func<SystemConfiguration, bool>> criteria, int pageNumber = 1, int pageSize = 50, Expression<Func<SystemConfiguration, object>>? orderBy = null, bool isDescending = false, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 캐싱 지원
        public Task<IEnumerable<SystemConfiguration>> GetCacheableConfigurationsAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public string GenerateCacheKey(string configurationKey)
        {
            throw new NotImplementedException();
        }

        public Task<bool> NotifyCacheInvalidationAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> InvalidateAllCacheAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 검증 및 기본값
        public Task<(bool IsValid, string? ErrorMessage)> ValidateValueAsync(string configurationKey, string value, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> InitializeDefaultConfigurationsAsync(bool overwriteExisting = false, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> ResetToDefaultAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetDefaultValueAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region 통계 및 모니터링
        public Task<ConfigurationUsageStatistics?> GetUsageStatisticsAsync(string configurationKey, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<(SystemConfiguration Configuration, int AccessCount)>> GetMostUsedConfigurationsAsync(int topCount = 10, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SystemConfiguration>> GetUnusedConfigurationsAsync(int unusedSinceDays = 90, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}

