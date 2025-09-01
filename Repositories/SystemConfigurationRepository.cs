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
using System.Linq.Expressions;
using System.Text.Json;
using AuthHive.Core.Interfaces.Infra.Security;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 시스템 설정 리포지토리 구현체
    /// AuthHive 플랫폼 전반에 걸친 모든 설정을 데이터베이스에서 관리합니다.
    /// </summary>
    public class SystemConfigurationRepository : BaseRepository<SystemConfiguration>, ISystemConfigurationRepository
    {
        private readonly IEncryptionService _encryptionService;
        // _logger 필드를 이 클래스 내에서 직접 관리하도록 수정합니다.
        private readonly ILogger<SystemConfigurationRepository> _logger;

        public SystemConfigurationRepository(
            AuthDbContext context,
            ILogger<SystemConfigurationRepository> logger,
            IEncryptionService encryptionService)
            : base(context) // BUG FIX: BaseRepository는 context만 받도록 수정합니다.
        {
            _encryptionService = encryptionService;
            _logger = logger; // BUG FIX: _logger 필드를 여기서 초기화합니다.
        }

        #region 기본 조회

        /// <summary>
        /// 설정 키(Key)를 사용해 특정 설정 항목 하나를 조회합니다.
        /// 가장 기본적이고 자주 사용되는 설정 조회 메서드입니다.
        /// </summary>
        /// <example>
        /// // SMTP 서버 주소 설정값을 가져올 때
        /// var smtpSetting = await _repo.GetByKeyAsync("SmtpServerAddress");
        /// </example>
        /// <param name="configurationKey">고유한 설정 키 (예: "SessionTimeoutMinutes")</param>
        /// <param name="includeInactive">유효 기간이 지난 비활성 설정도 포함할지 여부</param>
        public async Task<SystemConfiguration?> GetByKeyAsync(string configurationKey, bool includeInactive = false)
        {
            var query = _dbSet.AsQueryable();
            // false일 경우, 현재 시각(UTC)을 기준으로 유효한 설정만 가져옵니다.
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            return await query.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
        }

        /// <summary>
        /// 여러 개의 설정 키를 목록으로 전달하여 한 번의 쿼리로 모두 조회합니다.
        /// </summary>
        /// <example>
        /// // 이메일 관련 설정들을 한 번에 가져올 때
        /// var emailKeys = new[] { "SmtpServer", "SmtpPort", "SmtpUsername" };
        /// var emailSettings = await _repo.GetByKeysAsync(emailKeys);
        /// </example>
        public async Task<IEnumerable<SystemConfiguration>> GetByKeysAsync(IEnumerable<string> configurationKeys)
        {
            return await _dbSet.Where(c => configurationKeys.Contains(c.ConfigurationKey)).ToListAsync();
        }

        /// <summary>
        /// 설정 타입(Type)으로 관련된 모든 설정을 조회합니다.
        /// </summary>
        /// <example>
        /// // 모든 보안 관련(Security) 설정을 가져올 때
        /// var securitySettings = await _repo.GetByTypeAsync(SystemConfigurationType.Security);
        /// </example>
        public async Task<IEnumerable<SystemConfiguration>> GetByTypeAsync(SystemConfigurationType configurationType, bool includeInactive = false)
        {
             var query = _dbSet.Where(c => c.ConfigurationType == configurationType);
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            return await query.ToListAsync();
        }

        /// <summary>
        /// 카테고리(Category)로 관련된 모든 설정을 조회합니다.
        /// </summary>
        /// <example>
        /// // 인증(Authentication) 카테고리에 속한 모든 설정을 가져올 때
        /// var authSettings = await _repo.GetByCategoryAsync(SystemConfigurationCategory.Authentication);
        /// </example>
        public async Task<IEnumerable<SystemConfiguration>> GetByCategoryAsync(SystemConfigurationCategory category, bool includeInactive = false)
        {
            var query = _dbSet.Where(c => c.Category == category);
            if (!includeInactive)
            {
                var now = DateTime.UtcNow;
                query = query.Where(c => 
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now));
            }
            return await query.ToListAsync();
        }

        /// <summary>
        /// 특정 설정 키가 존재하는지 확인합니다.
        /// </summary>
        public async Task<bool> ExistsAsync(string configurationKey)
        {
            return await _dbSet.AnyAsync(c => c.ConfigurationKey == configurationKey);
        }

        #endregion

        #region 값 조회 및 타입 변환

        /// <summary>
        /// 설정 값을 문자열(string)로 간편하게 조회합니다. 값이 없으면 기본값을 반환합니다.
        /// </summary>
        /// <example>
        /// var siteName = await _repo.GetStringValueAsync("SiteName", "Default Site");
        /// </example>
        public async Task<string?> GetStringValueAsync(string configurationKey, string? defaultValue = null)
        {
            var config = await GetByKeyAsync(configurationKey);
            return config?.ConfigurationValue ?? defaultValue;
        }

        /// <summary>
        /// 설정 값을 정수(int)로 간편하게 조회합니다. 변환에 실패하면 기본값을 반환합니다.
        /// </summary>
        /// <example>
        /// var timeout = await _repo.GetIntValueAsync("SessionTimeoutMinutes", 30);
        /// </example>
        public async Task<int> GetIntValueAsync(string configurationKey, int defaultValue = 0)
        {
            var configValue = await GetStringValueAsync(configurationKey);
            return int.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값을 불리언(bool)으로 간편하게 조회합니다. 변환에 실패하면 기본값을 반환합니다.
        /// </summary>
        /// <example>
        /// bool enableAudit = await _repo.GetBoolValueAsync("EnableAuditing", false);
        /// </example>
        public async Task<bool> GetBoolValueAsync(string configurationKey, bool defaultValue = false)
        {
            var configValue = await GetStringValueAsync(configurationKey);
            return bool.TryParse(configValue, out var result) ? result : defaultValue;
        }

        /// <summary>
        /// 설정 값이 JSON 형식일 때, 지정된 클래스 객체(T)로 자동 역직렬화하여 조회합니다.
        /// </summary>
        /// <example>
        /// // SmtpSettings 클래스가 있다고 가정
        /// var smtpConfig = await _repo.GetJsonValueAsync<SmtpSettings>("SmtpConfiguration");
        /// if (smtpConfig != null) { var host = smtpConfig.Host; }
        /// </example>
        public async Task<T?> GetJsonValueAsync<T>(string configurationKey) where T : class
        {
            var jsonValue = await GetStringValueAsync(configurationKey);
            if (string.IsNullOrEmpty(jsonValue)) return null;

            try
            {
                return JsonSerializer.Deserialize<T>(jsonValue);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to deserialize JSON for key {Key}", configurationKey);
                return null;
            }
        }

        /// <summary>
        /// 암호화된 설정 값을 자동으로 복호화하여 평문으로 조회합니다.
        /// IsEncrypted 플래그가 true인 설정에 사용됩니다.
        /// </summary>
        /// <example>
        /// // 외부 API 비밀 키를 안전하게 가져올 때
        /// var stripeSecretKey = await _repo.GetDecryptedValueAsync("StripeApiSecretKey");
        /// </example>
        public async Task<string?> GetDecryptedValueAsync(string configurationKey)
        {
            var config = await GetByKeyAsync(configurationKey);
            if (config == null || string.IsNullOrEmpty(config.ConfigurationValue))
            {
                return null;
            }

            if (!config.IsEncrypted)
            {
                _logger.LogWarning("Attempted to decrypt a non-encrypted value for key {Key}", configurationKey);
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

        #region 설정 생성 및 업데이트

        /// <summary>
        /// 설정이 존재하면 업데이트하고, 없으면 새로 생성(Upsert)합니다.
        /// </summary>
        public async Task<SystemConfiguration> UpsertAsync(string configurationKey, string value, SystemConfigurationType configurationType, SystemConfigurationCategory? category = null, string? description = null)
        {
            var existingConfig = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (existingConfig != null)
            {
                existingConfig.ConfigurationValue = value;
                existingConfig.ConfigurationType = configurationType;
                existingConfig.Category = category ?? existingConfig.Category;
                existingConfig.Description = description ?? existingConfig.Description;
                await UpdateAsync(existingConfig);
                return existingConfig;
            }
            else
            {
                var newConfig = new SystemConfiguration
                {
                    ConfigurationKey = configurationKey,
                    ConfigurationValue = value,
                    ConfigurationType = configurationType,
                    Category = category,
                    Description = description
                };
                return await AddAsync(newConfig);
            }
        }
        
        /// <summary>
        /// 특정 설정의 값(Value)만 업데이트합니다. 변경 이력을 자동으로 기록할 수 있습니다.
        /// </summary>
        /// <param name="recordHistory">true일 경우, 변경 전/후 값을 ChangeHistory 필드에 기록합니다.</param>
        public async Task<bool> UpdateValueAsync(string configurationKey, string newValue, bool recordHistory = true)
        {
            var config = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null) return false;

            if (recordHistory)
            {
                // TODO: 현재 로그인한 사용자의 ID를 가져와 "SYSTEM" 대신 채워넣어야 합니다.
                await RecordChangeHistoryAsync(configurationKey, config.ConfigurationValue, newValue, "SYSTEM");
            }
            
            config.ConfigurationValue = newValue;
            await UpdateAsync(config);
            return true;
        }

        /// <summary>
        /// 전달된 평문 값을 자동으로 암호화하여 저장합니다.
        /// IsEncrypted 플래그도 true로 자동 설정됩니다.
        /// </summary>
        /// <example>
        /// // 관리자 페이지에서 외부 서비스 API 키를 업데이트할 때
        /// await _repo.UpdateEncryptedValueAsync("SendGridApiKey", "SG.xxxxxxxx");
        /// </example>
        public async Task<bool> UpdateEncryptedValueAsync(string configurationKey, string plainValue)
        {
            var encryptedValue = await _encryptionService.EncryptAsync(plainValue);
            // 변경 이력에는 암호화된 값이 아닌 평문을 기록하는 것이 더 유용할 수 있으나, 여기서는 이력 기록을 생략합니다.
            var result = await UpdateValueAsync(configurationKey, encryptedValue, recordHistory: false); 
            
            if(result)
            {
                var config = await GetByKeyAsync(configurationKey);
                if(config != null && !config.IsEncrypted)
                {
                    config.IsEncrypted = true;
                    await UpdateAsync(config);
                }
            }
            return result;
        }

        /// <summary>
        /// 전달된 객체를 JSON 문자열로 직렬화하여 저장합니다.
        /// </summary>
        public async Task<bool> UpdateJsonValueAsync<T>(string configurationKey, T value) where T : class
        {
            var jsonValue = JsonSerializer.Serialize(value);
            return await UpdateValueAsync(configurationKey, jsonValue);
        }
        
        #endregion

        #region 유효 기간 관리
        
        /// <summary>
        /// 현재 시점에서 유효한 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetEffectiveConfigurationsAsync(DateTime? asOfDate = null)
        {
            var now = asOfDate ?? DateTime.UtcNow;
            return await _dbSet.Where(c =>
                    (!c.EffectiveFrom.HasValue || c.EffectiveFrom.Value <= now) &&
                    (!c.EffectiveUntil.HasValue || c.EffectiveUntil.Value >= now))
                .ToListAsync();
        }

        /// <summary>
        /// 특정 설정의 유효 기간(시작일, 종료일)을 설정합니다.
        /// </summary>
        /// <example>
        /// // "DiscountEvent" 설정을 다음 주 월요일부터 일주일간만 유효하도록 설정
        /// var nextMonday = ...;
        /// await _repo.SetEffectivePeriodAsync("DiscountEvent", nextMonday, nextMonday.AddDays(7));
        /// </example>
        public async Task<bool> SetEffectivePeriodAsync(string configurationKey, DateTime? effectiveFrom, DateTime? effectiveUntil)
        {
            var config = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null) return false;

            config.EffectiveFrom = effectiveFrom;
            config.EffectiveUntil = effectiveUntil;
            await UpdateAsync(config);
            return true;
        }
        
        /// <summary>
        /// 유효 기간이 만료된 모든 설정을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetExpiredConfigurationsAsync()
        {
            var now = DateTime.UtcNow;
            return await _dbSet.Where(c => c.EffectiveUntil.HasValue && c.EffectiveUntil.Value < now).ToListAsync();
        }
        
        /// <summary>
        /// 특정 기간 동안만 유효한 임시 설정을 생성합니다.
        /// </summary>
        /// <example>
        /// // 1시간 동안만 유지되는 긴급 점검 공지를 생성할 때
        /// await _repo.CreateTemporaryConfigurationAsync("MaintenanceNotice", "긴급 점검 중입니다.", TimeSpan.FromHours(1));
        /// </example>
        public async Task<SystemConfiguration> CreateTemporaryConfigurationAsync(string configurationKey, string value, TimeSpan duration)
        {
            var now = DateTime.UtcNow;
            var newConfig = new SystemConfiguration
            {
                ConfigurationKey = configurationKey,
                ConfigurationValue = value,
                EffectiveFrom = now,
                EffectiveUntil = now.Add(duration),
                ConfigurationType = SystemConfigurationType.Maintenance
            };
            return await AddAsync(newConfig);
        }
        #endregion

        #region 변경 이력 관리
        
        /// <summary>
        /// 특정 설정의 값 변경 이력을 조회합니다. 이력은 JSON으로 저장됩니다.
        /// </summary>
        public async Task<IEnumerable<ConfigurationChangeHistory>> GetChangeHistoryAsync(string configurationKey, int limit = 5)
        {
            var config = await _dbSet.AsNoTracking().FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null || string.IsNullOrEmpty(config.ChangeHistory))
            {
                return Enumerable.Empty<ConfigurationChangeHistory>();
            }

            try
            {
                var history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(config.ChangeHistory)
                              ?? new List<ConfigurationChangeHistory>();
                return history.OrderByDescending(h => h.ChangedAt).Take(limit);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse change history for key {Key}", configurationKey);
                return Enumerable.Empty<ConfigurationChangeHistory>();
            }
        }
        
        /// <summary>
        /// 설정 값 변경이 발생했을 때, 변경 내역을 JSON 필드에 기록합니다.
        /// UpdateValueAsync 메서드 내부에서 자동으로 호출될 수 있습니다.
        /// </summary>
        public async Task<bool> RecordChangeHistoryAsync(string configurationKey, string? oldValue, string newValue, string changedBy)
        {
            var config = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null) return false;

            var history = new List<ConfigurationChangeHistory>();
            if (!string.IsNullOrEmpty(config.ChangeHistory))
            {
                try
                {
                    history = JsonSerializer.Deserialize<List<ConfigurationChangeHistory>>(config.ChangeHistory) ?? new List<ConfigurationChangeHistory>();
                }
                catch (JsonException ex)
                {
                     _logger.LogError(ex, "Could not deserialize existing change history for key {Key}. A new history will be created.", configurationKey);
                }
            }
            
            history.Add(new ConfigurationChangeHistory
            {
                OldValue = oldValue,
                NewValue = newValue,
                ChangedBy = changedBy,
                ChangedAt = DateTime.UtcNow
            });

            // 성능을 위해 최근 10개의 이력만 유지합니다.
            var trimmedHistory = history.OrderByDescending(h => h.ChangedAt).Take(10).ToList();
            config.ChangeHistory = JsonSerializer.Serialize(trimmedHistory);
            
            // `UpdateAsync`는 BaseRepository에 있으므로 직접 호출하지 않고 SaveChangesAsync를 사용합니다.
            await _context.SaveChangesAsync();
            return true;
        }
        
        /// <summary>
        /// 변경 이력을 추적하여, 과거 특정 시점의 설정 값이 무엇이었는지 조회합니다.
        /// </summary>
        public async Task<string?> GetValueAsOfDateAsync(string configurationKey, DateTime asOfDate)
        {
             var history = await GetChangeHistoryAsync(configurationKey, 100); // 충분히 많은 이력 조회
             var record = history
                .OrderByDescending(h => h.ChangedAt)
                .FirstOrDefault(h => h.ChangedAt <= asOfDate);

             // 해당 시점의 기록이 있으면 그 기록의 새 값(NewValue)을, 없으면 null 반환
             return record?.NewValue;
        }

        #endregion
        
        #region 고급 기능 (읽기전용, 재시작 등)

        public async Task<IEnumerable<SystemConfiguration>> GetReadOnlyConfigurationsAsync()
        {
            return await _dbSet.Where(c => c.IsReadOnly).ToListAsync();
        }

        public async Task<bool> SetReadOnlyAsync(string configurationKey, bool isReadOnly)
        {
            var config = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null) return false;
            config.IsReadOnly = isReadOnly;
            await UpdateAsync(config);
            return true;
        }

        public async Task<IEnumerable<SystemConfiguration>> GetEncryptedConfigurationsAsync()
        {
             return await _dbSet.Where(c => c.IsEncrypted).ToListAsync();
        }

        public async Task<IEnumerable<SystemConfiguration>> GetSystemManagedConfigurationsAsync()
        {
            return await _dbSet.Where(c => c.IsSystemManaged).ToListAsync();
        }

        public async Task<IEnumerable<SystemConfiguration>> GetRestartRequiredConfigurationsAsync()
        {
            return await _dbSet.Where(c => c.RequiresRestart).ToListAsync();
        }
        
        public Task<IEnumerable<SystemConfiguration>> GetPendingRestartConfigurationsAsync()
        {
            // 이 기능은 보통 실제 적용 값과 DB 값이 다른 경우를 확인하는 로직이 필요합니다.
            // (예: 인메모리 캐시 값과 DB 값 비교)
            // 여기서는 RequiresRestart 플래그가 설정된 항목을 반환하는 것으로 단순화합니다.
            return GetRestartRequiredConfigurationsAsync();
        }

        public async Task<bool> SetRestartRequiredAsync(string configurationKey, bool requiresRestart)
        {
            var config = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == configurationKey);
            if (config == null) return false;
            config.RequiresRestart = requiresRestart;
            await UpdateAsync(config);
            return true;
        }
        #endregion

        #region 일괄 작업

        /// <summary>
        /// 여러 설정 값을 Dictionary 형태로 받아 한 번에 업데이트합니다.
        /// </summary>
        public async Task<int> BulkUpdateAsync(Dictionary<string, string> configurations)
        {
            var keys = configurations.Keys;
            var existingConfigs = await _dbSet.Where(c => keys.Contains(c.ConfigurationKey)).ToListAsync();
            
            foreach (var config in existingConfigs)
            {
                if(configurations.TryGetValue(config.ConfigurationKey, out var newValue))
                {
                    config.ConfigurationValue = newValue;
                }
            }
            
            await _context.SaveChangesAsync();
            return existingConfigs.Count;
        }

        /// <summary>
        /// 특정 카테고리에 속한 모든 설정을 일괄 삭제합니다.
        /// 시스템 관리 설정은 기본적으로 제외하여 안전을 확보합니다.
        /// </summary>
        public async Task<int> DeleteByCategoryAsync(SystemConfigurationCategory category, bool excludeSystemManaged = true)
        {
            var query = _dbSet.Where(c => c.Category == category);
            if (excludeSystemManaged)
            {
                query = query.Where(c => !c.IsSystemManaged);
            }
            var toDelete = await query.ToListAsync();
            _dbSet.RemoveRange(toDelete);
            return await _context.SaveChangesAsync();
        }
        
        /// <summary>
        /// DB에 저장된 설정들을 파일(JSON 등)로 내보내기 위해 Dictionary 형태로 변환합니다.
        /// 백업 또는 다른 환경으로의 마이그레이션에 사용됩니다.
        /// </summary>
        public async Task<Dictionary<string, object>> ExportConfigurationsAsync(IEnumerable<SystemConfigurationCategory>? categories = null)
        {
            var query = _dbSet.AsQueryable();
            if (categories != null && categories.Any())
            {
                query = query.Where(c => c.Category.HasValue && categories.Contains(c.Category.Value));
            }

            var configurations = await query
                .Where(c => c.ConfigurationValue != null)
                .ToListAsync();

            return configurations.ToDictionary(c => c.ConfigurationKey, c => c.ConfigurationValue as object)!;
        }

        /// <summary>
        /// 파일(JSON 등)로부터 읽어온 설정들을 DB로 가져옵니다(Import).
        /// </summary>
        public async Task<int> ImportConfigurationsAsync(Dictionary<string, object> configurations, bool overwriteExisting = false)
        {
            int count = 0;
            foreach (var kvp in configurations)
            {
                var existing = await _dbSet.FirstOrDefaultAsync(c => c.ConfigurationKey == kvp.Key);
                if (existing != null)
                {
                    if (overwriteExisting)
                    {
                        existing.ConfigurationValue = kvp.Value.ToString();
                        count++;
                    }
                }
                else
                {
                    // 가져온 설정은 기본적으로 'General' 타입으로 생성합니다.
                    await AddAsync(new SystemConfiguration { ConfigurationKey = kvp.Key, ConfigurationValue = kvp.Value.ToString(), ConfigurationType = SystemConfigurationType.General });
                    count++;
                }
            }
            await _context.SaveChangesAsync();
            return count;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 키워드를 사용하여 설정 키 또는 설명에서 원하는 설정을 검색합니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> SearchAsync(string keyword, bool searchInDescription = true)
        {
            var lowerKeyword = keyword.ToLower();
            return await _dbSet.Where(c => c.ConfigurationKey.ToLower().Contains(lowerKeyword) ||
                                      (searchInDescription && c.Description != null && c.Description.ToLower().Contains(lowerKeyword)))
                               .ToListAsync();
        }

        /// <summary>
        /// 복잡한 조건(LINQ Expression)을 사용하여 설정을 검색하고, 결과를 페이징하여 반환합니다.
        /// 관리자 페이지의 고급 검색 기능에 사용됩니다.
        /// </summary>
        public async Task<PagedResult<SystemConfiguration>> AdvancedSearchAsync(Expression<Func<SystemConfiguration, bool>> criteria, int pageNumber = 1, int pageSize = 50)
        {
             var query = _dbSet.Where(criteria);
             var totalCount = await query.CountAsync();
             var items = await query.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();
             
             return PagedResult<SystemConfiguration>.Create(items, totalCount, pageNumber, pageSize);
        }

        #endregion
        
        #region 캐싱 지원
        
        /// <summary>
        /// 자주 조회되지만 거의 변경되지 않는 설정들을 조회합니다.
        /// 시스템 시작 시 이 설정들을 미리 캐시(예: Redis)에 올려두어 DB 부하를 줄일 수 있습니다.
        /// </summary>
        public async Task<IEnumerable<SystemConfiguration>> GetCacheableConfigurationsAsync()
        {
            // 캐싱 전략에 따라 IsCacheable 같은 플래그를 엔티티에 추가할 수도 있습니다.
            // 여기서는 FeatureFlag와 Performance 관련 설정을 캐시 가능하다고 가정합니다.
            return await _dbSet.Where(c => c.ConfigurationType == SystemConfigurationType.FeatureFlag || 
                                           c.ConfigurationType == SystemConfigurationType.Performance)
                               .ToListAsync();
        }

        /// <summary>
        /// 캐시 키의 일관된 형식을 생성합니다. (예: "config:SessionTimeoutMinutes")
        /// </summary>
        public string GenerateCacheKey(string configurationKey)
        {
            return $"config:{configurationKey}";
        }

        /// <summary>
        /// 설정이 변경되었을 때, 다른 서비스나 서버에 캐시를 무효화하라고 알리는 역할을 합니다.
        /// </summary>
        /// <remarks>
        /// 실제 구현에서는 Redis Pub/Sub이나 Kafka 같은 메시징 시스템을 통해
        /// 다른 서비스 인스턴스에 "config:SessionTimeoutMinutes 캐시를 지워라"는 메시지를 보냅니다.
        /// </remarks>
        public Task<bool> NotifyCacheInvalidationAsync(string configurationKey)
        {
            _logger.LogInformation("Cache invalidation notification for {Key}", configurationKey);
            return Task.FromResult(true);
        }
        #endregion

        #region 검증 및 기본값
        
        // 아래 메서드들은 시스템의 안정성을 위해 추가적인 구현이 필요한 부분입니다.

        public Task<bool> ValidateValueAsync(string configurationKey, string value)
        {
            // TODO: 각 설정 키에 대한 유효성 검사 규칙(예: 정규식, 값의 범위 등)을
            // 별도로 정의하고 로드하여, 값이 저장되기 전에 유효한지 검증하는 로직이 필요합니다.
            // 예) "SmtpPort"는 숫자여야 하고 1~65535 사이여야 한다는 규칙.
            return Task.FromResult(true); // 현재는 임시로 항상 true를 반환합니다.
        }

        public Task<int> InitializeDefaultConfigurationsAsync()
        {
            // TODO: 시스템이 처음 설치될 때, 코드나 별도의 설정 파일(JSON, XML 등)에 정의된
            // 플랫폼 운영에 필수적인 기본 설정값들을 DB에 자동으로 기록(seeding)하는 로직이 필요합니다.
            return Task.FromResult(0);
        }

        public Task<bool> ResetToDefaultAsync(string configurationKey)
        {
            // TODO: InitializeDefaultConfigurationsAsync 로직과 연계하여,
            // 관리자가 실수로 잘못 수정한 특정 설정을 원래의 기본값으로 되돌리는 기능이 필요합니다.
            return Task.FromResult(false);
        }
        #endregion
    }
}

