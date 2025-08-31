// Path: AuthHive.Auth/Repositories/OrganizationSettingsRepository.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using System.Text.Json;
using System.Linq.Expressions;
using AuthHive.Core.Models.Common;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationSettings Repository 구현체 - AuthHive v15
    /// 조직별 설정의 CRUD, 상속, 템플릿 등 복잡한 설정 관리를 담당합니다.
    /// </summary>
    public class OrganizationSettingsRepository : OrganizationScopedRepository<OrganizationSettings>,
        IOrganizationSettingsRepository,
        IOrganizationSettingsQueryRepository,
        IOrganizationSettingsCommandRepository
    {
        public OrganizationSettingsRepository(AuthDbContext context) : base(context)
        {
        }

        #region IOrganizationSettingsRepository 구현

        /// <summary>
        /// 특정 설정 조회
        /// </summary>
        public async Task<OrganizationSettings?> GetSettingAsync(Guid organizationId, string category, string settingKey, bool includeInherited = true)
        {
            var setting = await _dbSet
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey &&
                    !s.IsDeleted);

            // 직접 설정이 없고 상속을 허용하는 경우, 상위 조직에서 찾기
            if (setting == null && includeInherited)
            {
                setting = await GetInheritedSettingAsync(organizationId, category, settingKey);
            }

            return setting;
        }

        /// <summary>
        /// 설정 추가 또는 업데이트 (Upsert)
        /// </summary>
        public async Task<OrganizationSettings> UpsertSettingAsync(OrganizationSettings setting, Guid modifiedByConnectedId)
        {
            var existing = await _dbSet
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == setting.OrganizationId &&
                    s.Category == setting.Category &&
                    s.SettingKey == setting.SettingKey &&
                    !s.IsDeleted);

            var timestamp = DateTime.UtcNow;

            if (existing != null)
            {
                // 업데이트
                existing.SettingValue = setting.SettingValue;
                existing.Description = setting.Description;
                existing.IsActive = setting.IsActive;
                existing.RequiresEncryption = setting.RequiresEncryption;
                existing.Priority = setting.Priority;
                existing.ValidationRule = setting.ValidationRule;
                existing.MinValue = setting.MinValue;
                existing.MaxValue = setting.MaxValue;
                existing.AllowedValues = setting.AllowedValues;
                existing.RequiredPlan = setting.RequiredPlan;
                existing.UpdatedByConnectedId = modifiedByConnectedId;
                existing.UpdatedAt = timestamp;

                _dbSet.Update(existing);
                await _context.SaveChangesAsync();
                return existing;
            }
            else
            {
                // 생성
                if (setting.Id == Guid.Empty)
                {
                    setting.Id = Guid.NewGuid();
                }
                setting.CreatedByConnectedId = modifiedByConnectedId;
                setting.CreatedAt = timestamp;

                return await AddAsync(setting);
            }
        }

        /// <summary>
        /// 설정 삭제
        /// </summary>
        public async Task<bool> DeleteSettingAsync(Guid organizationId, string category, string settingKey, Guid deletedByConnectedId)
        {
            var setting = await _dbSet
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey &&
                    !s.IsDeleted);

            if (setting == null) return false;

            setting.IsDeleted = true;
            setting.DeletedAt = DateTime.UtcNow;
            setting.DeletedByConnectedId = deletedByConnectedId;

            _dbSet.Update(setting);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 여러 설정 일괄 업데이트
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> BulkUpsertAsync(IEnumerable<OrganizationSettings> settings, Guid modifiedByConnectedId)
        {
            var result = new List<OrganizationSettings>();

            foreach (var setting in settings)
            {
                var upserted = await UpsertSettingAsync(setting, modifiedByConnectedId);
                result.Add(upserted);
            }

            return result;
        }

        /// <summary>
        /// 상위 조직으로부터 설정 상속
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> InheritSettingsFromParentAsync(Guid organizationId, Guid parentOrganizationId, IEnumerable<string>? categories = null)
        {
            var parentQuery = _dbSet.Where(s =>
                s.OrganizationId == parentOrganizationId &&
                s.IsActive &&
                !s.IsDeleted);

            if (categories != null && categories.Any())
            {
                parentQuery = parentQuery.Where(s => categories.Contains(s.Category));
            }

            var parentSettings = await parentQuery.ToListAsync();
            var inheritedSettings = new List<OrganizationSettings>();

            foreach (var parentSetting in parentSettings)
            {
                // 해당 설정이 이미 조직에 존재하는지 확인
                var existingSetting = await _dbSet
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        s.Category == parentSetting.Category &&
                        s.SettingKey == parentSetting.SettingKey &&
                        !s.IsDeleted);

                if (existingSetting == null)
                {
                    // 새로운 상속 설정 생성
                    var inheritedSetting = new OrganizationSettings
                    {
                        Id = Guid.NewGuid(),
                        OrganizationId = organizationId,
                        Category = parentSetting.Category,
                        SettingKey = parentSetting.SettingKey,
                        SettingValue = parentSetting.SettingValue,
                        DataType = parentSetting.DataType,
                        Description = parentSetting.Description,
                        DefaultValue = parentSetting.DefaultValue,
                        IsActive = parentSetting.IsActive,
                        RequiresEncryption = parentSetting.RequiresEncryption,
                        Priority = parentSetting.Priority,
                        ValidationRule = parentSetting.ValidationRule,
                        MinValue = parentSetting.MinValue,
                        MaxValue = parentSetting.MaxValue,
                        AllowedValues = parentSetting.AllowedValues,
                        RequiredPlan = parentSetting.RequiredPlan,
                        IsInherited = true,
                        CanOverrideInherited = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    inheritedSettings.Add(inheritedSetting);
                }
            }

            if (inheritedSettings.Any())
            {
                await _dbSet.AddRangeAsync(inheritedSettings);
                await _context.SaveChangesAsync();
            }

            return inheritedSettings;
        }

        #endregion

        #region IOrganizationSettingsQueryRepository 구현

        /// <summary>
        /// 조직의 모든 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetAllSettingsAsync(Guid organizationId, bool includeInherited = true, bool activeOnly = true)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId && !s.IsDeleted);

            if (activeOnly)
            {
                query = query.Where(s => s.IsActive);
            }

            var settings = await query.OrderBy(s => s.Category).ThenBy(s => s.Priority).ThenBy(s => s.SettingKey).ToListAsync();

            if (includeInherited)
            {
                var inheritedSettings = await GetAllInheritedSettingsAsync(organizationId, activeOnly);
                settings.AddRange(inheritedSettings);
            }

            return settings;
        }

        /// <summary>
        /// 카테고리별 설정 조회 (문자열)
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, string category, bool includeInherited = true)
        {
            var settings = await _dbSet
                .Where(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.IsActive &&
                    !s.IsDeleted)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.SettingKey)
                .ToListAsync();

            if (includeInherited)
            {
                var inheritedSettings = await GetInheritedSettingsByCategoryAsync(organizationId, category);
                settings.AddRange(inheritedSettings);
            }

            return settings;
        }

        /// <summary>
        /// 카테고리별 설정 조회 (Enum)
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, OrganizationSettingCategory category, bool includeInherited = true)
        {
            return await GetSettingsByCategoryAsync(organizationId, category.ToString(), includeInherited);
        }

        /// <summary>
        /// 활성화된 설정만 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetActiveSettingsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(s => s.OrganizationId == organizationId && s.IsActive && !s.IsDeleted)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 상속된 설정만 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetInheritedSettingsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(s => s.OrganizationId == organizationId && s.IsInherited && !s.IsDeleted)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 사용자가 수정 가능한 설정만 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetUserConfigurableSettingsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(s =>
                    s.OrganizationId == organizationId &&
                    s.IsUserConfigurable &&
                    s.IsActive &&
                    !s.IsDeleted)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 플랜별 필터링된 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByPlanAsync(Guid organizationId, string planType)
        {
            return await _dbSet
                .Where(s =>
                    s.OrganizationId == organizationId &&
                    (s.RequiredPlan == null || s.RequiredPlan == planType) &&
                    s.IsActive &&
                    !s.IsDeleted)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 암호화가 필요한 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetEncryptedSettingsAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(s =>
                    s.OrganizationId == organizationId &&
                    s.RequiresEncryption &&
                    !s.IsDeleted)
                .ToListAsync();
        }

        /// <summary>
        /// 설정 존재 여부 확인
        /// </summary>
        public async Task<bool> SettingExistsAsync(Guid organizationId, string category, string settingKey)
        {
            return await _dbSet.AnyAsync(s =>
                s.OrganizationId == organizationId &&
                s.Category == category &&
                s.SettingKey == settingKey &&
                !s.IsDeleted);
        }

        /// <summary>
        /// 최근 수정된 설정 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetRecentlyModifiedSettingsAsync(Guid organizationId, int days = 7)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-days);

            return await _dbSet
                .Where(s =>
                    s.OrganizationId == organizationId &&
                    s.UpdatedAt.HasValue &&
                    s.UpdatedAt.Value >= cutoffDate &&
                    !s.IsDeleted)
                .OrderByDescending(s => s.UpdatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 설정 검증 (ValidationRule 기반)
        /// </summary>
        public async Task<bool> ValidateSettingValueAsync(Guid organizationId, string category, string settingKey, string value)
        {
            var setting = await GetSettingAsync(organizationId, category, settingKey, false);
            if (setting == null) return false;

            // 기본 검증
            if (string.IsNullOrEmpty(value) && setting.IsRequired) return false;

            // ValidationRule이 있는 경우 검증
            if (!string.IsNullOrEmpty(setting.ValidationRule))
            {
                return ValidateAgainstRule(value, setting.ValidationRule);
            }

            // Min/Max 값 검증
            if (!string.IsNullOrEmpty(setting.MinValue) || !string.IsNullOrEmpty(setting.MaxValue))
            {
                return ValidateRange(value, setting.DataType, setting.MinValue, setting.MaxValue);
            }

            // 허용된 값 검증
            if (!string.IsNullOrEmpty(setting.AllowedValues))
            {
                var allowedValues = JsonSerializer.Deserialize<string[]>(setting.AllowedValues);
                return allowedValues?.Contains(value) == true;
            }

            return true;
        }

        #endregion

        #region IOrganizationSettingsCommandRepository 구현

        /// <summary>
        /// 기본값으로 설정 초기화
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> ResetToDefaultsAsync(Guid organizationId, string? category = null, Guid resetByConnectedId = default)
        {
            var query = _dbSet.Where(s => s.OrganizationId == organizationId && !s.IsDeleted);

            if (!string.IsNullOrEmpty(category))
            {
                query = query.Where(s => s.Category == category);
            }

            var settings = await query.ToListAsync();
            var resetSettings = new List<OrganizationSettings>();

            foreach (var setting in settings)
            {
                if (!string.IsNullOrEmpty(setting.DefaultValue))
                {
                    setting.SettingValue = setting.DefaultValue;
                    setting.UpdatedByConnectedId = resetByConnectedId;
                    setting.UpdatedAt = DateTime.UtcNow;
                    resetSettings.Add(setting);
                }
            }

            if (resetSettings.Any())
            {
                _dbSet.UpdateRange(resetSettings);
                await _context.SaveChangesAsync();
            }

            return resetSettings;
        }

        /// <summary>
        /// 하위 조직에 설정 전파
        /// </summary>
        public async Task<int> PropagateSettingsToChildrenAsync(Guid parentOrganizationId, IEnumerable<string> settingKeys, bool overrideExisting = false)
        {
            // 하위 조직 조회
            var childOrganizations = await _context.Set<AuthHive.Core.Entities.Organization.Organization>()
                .Where(o => o.ParentId == parentOrganizationId && !o.IsDeleted)
                .Select(o => o.Id)
                .ToListAsync();

            if (!childOrganizations.Any()) return 0;

            // 전파할 설정들 조회
            var settingsToPropagate = await _dbSet
                .Where(s =>
                    s.OrganizationId == parentOrganizationId &&
                    settingKeys.Contains(s.SettingKey) &&
                    !s.IsDeleted)
                .ToListAsync();

            var propagatedCount = 0;

            foreach (var childOrgId in childOrganizations)
            {
                foreach (var setting in settingsToPropagate)
                {
                    var existingSetting = await _dbSet
                        .FirstOrDefaultAsync(s =>
                            s.OrganizationId == childOrgId &&
                            s.Category == setting.Category &&
                            s.SettingKey == setting.SettingKey &&
                            !s.IsDeleted);

                    if (existingSetting == null || overrideExisting)
                    {
                        if (existingSetting == null)
                        {
                            // 새로 생성
                            var newSetting = new OrganizationSettings
                            {
                                Id = Guid.NewGuid(),
                                OrganizationId = childOrgId,
                                Category = setting.Category,
                                SettingKey = setting.SettingKey,
                                SettingValue = setting.SettingValue,
                                DataType = setting.DataType,
                                Description = setting.Description,
                                DefaultValue = setting.DefaultValue,
                                IsActive = setting.IsActive,
                                RequiresEncryption = setting.RequiresEncryption,
                                Priority = setting.Priority,
                                ValidationRule = setting.ValidationRule,
                                MinValue = setting.MinValue,
                                MaxValue = setting.MaxValue,
                                AllowedValues = setting.AllowedValues,
                                RequiredPlan = setting.RequiredPlan,
                                IsInherited = true,
                                CanOverrideInherited = true,
                                CreatedAt = DateTime.UtcNow
                            };

                            await _dbSet.AddAsync(newSetting);
                        }
                        else
                        {
                            // 기존 설정 업데이트
                            existingSetting.SettingValue = setting.SettingValue;
                            existingSetting.UpdatedAt = DateTime.UtcNow;
                            _dbSet.Update(existingSetting);
                        }

                        propagatedCount++;
                    }
                }
            }

            if (propagatedCount > 0)
            {
                await _context.SaveChangesAsync();
            }

            return propagatedCount;
        }

        /// <summary>
        /// 설정 템플릿 적용
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> ApplySettingsTemplateAsync(Guid organizationId, string templateName, Guid appliedByConnectedId)
        {
            // 템플릿 데이터 조회 (실제로는 별도 템플릿 저장소에서 가져와야 함)
            var templateSettings = await GetSettingsTemplateAsync(templateName);
            var appliedSettings = new List<OrganizationSettings>();

            foreach (var templateSetting in templateSettings)
            {
                var setting = new OrganizationSettings
                {
                    OrganizationId = organizationId,
                    Category = templateSetting.Category,
                    SettingKey = templateSetting.SettingKey,
                    SettingValue = templateSetting.SettingValue,
                    DataType = templateSetting.DataType,
                    Description = templateSetting.Description,
                    DefaultValue = templateSetting.DefaultValue,
                    IsActive = templateSetting.IsActive,
                    RequiresEncryption = templateSetting.RequiresEncryption,
                    Priority = templateSetting.Priority,
                    ValidationRule = templateSetting.ValidationRule,
                    MinValue = templateSetting.MinValue,
                    MaxValue = templateSetting.MaxValue,
                    AllowedValues = templateSetting.AllowedValues,
                    RequiredPlan = templateSetting.RequiredPlan,
                    IsUserConfigurable = templateSetting.IsUserConfigurable
                };

                var applied = await UpsertSettingAsync(setting, appliedByConnectedId);
                appliedSettings.Add(applied);
            }

            return appliedSettings;
        }

        /// <summary>
        /// 설정 백업
        /// </summary>
        public async Task<string> BackupSettingsAsync(Guid organizationId, string? category = null)
        {
            var settings = await GetAllSettingsAsync(organizationId, false, false);

            if (!string.IsNullOrEmpty(category))
            {
                settings = settings.Where(s => s.Category == category);
            }

            var backup = new
            {
                OrganizationId = organizationId,
                BackupDate = DateTime.UtcNow,
                Version = "15.0",
                Settings = settings.Select(s => new
                {
                    s.Category,
                    s.SettingKey,
                    s.SettingValue,
                    s.DataType,
                    s.Description,
                    s.IsActive,
                    s.Priority,
                    s.ValidationRule,
                    s.MinValue,
                    s.MaxValue,
                    s.AllowedValues,
                    s.RequiredPlan,
                    s.IsUserConfigurable,
                    s.RequiresEncryption
                })
            };

            return JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true });
        }

        /// <summary>
        /// 설정 복원
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> RestoreSettingsAsync(Guid organizationId, string backupData, Guid restoredByConnectedId)
        {
            var backup = JsonSerializer.Deserialize<JsonElement>(backupData);
            var restoredSettings = new List<OrganizationSettings>();

            if (backup.TryGetProperty("Settings", out var settingsElement))
            {
                foreach (var settingElement in settingsElement.EnumerateArray())
                {
                    var setting = new OrganizationSettings
                    {
                        OrganizationId = organizationId,
                        Category = settingElement.GetProperty("Category").GetString() ?? "",
                        SettingKey = settingElement.GetProperty("SettingKey").GetString() ?? "",
                        SettingValue = settingElement.GetProperty("SettingValue").GetString(),
                        DataType = settingElement.GetProperty("DataType").GetString() ?? "String",
                        Description = settingElement.GetProperty("Description").GetString(),
                        IsActive = settingElement.GetProperty("IsActive").GetBoolean(),
                        Priority = settingElement.GetProperty("Priority").GetInt32(),
                        ValidationRule = settingElement.GetProperty("ValidationRule").GetString(),
                        MinValue = settingElement.GetProperty("MinValue").GetString(),
                        MaxValue = settingElement.GetProperty("MaxValue").GetString(),
                        AllowedValues = settingElement.GetProperty("AllowedValues").GetString(),
                        RequiredPlan = settingElement.GetProperty("RequiredPlan").GetString(),
                        IsUserConfigurable = settingElement.GetProperty("IsUserConfigurable").GetBoolean(),
                        RequiresEncryption = settingElement.GetProperty("RequiresEncryption").GetBoolean()
                    };

                    var restored = await UpsertSettingAsync(setting, restoredByConnectedId);
                    restoredSettings.Add(restored);
                }
            }

            return restoredSettings;
        }

        #endregion

        #region IReadRepository<OrganizationSettings> 구현

        /// <summary>
        /// 페이징된 설정 조회 (IReadRepository 구현)
        /// </summary>
        public async Task<PagedResult<OrganizationSettings>> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<OrganizationSettings, bool>>? predicate = null,
            Func<IQueryable<OrganizationSettings>, IOrderedQueryable<OrganizationSettings>>? orderBy = null)
        {
            var query = _dbSet.Where(s => !s.IsDeleted);

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            var totalCount = await query.CountAsync();

            IQueryable<OrganizationSettings> orderedQuery = query;
            if (orderBy != null)
            {
                orderedQuery = orderBy(query);
            }
            else
            {
                orderedQuery = query.OrderBy(s => s.Category).ThenBy(s => s.Priority).ThenBy(s => s.SettingKey);
            }

            var items = await orderedQuery
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new PagedResult<OrganizationSettings>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize
            };
        }

        #endregion

        #region 헬퍼 메서드

        /// <summary>
        /// 상속된 설정 조회 (단일)
        /// </summary>
        private async Task<OrganizationSettings?> GetInheritedSettingAsync(Guid organizationId, string category, string settingKey)
        {
            // 상위 조직 경로 추적하여 설정 찾기
            var organization = await _context.Set<AuthHive.Core.Entities.Organization.Organization>()
                .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

            if (organization?.ParentId == null) return null;

            return await GetSettingAsync(organization.ParentId.Value, category, settingKey, true);
        }

        /// <summary>
        /// 모든 상속된 설정 조회
        /// </summary>
        private async Task<List<OrganizationSettings>> GetAllInheritedSettingsAsync(Guid organizationId, bool activeOnly)
        {
            var inheritedSettings = new List<OrganizationSettings>();
            var organization = await _context.Set<AuthHive.Core.Entities.Organization.Organization>()
                .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

            if (organization?.ParentId != null)
            {
                var parentSettings = await GetAllSettingsAsync(organization.ParentId.Value, true, activeOnly);

                // 현재 조직에 이미 정의되지 않은 설정만 상속
                var currentSettingKeys = await _dbSet
                    .Where(s => s.OrganizationId == organizationId && !s.IsDeleted)
                    .Select(s => $"{s.Category}:{s.SettingKey}")
                    .ToListAsync();

                inheritedSettings = parentSettings
                    .Where(s => !currentSettingKeys.Contains($"{s.Category}:{s.SettingKey}"))
                    .Select(s =>
                    {
                        s.IsInherited = true;
                        return s;
                    })
                    .ToList();
            }

            return inheritedSettings;
        }

        /// <summary>
        /// 카테고리별 상속된 설정 조회
        /// </summary>
        private async Task<List<OrganizationSettings>> GetInheritedSettingsByCategoryAsync(Guid organizationId, string category)
        {
            var allInherited = await GetAllInheritedSettingsAsync(organizationId, true);
            return allInherited.Where(s => s.Category == category).ToList();
        }

        /// <summary>
        /// 설정 템플릿 조회 (실제로는 별도 구현 필요)
        /// </summary>
        private async Task<IEnumerable<OrganizationSettings>> GetSettingsTemplateAsync(string templateName)
        {
            // 실제로는 별도 템플릿 저장소에서 조회
            // 현재는 빈 목록 반환
            await Task.CompletedTask;
            return Enumerable.Empty<OrganizationSettings>();
        }

        /// <summary>
        /// 검증 규칙에 따른 값 검증
        /// </summary>
        private bool ValidateAgainstRule(string value, string validationRule)
        {
            // 실제로는 더 복잡한 규칙 엔진 구현 필요
            // 현재는 간단한 정규식 검증만 구현
            try
            {
                return System.Text.RegularExpressions.Regex.IsMatch(value, validationRule);
            }
            catch
            {
                return true; // 규칙이 잘못된 경우 통과
            }
        }

        /// <summary>
        /// 범위 검증
        /// </summary>
        private bool ValidateRange(string value, string dataType, string? minValue, string? maxValue)
        {
            switch (dataType.ToLower())
            {
                case "int":
                case "integer":
                    if (int.TryParse(value, out var intVal))
                    {
                        if (minValue != null && int.TryParse(minValue, out var minInt) && intVal < minInt) return false;
                        if (maxValue != null && int.TryParse(maxValue, out var maxInt) && intVal > maxInt) return false;
                    }
                    break;

                case "decimal":
                case "double":
                    if (decimal.TryParse(value, out var decVal))
                    {
                        if (minValue != null && decimal.TryParse(minValue, out var minDec) && decVal < minDec) return false;
                        if (maxValue != null && decimal.TryParse(maxValue, out var maxDec) && decVal > maxDec) return false;
                    }
                    break;

                case "string":
                    if (minValue != null && int.TryParse(minValue, out var minLen) && value.Length < minLen) return false;
                    if (maxValue != null && int.TryParse(maxValue, out var maxLen) && value.Length > maxLen) return false;
                    break;
            }

            return true;
        }

        #endregion
    }
}