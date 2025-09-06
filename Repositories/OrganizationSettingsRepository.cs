using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using System.Text.Json;
using System.Linq.Expressions;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;

using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationSettings Repository 구현체 - AuthHive v15
    /// BaseRepository를 상속받아 조직별 설정의 CRUD, 상속, 템플릿 등 복잡한 설정 관리를 담당합니다.
    /// </summary>
    public class OrganizationSettingsRepository : BaseRepository<OrganizationSettings>,
        IOrganizationSettingsRepository,
        IOrganizationSettingsQueryRepository,
        IOrganizationSettingsCommandRepository
    {
        public OrganizationSettingsRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region IOrganizationSettingsRepository 구현

        /// <summary>
        /// 특정 설정 조회 - 캐시와 상속 지원
        /// 사용 시점: 개별 설정값을 읽을 때 (예: 조직의 타임존 설정)
        /// </summary>
        public async Task<OrganizationSettings?> GetSettingAsync(
            Guid organizationId,
            string category,
            string settingKey,
            bool includeInherited = true)
        {
            // 직접 설정 조회
            var setting = await Query()
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey);

            // 직접 설정이 없고 상속을 허용하는 경우, 상위 조직에서 찾기
            if (setting == null && includeInherited)
            {
                setting = await GetInheritedSettingAsync(organizationId, category, settingKey);
            }

            return setting;
        }

        /// <summary>
        /// 설정 추가 또는 업데이트 (Upsert)
        /// 사용 시점: 관리자가 설정을 변경하거나 새로운 설정을 추가할 때
        /// </summary>
        public async Task<OrganizationSettings> UpsertSettingAsync(
            OrganizationSettings setting,
            Guid modifiedByConnectedId)
        {
            var existing = await Query()
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == setting.OrganizationId &&
                    s.Category == setting.Category &&
                    s.SettingKey == setting.SettingKey);

            if (existing != null)
            {
                // 기존 설정 업데이트
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
                existing.UpdatedAt = DateTime.UtcNow;

                await UpdateAsync(existing);
                await _context.SaveChangesAsync();
                return existing;
            }
            else
            {
                // 새 설정 생성
                if (setting.Id == Guid.Empty)
                {
                    setting.Id = Guid.NewGuid();
                }
                setting.CreatedByConnectedId = modifiedByConnectedId;
                setting.CreatedAt = DateTime.UtcNow;

                var result = await AddAsync(setting);
                await _context.SaveChangesAsync();
                return result;
            }
        }

        /// <summary>
        /// 설정 삭제 (Soft Delete)
        /// 사용 시점: 관리자가 특정 설정을 제거할 때
        /// </summary>
        public async Task<bool> DeleteSettingAsync(
            Guid organizationId,
            string category,
            string settingKey,
            Guid deletedByConnectedId)
        {
            var setting = await Query()
                .FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey);

            if (setting == null) return false;

            setting.DeletedByConnectedId = deletedByConnectedId;
            await DeleteAsync(setting);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 여러 설정 일괄 업데이트
        /// 사용 시점: 설정 페이지에서 여러 설정을 한번에 저장할 때
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> BulkUpsertAsync(
            IEnumerable<OrganizationSettings> settings,
            Guid modifiedByConnectedId)
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
        /// 사용 시점: 새로운 하위 조직 생성 시 또는 상속 정책 변경 시
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> InheritSettingsFromParentAsync(
            Guid organizationId,
            Guid parentOrganizationId,
            IEnumerable<string>? categories = null)
        {
            // 부모 조직의 설정 조회
            var parentQuery = QueryForOrganization(parentOrganizationId)
                .Where(s => s.IsActive);

            if (categories?.Any() == true)
            {
                parentQuery = parentQuery.Where(s => categories.Contains(s.Category));
            }

            var parentSettings = await parentQuery.ToListAsync();
            var inheritedSettings = new List<OrganizationSettings>();

            foreach (var parentSetting in parentSettings)
            {
                // 해당 설정이 이미 존재하는지 확인
                var exists = await Query()
                    .AnyAsync(s =>
                        s.OrganizationId == organizationId &&
                        s.Category == parentSetting.Category &&
                        s.SettingKey == parentSetting.SettingKey);

                if (!exists)
                {
                    // 새로운 상속 설정 생성
                    var inheritedSetting = CloneSettingForInheritance(parentSetting, organizationId);
                    inheritedSettings.Add(inheritedSetting);
                }
            }

            if (inheritedSettings.Any())
            {
                await AddRangeAsync(inheritedSettings);
                await _context.SaveChangesAsync();
            }

            return inheritedSettings;
        }

        #endregion

        #region IOrganizationSettingsQueryRepository 구현

        /// <summary>
        /// IReadRepository의 ExistsAsync 구현
        /// Expression 기반 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(Expression<Func<OrganizationSettings, bool>> predicate)
        {
            // BaseRepository의 AnyAsync를 호출
            return await AnyAsync(predicate);
        }

        /// <summary>
        /// 조직의 모든 설정 조회
        /// 사용 시점: 설정 관리 페이지 로드 시
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetAllSettingsAsync(
            Guid organizationId,
            bool includeInherited = true,
            bool activeOnly = true)
        {
            var query = QueryForOrganization(organizationId);

            if (activeOnly)
            {
                query = query.Where(s => s.IsActive);
            }

            var settings = await query
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ThenBy(s => s.SettingKey)
                .ToListAsync();

            if (includeInherited)
            {
                var inheritedSettings = await GetAllInheritedSettingsAsync(organizationId, activeOnly);
                // 중복 제거: 직접 설정이 있으면 상속된 설정은 무시
                var existingKeys = settings.Select(s => $"{s.Category}:{s.SettingKey}").ToHashSet();
                settings.AddRange(inheritedSettings.Where(s =>
                    !existingKeys.Contains($"{s.Category}:{s.SettingKey}")));
            }

            return settings;
        }

        /// <summary>
        /// 카테고리별 설정 조회 (문자열)
        /// 사용 시점: 특정 카테고리의 설정만 필요할 때 (예: 보안 설정만 조회)
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(
            Guid organizationId,
            string category,
            bool includeInherited = true)
        {
            var settings = await QueryForOrganization(organizationId)
                .Where(s => s.Category == category && s.IsActive)
                .OrderBy(s => s.Priority)
                .ThenBy(s => s.SettingKey)
                .ToListAsync();

            if (includeInherited)
            {
                var inheritedSettings = await GetInheritedSettingsByCategoryAsync(organizationId, category);
                // 중복 제거
                var existingKeys = settings.Select(s => s.SettingKey).ToHashSet();
                settings.AddRange(inheritedSettings.Where(s => !existingKeys.Contains(s.SettingKey)));
            }

            return settings;
        }

        /// <summary>
        /// 카테고리별 설정 조회 (Enum) - 위 메서드를 재사용
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(
            Guid organizationId,
            OrganizationSettingCategory category,
            bool includeInherited = true)
        {
            return await GetSettingsByCategoryAsync(organizationId, category.ToString(), includeInherited);
        }

        /// <summary>
        /// 활성화된 설정만 조회
        /// 사용 시점: 런타임에서 실제 적용되는 설정만 필요할 때
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetActiveSettingsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(s => s.IsActive)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 상속된 설정만 조회
        /// 사용 시점: 상속 정책 검토 또는 오버라이드 가능한 설정 확인 시
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetInheritedSettingsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(s => s.IsInherited)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 사용자가 수정 가능한 설정만 조회
        /// 사용 시점: 일반 사용자용 설정 페이지 표시
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetUserConfigurableSettingsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(s => s.IsUserConfigurable && s.IsActive)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 플랜별 필터링된 설정 조회
        /// 사용 시점: 구독 플랜에 따른 기능 제한 확인
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByPlanAsync(
            Guid organizationId,
            string planType)
        {
            return await QueryForOrganization(organizationId)
                .Where(s => (s.RequiredPlan == null || s.RequiredPlan == planType) && s.IsActive)
                .OrderBy(s => s.Category)
                .ThenBy(s => s.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 암호화가 필요한 설정 조회
        /// 사용 시점: 보안 감사 또는 암호화 키 변경 시
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetEncryptedSettingsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(s => s.RequiresEncryption)
                .ToListAsync();
        }

        /// <summary>
        /// 설정 존재 여부 확인 - BaseRepository의 AnyAsync 활용
        /// </summary>
        public async Task<bool> SettingExistsAsync(
            Guid organizationId,
            string category,
            string settingKey)
        {
            return await AnyAsync(s =>
                s.OrganizationId == organizationId &&
                s.Category == category &&
                s.SettingKey == settingKey);
        }

        /// <summary>
        /// 최근 수정된 설정 조회
        /// 사용 시점: 변경 이력 확인 또는 감사 로그
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> GetRecentlyModifiedSettingsAsync(
            Guid organizationId,
            int days = 7)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-days);

            return await QueryForOrganization(organizationId)
                .Where(s => s.UpdatedAt.HasValue && s.UpdatedAt.Value >= cutoffDate)
                .OrderByDescending(s => s.UpdatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 설정 검증 (ValidationRule 기반)
        /// 사용 시점: 설정값 변경 전 유효성 검사
        /// </summary>
        public async Task<bool> ValidateSettingValueAsync(
            Guid organizationId,
            string category,
            string settingKey,
            string value)
        {
            var setting = await GetSettingAsync(organizationId, category, settingKey, false);
            if (setting == null) return false;

            // 필수값 검증
            if (string.IsNullOrEmpty(value) && setting.IsRequired) return false;

            // ValidationRule 검증
            if (!string.IsNullOrEmpty(setting.ValidationRule))
            {
                return ValidateAgainstRule(value, setting.ValidationRule);
            }

            // 범위 검증
            if (!string.IsNullOrEmpty(setting.MinValue) || !string.IsNullOrEmpty(setting.MaxValue))
            {
                return ValidateRange(value, setting.DataType, setting.MinValue, setting.MaxValue);
            }

            // 허용된 값 목록 검증
            if (!string.IsNullOrEmpty(setting.AllowedValues))
            {
                var allowedValues = JsonSerializer.Deserialize<string[]>(setting.AllowedValues);
                return allowedValues?.Contains(value) == true;
            }

            return true;
        }

        /// <summary>
        /// IReadRepository의 GetPagedAsync 구현
        /// 사용 시점: 설정 목록 페이징 표시
        /// </summary>
        /// <summary>
        /// IReadRepository의 GetPagedAsync 구현
        /// 사용 시점: 설정 목록 페이징 표시
        /// </summary>
        public async Task<PagedResult<OrganizationSettings>> GetPagedAsync(
            int pageNumber,
            int pageSize,
            Expression<Func<OrganizationSettings, bool>>? predicate = null,
            Func<IQueryable<OrganizationSettings>, IOrderedQueryable<OrganizationSettings>>? orderBy = null)
        {
            // BaseRepository의 GetPagedAsync를 활용
            var (items, totalCount) = await base.GetPagedAsync(
                pageNumber,
                pageSize,
                predicate,
                orderBy != null ? s => s.Category : null,  // 기본 정렬
                false);

            return new PagedResult<OrganizationSettings>
            {
                Items = items.ToList(),  // <- 이 부분만 수정 (기존: Items = items)
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize
            };
        }

        #endregion

        #region IOrganizationSettingsCommandRepository 구현

        /// <summary>
        /// 기본값으로 설정 초기화
        /// 사용 시점: 설정 오류 시 초기화 또는 조직 리셋
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> ResetToDefaultsAsync(
            Guid organizationId,
            string? category = null,
            Guid resetByConnectedId = default)
        {
            var query = QueryForOrganization(organizationId);

            if (!string.IsNullOrEmpty(category))
            {
                query = query.Where(s => s.Category == category);
            }

            var settings = await query.ToListAsync();
            var resetSettings = new List<OrganizationSettings>();

            foreach (var setting in settings.Where(s => !string.IsNullOrEmpty(s.DefaultValue)))
            {
                setting.SettingValue = setting.DefaultValue;
                setting.UpdatedByConnectedId = resetByConnectedId;
                setting.UpdatedAt = DateTime.UtcNow;
                resetSettings.Add(setting);
            }

            if (resetSettings.Any())
            {
                await UpdateRangeAsync(resetSettings);
                await _context.SaveChangesAsync();
            }

            return resetSettings;
        }

        /// <summary>
        /// 하위 조직에 설정 전파
        /// 사용 시점: 정책 변경 시 하위 조직에 일괄 적용
        /// </summary>
        public async Task<int> PropagateSettingsToChildrenAsync(
            Guid parentOrganizationId,
            IEnumerable<string> settingKeys,
            bool overrideExisting = false)
        {
            // 하위 조직 조회
            var childOrganizations = await _context.Set<OrganizationEntity>()
                .Where(o => o.ParentId == parentOrganizationId && !o.IsDeleted)
                .Select(o => o.Id)
                .ToListAsync();

            if (!childOrganizations.Any()) return 0;

            // 전파할 설정들 조회
            var settingsToPropagate = await QueryForOrganization(parentOrganizationId)
                .Where(s => settingKeys.Contains(s.SettingKey))
                .ToListAsync();

            var propagatedCount = 0;
            var settingsToAdd = new List<OrganizationSettings>();
            var settingsToUpdate = new List<OrganizationSettings>();

            foreach (var childOrgId in childOrganizations)
            {
                foreach (var setting in settingsToPropagate)
                {
                    var existingSetting = await QueryForOrganization(childOrgId)
                        .FirstOrDefaultAsync(s =>
                            s.Category == setting.Category &&
                            s.SettingKey == setting.SettingKey);

                    if (existingSetting == null)
                    {
                        // 새로 생성
                        var newSetting = CloneSettingForInheritance(setting, childOrgId);
                        settingsToAdd.Add(newSetting);
                        propagatedCount++;
                    }
                    else if (overrideExisting)
                    {
                        // 기존 설정 업데이트
                        existingSetting.SettingValue = setting.SettingValue;
                        existingSetting.UpdatedAt = DateTime.UtcNow;
                        settingsToUpdate.Add(existingSetting);
                        propagatedCount++;
                    }
                }
            }

            if (settingsToAdd.Any())
            {
                await AddRangeAsync(settingsToAdd);
            }

            if (settingsToUpdate.Any())
            {
                await UpdateRangeAsync(settingsToUpdate);
            }

            if (propagatedCount > 0)
            {
                await _context.SaveChangesAsync();
            }

            return propagatedCount;
        }

        /// <summary>
        /// 설정 템플릿 적용
        /// 사용 시점: 새 조직 생성 시 템플릿 기반 초기화
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> ApplySettingsTemplateAsync(
            Guid organizationId,
            string templateName,
            Guid appliedByConnectedId)
        {
            // 템플릿 데이터 조회
            var templateSettings = await GetSettingsTemplateAsync(templateName);
            var appliedSettings = new List<OrganizationSettings>();

            foreach (var templateSetting in templateSettings)
            {
                templateSetting.OrganizationId = organizationId;
                var applied = await UpsertSettingAsync(templateSetting, appliedByConnectedId);
                appliedSettings.Add(applied);
            }

            return appliedSettings;
        }

        /// <summary>
        /// 설정 백업
        /// 사용 시점: 주요 변경 전 백업 또는 정기 백업
        /// </summary>
        public async Task<string> BackupSettingsAsync(
            Guid organizationId,
            string? category = null)
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
        /// 사용 시점: 백업으로부터 설정 복구
        /// </summary>
        public async Task<IEnumerable<OrganizationSettings>> RestoreSettingsAsync(
            Guid organizationId,
            string backupData,
            Guid restoredByConnectedId)
        {
            var backup = JsonSerializer.Deserialize<JsonElement>(backupData);
            var restoredSettings = new List<OrganizationSettings>();

            if (backup.TryGetProperty("Settings", out var settingsElement))
            {
                foreach (var settingElement in settingsElement.EnumerateArray())
                {
                    var setting = DeserializeSettingFromBackup(settingElement, organizationId);
                    var restored = await UpsertSettingAsync(setting, restoredByConnectedId);
                    restoredSettings.Add(restored);
                }
            }

            return restoredSettings;
        }

        #endregion

        #region 헬퍼 메서드

        /// <summary>
        /// 상속을 위한 설정 복제
        /// </summary>
        private OrganizationSettings CloneSettingForInheritance(OrganizationSettings source, Guid targetOrganizationId)
        {
            return new OrganizationSettings
            {
                Id = Guid.NewGuid(),
                OrganizationId = targetOrganizationId,
                Category = source.Category,
                SettingKey = source.SettingKey,
                SettingValue = source.SettingValue,
                DataType = source.DataType,
                Description = source.Description,
                DefaultValue = source.DefaultValue,
                IsActive = source.IsActive,
                RequiresEncryption = source.RequiresEncryption,
                Priority = source.Priority,
                ValidationRule = source.ValidationRule,
                MinValue = source.MinValue,
                MaxValue = source.MaxValue,
                AllowedValues = source.AllowedValues,
                RequiredPlan = source.RequiredPlan,
                IsInherited = true,
                CanOverrideInherited = true,
                IsUserConfigurable = source.IsUserConfigurable,
                CreatedAt = DateTime.UtcNow
            };
        }

        /// <summary>
        /// 백업 데이터에서 설정 역직렬화
        /// </summary>
        private OrganizationSettings DeserializeSettingFromBackup(JsonElement element, Guid organizationId)
        {
            return new OrganizationSettings
            {
                OrganizationId = organizationId,
                Category = element.GetProperty("Category").GetString() ?? "",
                SettingKey = element.GetProperty("SettingKey").GetString() ?? "",
                SettingValue = element.GetProperty("SettingValue").GetString(),
                DataType = element.GetProperty("DataType").GetString() ?? "String",
                Description = element.GetProperty("Description").GetString(),
                IsActive = element.GetProperty("IsActive").GetBoolean(),
                Priority = element.GetProperty("Priority").GetInt32(),
                ValidationRule = element.GetProperty("ValidationRule").GetString(),
                MinValue = element.GetProperty("MinValue").GetString(),
                MaxValue = element.GetProperty("MaxValue").GetString(),
                AllowedValues = element.GetProperty("AllowedValues").GetString(),
                RequiredPlan = element.GetProperty("RequiredPlan").GetString(),
                IsUserConfigurable = element.GetProperty("IsUserConfigurable").GetBoolean(),
                RequiresEncryption = element.GetProperty("RequiresEncryption").GetBoolean()
            };
        }

        /// <summary>
        /// 상속된 설정 조회 (단일) - 재귀적으로 부모 탐색
        /// </summary>
        private async Task<OrganizationSettings?> GetInheritedSettingAsync(
            Guid organizationId,
            string category,
            string settingKey)
        {
            var organization = await _context.Set<OrganizationEntity>()
                .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

            if (organization?.ParentId == null) return null;

            return await GetSettingAsync(organization.ParentId.Value, category, settingKey, true);
        }

        /// <summary>
        /// 모든 상속된 설정 조회 - List<T> 반환으로 수정
        /// </summary>
        private async Task<List<OrganizationSettings>> GetAllInheritedSettingsAsync(
            Guid organizationId,
            bool activeOnly)
        {
            var organization = await _context.Set<OrganizationEntity>()
                .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

            if (organization?.ParentId == null)
                return new List<OrganizationSettings>();

            var parentSettings = await GetAllSettingsAsync(organization.ParentId.Value, true, activeOnly);

            // 현재 조직에 이미 정의되지 않은 설정만 상속
            var currentSettingKeys = await QueryForOrganization(organizationId)
                .Select(s => $"{s.Category}:{s.SettingKey}")
                .ToListAsync();

            // ToList()를 호출하여 List<T> 반환
            var result = parentSettings
                .Where(s => !currentSettingKeys.Contains($"{s.Category}:{s.SettingKey}"))
                .Select(s =>
                {
                    s.IsInherited = true;
                    return s;
                })
                .ToList();

            return result;
        }

        /// <summary>
        /// 카테고리별 상속된 설정 조회
        /// </summary>
        private async Task<IEnumerable<OrganizationSettings>> GetInheritedSettingsByCategoryAsync(
            Guid organizationId,
            string category)
        {
            var allInherited = await GetAllInheritedSettingsAsync(organizationId, true);
            return allInherited.Where(s => s.Category == category).ToList();
        }

        /// <summary>
        /// 설정 템플릿 조회 - 추후 별도 템플릿 저장소 구현 필요
        /// </summary>
        private async Task<IEnumerable<OrganizationSettings>> GetSettingsTemplateAsync(string templateName)
        {
            // TODO: 실제 템플릿 저장소 구현
            await Task.CompletedTask;
            return Enumerable.Empty<OrganizationSettings>();
        }

        /// <summary>
        /// 정규식 기반 검증
        /// </summary>
        private bool ValidateAgainstRule(string value, string validationRule)
        {
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
        /// 데이터 타입별 범위 검증
        /// </summary>
        private bool ValidateRange(string value, string dataType, string? minValue, string? maxValue)
        {
            switch (dataType.ToLower())
            {
                case "int":
                case "integer":
                    if (int.TryParse(value, out var intVal))
                    {
                        if (minValue != null && int.TryParse(minValue, out var minInt) && intVal < minInt)
                            return false;
                        if (maxValue != null && int.TryParse(maxValue, out var maxInt) && intVal > maxInt)
                            return false;
                    }
                    break;

                case "decimal":
                case "double":
                    if (decimal.TryParse(value, out var decVal))
                    {
                        if (minValue != null && decimal.TryParse(minValue, out var minDec) && decVal < minDec)
                            return false;
                        if (maxValue != null && decimal.TryParse(maxValue, out var maxDec) && decVal > maxDec)
                            return false;
                    }
                    break;

                case "string":
                    if (minValue != null && int.TryParse(minValue, out var minLen) && value.Length < minLen)
                        return false;
                    if (maxValue != null && int.TryParse(maxValue, out var maxLen) && value.Length > maxLen)
                        return false;
                    break;
            }

            return true;
        }

        #endregion
    }
}