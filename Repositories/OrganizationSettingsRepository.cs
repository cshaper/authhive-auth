// --- 1. 필요한 네임스페이스 선언 ---
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
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Interfaces.Infra.Cache;
using System.Threading;

// Organization 엔티티의 이름 충돌을 피하기 위해 별칭을 사용합니다.
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationSettings Repository 구현체 - AuthHive v16 아키텍처 적용
    /// </summary>
    public class OrganizationSettingsRepository : BaseRepository<OrganizationSettings>,
        IOrganizationSettingsRepository,
        IOrganizationSettingsQueryRepository,
        IOrganizationSettingsCommandRepository
    {
        public OrganizationSettingsRepository(AuthDbContext context, ICacheService? cacheService = null)
            : base(context)
        {
        }

        protected override bool IsOrganizationScopedEntity() => true;

        #region 핵심 조회 메서드 (IOrganizationSettingsQueryRepository)

        public async Task<OrganizationSettings?> GetSettingAsync(
            Guid organizationId,
            string category,
            string settingKey,
            bool includeInherited = true,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"org_setting:{organizationId}:{category}:{settingKey}";

            if (_cacheService != null)
            {
                var cachedSetting = await _cacheService.GetAsync<OrganizationSettings>(cacheKey, cancellationToken);
                if (cachedSetting != null) return cachedSetting;
            }

            var setting = await Query().FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey, cancellationToken);

            if (setting == null && includeInherited)
            {
                setting = await GetInheritedSettingRecursiveAsync(organizationId, category, settingKey, cancellationToken);
            }

            if (setting != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, setting, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return setting;
        }

        public async Task<IEnumerable<OrganizationSettings>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).ToListAsync(cancellationToken);
        }

        public async Task<OrganizationSettings?> GetByOrgIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await Query().FirstOrDefaultAsync(s => s.OrganizationId == organizationId, cancellationToken);
        }

        #endregion

        #region 핵심 명령 메서드 (IOrganizationSettingsCommandRepository)

        public async Task<OrganizationSettings> UpsertSettingAsync(
            OrganizationSettings setting,
            Guid modifiedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var existing = await FirstOrDefaultAsync(s =>
                s.OrganizationId == setting.OrganizationId &&
                s.Category == setting.Category &&
                s.SettingKey == setting.SettingKey, cancellationToken);

            OrganizationSettings result;

            if (existing != null)
            {
                existing.SettingValue = setting.SettingValue;
                existing.UpdatedAt = DateTime.UtcNow;
                existing.UpdatedByConnectedId = modifiedByConnectedId;
                await UpdateAsync(existing, cancellationToken);
                result = existing;
            }
            else
            {
                setting.CreatedAt = DateTime.UtcNow;
                setting.CreatedByConnectedId = modifiedByConnectedId;
                result = await AddAsync(setting, cancellationToken);
            }

            var cacheKey = $"org_setting:{setting.OrganizationId}:{setting.Category}:{setting.SettingKey}";
            if (_cacheService != null) await _cacheService.RemoveAsync(cacheKey, cancellationToken);

            return result;
        }

        public async Task<bool> DeleteSettingAsync(
            Guid organizationId,
            string category,
            string settingKey,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var setting = await FirstOrDefaultAsync(s =>
                s.OrganizationId == organizationId &&
                s.Category == category &&
                s.SettingKey == settingKey, cancellationToken);

            if (setting == null) return false;

            setting.DeletedByConnectedId = deletedByConnectedId;
            await DeleteAsync(setting, cancellationToken);

            var cacheKey = $"org_setting:{organizationId}:{category}:{settingKey}";
            if (_cacheService != null) await _cacheService.RemoveAsync(cacheKey, cancellationToken);

            return true;
        }

        #endregion

        #region Private Helper: 상속 관련 로직

        private async Task<OrganizationSettings?> GetInheritedSettingRecursiveAsync(
            Guid organizationId, string category, string settingKey, CancellationToken cancellationToken)
        {
            var parentId = await _context.Set<OrganizationEntity>()
                .Where(o => o.Id == organizationId && !o.IsDeleted)
                .Select(o => o.ParentId)
                .FirstOrDefaultAsync(cancellationToken);

            if (parentId == null) return null;

            return await GetSettingAsync(parentId.Value, category, settingKey, true, cancellationToken);
        }

        #endregion

        #region 인터페이스 멤버 구현 (대부분 BaseRepository에 위임)

        // 🗑️ 'GetPagedAsync'와 'ExistsAsync'의 중복 구현을 여기서 삭제
        // BaseRepository가 이미 올바른 구현을 제공하므로 상속받아 사용합니다.

        public Task<IEnumerable<OrganizationSettings>> GetAllSettingsAsync(Guid organizationId, bool includeInherited = true, bool activeOnly = true, CancellationToken cancellationToken = default) => throw new NotImplementedException("TODO: 상속 로직을 포함한 전체 설정 조회 구현 필요");
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, string category, bool includeInherited = true, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.Category == category, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, OrganizationSettingCategory category, bool includeInherited = true, CancellationToken cancellationToken = default) => await GetSettingsByCategoryAsync(organizationId, category.ToString(), includeInherited, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetActiveSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.IsActive, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetInheritedSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.IsInherited, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetUserConfigurableSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.IsUserConfigurable && s.IsActive, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByPlanAsync(Guid organizationId, string planType, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && (s.RequiredPlan == null || s.RequiredPlan == planType) && s.IsActive, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetEncryptedSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.RequiresEncryption, cancellationToken);
        public Task<bool> SettingExistsAsync(Guid organizationId, string category, string settingKey, CancellationToken cancellationToken = default)
    => AnyAsync(s => s.OrganizationId == organizationId && s.Category == category && s.SettingKey == settingKey, cancellationToken);
        public async Task<IEnumerable<OrganizationSettings>> GetRecentlyModifiedSettingsAsync(Guid organizationId, int days = 7, CancellationToken cancellationToken = default) => await FindAsync(s => s.OrganizationId == organizationId && s.UpdatedAt.HasValue && s.UpdatedAt.Value >= DateTime.UtcNow.AddDays(-days), cancellationToken);
        public Task<bool> ValidateSettingValueAsync(Guid organizationId, string category, string settingKey, string value, CancellationToken cancellationToken = default) => throw new NotImplementedException("TODO: 정규식, 범위 등 복잡한 유효성 검증 로직 구현 필요");
        public Task<IEnumerable<OrganizationSettings>> BulkUpsertAsync(IEnumerable<OrganizationSettings> settings, Guid modifiedByConnectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<IEnumerable<OrganizationSettings>> InheritSettingsFromParentAsync(Guid organizationId, Guid parentOrganizationId, IEnumerable<string>? categories = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<IEnumerable<OrganizationSettings>> ResetToDefaultsAsync(Guid organizationId, string? category = null, Guid resetByConnectedId = default, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<int> PropagateSettingsToChildrenAsync(Guid parentOrganizationId, IEnumerable<string> settingKeys, bool overrideExisting = false, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<IEnumerable<OrganizationSettings>> ApplySettingsTemplateAsync(Guid organizationId, string templateName, Guid appliedByConnectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public async Task<string> BackupSettingsAsync(Guid organizationId, string? category = null, CancellationToken cancellationToken = default)
        {
            var settings = await FindAsync(s => s.OrganizationId == organizationId && (category == null || s.Category == category), cancellationToken);
            return JsonSerializer.Serialize(new { OrganizationId = organizationId, BackupDate = DateTime.UtcNow, Settings = settings });
        }
        public Task<IEnumerable<OrganizationSettings>> RestoreSettingsAsync(Guid organizationId, string backupData, Guid restoredByConnectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        #endregion
    }
}