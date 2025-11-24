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
using System.Linq;
using System.Collections.Generic;
using System;

// Organization 엔티티의 이름 충돌을 피하기 위해 별칭을 사용합니다.
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationSettings Repository 구현체 - AuthHive v16 아키텍처 적용
    /// [FIXED] DTO/비즈니스 로직을 제거하고, 엔티티 데이터 접근만 책임집니다.
    /// </summary>
    public class OrganizationSettingsRepository : BaseRepository<OrganizationSettings>,
        IOrganizationSettingsRepository,
        IOrganizationSettingsQueryRepository
    {
        public OrganizationSettingsRepository(AuthDbContext context, ICacheService? cacheService = null)
            : base(context, cacheService) 
        {
        }

        protected override bool IsOrganizationBaseEntity() => true;

        #region 핵심 조회 메서드 (IOrganizationSettingsQueryRepository)

        /// <summary>
        /// 리포지토리는 엔티티를 반환합니다. DTO 변환은 서비스의 책임입니다.
        /// 상속 로직(includeInherited)은 서비스 계층에서 처리해야 합니다.
        /// </summary>
        public async Task<OrganizationSettings?> GetSettingAsync(
            Guid organizationId,
            string category,
            string settingKey,
            bool includeInherited = true, // 참고: 이 플래그는 서비스 계층에서 사용되어야 합니다.
            CancellationToken cancellationToken = default)
        {
            var cacheKey = $"org_setting:{organizationId}:{category}:{settingKey}";

            if (_cacheService != null)
            {
                var cachedSetting = await _cacheService.GetAsync<OrganizationSettings>(cacheKey, cancellationToken);
                if (cachedSetting != null) return cachedSetting;
            }

            // 리포지토리는 '직접' 소유한 설정만 조회합니다.
            var setting = await Query().FirstOrDefaultAsync(s =>
                    s.OrganizationId == organizationId &&
                    s.Category == category &&
                    s.SettingKey == settingKey, cancellationToken);

            // 상속 처리는 이 메서드를 호출하는 서비스 계층의 책임입니다.

            if (setting != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, setting, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return setting;
        }

        // IOrganizationSettingsQueryRepository 인터페이스의 GetSettingAsync 구현
        public async Task<OrganizationSettings?> GetSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, bool includeInherited = true, CancellationToken cancellationToken = default)
        {
            return await GetSettingAsync(organizationId, category.ToString(), settingKey, includeInherited, cancellationToken);
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

        #region 핵심 명령 메서드 (IOrganizationSettingsRepository)

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
            await DeleteAsync(setting, cancellationToken); // BaseRepository의 Soft Delete 호출

            var cacheKey = $"org_setting:{organizationId}:{category}:{settingKey}";
            if (_cacheService != null) await _cacheService.RemoveAsync(cacheKey, cancellationToken);

            return true;
        }
        
        public async Task<IEnumerable<OrganizationSettings>> BulkUpsertAsync(IEnumerable<OrganizationSettings> settings, Guid modifiedByConnectedId, CancellationToken cancellationToken = default)
        {
            var results = new List<OrganizationSettings>();
            foreach(var setting in settings)
            {
                results.Add(await UpsertSettingAsync(setting, modifiedByConnectedId, cancellationToken));
            }
            return results;
        }

        public Task<IEnumerable<OrganizationSettings>> InheritSettingsFromParentAsync(Guid organizationId, Guid parentOrganizationId, IEnumerable<string>? categories = null, CancellationToken cancellationToken = default) 
            => throw new NotImplementedException("상속 로직은 리포지토리가 아닌 서비스 계층에서 구현해야 합니다.");

        #endregion

        #region IOrganizationSettingsQueryRepository 구현
        
        public Task<IEnumerable<OrganizationSettings>> GetAllSettingsAsync(Guid organizationId, bool includeInherited = true, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
             // 상속 로직은 서비스 계층에서 처리해야 합니다.
             return FindAsync(s => s.OrganizationId == organizationId && (!activeOnly || s.IsActive), cancellationToken);
        }

        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, string category, bool includeInherited = true, CancellationToken cancellationToken = default) 
        {
            // 상속 로직은 서비스 계층에서 처리해야 합니다.
            return await FindAsync(s => s.OrganizationId == organizationId && s.Category == category, cancellationToken);
        }
        
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByCategoryAsync(Guid organizationId, OrganizationSettingCategory category, bool includeInherited = true, CancellationToken cancellationToken = default) 
            => await GetSettingsByCategoryAsync(organizationId, category.ToString(), includeInherited, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetActiveSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && s.IsActive, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetInheritedSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && s.IsInherited, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetUserConfigurableSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && s.IsUserConfigurable && s.IsActive, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetSettingsByPlanAsync(Guid organizationId, string planType, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && (s.RequiredPlan == null || s.RequiredPlan == planType) && s.IsActive, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetEncryptedSettingsAsync(Guid organizationId, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && s.RequiresEncryption, cancellationToken);
        
        public Task<bool> SettingExistsAsync(Guid organizationId, string category, string settingKey, CancellationToken cancellationToken = default)
            => AnyAsync(s => s.OrganizationId == organizationId && s.Category == category && s.SettingKey == settingKey, cancellationToken);
        
        public async Task<IEnumerable<OrganizationSettings>> GetRecentlyModifiedSettingsAsync(Guid organizationId, int days = 7, CancellationToken cancellationToken = default) 
            => await FindAsync(s => s.OrganizationId == organizationId && s.UpdatedAt.HasValue && s.UpdatedAt.Value >= DateTime.UtcNow.AddDays(-days), cancellationToken);

        #endregion
    }
}