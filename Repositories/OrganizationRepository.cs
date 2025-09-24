using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// Organization 리포지토리 최종 구현체 - AuthHive v15 (Refactored)
    /// 모호한 계층 조회 메서드를 명확한 역할의 두 메서드로 분리하여 안정성을 높였습니다.
    /// </summary>
    public class OrganizationRepository : BaseRepository<Core.Entities.Organization.Organization>, IOrganizationRepository
    {
        private readonly MemoryCacheEntryOptions _organizationCacheOptions = new()
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
            SlidingExpiration = TimeSpan.FromMinutes(10),
            Priority = CacheItemPriority.High
        };

        public OrganizationRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        public async Task<Core.Entities.Organization.Organization?> GetByOrganizationKeyAsync(string organizationKey)
        {
            if (string.IsNullOrWhiteSpace(organizationKey))
                return null;

            string cacheKey = GetOrganizationCacheKey("GetByKey", organizationKey);
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out Core.Entities.Organization.Organization? cachedOrg))
            {
                return cachedOrg;
            }

            var organization = await Query()
                .Include(o => o.ChildOrganizations.Where(c => !c.IsDeleted))
                .Include(o => o.Capabilities)
                .Include(o => o.Domains)
                .Include(o => o.SSOConfigurations)
                .FirstOrDefaultAsync(o => o.OrganizationKey == organizationKey);

            if (organization != null && _cache != null)
            {
                _cache.Set(cacheKey, organization, _organizationCacheOptions);
            }

            return organization;
        }

        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetByStatusAsync(OrganizationStatus status)
        {
            return await Query()
                .Where(o => o.Status == status)
                .OrderBy(o => o.Name)
                .ToListAsync();
        }
        
        public async Task<bool> IsOrganizationKeyExistsAsync(string organizationKey, Guid? excludeId = null)
        {
            if (string.IsNullOrWhiteSpace(organizationKey))
                return false;

            var query = Query().Where(o => o.OrganizationKey == organizationKey);

            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            return await query.AnyAsync();
        }

        public async Task<bool> IsNameExistsAsync(string name, Guid? excludeId = null)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            var query = Query().Where(o => o.Name == name);

            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            return await query.AnyAsync();
        }

        #region Refactored Hierarchy Methods

        /// <summary>
        /// 특정 부모 조직의 '직접적인' 자식 조직 목록만 조회합니다. (재귀 없음)
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetDirectChildrenAsync(Guid parentId)
        {
            return await Query()
                .Where(o => o.ParentId == parentId)
                .OrderBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 특정 조직의 모든 하위 조직(자식, 손자 등) 목록을 재귀적으로 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetDescendantsAsync(Guid organizationId)
        {
            var allDescendants = new List<Core.Entities.Organization.Organization>();
            await GetChildrenRecursiveAsync(organizationId, allDescendants);
            return allDescendants;
        }

        #endregion

        #region Overridden CUD Methods

        public override async Task<Core.Entities.Organization.Organization> AddAsync(Core.Entities.Organization.Organization entity)
        {
            // 계층 구조 정보 설정
            if (entity.ParentId.HasValue)
            {
                var parent = await GetByIdAsync(entity.ParentId.Value);
                if (parent != null)
                {
                    entity.Path = $"{parent.Path}/{entity.Id}";
                    entity.Level = parent.Level + 1;
                    await ValidateOrganizationDepthAsync(parent);
                }
            }
            else
            {
                entity.Path = $"/{entity.Id}";
                entity.Level = 0;
            }

            // Slug, 정책 등 기본값 설정
            if (string.IsNullOrWhiteSpace(entity.Slug)) { entity.Slug = GenerateSlug(entity.Name); }
            if (entity.PolicyInheritanceMode == 0) { entity.PolicyInheritanceMode = PolicyInheritanceMode.Inherit; }
            if (entity.Status == OrganizationStatus.Active && !entity.ActivatedAt.HasValue) { entity.ActivatedAt = DateTime.UtcNow; }

            return await base.AddAsync(entity);
        }

        public override async Task UpdateAsync(Core.Entities.Organization.Organization entity)
        {
            var existing = await _dbSet.AsNoTracking().FirstOrDefaultAsync(o => o.Id == entity.Id);

            if (existing != null)
            {
                // 상태 변경 추적
                if (existing.Status != entity.Status)
                {
                    switch (entity.Status)
                    {
                        case OrganizationStatus.Active:
                            entity.ActivatedAt = DateTime.UtcNow; entity.SuspendedAt = null; entity.SuspensionReason = null; break;
                        case OrganizationStatus.Suspended:
                            entity.SuspendedAt = DateTime.UtcNow; break;
                    }
                }
                // 부모 변경 시 전체 경로 재계산
                if (existing.ParentId != entity.ParentId) 
                { 
                    await UpdateHierarchyPathAsync(entity); 
                }
            }

            InvalidateOrganizationCache(entity);
            await base.UpdateAsync(entity);
        }

        public override async Task DeleteAsync(Core.Entities.Organization.Organization entity)
        {
            // 명확하게 모든 하위 조직을 가져와서 삭제 처리
            var children = await GetDescendantsAsync(entity.Id);
            foreach (var child in children)
            {
                // BaseRepository의 DeleteAsync는 Soft Delete를 수행
                await base.DeleteAsync(child);
            }

            InvalidateOrganizationCache(entity);
            await base.DeleteAsync(entity);
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 재귀적으로 모든 하위 조직을 조회하는 내부 헬퍼 메서드
        /// </summary>
        private async Task GetChildrenRecursiveAsync(Guid parentId, List<Core.Entities.Organization.Organization> result)
        {
            var children = await Query()
                .Where(o => o.ParentId == parentId)
                .OrderBy(o => o.SortOrder).ThenBy(o => o.Name)
                .ToListAsync();

            result.AddRange(children);

            foreach (var child in children)
            {
                await GetChildrenRecursiveAsync(child.Id, result);
            }
        }

        /// <summary>
        /// 조직의 계층 경로를 재귀적으로 업데이트하는 헬퍼 메서드
        /// </summary>
        private async Task UpdateHierarchyPathAsync(Core.Entities.Organization.Organization entity)
        {
            if (entity.ParentId.HasValue)
            {
                var parent = await GetByIdAsync(entity.ParentId.Value);
                if (parent != null)
                {
                    entity.Path = $"{parent.Path}/{entity.Id}";
                    entity.Level = parent.Level + 1;
                }
            }
            else
            {
                entity.Path = $"/{entity.Id}";
                entity.Level = 0;
            }

            var children = await GetDescendantsAsync(entity.Id);
            foreach (var child in children)
            {
                await UpdateHierarchyPathAsync(child); 
                await base.UpdateAsync(child);
            }
        }

        private async Task ValidateOrganizationDepthAsync(Core.Entities.Organization.Organization parent)
        {
            const int maxDepth = 10; // 예시: 최대 깊이를 10으로 설정
            if (parent.Level >= maxDepth - 1)
            {
                throw new InvalidOperationException($"Organization hierarchy depth cannot exceed {maxDepth} levels.");
            }
            await Task.CompletedTask;
        }

        private string GenerateSlug(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return Guid.NewGuid().ToString("N").Substring(0, 12);
            // URL에 안전한 문자열로 변환하는 로직 (간소화됨)
            return name.Trim().ToLower().Replace(" ", "-").Substring(0, Math.Min(name.Length, 50));
        }

        private void InvalidateOrganizationCache(Core.Entities.Organization.Organization entity)
        {
            if (_cache == null) return;
            InvalidateCache(entity.Id); // ID 기반 캐시
            _cache.Remove(GetOrganizationCacheKey("GetByKey", entity.OrganizationKey)); // Key 기반 캐시
            if (entity.ParentId.HasValue) 
            {
                InvalidateCache(entity.ParentId.Value); // 부모 캐시도 무효화
            }
        }

        private string GetOrganizationCacheKey(string operation, params object[] parameters)
        {
            var orgId = _organizationContext.CurrentOrganizationId?.ToString() ?? "Global";
            var paramStr = string.Join(":", parameters);
            return $"Organization:{operation}:{orgId}:{paramStr}";
        }

        #endregion
    }
}
