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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// Organization 리포지토리 구현체 - AuthHive v15
    /// BaseRepository를 상속받아 조직 관리의 모든 기능을 제공합니다.
    /// 계층 구조, 상태 관리, 중복 검사 등 조직 특화 기능을 포함합니다.
    /// </summary>
    public class OrganizationRepository : BaseRepository<Core.Entities.Organization.Organization>, 
        IOrganizationRepository
    {
        // 조직 리포지토리 전용 캐시 옵션
        private readonly MemoryCacheEntryOptions _organizationCacheOptions = new()
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30), // 조직 정보는 더 길게 캐싱
            SlidingExpiration = TimeSpan.FromMinutes(10),
            Priority = CacheItemPriority.High // 조직 정보는 높은 우선순위
        };

        public OrganizationRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        /// <summary>
        /// 조직의 고유 키로 단일 조직을 조회합니다.
        /// 사용 시점: 도메인이나 슬러그 기반 라우팅, 외부 시스템 연동
        /// </summary>
        public async Task<Core.Entities.Organization.Organization?> GetByOrganizationKeyAsync(string organizationKey)
        {
            if (string.IsNullOrWhiteSpace(organizationKey))
                return null;

            // 캐시 키 생성
            string cacheKey = GetOrganizationCacheKey("GetByKey", organizationKey);
            
            // 캐시 확인
            if (_cache != null && _cache.TryGetValue(cacheKey, out Core.Entities.Organization.Organization? cachedOrg))
            {
                return cachedOrg;
            }

            // DB 조회
            var organization = await Query()
                .Include(o => o.ChildOrganizations.Where(c => !c.IsDeleted))
                .Include(o => o.Capabilities)
                .Include(o => o.Domains)
                .Include(o => o.SSOConfigurations)
                .FirstOrDefaultAsync(o => o.OrganizationKey == organizationKey);

            // 캐시 저장
            if (organization != null && _cache != null)
            {
                _cache.Set(cacheKey, organization, _organizationCacheOptions);
            }

            return organization;
        }

        /// <summary>
        /// 특정 상태를 가진 모든 조직 목록을 조회합니다.
        /// 사용 시점: 관리자 대시보드, 정기 작업(활성 조직 통계 등)
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetByStatusAsync(OrganizationStatus status)
        {
            return await Query()
                .Where(o => o.Status == status)
                .OrderBy(o => o.Name)
                .ToListAsync();
        }

        /// <summary>
        /// 특정 부모 조직에 속한 모든 자식 조직 목록을 조회합니다.
        /// 사용 시점: 조직 트리 구조 표시, 계층별 권한 관리
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetChildOrganizationsAsync(
            Guid parentId, 
            bool recursive = false)
        {
            if (!recursive)
            {
                // 직접 자식만 조회
                return await Query()
                    .Where(o => o.ParentId == parentId)
                    .OrderBy(o => o.SortOrder)
                    .ThenBy(o => o.Name)
                    .ToListAsync();
            }
            else
            {
                // 재귀적으로 모든 하위 조직 조회
                var allChildren = new List<Core.Entities.Organization.Organization>();
                await GetChildrenRecursiveAsync(parentId, allChildren);
                return allChildren;
            }
        }

        /// <summary>
        /// 조직 키가 이미 존재하는지 확인합니다.
        /// 사용 시점: 새 조직 생성 시 중복 검사
        /// </summary>
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

        /// <summary>
        /// 조직명이 이미 존재하는지 확인합니다.
        /// 사용 시점: 새 조직 생성 또는 이름 변경 시 중복 검사
        /// </summary>
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

        /// <summary>
        /// 조직 생성 시 계층 구조 경로 자동 설정
        /// override 사용: 부모의 AddAsync를 확장하여 조직 특화 로직 추가
        /// </summary>
        public override async Task<Core.Entities.Organization.Organization> AddAsync(
            Core.Entities.Organization.Organization entity)
        {
            // 계층 구조 정보 설정
            if (entity.ParentId.HasValue)
            {
                var parent = await GetByIdAsync(entity.ParentId.Value);
                if (parent != null)
                {
                    entity.Path = $"{parent.Path}/{entity.Id}";
                    entity.Level = parent.Level + 1;
                    
                    // 플랜별 계층 깊이 제한 확인
                    await ValidateOrganizationDepthAsync(parent);
                }
            }
            else
            {
                entity.Path = $"/{entity.Id}";
                entity.Level = 0;
            }

            // Slug 자동 생성 (없는 경우)
            if (string.IsNullOrWhiteSpace(entity.Slug))
            {
                entity.Slug = GenerateSlug(entity.Name);
            }

            // 기본 정책 상속 모드 설정
            if (entity.PolicyInheritanceMode == 0)
            {
                entity.PolicyInheritanceMode = PolicyInheritanceMode.Inherit;
            }

            // 활성화 시간 설정
            if (entity.Status == OrganizationStatus.Active && !entity.ActivatedAt.HasValue)
            {
                entity.ActivatedAt = DateTime.UtcNow;
            }

            return await base.AddAsync(entity);
        }

        /// <summary>
        /// 조직 업데이트 시 상태 변경 추적
        /// override 사용: 부모의 UpdateAsync를 확장하여 상태 변경 로직 추가
        /// </summary>
        public override async Task UpdateAsync(Core.Entities.Organization.Organization entity)
        {
            // 기존 엔티티 조회하여 상태 변경 확인
            var existing = await _dbSet.AsNoTracking()
                .FirstOrDefaultAsync(o => o.Id == entity.Id);

            if (existing != null)
            {
                // 상태 변경 추적
                if (existing.Status != entity.Status)
                {
                    switch (entity.Status)
                    {
                        case OrganizationStatus.Active:
                            entity.ActivatedAt = DateTime.UtcNow;
                            entity.SuspendedAt = null;
                            entity.SuspensionReason = null;
                            break;
                        case OrganizationStatus.Suspended:
                            entity.SuspendedAt = DateTime.UtcNow;
                            break;
                    }
                }

                // 부모 조직 변경 시 경로 재계산
                if (existing.ParentId != entity.ParentId)
                {
                    await UpdateHierarchyPathAsync(entity);
                }
            }

            // 캐시 무효화
            InvalidateOrganizationCache(entity);

            await base.UpdateAsync(entity);
        }

        /// <summary>
        /// 조직 삭제 시 하위 조직도 함께 처리
        /// override 사용: 부모의 DeleteAsync를 확장하여 계층 삭제 로직 추가
        /// </summary>
        public override async Task DeleteAsync(Core.Entities.Organization.Organization entity)
        {
            // 하위 조직들도 함께 삭제 처리
            var children = await GetChildOrganizationsAsync(entity.Id, recursive: true);
            foreach (var child in children)
            {
                await base.DeleteAsync(child);
            }

            // 캐시 무효화
            InvalidateOrganizationCache(entity);

            await base.DeleteAsync(entity);
        }

        #region 헬퍼 메서드

        /// <summary>
        /// 재귀적으로 모든 하위 조직 조회
        /// </summary>
        private async Task GetChildrenRecursiveAsync(
            Guid parentId, 
            List<Core.Entities.Organization.Organization> result)
        {
            var children = await Query()
                .Where(o => o.ParentId == parentId)
                .OrderBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync();

            result.AddRange(children);

            foreach (var child in children)
            {
                await GetChildrenRecursiveAsync(child.Id, result);
            }
        }

        /// <summary>
        /// 계층 구조 경로 업데이트
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

            // 하위 조직들의 경로도 업데이트
            var children = await GetChildOrganizationsAsync(entity.Id, recursive: true);
            foreach (var child in children)
            {
                await UpdateHierarchyPathAsync(child);
                await base.UpdateAsync(child);
            }
        }

        /// <summary>
        /// 조직 계층 깊이 제한 검증
        /// </summary>
        private async Task ValidateOrganizationDepthAsync(Core.Entities.Organization.Organization parent)
        {
            // TODO: PlanSubscription을 통해 플랜별 깊이 제한 확인
            // PricingConstants.SubscriptionPlans.OrganizationDepthLimits 참조
            
            // 예시 구현 (실제로는 PlanSubscription 서비스 주입 필요)
            const int maxDepth = 3; // Business 플랜 기준
            
            if (parent.Level >= maxDepth - 1)
            {
                throw new InvalidOperationException(
                    $"조직 계층 깊이 제한({maxDepth}단계)을 초과할 수 없습니다.");
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// Slug 생성 (URL 친화적인 식별자)
        /// </summary>
        private string GenerateSlug(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return Guid.NewGuid().ToString("N").Substring(0, 8);

            return name.ToLower()
                .Replace(" ", "-")
                .Replace("_", "-")
                .Replace(".", "")
                .Replace(",", "")
                .Replace("'", "")
                .Replace("\"", "")
                .Replace("&", "and")
                .Replace("@", "at")
                .Substring(0, Math.Min(name.Length, 50));
        }

        /// <summary>
        /// 조직 관련 캐시 무효화
        /// </summary>
        private void InvalidateOrganizationCache(Core.Entities.Organization.Organization entity)
        {
            if (_cache == null) return;

            // ID 기반 캐시 제거
            InvalidateCache(entity.Id);

            // OrganizationKey 기반 캐시 제거
            string keyCache = GetOrganizationCacheKey("GetByKey", entity.OrganizationKey);
            _cache.Remove(keyCache);

            // 부모 조직 캐시도 무효화 (자식 목록이 변경되었을 수 있음)
            if (entity.ParentId.HasValue)
            {
                InvalidateCache(entity.ParentId.Value);
            }
        }

        /// <summary>
        /// 조직 전용 캐시 키 생성
        /// </summary>
        private string GetOrganizationCacheKey(string operation, params object[] parameters)
        {
            var orgId = _organizationContext.CurrentOrganizationId?.ToString() ?? "Global";
            var paramStr = string.Join(":", parameters);
            return $"Organization:{operation}:{orgId}:{paramStr}";
        }

        #endregion
    }
}