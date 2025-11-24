using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
// REFACTORED: IOrganizationContextService is no longer injected into the base repository
// using AuthHive.Core.Interfaces.Organization.Service; 
using AuthHive.Core.Constants.Auth; // RoleConstants 사용을 위해 추가
using Microsoft.EntityFrameworkCore;
// REFACTORED: IMemoryCache is no longer used. ICacheService is used instead.
// using Microsoft.Extensions.Caching.Memory; 
using OrgEntity = AuthHive.Core.Entities.Organization.Organization;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// Organization 리포지토리 최종 구현체 - AuthHive v16
    /// 데이터 지속성 및 계층적 데이터 무결성 보장 책임을 가집니다.
    /// </summary>
    public class OrganizationRepository : BaseRepository<OrgEntity>, IOrganizationRepository
    {
        /// <summary>
        /// [FIXED] 생성자: BaseRepository v16 원칙에 따라 AuthDbContext와 ICacheService만 주입받습니다.
        /// IOrganizationContext 의존성을 제거합니다.
        /// </summary>
        public OrganizationRepository(
            AuthDbContext context,
            ICacheService? cacheService = null) // REFACTORED: IOrganizationContext 제거
            : base(context, cacheService) // [FIXED] CS1729: BaseRepository 생성자 시그니처 수정
        {
        }

        /// <summary>
        /// [FIXED] CS0534: 이 리포지토리가 다루는 엔티티(Organization)가
        /// 조직 범위에 속하는지(조직 ID로 필터링되어야 하는지) 여부를 결정합니다.
        /// Organization은 그 자체로 조직 범위의 루트이므로 true입니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        /// <summary>
        /// 조직 키(samsung-semiconduct)로 조직 정보를 조회합니다.
        /// 캐시를 우선 조회하고, 없을 경우 DB에서 조회 후 캐시에 저장합니다.
        /// </summary>
        public async Task<OrgEntity?> GetByOrganizationKeyAsync(
            string organizationKey,
            CancellationToken cancellationToken = default)
        {
            // 1️⃣ 유효성 검사: 빈 문자열 또는 null이면 조회 불가
            if (string.IsNullOrWhiteSpace(organizationKey))
                return null;

            // 2️⃣ 캐시 키 생성: [FIXED] BaseRepository의 GetCacheKey(string) 사용
            string cacheKey = GetCacheKey($"OrganizationKey:{organizationKey.ToLowerInvariant()}");

            // 3️⃣ 캐시 조회: ICacheService를 통해 비동기적으로 조회
            if (_cacheService != null)
            {
                var cachedOrg = await _cacheService.GetAsync<OrgEntity>(cacheKey, cancellationToken);
                if (cachedOrg != null) return cachedOrg;
            }


            // 4️⃣ DB 조회: 관련 엔티티 포함하여 조직 정보 조회
            var organization = await Query()
                .Include(o => o.ChildOrganizations.Where(c => !c.IsDeleted)) // 자식 조직 중 삭제되지 않은 것만 포함
                .Include(o => o.Capabilities)           // 기능 정보 포함
                .Include(o => o.Domains)                // 도메인 정보 포함
                .Include(o => o.SSOConfigurations)      // SSO 설정 포함
                .FirstOrDefaultAsync(o => o.OrganizationKey == organizationKey, cancellationToken); // 조직 키로 조회

            // 5️⃣ 캐시 저장: 조회된 조직 정보를 TTL과 함께 저장
            if (organization != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, organization, TimeSpan.FromMinutes(15), cancellationToken);
            }

            // 6️⃣ 결과 반환
            return organization;
        }

        /// <summary>
        /// 조직 상태에 따라 조직 목록을 조회합니다.
        /// 결과는 이름(Name) 기준으로 오름차순 정렬되며, 요청 취소를 지원합니다.
        /// </summary>
        public async Task<IEnumerable<OrgEntity>> GetByStatusAsync(
        OrganizationStatus status,
        CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.Status == status)              // 1️⃣ 상태 필터링
                .OrderBy(o => o.Name)                        // 2️⃣ 이름 기준 정렬
                .ToListAsync(cancellationToken);             // 3️⃣ CancellationToken 전달
        }

        /// <summary>
        /// 특정 조직 키(도메인 모델의 속성값)가 이미 존재하는지 확인합니다.
        /// organizationKey(키)  "acme-corp"(키의 값)
        /// 선택적으로 특정 ID를 제외할 수 있으며, 요청 취소를 지원합니다.
        /// </summary>
        public async Task<bool> IsOrganizationKeyExistsAsync(
            string organizationKey,
            Guid? excludeId = null,
            CancellationToken cancellationToken = default)
        {
            // 1️⃣ 유효성 검사: 조직 키가 null 또는 공백이면 존재할 수 없으므로 false 반환
            if (string.IsNullOrWhiteSpace(organizationKey))
                return false;

            // 2️⃣ 기본 쿼리: 해당 조직 키를 가진 엔티티 조회
            var query = Query().Where(o => o.OrganizationKey == organizationKey);

            // 3️⃣ 제외 ID가 있을 경우: 해당 ID는 제외하고 중복 여부 확인
            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            // 4️⃣ 존재 여부 확인: CancellationToken을 전달하여 요청 취소 가능
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsNameExistsAsync(string name, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            var query = Query().Where(o => o.Name == name);

            if (excludeId.HasValue)
            {
                query = query.Where(o => o.Id != excludeId.Value);
            }

            return await query.AnyAsync(cancellationToken); // ✅ 취소 토큰 전달
        }


        #region Refactored Hierarchy Methods

        /// <summary>
        /// 특정 부모 조직의 '직속' 자식 조직 목록을 조회합니다. (재귀 없음)
        /// 정렬 기준: SortOrder → Name 순서이며, 요청 취소를 지원합니다.
        /// </summary>
        public async Task<IEnumerable<OrgEntity>> GetDirectChildrenAsync(
            Guid parentId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.ParentId == parentId)              // 1️⃣ 부모 ID 기준 필터링
                .OrderBy(o => o.SortOrder)                       // 2️⃣ 정렬 우선순위
                .ThenBy(o => o.Name)                             // 3️⃣ 이름 기준 보조 정렬
                .ToListAsync(cancellationToken);                 // 4️⃣ 취소 토큰 전달
        }
        /// <summary>
        /// 특정 조직의 모든 하위 조직(자식, 손자 등) 목록을 재귀적으로 조회합니다.
        /// </summary>
        public async Task<IEnumerable<OrgEntity>> GetDescendantsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var accumulator = new List<OrgEntity>();
            await GetChildrenRecursiveAsync(organizationId, accumulator, cancellationToken);
            return accumulator;
        }

        #endregion

        #region Overridden CUD Methods

        /// <summary>
        /// AddAsync 메서드의 역할은 **"새로 창출하는 것"이 아니라, 이미 준비된 엔티티를 데이터베이스 컨텍스트에 "추가(Add)하는 것"**입니다.
        /// 새로운 조직 엔티티를 데이터베이스에 추가합니다.
        /// 이 오버라이드 메서드는 데이터 무결성을 위해 조직의 계층 구조 경로(Path)와 레벨(Level)을 계산합니다.
        /// </summary>
        /// <param name="entity">저장할 Organization 엔티티 (ParentId가 설정되어 있을 수 있음)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>저장 완료된 Organization 엔티티</returns>
        public override async Task<OrgEntity> AddAsync(
            OrgEntity entity,
            CancellationToken cancellationToken = default)
        {
            // 1️⃣ 계층 구조 정보 설정 (데이터 무결성 책임)
            if (entity.ParentId.HasValue)
            {
                // 1-1. 부모 조직 조회 (Materialized Path 계산에 필요)
                var parent = await GetByIdAsync(entity.ParentId.Value, cancellationToken);

                // 1-2. 부모 조직이 유효할 경우 경로 및 레벨 계산
                if (parent != null)
                {
                    // [경로 계산] 부모의 경로에 현재 조직의 ID를 추가하여 전체 경로를 만듭니다.
                    // 예: Parent.Path="/123" 이면, Entity.Path="/123/456"이 됩니다.
                    entity.Path = $"{parent.Path}/{entity.Id}";

                    // [레벨 계산] 부모 레벨에 1을 더하여 현재 조직의 깊이를 설정합니다.
                    // 이 로직은 Service Layer에서 '최대 깊이 제한' 검증이 완료되었음을 가정합니다.
                    entity.Level = parent.Level + 1;
                }
                // else: 부모가 null인 경우, 이는 Service Layer의 유효성 검증(Parent Org 존재 여부) 실패로 간주되므로,
                // 현재 리포지토리는 NullReferenceException을 피하고, Service Layer에서 이를 처리할 수 있도록 그대로 진행합니다.
            }
            else
            {
                // 1-3. 최상위(Root) 조직의 경우
                // ParentId가 없으므로 경로를 자기 자신의 ID로만 설정하고, 레벨은 0으로 설정합니다.
                entity.Path = $"/{entity.Id}";
                entity.Level = 0;
            }

            // 2️⃣ Slug, 정책 등 기본값 설정
            // OrganizationKey(Slug)가 요청에서 제공되지 않은 경우, 기본 명칭을 기반으로 생성합니다.
            // REFACTORED: entity.Slug -> entity.OrganizationKey
            if (string.IsNullOrWhiteSpace(entity.OrganizationKey)) 
            {
                entity.OrganizationKey = GenerateSlug(entity.Name);
            }

            // PolicyInheritanceMode가 설정되지 않은 경우, 기본값(Inherit)으로 초기화합니다.
            if (entity.PolicyInheritanceMode == 0)
            {
                entity.PolicyInheritanceMode = PolicyInheritanceMode.Inherit;
            }

            // 상태가 Active이고 활성화 시간이 설정되지 않은 경우, 현재 시간을 기록합니다.
            if (entity.Status == OrganizationStatus.Active && !entity.ActivatedAt.HasValue)
            {
                entity.ActivatedAt = DateTime.UtcNow;
            }

            // 3️⃣ DB 저장
            // BaseRepository의 AddAsync를 호출하여 최종적으로 Context에 추가하고 변경사항을 추적합니다.
            return await base.AddAsync(entity, cancellationToken);
        }

        /// <summary>
        /// 조직 엔티티의 상태 및 계층 구조 변경을 처리하고 DB에 업데이트합니다.
        /// 상태 변경 시 활성화/정지 시간을 기록하고, 부모 변경 시 계층 경로를 재계산합니다.
        /// </summary>
        public override async Task UpdateAsync(OrgEntity entity, CancellationToken cancellationToken = default)
        {
            // 1. [DB 조회] 기존 엔티티 상태를 추적하지 않는 방식(AsNoTracking)으로 조회하여 현재 상태를 비교합니다.
            var existing = await _dbSet.AsNoTracking().FirstOrDefaultAsync(o => o.Id == entity.Id, cancellationToken);

            if (existing != null)
            {
                // 2. 상태 변경 추적 및 시간 기록
                if (existing.Status != entity.Status)
                {
                    switch (entity.Status)
                    {
                        case OrganizationStatus.Active:
                            // [상태: 활성화] 활성화 시간 기록 및 정지 사유/시간 초기화
                            entity.ActivatedAt = DateTime.UtcNow;
                            entity.SuspendedAt = null;
                            entity.SuspensionReason = null;
                            break;
                        case OrganizationStatus.Suspended:
                            // [상태: 정지] 정지 시간 기록
                            entity.SuspendedAt = DateTime.UtcNow;
                            // Note: 정지 사유(SuspensionReason)는 Service Layer에서 DTO를 통해 전달되어야 함.
                            break;
                    }
                }

                // 3. 부모 변경 시 계층 경로 재계산
                if (existing.ParentId != entity.ParentId)
                {
                    // Service Layer에서 순환 참조 및 깊이 제한 검증이 완료되었음을 가정하고,
                    // 리포지토리는 데이터 무결성을 위해 Path와 Level을 재계산합니다.
                    // UpdateHierarchyPathAsync는 하위 조직까지 재귀적으로 업데이트합니다.
                    await UpdateHierarchyPathAsync(entity, cancellationToken);
                }
            }

            // 4. 캐시 무효화 (ICacheService의 비동기 호출 사용)
            await InvalidateOrganizationCacheAsync(entity, cancellationToken);

            // 5. [DB 업데이트] BaseRepository의 UpdateAsync 호출 (변경된 엔티티 상태 반영)
            await base.UpdateAsync(entity, cancellationToken);
        }

        /// <summary>
        /// 조직 엔티티와 그 모든 하위 조직(자식, 손자 등)을 Soft Delete 처리합니다.
        /// 하위 조직을 먼저 처리한 후, 현재 조직을 처리합니다.
        /// </summary>
        /// <param name="entity">삭제할 조직 엔티티</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public override async Task DeleteAsync(OrgEntity entity, CancellationToken cancellationToken = default)
        {
            // 1. [하위 조직 처리] 명확하게 모든 하위 조직 목록을 재귀적으로 조회합니다.
            // GetDescendantsAsync에 취소 토큰 전달
            var children = await GetDescendantsAsync(entity.Id, cancellationToken);

            // 2. 하위 조직 Soft Delete 처리
            foreach (var child in children)
            {
                // BaseRepository의 DeleteAsync는 Soft Delete를 수행하며, 취소 토큰을 전달합니다.
                await base.DeleteAsync(child, cancellationToken);
            }

            // 3. 캐시 무효화 (모든 하위 조직의 삭제가 끝난 후, 캐시 무효화)
            // [수정] InvalidateOrganizationCache(entity)를 InvalidateOrganizationCacheAsync(entity, cancellationToken)으로 변경
            await InvalidateOrganizationCacheAsync(entity, cancellationToken);

            // 4. 현재 조직 Soft Delete 처리
            await base.DeleteAsync(entity, cancellationToken);
        }


        /// <summary>
        /// [핵심 구현] 특정 User가 소유하거나 생성한 (Owner 역할이 있는) 활성 조직의 수를 조회합니다. (플랜 제한 검증용)
        /// ConnectedId, Organization, Role 테이블을 조인하여 소유권(ORG_OWNER)을 확인합니다.
        /// </summary>
        /// <param name="userId">조직 생성 주체(User)의 ID</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>User가 소유한 활성 조직의 수</returns>
        public async Task<int> GetOrganizationCountForUserAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {

            // 1. ORG_OWNER 역할 ID를 조회합니다.
            var ownerRole = await _context.Roles
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.RoleKey == RoleConstants.DefaultRoleKeys.ORGANIZATION_OWNER, cancellationToken);

            if (ownerRole == null)
            {
                return 0;
            }

            // 2. ConnectedIdRoles (Owner 역할 할당), ConnectedIds (User 연결), Organizations (활성 조직)을 조인하여 카운트합니다.
            return await _context.ConnectedIdRoles // Context -> _context로 수정
                .AsNoTracking()
                .Where(cir => cir.RoleId == ownerRole.Id)

                // ConnectedId와 User 연결 및 상태 필터링
                .Join(_context.ConnectedIds.Where(c => c.UserId == userId && c.Status == ConnectedIdStatus.Active), // Context -> _context로 수정
                    cir => cir.ConnectedId,
                    c => c.Id,
                    (cir, c) => c.OrganizationId)

                // Organization 필터링 (Organization 자체의 활성 상태 & Soft Delete 되지 않음)
                .Join(_context.Organizations.Where(o => o.Status == OrganizationStatus.Active && !o.IsDeleted), // Context -> _context로 수정
                    orgId => orgId,
                    org => org.Id,
                    (orgId, org) => org.Id)

                .Distinct()
                .CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 재귀적으로 모든 하위 조직을 조회하는 내부 헬퍼 메서드
        /// </summary>
        private async Task GetChildrenRecursiveAsync(Guid parentId, List<OrgEntity> result, CancellationToken cancellationToken = default)
        {
            var children = await Query()
                .Where(o => o.ParentId == parentId)
                .OrderBy(o => o.SortOrder).ThenBy(o => o.Name)
                .ToListAsync(cancellationToken); // [FIXED] CancellationToken 전달

            result.AddRange(children);

            foreach (var child in children)
            {
                await GetChildrenRecursiveAsync(child.Id, result, cancellationToken);
            }
        }

        /// <summary>
        /// 조직의 계층 경로를 재귀적으로 업데이트하는 헬퍼 메서드
        /// </summary>
        private async Task UpdateHierarchyPathAsync(OrgEntity entity, CancellationToken cancellationToken = default)
        {
            if (entity.ParentId.HasValue)
            {
                var parent = await GetByIdAsync(entity.ParentId.Value, cancellationToken); // [FIXED] CancellationToken 전달
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

            var children = await GetDescendantsAsync(entity.Id, cancellationToken); // [FIXED] CancellationToken 전달
            foreach (var child in children)
            {
                // [FIXED] CancellationToken 전달
                await UpdateHierarchyPathAsync(child, cancellationToken); 
                await base.UpdateAsync(child, cancellationToken);
            }
        }

        private Task ValidateOrganizationDepthAsync(OrgEntity parent)
        {
            const int maxDepth = 10; // 예시: 최대 깊이를 10으로 설정
            if (parent.Level >= maxDepth - 1)
            {
                throw new InvalidOperationException($"Organization hierarchy depth cannot exceed {maxDepth} levels.");
            }
            return Task.CompletedTask;
        }

        private string GenerateSlug(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return Guid.NewGuid().ToString("N").Substring(0, 12);
            // URL에 안전한 문자열로 변환하는 로직 (간소화됨)
            return name.Trim().ToLower().Replace(" ", "-").Substring(0, Math.Min(name.Length, 50));
        }


        /// <summary>
        /// 조직 엔티티와 관련된 모든 캐시 항목을 비동기적으로 무효화합니다.
        /// </summary>
        /// <param name="entity">캐시를 무효화할 조직 엔티티</param>
        /// <param name="cancellationToken">취소 토큰</param>
        private async Task InvalidateOrganizationCacheAsync(OrgEntity entity, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null || entity == null) return;

            var tasks = new List<Task>();
            
            // 1. ID 기반 캐시 무효화 (GetByIdAsync에서 사용하는 캐시)
            // [FIXED] BaseRepository의 GetCacheKey(Guid id) 사용
            tasks.Add(_cacheService.RemoveAsync(GetCacheKey(entity.Id), cancellationToken));

            // 2. Key 기반 캐시 무효화 (GetByOrganizationKeyAsync에서 사용하는 캐시)
            // [FIXED] BaseRepository의 GetCacheKey(string keySuffix) 사용
            if (!string.IsNullOrWhiteSpace(entity.OrganizationKey))
            {
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey($"OrganizationKey:{entity.OrganizationKey.ToLowerInvariant()}"), cancellationToken));
            }

            // 3. 부모 조직의 캐시 무효화 (계층 트리 조회/직속 자식 목록 캐시가 변경되었을 가능성)
            if (entity.ParentId.HasValue)
            {
                // 부모 조직의 GetById 캐시 무효화
                // [FIXED] BaseRepository의 GetCacheKey(Guid id) 사용
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey(entity.ParentId.Value), cancellationToken));
            }
            
            await Task.WhenAll(tasks);
        }

        #endregion
    }
}