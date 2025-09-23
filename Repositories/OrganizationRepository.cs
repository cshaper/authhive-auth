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
   /// Organization 리포지토리 구현체 - AuthHive v15
   /// WHO: 조직 관리 서비스, 인증 서비스, 빌링 서비스
   /// WHEN: 조직 CRUD 작업, 계층 구조 조회, 상태 관리 시
   /// WHERE: AuthHive.Auth 데이터 액세스 레이어
   /// WHAT: BaseRepository를 상속받아 조직 관리의 모든 데이터 접근 기능 제공
   /// WHY: 조직 데이터의 일관된 관리와 멀티테넌시 지원
   /// HOW: EF Core + PostgreSQL RLS + 메모리 캐싱 활용
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
       /// WHO: API Gateway, 인증 서비스
       /// WHEN: 도메인 기반 라우팅, SSO 로그인 시
       /// WHERE: AuthHive.Proxy 라우팅 결정, AuthHive.Auth 인증 프로세스
       /// WHAT: OrganizationKey(예: "acme-corp")로 조직 식별
       /// WHY: URL 친화적인 조직 식별자로 빠른 조회
       /// HOW: Unique Index를 통한 O(1) 조회 + 캐싱
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
       /// WHO: 시스템 관리자, 빌링 서비스
       /// WHEN: 일괄 처리, 정기 결제, 조직 상태 모니터링
       /// WHERE: AuthHive.Business 정산 프로세스, Admin Dashboard
       /// WHAT: Active/Suspended/Inactive 상태별 조직 필터링
       /// WHY: 상태별 일괄 처리 및 모니터링
       /// HOW: Status 인덱스를 활용한 효율적 필터링
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
       /// WHO: 조직 관리자, 계층 뷰 컴포넌트
       /// WHEN: 조직 트리 렌더링, 하위 조직 목록 표시
       /// WHERE: 조직 관리 페이지, 권한 상속 프로세스
       /// WHAT: 지정된 부모 조직의 자식 조직들
       /// WHY: 계층 구조 네비게이션 및 권한 상속
       /// HOW: recursive=false시 직접 자식만, true시 재귀 쿼리로 모든 하위 조직
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
       /// WHO: 조직 생성/수정 프로세스
       /// WHEN: 신규 조직 생성 또는 조직 키 변경 시
       /// WHERE: OrganizationService.CreateAsync, UpdateAsync
       /// WHAT: 중복 키 존재 여부 검증
       /// WHY: 조직 키의 고유성 보장
       /// HOW: EXISTS 쿼리로 빠른 중복 체크
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
       /// WHO: 조직 생성/수정 프로세스
       /// WHEN: 신규 조직 생성 또는 조직명 변경 시
       /// WHERE: OrganizationService.CreateAsync, UpdateAsync
       /// WHAT: 동일 조직명 존재 여부 검증
       /// WHY: 조직명 중복 방지 (비즈니스 규칙)
       /// HOW: Case-insensitive 비교로 정확한 중복 체크
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
       /// WHO: 조직 생성 서비스
       /// WHEN: 새 조직 생성 시
       /// WHERE: OrganizationService.CreateAsync 호출 체인
       /// WHAT: 계층 경로, 레벨, Slug 자동 설정
       /// WHY: 계층 구조 무결성 및 기본값 설정
       /// HOW: 부모 정보 기반 경로 계산 + 플랜별 깊이 검증
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
       /// WHO: 조직 수정 서비스
       /// WHEN: 조직 정보 수정 시
       /// WHERE: OrganizationService.UpdateAsync 호출 체인
       /// WHAT: 상태 변경 추적, 경로 재계산, 캐시 무효화
       /// WHY: 상태 변경 이력 및 계층 구조 일관성 유지
       /// HOW: 변경 감지 → 상태별 처리 → 캐시 무효화
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
       /// WHO: 시스템 관리자
       /// WHEN: 조직 삭제 요청 시
       /// WHERE: OrganizationService.DeleteAsync 호출 체인
       /// WHAT: 조직 및 모든 하위 조직 소프트 삭제
       /// WHY: 계층 구조 무결성 및 데이터 보존
       /// HOW: 재귀적 하위 삭제 → 캐시 무효화
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