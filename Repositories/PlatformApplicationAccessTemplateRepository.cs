using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationContext 제거
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.Json;
using System.Threading; // CancellationToken 추가
using System.Threading.Tasks;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 접근 템플릿 저장소 구현 - AuthHive v16
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class PlatformApplicationAccessTemplateRepository
        : BaseRepository<PlatformApplicationAccessTemplate>, IPlatformApplicationAccessTemplateRepository
    {
        private readonly ILogger<PlatformApplicationAccessTemplateRepository> _logger;

        // 캐시 옵션은 ICacheService 구현 내에서 관리되므로 제거
        // private readonly MemoryCacheEntryOptions _templateCacheOptions = new() ...

        public PlatformApplicationAccessTemplateRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ILogger<PlatformApplicationAccessTemplateRepository> logger,
            ICacheService? cacheService = null) // IMemoryCache -> ICacheService?
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. 템플릿은 조직 범위에 속함 (true).
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region 기본 조회 (CancellationToken 추가)

        /// <summary>조직 ID로 템플릿 목록 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByOrganizationIdAsync(
            Guid organizationId, CancellationToken cancellationToken = default)
        {
             // TODO: 캐싱 추가 고려 (조직별 템플릿 목록)
            return await QueryForOrganization(organizationId)
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>템플릿 이름으로 조회 (특정 조직)</summary>
        public async Task<PlatformApplicationAccessTemplate?> GetByNameAsync(
            Guid organizationId, string name, CancellationToken cancellationToken = default)
        {
             // TODO: 캐싱 추가 고려 (조직 ID + 이름 기준)
            return await QueryForOrganization(organizationId)
                .Include(t => t.DefaultRole)
                .AsNoTracking() // 읽기 전용
                .FirstOrDefaultAsync(t => t.Name == name, cancellationToken);
        }

        /// <summary>접근 레벨별 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByLevelAsync(
            Guid organizationId, ApplicationAccessLevel level, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(t => t.Level == level);
            if (activeOnly) query = query.Where(t => t.IsActive);

            return await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>기본 역할 ID로 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByDefaultRoleAsync(
            Guid defaultRoleId, CancellationToken cancellationToken = default)
        {
            // 이 쿼리는 특정 조직에 국한되지 않음 (전체 DB 검색)
            return await Query() // Query() 사용 (IsDeleted=false 포함)
                .Where(t => t.DefaultRoleId == defaultRoleId)
                .Include(t => t.DefaultRole)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>템플릿 이름 중복 확인</summary>
        public async Task<bool> NameExistsAsync(
            Guid organizationId, string name, Guid? excludeTemplateId = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(t => t.Name == name);
            if (excludeTemplateId.HasValue) query = query.Where(t => t.Id != excludeTemplateId.Value);
            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region 템플릿 관리 (CancellationToken 추가)

        /// <summary>템플릿 생성 (Repository는 단순 추가만 담당)</summary>
        public async Task<PlatformApplicationAccessTemplate> CreateTemplateAsync(
            PlatformApplicationAccessTemplate template, CancellationToken cancellationToken = default)
        {
            // 권한 패턴 검증은 서비스 계층 책임
            // template.Id = template.Id == Guid.Empty ? Guid.NewGuid() : template.Id; // ID는 BaseEntity가 처리
            // template.CreatedAt = DateTime.UtcNow; // Interceptor가 처리

            var created = await AddAsync(template, cancellationToken); // BaseRepository.AddAsync 사용
            // 캐시 무효화 (BaseRepository.AddAsync는 캐시 무효화를 하지 않음)
            await InvalidateOrganizationCacheAsync(created.OrganizationId, cancellationToken);
            return created;
        }

        /// <summary>템플릿 업데이트 (Action<T> 사용)</summary>
        public async Task<PlatformApplicationAccessTemplate?> UpdateTemplateAsync(
            Guid templateId, Action<PlatformApplicationAccessTemplate> updates, CancellationToken cancellationToken = default)
        {
            var template = await GetByIdAsync(templateId, cancellationToken); // GetByIdAsync 사용 (캐시 활용 가능)
            if (template == null)
            {
                _logger.LogWarning("Attempted to update non-existent template {TemplateId}", templateId);
                return null;
            }

            var originalOrgId = template.OrganizationId; // 캐시 무효화를 위해 저장
            updates(template);
            // template.UpdatedAt = DateTime.UtcNow; // Interceptor가 처리

            await UpdateAsync(template, cancellationToken); // BaseRepository.UpdateAsync 사용 (캐시 무효화 포함)

            // 만약 OrganizationId가 변경되었다면 이전 조직 캐시도 무효화
            if (originalOrgId != template.OrganizationId)
            {
                 await InvalidateOrganizationCacheAsync(originalOrgId, cancellationToken);
            }
             await InvalidateOrganizationCacheAsync(template.OrganizationId, cancellationToken); // 현재 조직 캐시 무효화


            _logger.LogInformation("Updated access template {TemplateId}", templateId);
            return template;
        }

        /// <summary>템플릿 활성화/비활성화</summary>
        public async Task<bool> SetActiveStatusAsync(Guid templateId, bool isActive, CancellationToken cancellationToken = default)
        {
            var template = await GetByIdAsync(templateId, cancellationToken);
            if (template == null) return false;

            if (template.IsActive == isActive) return true; // 변경 사항 없음

            template.IsActive = isActive;
            // template.UpdatedAt = DateTime.UtcNow; // Interceptor가 처리
            await UpdateAsync(template, cancellationToken); // UpdateAsync 호출 (캐시 무효화 포함)
             await InvalidateOrganizationCacheAsync(template.OrganizationId, cancellationToken); // 조직 캐시 무효화 추가

            _logger.LogInformation("Set active status for template {TemplateId} to {IsActive}", templateId, isActive);
            return true;
        }

        /// <summary>템플릿 복제 (단순 복제)</summary>
        public async Task<PlatformApplicationAccessTemplate> CloneTemplateAsync(
            Guid sourceTemplateId, string newName, Guid? targetOrganizationId = null, CancellationToken cancellationToken = default)
        {
            // 원본 조회 (AsNoTracking 필요 없음, 어차피 새 객체 생성)
            var source = await GetByIdAsync(sourceTemplateId, cancellationToken);
            if (source == null) throw new InvalidOperationException($"Source template {sourceTemplateId} not found");

            var clone = new PlatformApplicationAccessTemplate
            {
                // Id, CreatedAt 등은 AddAsync에서 처리
                OrganizationId = targetOrganizationId ?? source.OrganizationId,
                Level = source.Level,
                Name = newName,
                Description = $"Copy of {source.Name}",
                DefaultRoleId = source.DefaultRoleId,
                PermissionPatterns = source.PermissionPatterns,
                Priority = source.Priority + 1, // 복제본 우선순위 조정 (예시)
                IsActive = source.IsActive,     // 원본 상태 따름
                IsSystemTemplate = false,      // 복제본은 시스템 템플릿 아님
                IncludesBillingAccess = source.IncludesBillingAccess,
                Metadata = source.Metadata
            };

            // CreateTemplateAsync 호출하여 저장 및 캐시 무효화
            return await CreateTemplateAsync(clone, cancellationToken);
        }

        #endregion

        #region 권한 패턴 관리 (CancellationToken 추가)

        /// <summary>권한 패턴 목록 업데이트</summary>
        public async Task<bool> UpdatePermissionPatternsAsync(
            Guid templateId, IEnumerable<string> patterns, CancellationToken cancellationToken = default)
        {
             // 패턴 검증은 서비스 계층 책임
            var updatedTemplate = await UpdateTemplateAsync(templateId, t =>
            {
                 // ToList() 호출하여 즉시 실행 및 null 방지
                t.PermissionPatterns = JsonSerializer.Serialize(patterns?.ToList() ?? new List<string>());
            }, cancellationToken);

            return updatedTemplate != null;
        }

        #endregion

        #region 시스템 템플릿 (CancellationToken 추가)

        /// <summary>시스템 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetSystemTemplatesAsync(
            Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
             // 시스템 템플릿은 자주 변경되지 않으므로 캐싱 효율 높음
            string cacheKey = $"SystemTemplates:{organizationId?.ToString() ?? "Global"}";
            if (_cacheService != null)
            {
                 var cached = await _cacheService.GetAsync<List<PlatformApplicationAccessTemplate>>(cacheKey, cancellationToken);
                 if (cached != null) return cached;
            }

            var query = Query().Where(t => t.IsSystemTemplate); // Query() 사용
            if (organizationId.HasValue) // 특정 조직의 시스템 템플릿 (커스터마이징된 경우)
                query = query.Where(t => t.OrganizationId == organizationId.Value);
            else // 전역 시스템 템플릿
                query = query.Where(t => t.OrganizationId == Guid.Empty); // 또는 OrganizationId가 Nullable이라면 == null

            var result = await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromHours(24), cancellationToken); // 장시간 캐싱
            }
            return result;
        }

        /// <summary>시스템 템플릿 여부 확인</summary>
        public async Task<bool> IsSystemTemplateAsync(Guid templateId, CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 캐시를 활용함
            var template = await GetByIdAsync(templateId, cancellationToken);
            return template?.IsSystemTemplate ?? false;
        }

        #endregion

        #region 우선순위 관리 (CancellationToken 추가)

        /// <summary>우선순위별 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByPriorityAsync(
            Guid organizationId, int minPriority = 0, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(t => t.Priority >= minPriority)
                .OrderBy(t => t.Priority)
                .Include(t => t.DefaultRole)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>우선순위 업데이트</summary>
        public async Task<bool> UpdatePriorityAsync(Guid templateId, int newPriority, CancellationToken cancellationToken = default)
        {
             var updatedTemplate = await UpdateTemplateAsync(templateId, t =>
             {
                 t.Priority = newPriority;
             }, cancellationToken);
            return updatedTemplate != null;
        }

        /// <summary>최고 우선순위 템플릿 조회</summary>
        public async Task<PlatformApplicationAccessTemplate?> GetHighestPriorityTemplateAsync(
            Guid organizationId, ApplicationAccessLevel level, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(t => t.Level == level && t.IsActive)
                .OrderBy(t => t.Priority) // 낮은 숫자가 높은 우선순위
                .Include(t => t.DefaultRole)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region 사용 현황 (기본 조회, CancellationToken 추가)

        /// <summary>템플릿 사용 횟수 조회</summary>
        public async Task<int> GetUsageCountAsync(Guid templateId, CancellationToken cancellationToken = default)
        {
             // UserPlatformApplicationAccess 엔티티 필요
            return await _context.Set<UserPlatformApplicationAccess>()
                .CountAsync(a => a.AccessTemplateId == templateId && !a.IsDeleted, cancellationToken);
        }

        /// <summary>템플릿을 사용하는 고유 사용자 수</summary>
        public async Task<int> GetUserCountAsync(Guid templateId, CancellationToken cancellationToken = default)
        {
            // UserPlatformApplicationAccess 엔티티 필요
            return await _context.Set<UserPlatformApplicationAccess>()
                .Where(a => a.AccessTemplateId == templateId && !a.IsDeleted)
                .Select(a => a.ConnectedId)
                .Distinct()
                .CountAsync(cancellationToken);
        }

        #endregion

        #region Billing 접근 (CancellationToken 추가)

        /// <summary>Billing 접근 권한이 있는 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetTemplatesWithBillingAccessAsync(
            Guid organizationId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(t => t.IncludesBillingAccess);
            if (activeOnly) query = query.Where(t => t.IsActive);

            return await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>Billing 접근 권한 설정</summary>
        public async Task<bool> SetBillingAccessAsync(Guid templateId, bool includesBilling, CancellationToken cancellationToken = default)
        {
             var updatedTemplate = await UpdateTemplateAsync(templateId, t =>
             {
                 t.IncludesBillingAccess = includesBilling;
             }, cancellationToken);
            return updatedTemplate != null;
        }

        #endregion

        #region 일괄 작업 (CancellationToken 추가)

        /// <summary>템플릿 일괄 생성 (AddRange)</summary>
        public async Task<int> BulkCreateAsync(IEnumerable<PlatformApplicationAccessTemplate> templates, CancellationToken cancellationToken = default)
        {
             if (templates == null || !templates.Any()) return 0;

            var templateList = templates.ToList();
            // ID, CreatedAt 등은 AddRangeAsync 내부 또는 Interceptor가 처리해야 함
            // foreach(var t in templateList) { if(t.Id == Guid.Empty) t.Id = Guid.NewGuid(); t.CreatedAt = DateTime.UtcNow; }

            await AddRangeAsync(templateList, cancellationToken); // BaseRepository.AddRangeAsync 사용

            // 조직별 캐시 무효화
            foreach (var orgId in templateList.Select(t => t.OrganizationId).Distinct())
            {
                 await InvalidateOrganizationCacheAsync(orgId, cancellationToken);
            }
            return templateList.Count;
        }

        /// <summary>조직의 템플릿 일괄 삭제 (Soft Delete)</summary>
        public async Task<int> DeleteAllByOrganizationAsync(
            Guid organizationId, bool excludeSystemTemplates = true, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (excludeSystemTemplates) query = query.Where(t => !t.IsSystemTemplate);

            var templatesToDelete = await query.ToListAsync(cancellationToken);
            if (!templatesToDelete.Any()) return 0;

            await DeleteRangeAsync(templatesToDelete, cancellationToken); // BaseRepository.DeleteRangeAsync 사용 (Soft Delete + 캐시 무효화)
            await InvalidateOrganizationCacheAsync(organizationId, cancellationToken); // 조직 캐시 무효화

            _logger.LogInformation("Soft deleted {Count} templates for organization {OrganizationId}", templatesToDelete.Count, organizationId);
            return templatesToDelete.Count;
        }

        /// <summary>템플릿 일괄 활성화/비활성화</summary>
        public async Task<int> BulkSetActiveStatusAsync(
            IEnumerable<Guid> templateIds, bool isActive, CancellationToken cancellationToken = default)
        {
             if (templateIds == null || !templateIds.Any()) return 0;

             var idList = templateIds.ToList();
             // ExecuteUpdateAsync 사용 (EF Core 7+) - 더 효율적
             int updatedCount = await Query()
                 .Where(t => idList.Contains(t.Id) && t.IsActive != isActive)
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(t => t.IsActive, isActive)
                     .SetProperty(t => t.UpdatedAt, DateTime.UtcNow), // Interceptor가 처리 못할 수 있으므로 명시
                     cancellationToken);

             // 변경된 템플릿들의 캐시 무효화 (ExecuteUpdate는 개별 엔티티를 반환하지 않음)
             // 조직 ID를 알아내기 위해 추가 쿼리 필요 또는 더 넓은 범위 캐시 무효화
             if (updatedCount > 0)
             {
                  var affectedOrgIds = await Query()
                      .Where(t => idList.Contains(t.Id))
                      .Select(t => t.OrganizationId)
                      .Distinct()
                      .ToListAsync(cancellationToken);

                  foreach(var orgId in affectedOrgIds)
                  {
                       await InvalidateOrganizationCacheAsync(orgId, cancellationToken);
                  }
                  // 개별 템플릿 캐시 무효화 (필요 시)
                  foreach (var id in idList)
                  {
                      await InvalidateCacheAsync(id, cancellationToken);
                  }
             }

            _logger.LogInformation("Bulk updated active status for {Count} templates to {IsActive}", updatedCount, isActive);
            return updatedCount;
        }

        #endregion

        #region 검색 및 필터링 (CancellationToken 추가)

        /// <summary>키워드로 템플릿 검색</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> SearchAsync(
            Guid organizationId, string keyword, bool searchInPatterns = false, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            var lowerKeyword = keyword?.ToLowerInvariant() ?? ""; // null 처리 추가

            if (!string.IsNullOrWhiteSpace(lowerKeyword))
            {
                query = query.Where(t =>
                    (t.Name != null && t.Name.ToLower().Contains(lowerKeyword)) || // null 체크 추가
                    (t.Description != null && t.Description.ToLower().Contains(lowerKeyword)) ||
                    (searchInPatterns && t.PermissionPatterns != null && t.PermissionPatterns.ToLower().Contains(lowerKeyword))); // null 체크 추가
            }

            return await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods (CancellationToken 추가)

        /// <summary>조직 관련 캐시 무효화</summary>
        private async Task InvalidateOrganizationCacheAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;
            // 조직별 템플릿 목록 캐시 등 무효화
            await _cacheService.RemoveAsync($"SystemTemplates:{organizationId}", cancellationToken);
            // 다른 조직 관련 캐시 키 추가...
             _logger.LogDebug("Invalidated organization-level template cache for Org={OrganizationId}", organizationId);
        }

        // BaseRepository의 InvalidateCacheAsync(Guid id) 사용, 별도 InvalidateCache 제거

        // DetermineAccessLevel, CreateDefaultSystemTemplates 는 서비스 로직이므로 제거됨
        // private ApplicationAccessLevel DetermineAccessLevel(...) { ... }
        // private List<PlatformApplicationAccessTemplate> CreateDefaultSystemTemplates(...) { ... }

        #endregion

        // [FIXED] 서비스 계층 로직 메서드 구현 제거됨:
        // - AddPermissionPatternAsync
        // - RemovePermissionPatternAsync
        // - ValidatePermissionPatternsAsync
        // - ExpandPermissionsAsync
        // - InitializeSystemTemplatesAsync
        // - GetMostUsedTemplatesAsync
        // - GetUnusedTemplatesAsync
        // - MigrateToOrganizationAsync
        // - ConvertLegacyPermissionsAsync
        // - AdvancedSearchAsync (BaseRepository.GetPagedAsync 사용)
        // - GetTemplateStatisticsAsync
        // - AnalyzePermissionPatternsAsync
    }
}