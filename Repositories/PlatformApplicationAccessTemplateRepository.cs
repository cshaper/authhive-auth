using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Common;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 플랫폼 애플리케이션 접근 템플릿 저장소 구현 - AuthHive v15
    /// </summary>
    public class PlatformApplicationAccessTemplateRepository : OrganizationScopedRepository<PlatformApplicationAccessTemplate>, IPlatformApplicationAccessTemplateRepository
    {
        private readonly ILogger<PlatformApplicationAccessTemplateRepository> _logger;

        public PlatformApplicationAccessTemplateRepository(
            AuthDbContext context,
            ILogger<PlatformApplicationAccessTemplateRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>템플릿 이름으로 조회</summary>
        public async Task<PlatformApplicationAccessTemplate?> GetByNameAsync(Guid organizationId, string name)
        {
            return await Query()
                .Include(t => t.DefaultRole)
                .FirstOrDefaultAsync(t => t.OrganizationId == organizationId && t.Name == name);
        }

        /// <summary>접근 레벨별 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByLevelAsync(
            Guid organizationId, ApplicationAccessLevel level, bool activeOnly = true)
        {
            var query = Query().Where(t => t.OrganizationId == organizationId && t.Level == level);
            if (activeOnly) query = query.Where(t => t.IsActive);
            
            return await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .ToListAsync();
        }

        /// <summary>기본 역할 ID로 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByDefaultRoleAsync(Guid defaultRoleId)
        {
            return await Query()
                .Where(t => t.DefaultRoleId == defaultRoleId)
                .Include(t => t.DefaultRole)
                .ToListAsync();
        }

        /// <summary>템플릿 이름 중복 확인</summary>
        public async Task<bool> NameExistsAsync(Guid organizationId, string name, Guid? excludeTemplateId = null)
        {
            var query = Query().Where(t => t.OrganizationId == organizationId && t.Name == name);
            if (excludeTemplateId.HasValue) query = query.Where(t => t.Id != excludeTemplateId.Value);
            return await query.AnyAsync();
        }

        #endregion

        #region 템플릿 관리

        /// <summary>템플릿 생성 (권한 패턴 검증 포함)</summary>
        public async Task<PlatformApplicationAccessTemplate> CreateTemplateAsync(
            PlatformApplicationAccessTemplate template, bool validatePermissions = true)
        {
            if (validatePermissions)
            {
                var patterns = JsonSerializer.Deserialize<List<string>>(template.PermissionPatterns ?? "[]");
                var validation = await ValidatePermissionPatternsAsync(patterns ?? new List<string>());
                if (!validation.IsValid)
                {
                    throw new InvalidOperationException($"Invalid permission patterns: {string.Join(", ", validation.Errors)}");
                }
            }

            var entry = await _context.PlatformApplicationAccessTemplates.AddAsync(template);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created access template {TemplateId} for organization {OrganizationId}", 
                template.Id, template.OrganizationId);

            return entry.Entity;
        }

        /// <summary>템플릿 업데이트</summary>
        public async Task<PlatformApplicationAccessTemplate?> UpdateTemplateAsync(
            Guid templateId, Action<PlatformApplicationAccessTemplate> updates)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return null;

            updates(template);
            template.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return template;
        }

        /// <summary>템플릿 활성화/비활성화</summary>
        public async Task<bool> SetActiveStatusAsync(Guid templateId, bool isActive)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            template.IsActive = isActive;
            template.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>템플릿 복제</summary>
        public async Task<PlatformApplicationAccessTemplate> CloneTemplateAsync(
            Guid sourceTemplateId, string newName, Guid? targetOrganizationId = null)
        {
            var source = await GetByIdAsync(sourceTemplateId);
            if (source == null) throw new InvalidOperationException("Source template not found");

            var clone = new PlatformApplicationAccessTemplate
            {
                Id = Guid.NewGuid(),
                OrganizationId = targetOrganizationId ?? source.OrganizationId,
                Level = source.Level,
                Name = newName,
                Description = $"Copy of {source.Name}",
                DefaultRoleId = source.DefaultRoleId,
                PermissionPatterns = source.PermissionPatterns,
                Priority = source.Priority,
                IsActive = true,
                IsSystemTemplate = false, // 복제본은 시스템 템플릿이 아님
                IncludesBillingAccess = source.IncludesBillingAccess,
                Metadata = source.Metadata,
                CreatedAt = DateTime.UtcNow
            };

            return await CreateTemplateAsync(clone, false);
        }

        #endregion

        #region 권한 패턴 관리

        /// <summary>권한 패턴 추가</summary>
        public async Task<bool> AddPermissionPatternAsync(Guid templateId, string pattern)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            var patterns = JsonSerializer.Deserialize<List<string>>(template.PermissionPatterns ?? "[]") ?? new List<string>();
            if (!patterns.Contains(pattern))
            {
                patterns.Add(pattern);
                template.PermissionPatterns = JsonSerializer.Serialize(patterns);
                await _context.SaveChangesAsync();
            }

            return true;
        }

        /// <summary>권한 패턴 제거</summary>
        public async Task<bool> RemovePermissionPatternAsync(Guid templateId, string pattern)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            var patterns = JsonSerializer.Deserialize<List<string>>(template.PermissionPatterns ?? "[]") ?? new List<string>();
            if (patterns.Remove(pattern))
            {
                template.PermissionPatterns = JsonSerializer.Serialize(patterns);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }

        /// <summary>권한 패턴 목록 업데이트</summary>
        public async Task<bool> UpdatePermissionPatternsAsync(Guid templateId, IEnumerable<string> patterns)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            template.PermissionPatterns = JsonSerializer.Serialize(patterns.ToList());
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>권한 패턴 검증 (기본 구현)</summary>
        public async Task<(bool IsValid, List<string> Errors)> ValidatePermissionPatternsAsync(IEnumerable<string> patterns)
        {
            await Task.CompletedTask; // async 호환성
            var errors = new List<string>();

            foreach (var pattern in patterns)
            {
                if (string.IsNullOrWhiteSpace(pattern))
                {
                    errors.Add("Empty pattern not allowed");
                    continue;
                }

                // 기본 패턴 검증 (실제로는 더 복잡한 로직 필요)
                if (!pattern.Contains(':'))
                {
                    errors.Add($"Invalid pattern format: {pattern}");
                }
            }

            return (errors.Count == 0, errors);
        }

        /// <summary>실제 권한으로 확장 (기본 구현)</summary>
        public async Task<IEnumerable<string>> ExpandPermissionsAsync(Guid templateId)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return new List<string>();

            var patterns = JsonSerializer.Deserialize<List<string>>(template.PermissionPatterns ?? "[]") ?? new List<string>();
            
            // 기본 구현 - 실제로는 패턴 매칭 엔진 필요
            return patterns;
        }

        #endregion

        #region 시스템 템플릿

        /// <summary>시스템 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetSystemTemplatesAsync(Guid? organizationId = null)
        {
            var query = Query().Where(t => t.IsSystemTemplate);
            if (organizationId.HasValue) query = query.Where(t => t.OrganizationId == organizationId.Value);
            
            return await query.Include(t => t.DefaultRole).ToListAsync();
        }

        /// <summary>시스템 템플릿 초기화</summary>
        public async Task<int> InitializeSystemTemplatesAsync(Guid organizationId)
        {
            var existingCount = await Query().Where(t => t.OrganizationId == organizationId && t.IsSystemTemplate).CountAsync();
            if (existingCount > 0) return 0; // 이미 초기화됨

            var systemTemplates = new List<PlatformApplicationAccessTemplate>
            {
                new PlatformApplicationAccessTemplate
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    Level = ApplicationAccessLevel.Owner,
                    Name = "Owner Template",
                    Description = "Full access to all features",
                    PermissionPatterns = JsonSerializer.Serialize(new[] { "application:*:*" }),
                    Priority = 10,
                    IsActive = true,
                    IsSystemTemplate = true,
                    CreatedAt = DateTime.UtcNow
                },
                new PlatformApplicationAccessTemplate
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    Level = ApplicationAccessLevel.Admin,
                    Name = "Admin Template",
                    Description = "Administrative access",
                    PermissionPatterns = JsonSerializer.Serialize(new[] { "application:*:read", "application:*:write", "!application:billing:*" }),
                    Priority = 20,
                    IsActive = true,
                    IsSystemTemplate = true,
                    CreatedAt = DateTime.UtcNow
                },
                new PlatformApplicationAccessTemplate
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    Level = ApplicationAccessLevel.User,
                    Name = "User Template",
                    Description = "Standard user access",
                    PermissionPatterns = JsonSerializer.Serialize(new[] { "application:*:read", "application:data:write" }),
                    Priority = 30,
                    IsActive = true,
                    IsSystemTemplate = true,
                    CreatedAt = DateTime.UtcNow
                },
                new PlatformApplicationAccessTemplate
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    Level = ApplicationAccessLevel.Viewer,
                    Name = "Viewer Template",
                    Description = "Read-only access",
                    PermissionPatterns = JsonSerializer.Serialize(new[] { "application:*:read" }),
                    Priority = 40,
                    IsActive = true,
                    IsSystemTemplate = true,
                    CreatedAt = DateTime.UtcNow
                }
            };

            await _context.PlatformApplicationAccessTemplates.AddRangeAsync(systemTemplates);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Initialized {Count} system templates for organization {OrganizationId}", 
                systemTemplates.Count, organizationId);

            return systemTemplates.Count;
        }

        /// <summary>시스템 템플릿 여부 확인</summary>
        public async Task<bool> IsSystemTemplateAsync(Guid templateId)
        {
            return await Query().Where(t => t.Id == templateId).Select(t => t.IsSystemTemplate).FirstOrDefaultAsync();
        }

        #endregion

        #region 우선순위 관리

        /// <summary>우선순위별 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetByPriorityAsync(Guid organizationId, int minPriority = 0)
        {
            return await Query()
                .Where(t => t.OrganizationId == organizationId && t.Priority >= minPriority)
                .OrderBy(t => t.Priority)
                .Include(t => t.DefaultRole)
                .ToListAsync();
        }

        /// <summary>우선순위 업데이트</summary>
        public async Task<bool> UpdatePriorityAsync(Guid templateId, int newPriority)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            template.Priority = newPriority;
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>최고 우선순위 템플릿 조회</summary>
        public async Task<PlatformApplicationAccessTemplate?> GetHighestPriorityTemplateAsync(
            Guid organizationId, ApplicationAccessLevel level)
        {
            return await Query()
                .Where(t => t.OrganizationId == organizationId && t.Level == level && t.IsActive)
                .OrderBy(t => t.Priority)
                .Include(t => t.DefaultRole)
                .FirstOrDefaultAsync();
        }

        #endregion

        #region 사용 현황

        /// <summary>템플릿 사용 횟수 조회</summary>
        public async Task<int> GetUsageCountAsync(Guid templateId)
        {
            return await _context.UserApplicationAccesses
                .Where(a => a.AccessTemplateId == templateId && !a.IsDeleted)
                .CountAsync();
        }

        /// <summary>템플릿을 사용하는 사용자 수</summary>
        public async Task<int> GetUserCountAsync(Guid templateId)
        {
            return await _context.UserApplicationAccesses
                .Where(a => a.AccessTemplateId == templateId && !a.IsDeleted)
                .Select(a => a.ConnectedId)
                .Distinct()
                .CountAsync();
        }

        /// <summary>가장 많이 사용되는 템플릿</summary>
        public async Task<IEnumerable<(PlatformApplicationAccessTemplate Template, int UsageCount)>> GetMostUsedTemplatesAsync(
            Guid organizationId, int limit = 10)
        {
            return await Query()
                .Where(t => t.OrganizationId == organizationId)
                .Include(t => t.DefaultRole)
                .Select(t => new 
                { 
                    Template = t, 
                    UsageCount = _context.UserApplicationAccesses
                        .Where(a => a.AccessTemplateId == t.Id && !a.IsDeleted)
                        .Count()
                })
                .OrderByDescending(x => x.UsageCount)
                .Take(limit)
                .Select(x => ValueTuple.Create(x.Template, x.UsageCount))
                .ToListAsync();
        }

        /// <summary>사용되지 않는 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetUnusedTemplatesAsync(Guid organizationId)
        {
            return await Query()
                .Where(t => t.OrganizationId == organizationId && 
                           !_context.UserApplicationAccesses.Any(a => a.AccessTemplateId == t.Id && !a.IsDeleted))
                .Include(t => t.DefaultRole)
                .ToListAsync();
        }

        #endregion

        #region Billing 접근

        /// <summary>Billing 접근 권한이 있는 템플릿 조회</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> GetTemplatesWithBillingAccessAsync(
            Guid organizationId, bool activeOnly = true)
        {
            var query = Query().Where(t => t.OrganizationId == organizationId && t.IncludesBillingAccess);
            if (activeOnly) query = query.Where(t => t.IsActive);

            return await query.Include(t => t.DefaultRole).ToListAsync();
        }

        /// <summary>Billing 접근 권한 설정</summary>
        public async Task<bool> SetBillingAccessAsync(Guid templateId, bool includesBilling)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return false;

            template.IncludesBillingAccess = includesBilling;
            await _context.SaveChangesAsync();
            return true;
        }

        #endregion

        #region 일괄 작업

        /// <summary>템플릿 일괄 생성</summary>
        public async Task<int> BulkCreateAsync(IEnumerable<PlatformApplicationAccessTemplate> templates)
        {
            var templateList = templates.ToList();
            await _context.PlatformApplicationAccessTemplates.AddRangeAsync(templateList);
            await _context.SaveChangesAsync();
            return templateList.Count;
        }

        /// <summary>조직의 모든 템플릿 삭제</summary>
        public async Task<int> DeleteAllByOrganizationAsync(Guid organizationId, bool excludeSystemTemplates = true)
        {
            var query = Query().Where(t => t.OrganizationId == organizationId);
            if (excludeSystemTemplates) query = query.Where(t => !t.IsSystemTemplate);

            var templates = await query.ToListAsync();
            foreach (var template in templates)
            {
                template.IsDeleted = true;
                template.DeletedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            return templates.Count;
        }

        /// <summary>템플릿 일괄 활성화/비활성화</summary>
        public async Task<int> BulkSetActiveStatusAsync(IEnumerable<Guid> templateIds, bool isActive)
        {
            var templates = await Query().Where(t => templateIds.Contains(t.Id)).ToListAsync();
            foreach (var template in templates)
            {
                template.IsActive = isActive;
                template.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            return templates.Count;
        }

        #endregion

        #region 마이그레이션

        /// <summary>템플릿을 다른 조직으로 마이그레이션</summary>
        public async Task<PlatformApplicationAccessTemplate> MigrateToOrganizationAsync(
            Guid templateId, Guid targetOrganizationId, bool includeUsers = false)
        {
            var sourceTemplate = await GetByIdAsync(templateId);
            if (sourceTemplate == null) throw new InvalidOperationException("Source template not found");

            var migratedTemplate = await CloneTemplateAsync(templateId, sourceTemplate.Name, targetOrganizationId);

            if (includeUsers)
            {
                // 사용자 마이그레이션은 복잡한 비즈니스 로직이므로 Service에서 처리하는 것이 좋음
                _logger.LogWarning("User migration not implemented in repository layer");
            }

            return migratedTemplate;
        }

        /// <summary>레거시 권한을 템플릿으로 변환</summary>
        public async Task<PlatformApplicationAccessTemplate> ConvertLegacyPermissionsAsync(
            Guid organizationId, IEnumerable<string> legacyPermissions, string templateName)
        {
            var template = new PlatformApplicationAccessTemplate
            {
                Id = Guid.NewGuid(),
                OrganizationId = organizationId,
                Level = ApplicationAccessLevel.User,
                Name = templateName,
                Description = "Converted from legacy permissions",
                PermissionPatterns = JsonSerializer.Serialize(legacyPermissions.ToList()),
                Priority = 50,
                IsActive = true,
                IsSystemTemplate = false,
                CreatedAt = DateTime.UtcNow
            };

            return await CreateTemplateAsync(template, false);
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>키워드로 템플릿 검색</summary>
        public async Task<IEnumerable<PlatformApplicationAccessTemplate>> SearchAsync(
            Guid organizationId, string keyword, bool searchInPatterns = false)
        {
            var query = Query().Where(t => t.OrganizationId == organizationId);

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                query = query.Where(t => 
                    t.Name.Contains(keyword) || 
                    (t.Description != null && t.Description.Contains(keyword)) ||
                    (searchInPatterns && t.PermissionPatterns.Contains(keyword)));
            }

            return await query.Include(t => t.DefaultRole).ToListAsync();
        }

        /// <summary>고급 검색</summary>
        public async Task<PagedResult<PlatformApplicationAccessTemplate>> AdvancedSearchAsync(
            Expression<Func<PlatformApplicationAccessTemplate, bool>> criteria, int pageNumber = 1, int pageSize = 50)
        {
            var query = Query().Where(criteria);
            var totalCount = await query.CountAsync();

            var items = await query
                .Include(t => t.DefaultRole)
                .OrderBy(t => t.Priority)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return PagedResult<PlatformApplicationAccessTemplate>.Create(items, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 통계 및 분석

        /// <summary>템플릿 사용 통계</summary>
        public async Task<Dictionary<ApplicationAccessLevel, (int TemplateCount, int UsageCount)>> GetTemplateStatisticsAsync(Guid organizationId)
        {
            return await Query()
                .Where(t => t.OrganizationId == organizationId)
                .GroupBy(t => t.Level)
                .Select(g => new 
                { 
                    Level = g.Key,
                    TemplateCount = g.Count(),
                    UsageCount = g.Sum(t => _context.UserApplicationAccesses
                        .Where(a => a.AccessTemplateId == t.Id && !a.IsDeleted)
                        .Count())
                })
                .ToDictionaryAsync(x => x.Level, x => (x.TemplateCount, x.UsageCount));
        }

        /// <summary>권한 패턴 분석</summary>
        public async Task<Dictionary<string, int>> AnalyzePermissionPatternsAsync(Guid templateId)
        {
            var template = await GetByIdAsync(templateId);
            if (template == null) return new Dictionary<string, int>();

            var patterns = JsonSerializer.Deserialize<List<string>>(template.PermissionPatterns ?? "[]") ?? new List<string>();
            
            return patterns
                .GroupBy(p => p.Split(':').FirstOrDefault() ?? "unknown")
                .ToDictionary(g => g.Key, g => g.Count());
        }

        #endregion

        #region Helper Methods

        /// <summary>기본 쿼리 (소프트 삭제된 항목 제외)</summary>
        private new IQueryable<PlatformApplicationAccessTemplate> Query()
        {
            return _context.PlatformApplicationAccessTemplates.Where(t => !t.IsDeleted);
        }

        #endregion
    }
}