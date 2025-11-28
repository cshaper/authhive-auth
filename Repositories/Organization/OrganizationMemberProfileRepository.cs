using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache;


namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 멤버 프로필 Repository 구현체 - AuthHive v16
    /// v16 아키텍처 원칙(IUnitOfWork, ICacheService, CancellationToken, 성능 최적화)이 적용되었습니다.
    /// </summary>
    public class OrganizationMemberProfileRepository : BaseRepository<OrganizationMemberProfile>, IOrganizationMemberProfileRepository
    {
        /// <summary>
        /// v16 원칙에 따라 IOrganizationContext를 제거하고 ICacheService를 주입받습니다.
        /// </summary>
        public OrganizationMemberProfileRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
        }

        /// <summary>
        /// 이 리포지토리가 다루는 OrganizationMemberProfile 엔티티는 조직 범위(Organization-scoped)임을 명시합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region 캐시 무효화 오버라이드 (v16)

        /// <summary>
        /// 조직 범위 엔티티에 맞는 캐시 키를 사용하여 캐시를 무효화합니다.
        /// BaseRepository의 가이드라인을 따릅니다.
        /// </summary>
        public override Task UpdateAsync(OrganizationMemberProfile entity, CancellationToken cancellationToken = default)
        {
            // UpdatedAt 타임스탬프를 중앙에서 관리하여 일관성을 보장합니다.
            entity.UpdatedAt = DateTime.UtcNow;
            _dbSet.Update(entity);
            return InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken);
        }

        /// <summary>
        /// 조직 범위 엔티티에 맞는 캐시 키를 사용하여 여러 캐시를 무효화합니다.
        /// </summary>
        public override Task UpdateRangeAsync(IEnumerable<OrganizationMemberProfile> entities, CancellationToken cancellationToken = default)
        {
            var timestamp = DateTime.UtcNow;
            var entityList = entities.ToList();
            foreach (var entity in entityList)
            {
                entity.UpdatedAt = timestamp;
            }

            _dbSet.UpdateRange(entityList);
            var tasks = entityList.Select(e => InvalidateCacheAsync(e.Id, e.OrganizationId, cancellationToken));
            return Task.WhenAll(tasks);
        }

        /// <summary>
        /// 조직 범위 엔티티에 맞는 캐시 키를 사용하여 캐시를 무효화합니다.
        /// </summary>
        public override async Task DeleteAsync(OrganizationMemberProfile entity, CancellationToken cancellationToken = default)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            _dbSet.Update(entity);
            await InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken);
        }

        /// <summary>
        /// 조직 범위 엔티티에 맞는 캐시 키를 사용하여 여러 캐시를 무효화합니다.
        /// </summary>
        public override async Task DeleteRangeAsync(IEnumerable<OrganizationMemberProfile> entities, CancellationToken cancellationToken = default)
        {
            var timestamp = DateTime.UtcNow;
            var entityList = entities.ToList();
            var tasks = new List<Task>();
            foreach (var entity in entityList)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = timestamp;
                tasks.Add(InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken));
            }
            _dbSet.UpdateRange(entityList);
            await Task.WhenAll(tasks);
        }

        #endregion

        #region IOrganizationScopedRepository Implementations
        
        /// <summary>
        /// IOrganizationScopedRepository 인터페이스를 구현합니다.
        /// 특정 조직의 모든 멤버 프로필을 조회하며, 선택적으로 날짜 범위 및 개수 제한을 적용합니다.
        /// [FIXED] CS0266 오류를 해결하기 위해 Where 필터링 후 OrderBy를 적용하도록 순서를 수정했습니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByOrganizationIdAsync(Guid organizationId, DateTime? startDate = null, DateTime? endDate = null, int? limit = null, CancellationToken cancellationToken = default)
        {
            IQueryable<OrganizationMemberProfile> query = QueryForOrganization(organizationId).AsNoTracking();

            if (startDate.HasValue)
            {
                query = query.Where(p => p.CreatedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                // endDate의 자정까지 포함하기 위해 +1일하고 미만(<)으로 비교합니다.
                query = query.Where(p => p.CreatedAt < endDate.Value.AddDays(1));
            }

            // 모든 필터링이 끝난 후 정렬을 적용합니다.
            var orderedQuery = query.OrderByDescending(p => p.CreatedAt);

            // 최종적으로 개수 제한을 적용합니다.
            IQueryable<OrganizationMemberProfile> finalQuery = orderedQuery;
            if (limit.HasValue && limit > 0)
            {
                finalQuery = finalQuery.Take(limit.Value);
            }

            return await finalQuery.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직 ID와 엔티티 ID로 특정 프로필을 조회합니다.
        /// </summary>
        public async Task<OrganizationMemberProfile?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(e => e.Id == id, cancellationToken);
        }

        /// <summary>
        /// 조직 내에서 특정 조건을 만족하는 프로필 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> FindByOrganizationAsync(Guid organizationId, Expression<Func<OrganizationMemberProfile, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(predicate)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직 내에서 페이징된 프로필 목록을 조회합니다.
        /// </summary>
        public async Task<(IEnumerable<OrganizationMemberProfile> Items, int TotalCount)> GetPagedByOrganizationAsync(Guid organizationId, int pageNumber, int pageSize, Expression<Func<OrganizationMemberProfile, bool>>? additionalPredicate = null, Expression<Func<OrganizationMemberProfile, object>>? orderBy = null, bool isDescending = false, CancellationToken cancellationToken = default)
        {
            var baseQuery = QueryForOrganization(organizationId);
            
            // BaseRepository의 GetPagedAsync 메서드를 재사용하여 코드 중복을 최소화합니다.
            return await GetPagedAsync(pageNumber, pageSize, additionalPredicate, orderBy, isDescending, cancellationToken);
        }

        /// <summary>
        /// 조직 내에 특정 ID의 프로필이 존재하는지 확인합니다.
        /// </summary>
        public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(e => e.Id == id, cancellationToken);
        }

        /// <summary>
        /// 조직 내의 프로필 수를 계산합니다.
        /// </summary>
        public async Task<int> CountByOrganizationAsync(Guid organizationId, Expression<Func<OrganizationMemberProfile, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직의 모든 프로필을 소프트 삭제 처리합니다.
        /// </summary>
        public async Task DeleteAllByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var entitiesToDelete = await QueryForOrganization(organizationId)
                .ToListAsync(cancellationToken);

            if (entitiesToDelete.Any())
            {
                await DeleteRangeAsync(entitiesToDelete, cancellationToken);
            }
        }
        
        #endregion

        #region 기본 조회

        public async Task<OrganizationMemberProfile?> GetByConnectedIdAsync(Guid connectedId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);
        }

        public async Task<OrganizationMemberProfile?> GetByEmployeeIdAsync(string employeeId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .FirstOrDefaultAsync(p => p.EmployeeId == employeeId, cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMemberProfile>> GetByConnectedIdsAsync(IEnumerable<Guid> connectedIds, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var idList = connectedIds.ToList();
            if (!idList.Any())
            {
                return Enumerable.Empty<OrganizationMemberProfile>();
            }
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> ExistsAsync(Guid connectedId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(p => p.ConnectedId == connectedId, cancellationToken);
        }

        #endregion

        #region 부서 관련

        public async Task<IEnumerable<OrganizationMemberProfile>> GetByDepartmentAsync(string department, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .Where(p => p.Department == department)
                .OrderBy(p => p.JobTitle)
                .ThenBy(p => p.EmployeeId)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<string>> GetAllDepartmentsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.Department))
                .Select(p => p.Department!)
                .Distinct()
                .OrderBy(d => d)
                .ToListAsync(cancellationToken);
        }

        public async Task<Dictionary<string, int>> GetDepartmentStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.Department))
                .GroupBy(p => p.Department!)
                .Select(g => new { Department = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Department, x => x.Count, cancellationToken);
        }

        public async Task<bool> ChangeDepartmentAsync(Guid connectedId, Guid organizationId, string newDepartment, CancellationToken cancellationToken = default)
        {
            var profile = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);

            if (profile == null)
                return false;

            profile.Department = newDepartment;
            await UpdateAsync(profile, cancellationToken);
            return true;
        }

        #endregion

        #region 직책 관련

        public async Task<IEnumerable<OrganizationMemberProfile>> GetByJobTitleAsync(string jobTitle, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .Where(p => p.JobTitle == jobTitle)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.EmployeeId)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<string>> GetAllJobTitlesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.JobTitle))
                .Select(p => p.JobTitle!)
                .Distinct()
                .OrderBy(j => j)
                .ToListAsync(cancellationToken);
        }

        public async Task<Dictionary<string, int>> GetJobTitleStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.JobTitle))
                .GroupBy(p => p.JobTitle!)
                .Select(g => new { JobTitle = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.JobTitle, x => x.Count, cancellationToken);
        }

        public async Task<bool> UpdateJobTitleAsync(Guid connectedId, Guid organizationId, string newJobTitle, CancellationToken cancellationToken = default)
        {
            var profile = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);

            if (profile == null)
                return false;

            profile.JobTitle = newJobTitle;
            await UpdateAsync(profile, cancellationToken);
            return true;
        }

        #endregion

        #region 관리자 계층 구조 (N+1 성능 최적화)

        public async Task<IEnumerable<OrganizationMemberProfile>> GetDirectReportsAsync(Guid managerConnectedId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Where(p => p.ManagerConnectedId == managerConnectedId)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationMemberProfile>> GetManagerChainAsync(Guid connectedId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var allProfiles = await QueryForOrganization(organizationId)
                .AsNoTracking()
                .ToDictionaryAsync(p => p.ConnectedId, p => p, cancellationToken);

            var chain = new List<OrganizationMemberProfile>();
            if (!allProfiles.TryGetValue(connectedId, out var currentProfile))
            {
                return chain;
            }

            var visited = new HashSet<Guid> { currentProfile.ConnectedId };

            while (currentProfile?.ManagerConnectedId != null && allProfiles.TryGetValue(currentProfile.ManagerConnectedId.Value, out var manager))
            {
                if (!visited.Add(manager.ConnectedId)) 
                    break;

                chain.Add(manager);
                currentProfile = manager;
            }

            return chain;
        }

        public async Task<IEnumerable<OrganizationMemberProfile>> GetOrganizationHierarchyAsync(Guid organizationId, Guid? rootManagerId = null, CancellationToken cancellationToken = default)
        {
            var allProfiles = await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .ToListAsync(cancellationToken);
            
            var lookup = allProfiles.ToLookup(p => p.ManagerConnectedId);

            var hierarchy = new List<OrganizationMemberProfile>();
            var rootNodes = rootManagerId.HasValue
                ? allProfiles.Where(p => p.ConnectedId == rootManagerId.Value)
                : allProfiles.Where(p => p.ManagerConnectedId == null);

            var visited = new HashSet<Guid>();
            foreach (var root in rootNodes)
            {
                BuildHierarchyRecursive(root, lookup, hierarchy, visited);
            }
            
            return hierarchy;
        }
        
        private void BuildHierarchyRecursive(OrganizationMemberProfile current, ILookup<Guid?, OrganizationMemberProfile> lookup, List<OrganizationMemberProfile> result, HashSet<Guid> visited)
        {
            if (!visited.Add(current.ConnectedId)) return;

            result.Add(current);
            
            foreach (var directReport in lookup[current.ConnectedId].OrderBy(r => r.EmployeeId))
            {
                BuildHierarchyRecursive(directReport, lookup, result, visited);
            }
        }


        public async Task<bool> ChangeManagerAsync(Guid connectedId, Guid organizationId, Guid? newManagerId, CancellationToken cancellationToken = default)
        {
            if (newManagerId.HasValue)
            {
                if (connectedId == newManagerId.Value) return false;
                
                if (await CheckCircularReferenceAsync(connectedId, newManagerId.Value, organizationId, cancellationToken))
                    return false;
            }

            var profile = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);

            if (profile == null) return false;

            profile.ManagerConnectedId = newManagerId;
            await UpdateAsync(profile, cancellationToken);
            return true;
        }

        public async Task<IEnumerable<OrganizationMemberProfile>> GetMembersWithoutManagerAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Where(p => p.ManagerConnectedId == null)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> CheckCircularReferenceAsync(Guid connectedId, Guid proposedManagerId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            if (connectedId == proposedManagerId) return true;
            
            var managerChain = await GetManagerChainAsync(proposedManagerId, organizationId, cancellationToken);
            return managerChain.Any(m => m.ConnectedId == connectedId);
        }
        
        #endregion

        #region 사무실 위치
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByOfficeLocationAsync(string officeLocation, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .Include(p => p.Manager)
                .Where(p => p.OfficeLocation == officeLocation)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<string>> GetAllOfficeLocationsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.OfficeLocation))
                .Select(p => p.OfficeLocation!)
                .Distinct()
                .OrderBy(o => o)
                .ToListAsync(cancellationToken);
        }

        public async Task<Dictionary<string, int>> GetOfficeLocationStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !string.IsNullOrEmpty(p.OfficeLocation))
                .GroupBy(p => p.OfficeLocation!)
                .Select(g => new { Location = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Location, x => x.Count, cancellationToken);
        }

        #endregion

        #region 프로필 관리

        public async Task<OrganizationMemberProfile> UpsertAsync(OrganizationMemberProfile profile, CancellationToken cancellationToken = default)
        {
            var existing = await QueryForOrganization(profile.OrganizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == profile.ConnectedId, cancellationToken);

            if (existing != null)
            {
                existing.JobTitle = profile.JobTitle;
                existing.Department = profile.Department;
                existing.EmployeeId = profile.EmployeeId;
                existing.OfficeLocation = profile.OfficeLocation;
                existing.ManagerConnectedId = profile.ManagerConnectedId;
                await UpdateAsync(existing, cancellationToken);
                return existing;
            }
            else
            {
                profile.CreatedAt = DateTime.UtcNow;
                await AddAsync(profile, cancellationToken);
                return profile;
            }
        }

        public async Task<OrganizationMemberProfile?> UpdateProfileAsync(Guid connectedId, Guid organizationId, Action<OrganizationMemberProfile> updates, CancellationToken cancellationToken = default)
        {
            var profile = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);

            if (profile == null) return null;

            updates(profile);
            await UpdateAsync(profile, cancellationToken);

            return profile;
        }

        public async Task<bool> UpdateEmployeeIdAsync(Guid connectedId, Guid organizationId, string employeeId, CancellationToken cancellationToken = default)
        {
            var profile = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId, cancellationToken);
            if (profile == null) return false;

            profile.EmployeeId = employeeId;
            await UpdateAsync(profile, cancellationToken);

            return true;
        }

        #endregion

        #region 검색 및 필터링

        public async Task<IEnumerable<OrganizationMemberProfile>> SearchAsync(string keyword, Guid organizationId, string[]? searchFields = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).AsNoTracking();
            
            if (string.IsNullOrWhiteSpace(keyword)) return await query.ToListAsync(cancellationToken);

            searchFields ??= new[] { "JobTitle", "Department", "EmployeeId", "OfficeLocation" };

            var predicate = PredicateBuilder.False<OrganizationMemberProfile>();

            foreach (var field in searchFields)
            {
                switch (field.ToLowerInvariant())
                {
                    case "jobtitle":
                        predicate = predicate.Or(p => p.JobTitle != null && p.JobTitle.Contains(keyword));
                        break;
                    case "department":
                        predicate = predicate.Or(p => p.Department != null && p.Department.Contains(keyword));
                        break;
                    case "employeeid":
                        predicate = predicate.Or(p => p.EmployeeId != null && p.EmployeeId.Contains(keyword));
                        break;
                    case "officelocation":
                        predicate = predicate.Or(p => p.OfficeLocation != null && p.OfficeLocation.Contains(keyword));
                        break;
                }
            }

            return await query.Where(predicate).ToListAsync(cancellationToken);
        }

        /// <summary>
        /// [FIXED] BaseRepository의 GetPagedAsync를 호출하도록 수정하여 안정성과 일관성을 확보합니다.
        /// 서비스 계층에서 criteria에 OrganizationId 필터를 포함시켜 호출하는 것을 전제로 합니다.
        /// </summary>
        public async Task<PagedResult<OrganizationMemberProfile>> AdvancedSearchAsync(Expression<Func<OrganizationMemberProfile, bool>> criteria, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default)
        {
            var (items, totalCount) = await GetPagedAsync(
                pageNumber, 
                pageSize, 
                criteria, 
                orderBy: e => e.Department ?? string.Empty, 
                isDescending: false, 
                cancellationToken: cancellationToken);

            return new PagedResult<OrganizationMemberProfile>(items, totalCount, pageNumber, pageSize);
        }

        public async Task<IEnumerable<OrganizationMemberProfile>> GetFilteredAsync(Guid organizationId, string? department = null, string? jobTitle = null, string? officeLocation = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).AsNoTracking();

            if (!string.IsNullOrEmpty(department))
                query = query.Where(p => p.Department == department);

            if (!string.IsNullOrEmpty(jobTitle))
                query = query.Where(p => p.JobTitle == jobTitle);

            if (!string.IsNullOrEmpty(officeLocation))
                query = query.Where(p => p.OfficeLocation == officeLocation);

            return await query
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 일괄 작업

        public async Task<int> BulkCreateAsync(IEnumerable<OrganizationMemberProfile> profiles, CancellationToken cancellationToken = default)
        {
            var profileList = profiles.ToList();
            var now = DateTime.UtcNow;
            foreach(var p in profileList)
            {
                p.CreatedAt = now;
            }
            await AddRangeAsync(profileList, cancellationToken);
            return profileList.Count;
        }

        public async Task<int> BulkUpdateDepartmentAsync(IEnumerable<Guid> connectedIds, Guid organizationId, string newDepartment, CancellationToken cancellationToken = default)
        {
            var idList = connectedIds.ToList();
            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync(cancellationToken);
            
            foreach (var profile in profiles)
            {
                profile.Department = newDepartment;
            }

            await UpdateRangeAsync(profiles, cancellationToken);
            return profiles.Count;
        }

        public async Task<int> BulkAssignManagerAsync(IEnumerable<Guid> connectedIds, Guid organizationId, Guid managerId, CancellationToken cancellationToken = default)
        {
            var idList = connectedIds.ToList();
            idList.Remove(managerId);

            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync(cancellationToken);

            foreach (var profile in profiles)
            {
                profile.ManagerConnectedId = managerId;
            }

            await UpdateRangeAsync(profiles, cancellationToken);
            return profiles.Count;
        }

        public async Task<int> BulkRemoveFromOrganizationAsync(IEnumerable<Guid> connectedIds, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var idList = connectedIds.ToList();
            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync(cancellationToken);

            await DeleteRangeAsync(profiles, cancellationToken);
            return profiles.Count;
        }

        #endregion

        #region 통계 및 분석

        public async Task<OrganizationMemberStatistics> GetStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var profiles = await QueryForOrganization(organizationId).AsNoTracking().ToListAsync(cancellationToken);

            return new OrganizationMemberStatistics
            {
                OrganizationId = organizationId,
                TotalMembers = profiles.Count,
                MembersByDepartment = profiles
                    .Where(p => !string.IsNullOrEmpty(p.Department))
                    .GroupBy(p => p.Department!)
                    .ToDictionary(g => g.Key, g => g.Count()),
                MembersByRole = profiles
                    .Where(p => !string.IsNullOrEmpty(p.JobTitle))
                    .GroupBy(p => p.JobTitle!)
                    .ToDictionary(g => g.Key, g => g.Count()),
                MembersByRegion = profiles
                    .Where(p => !string.IsNullOrEmpty(p.OfficeLocation))
                    .GroupBy(p => p.OfficeLocation!)
                    .ToDictionary(g => g.Key, g => g.Count()),
                GeneratedAt = DateTime.UtcNow
            };
        }

        public async Task<Dictionary<string, double>> GetAverageTeamSizeByDepartmentAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
             return await QueryForOrganization(organizationId)
                .Where(p => p.Department != null && p.ManagerConnectedId != null)
                .GroupBy(p => p.Department!)
                .Select(deptGroup => new 
                {
                    Department = deptGroup.Key,
                    AvgTeamSize = deptGroup
                                    .GroupBy(p => p.ManagerConnectedId)
                                    .Average(managerGroup => managerGroup.Count())
                })
                .ToDictionaryAsync(x => x.Department, x => x.AvgTeamSize, cancellationToken);
        }

        public async Task<Dictionary<Guid, int>> GetDirectReportCountByManagerAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.ManagerConnectedId != null)
                .GroupBy(p => p.ManagerConnectedId!.Value)
                .Select(g => new { ManagerId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.ManagerId, x => x.Count, cancellationToken);
        }

        #endregion

        #region 데이터 정리

        public Task<int> CleanupOrphanedProfilesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // TODO: User 테이블이 구현되면, 해당 테이블과 조인하여 IsDeleted=true인 유저의 프로필을 찾아야 합니다.
            // 현재는 User 엔티티가 이 컨텍스트에 없으므로 실제 구현은 보류합니다.
            // 예시: var orphaned = await _context.OrganizationMemberProfiles.Where(p => p.OrganizationId == organizationId && p.User.IsDeleted)...
            return Task.FromResult(0);
        }

        public async Task<int> CleanupEmptyProfilesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var emptyProfiles = await QueryForOrganization(organizationId)
                .Where(p => string.IsNullOrEmpty(p.JobTitle) &&
                            string.IsNullOrEmpty(p.Department) &&
                            string.IsNullOrEmpty(p.EmployeeId) &&
                            string.IsNullOrEmpty(p.OfficeLocation) &&
                            p.ManagerConnectedId == null)
                .ToListAsync(cancellationToken);

            if (emptyProfiles.Any())
            {
                await DeleteRangeAsync(emptyProfiles, cancellationToken);
                return emptyProfiles.Count;
            }

            return 0;
        }

        #endregion
    }

}

