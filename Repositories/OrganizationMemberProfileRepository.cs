using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 멤버 프로필 Repository 구현체 - AuthHive v15
    /// 조직 구성원의 프로필 정보를 관리하는 데이터 접근 계층
    /// </summary>
    public class OrganizationMemberProfileRepository : BaseRepository<OrganizationMemberProfile>, IOrganizationMemberProfileRepository
    {
        public OrganizationMemberProfileRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회

        /// <summary>
        /// ConnectedId로 멤버 프로필 조회
        /// </summary>
        public async Task<OrganizationMemberProfile?> GetByConnectedIdAsync(
            Guid connectedId,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .FirstOrDefaultAsync(p => p.ConnectedId == connectedId);
        }

        /// <summary>
        /// 직원 ID로 멤버 프로필 조회
        /// </summary>
        public async Task<OrganizationMemberProfile?> GetByEmployeeIdAsync(
            string employeeId,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .FirstOrDefaultAsync(p => p.EmployeeId == employeeId);
        }

        /// <summary>
        /// 여러 ConnectedId로 프로필 일괄 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds,
            Guid organizationId)
        {
            var idList = connectedIds.ToList();
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync();
        }

        /// <summary>
        /// 프로필 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(Guid connectedId, Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .AnyAsync(p => p.ConnectedId == connectedId);
        }

        #endregion

        #region 부서 관련

        /// <summary>
        /// 부서별 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByDepartmentAsync(
            string department,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .Where(p => p.Department == department)
                .OrderBy(p => p.JobTitle)
                .ThenBy(p => p.EmployeeId)
                .ToListAsync();
        }

        /// <summary>
        /// 모든 부서 목록 조회
        /// </summary>
        public async Task<IEnumerable<string>> GetAllDepartmentsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.Department != null)
                .Select(p => p.Department!)
                .Distinct()
                .OrderBy(d => d)
                .ToListAsync();
        }

        /// <summary>
        /// 부서별 멤버 수 통계
        /// </summary>
        public async Task<Dictionary<string, int>> GetDepartmentStatisticsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.Department != null)
                .GroupBy(p => p.Department!)
                .Select(g => new { Department = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Department, x => x.Count);
        }

        /// <summary>
        /// 부서 변경
        /// </summary>
        public async Task<bool> ChangeDepartmentAsync(
            Guid connectedId,
            Guid organizationId,
            string newDepartment)
        {
            var profile = await GetByConnectedIdAsync(connectedId, organizationId);
            if (profile == null)
                return false;

            profile.Department = newDepartment;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            await _context.SaveChangesAsync();

            return true;
        }

        #endregion

        #region 직책 관련

        /// <summary>
        /// 직책별 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByJobTitleAsync(
            string jobTitle,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .Where(p => p.JobTitle == jobTitle)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.EmployeeId)
                .ToListAsync();
        }

        /// <summary>
        /// 모든 직책 목록 조회
        /// </summary>
        public async Task<IEnumerable<string>> GetAllJobTitlesAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.JobTitle != null)
                .Select(p => p.JobTitle!)
                .Distinct()
                .OrderBy(j => j)
                .ToListAsync();
        }

        /// <summary>
        /// 직책별 멤버 수 통계
        /// </summary>
        public async Task<Dictionary<string, int>> GetJobTitleStatisticsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.JobTitle != null)
                .GroupBy(p => p.JobTitle!)
                .Select(g => new { JobTitle = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.JobTitle, x => x.Count);
        }

        /// <summary>
        /// 직책 업데이트
        /// </summary>
        public async Task<bool> UpdateJobTitleAsync(
            Guid connectedId,
            Guid organizationId,
            string newJobTitle)
        {
            var profile = await GetByConnectedIdAsync(connectedId, organizationId);
            if (profile == null)
                return false;

            profile.JobTitle = newJobTitle;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            await _context.SaveChangesAsync();

            return true;
        }

        #endregion

        #region 관리자 계층 구조

        /// <summary>
        /// 관리자의 직속 부하 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetDirectReportsAsync(
            Guid managerConnectedId,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Where(p => p.ManagerConnectedId == managerConnectedId)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync();
        }

        /// <summary>
        /// 관리자 체인 조회 (상위 관리자들)
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetManagerChainAsync(
            Guid connectedId,
            Guid organizationId)
        {
            var chain = new List<OrganizationMemberProfile>();
            var currentProfile = await GetByConnectedIdAsync(connectedId, organizationId);

            while (currentProfile?.ManagerConnectedId != null)
            {
                var manager = await GetByConnectedIdAsync(currentProfile.ManagerConnectedId.Value, organizationId);
                if (manager == null)
                    break;

                chain.Add(manager);

                // 순환 참조 방지
                if (chain.Any(p => p.ConnectedId == manager.ConnectedId))
                    break;

                currentProfile = manager;
            }

            return chain;
        }

        /// <summary>
        /// 전체 조직 계층 구조 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetOrganizationHierarchyAsync(
            Guid organizationId,
            Guid? rootManagerId = null)
        {
            if (rootManagerId.HasValue)
            {
                // 특정 관리자부터 시작
                return await GetHierarchyRecursive(rootManagerId.Value, organizationId);
            }
            else
            {
                // 최상위 관리자들 찾기 (관리자가 없는 사람들)
                var topManagers = await QueryForOrganization(organizationId)
                    .Include(p => p.ConnectedIdNavigation)
                    .Where(p => p.ManagerConnectedId == null)
                    .ToListAsync();

                var result = new List<OrganizationMemberProfile>();
                foreach (var manager in topManagers)
                {
                    result.Add(manager);
                    result.AddRange(await GetHierarchyRecursive(manager.ConnectedId, organizationId));
                }

                return result;
            }
        }

        /// <summary>
        /// 재귀적으로 계층 구조 조회
        /// </summary>
        private async Task<IEnumerable<OrganizationMemberProfile>> GetHierarchyRecursive(
            Guid managerId,
            Guid organizationId,
            HashSet<Guid>? visited = null)
        {
            visited ??= new HashSet<Guid>();

            // 순환 참조 방지
            if (!visited.Add(managerId))
                return Enumerable.Empty<OrganizationMemberProfile>();

            var directReports = await GetDirectReportsAsync(managerId, organizationId);
            var result = new List<OrganizationMemberProfile>(directReports);

            foreach (var report in directReports)
            {
                result.AddRange(await GetHierarchyRecursive(report.ConnectedId, organizationId, visited));
            }

            return result;
        }

        /// <summary>
        /// 관리자 변경
        /// </summary>
        public async Task<bool> ChangeManagerAsync(
            Guid connectedId,
            Guid organizationId,
            Guid? newManagerId)
        {
            // 순환 참조 확인
            if (newManagerId.HasValue && await CheckCircularReferenceAsync(connectedId, newManagerId.Value, organizationId))
                return false;

            var profile = await GetByConnectedIdAsync(connectedId, organizationId);
            if (profile == null)
                return false;

            profile.ManagerConnectedId = newManagerId;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// 관리자가 없는 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetMembersWithoutManagerAsync(
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Where(p => p.ManagerConnectedId == null)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync();
        }

        /// <summary>
        /// 순환 참조 확인
        /// </summary>
        public async Task<bool> CheckCircularReferenceAsync(
            Guid connectedId,
            Guid proposedManagerId,
            Guid organizationId)
        {
            // 자기 자신을 관리자로 설정하려는 경우
            if (connectedId == proposedManagerId)
                return true;

            // 제안된 관리자의 상위 체인에 자신이 있는지 확인
            var managerChain = await GetManagerChainAsync(proposedManagerId, organizationId);
            return managerChain.Any(m => m.ConnectedId == connectedId);
        }

        #endregion

        #region 사무실 위치

        /// <summary>
        /// 사무실 위치별 멤버 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetByOfficeLocationAsync(
            string officeLocation,
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager)
                .Where(p => p.OfficeLocation == officeLocation)
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync();
        }

        /// <summary>
        /// 모든 사무실 위치 목록
        /// </summary>
        public async Task<IEnumerable<string>> GetAllOfficeLocationsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.OfficeLocation != null)
                .Select(p => p.OfficeLocation!)
                .Distinct()
                .OrderBy(o => o)
                .ToListAsync();
        }

        /// <summary>
        /// 사무실 위치별 통계
        /// </summary>
        public async Task<Dictionary<string, int>> GetOfficeLocationStatisticsAsync(Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.OfficeLocation != null)
                .GroupBy(p => p.OfficeLocation!)
                .Select(g => new { Location = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Location, x => x.Count);
        }

        #endregion

        #region 프로필 관리

        /// <summary>
        /// 프로필 생성 또는 업데이트
        /// </summary>
        public async Task<OrganizationMemberProfile> UpsertAsync(OrganizationMemberProfile profile)
        {
            var existing = await GetByConnectedIdAsync(profile.ConnectedId, profile.OrganizationId);

            if (existing != null)
            {
                // 업데이트
                existing.JobTitle = profile.JobTitle;
                existing.Department = profile.Department;
                existing.EmployeeId = profile.EmployeeId;
                existing.OfficeLocation = profile.OfficeLocation;
                existing.ManagerConnectedId = profile.ManagerConnectedId;
                existing.UpdatedAt = DateTime.UtcNow;

                await UpdateAsync(existing);
                await _context.SaveChangesAsync();
                return existing;
            }
            else
            {
                // 생성
                profile.CreatedAt = DateTime.UtcNow;
                await AddAsync(profile);
                await _context.SaveChangesAsync();
                return profile;
            }
        }

        /// <summary>
        /// 프로필 일괄 업데이트
        /// </summary>
        public async Task<OrganizationMemberProfile?> UpdateProfileAsync(
            Guid connectedId,
            Guid organizationId,
            Action<OrganizationMemberProfile> updates)
        {
            var profile = await GetByConnectedIdAsync(connectedId, organizationId);
            if (profile == null)
                return null;

            updates(profile);
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            await _context.SaveChangesAsync();

            return profile;
        }

        /// <summary>
        /// 직원 ID 업데이트
        /// </summary>
        public async Task<bool> UpdateEmployeeIdAsync(
            Guid connectedId,
            Guid organizationId,
            string employeeId)
        {
            var profile = await GetByConnectedIdAsync(connectedId, organizationId);
            if (profile == null)
                return false;

            profile.EmployeeId = employeeId;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            await _context.SaveChangesAsync();

            return true;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 키워드로 프로필 검색
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> SearchAsync(
            string keyword,
            Guid organizationId,
            string[]? searchFields = null)
        {
            var query = QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Include(p => p.Manager);

            // 검색 필드가 지정되지 않으면 모든 필드 검색
            if (searchFields == null || searchFields.Length == 0)
            {
                searchFields = new[] { "JobTitle", "Department", "EmployeeId", "OfficeLocation" };
            }

            var predicate = PredicateBuilder.False<OrganizationMemberProfile>();

            foreach (var field in searchFields)
            {
                switch (field.ToLower())
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

            return await query.Where(predicate).ToListAsync();
        }

        /// <summary>
        /// 고급 검색
        /// </summary>
        /// <summary>
        /// 고급 검색
        /// </summary>
        public async Task<PagedResult<OrganizationMemberProfile>> AdvancedSearchAsync(
            Expression<Func<OrganizationMemberProfile, bool>> criteria,
            int pageNumber = 1,
            int pageSize = 50)
        {
            IQueryable<OrganizationMemberProfile> query = Query();
            query = query.Include(p => p.ConnectedIdNavigation);
            query = query.Include(p => p.Manager);
            query = query.Where(criteria);

            var totalCount = await query.CountAsync();

            var items = await query
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new PagedResult<OrganizationMemberProfile>(items, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 필터링된 프로필 조회
        /// </summary>

        /// <summary>
        /// 필터링된 프로필 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationMemberProfile>> GetFilteredAsync(
            Guid organizationId,
            string? department = null,
            string? jobTitle = null,
            string? officeLocation = null)
        {
            IQueryable<OrganizationMemberProfile> query = QueryForOrganization(organizationId);
            query = query.Include(p => p.ConnectedIdNavigation);
            query = query.Include(p => p.Manager);

            if (!string.IsNullOrEmpty(department))
                query = query.Where(p => p.Department == department);

            if (!string.IsNullOrEmpty(jobTitle))
                query = query.Where(p => p.JobTitle == jobTitle);

            if (!string.IsNullOrEmpty(officeLocation))
                query = query.Where(p => p.OfficeLocation == officeLocation);

            return await query
                .OrderBy(p => p.Department)
                .ThenBy(p => p.JobTitle)
                .ToListAsync();
        }
        #endregion

        #region 일괄 작업

        /// <summary>
        /// 프로필 일괄 생성
        /// </summary>
        public async Task<int> BulkCreateAsync(IEnumerable<OrganizationMemberProfile> profiles)
        {
            var profileList = profiles.ToList();
            var now = DateTime.UtcNow;

            foreach (var profile in profileList)
            {
                profile.CreatedAt = now;
            }

            await AddRangeAsync(profileList);
            return await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 부서 일괄 업데이트
        /// </summary>
        public async Task<int> BulkUpdateDepartmentAsync(
            IEnumerable<Guid> connectedIds,
            Guid organizationId,
            string newDepartment)
        {
            var idList = connectedIds.ToList();
            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync();

            var now = DateTime.UtcNow;
            foreach (var profile in profiles)
            {
                profile.Department = newDepartment;
                profile.UpdatedAt = now;
            }

            await UpdateRangeAsync(profiles);
            return await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 관리자 일괄 할당
        /// </summary>
        public async Task<int> BulkAssignManagerAsync(
            IEnumerable<Guid> connectedIds,
            Guid organizationId,
            Guid managerId)
        {
            var idList = connectedIds.ToList();

            // 순환 참조 방지: 관리자 자신은 제외
            idList.Remove(managerId);

            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync();

            var now = DateTime.UtcNow;
            foreach (var profile in profiles)
            {
                profile.ManagerConnectedId = managerId;
                profile.UpdatedAt = now;
            }

            await UpdateRangeAsync(profiles);
            return await _context.SaveChangesAsync();
        }

        /// <summary>
        /// 조직에서 프로필 일괄 제거
        /// </summary>
        public async Task<int> BulkRemoveFromOrganizationAsync(
            IEnumerable<Guid> connectedIds,
            Guid organizationId)
        {
            var idList = connectedIds.ToList();
            var profiles = await QueryForOrganization(organizationId)
                .Where(p => idList.Contains(p.ConnectedId))
                .ToListAsync();

            await DeleteRangeAsync(profiles);
            return await _context.SaveChangesAsync();
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 조직 멤버 통계
        /// </summary>

        public async Task<OrganizationMemberStatistics> GetStatisticsAsync(Guid organizationId)
        {
            var profiles = await QueryForOrganization(organizationId).ToListAsync();

            return new OrganizationMemberStatistics
            {
                OrganizationId = organizationId,
                TotalMembers = profiles.Count,

                // 부서별 프로필 수
                MembersByDepartment = profiles
                    .Where(p => !string.IsNullOrEmpty(p.Department))
                    .GroupBy(p => p.Department!)
                    .ToDictionary(g => g.Key, g => g.Count()),

                // 직책을 역할(Role)로 매핑
                MembersByRole = profiles
                    .Where(p => !string.IsNullOrEmpty(p.JobTitle))
                    .GroupBy(p => p.JobTitle!)
                    .ToDictionary(g => g.Key, g => g.Count()),

                // 오피스 위치를 지역(Region)으로 매핑
                MembersByRegion = profiles
                    .Where(p => !string.IsNullOrEmpty(p.OfficeLocation))
                    .GroupBy(p => p.OfficeLocation!)
                    .ToDictionary(g => g.Key, g => g.Count()),

                GeneratedAt = DateTime.UtcNow
            };
        }

        /// <summary>
        /// 부서별 평균 팀 크기
        /// </summary>
        public async Task<Dictionary<string, double>> GetAverageTeamSizeByDepartmentAsync(
            Guid organizationId)
        {
            var profiles = await QueryForOrganization(organizationId)
                .Where(p => p.Department != null)
                .ToListAsync();

            var managersByDept = profiles
                .Where(p => p.ManagerConnectedId != null)
                .GroupBy(p => p.Department!)
                .ToDictionary(
                    g => g.Key,
                    g => g.GroupBy(p => p.ManagerConnectedId).Average(mg => mg.Count())
                );

            return managersByDept;
        }

        /// <summary>
        /// 관리자별 직속 부하 수
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetDirectReportCountByManagerAsync(
            Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.ManagerConnectedId != null)
                .GroupBy(p => p.ManagerConnectedId!.Value)
                .Select(g => new { ManagerId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.ManagerId, x => x.Count);
        }

        #endregion

        #region 데이터 정리

        /// <summary>
        /// 고아 프로필 정리 (ConnectedId가 삭제된 프로필)
        /// </summary>
        public async Task<int> CleanupOrphanedProfilesAsync(Guid organizationId)
        {
            // ConnectedId 테이블과 조인하여 존재하지 않는 프로필 찾기
            var orphanedProfiles = await QueryForOrganization(organizationId)
                .Include(p => p.ConnectedIdNavigation)
                .Where(p => p.ConnectedIdNavigation == null || p.ConnectedIdNavigation.IsDeleted)
                .ToListAsync();

            if (orphanedProfiles.Any())
            {
                await DeleteRangeAsync(orphanedProfiles);
                return await _context.SaveChangesAsync();
            }

            return 0;
        }

        /// <summary>
        /// 빈 프로필 정리 (필수 정보가 없는 프로필)
        /// </summary>
        public async Task<int> CleanupEmptyProfilesAsync(Guid organizationId)
        {
            // 모든 필드가 null인 프로필
            var emptyProfiles = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.JobTitle == null &&
                    p.Department == null &&
                    p.EmployeeId == null &&
                    p.OfficeLocation == null &&
                    p.ManagerConnectedId == null)
                .ToListAsync();

            if (emptyProfiles.Any())
            {
                await DeleteRangeAsync(emptyProfiles);
                return await _context.SaveChangesAsync();
            }

            return 0;
        }

        #endregion
    }

    /// <summary>
    /// PredicateBuilder for dynamic query building
    /// </summary>
    internal static class PredicateBuilder
    {
        public static Expression<Func<T, bool>> True<T>() { return f => true; }
        public static Expression<Func<T, bool>> False<T>() { return f => false; }

        public static Expression<Func<T, bool>> Or<T>(
            this Expression<Func<T, bool>> expr1,
            Expression<Func<T, bool>> expr2)
        {
            var parameter = Expression.Parameter(typeof(T));
            var leftVisitor = new ReplaceExpressionVisitor(expr1.Parameters[0], parameter);
            var left = leftVisitor.Visit(expr1.Body);
            var rightVisitor = new ReplaceExpressionVisitor(expr2.Parameters[0], parameter);
            var right = rightVisitor.Visit(expr2.Body);

            // null 체크 추가
            if (left == null || right == null)
            {
                throw new InvalidOperationException("Expression visit returned null");
            }

            return Expression.Lambda<Func<T, bool>>(
                Expression.OrElse(left, right), parameter);
        }

        private class ReplaceExpressionVisitor : ExpressionVisitor
        {
            private readonly Expression _oldValue;
            private readonly Expression _newValue;

            public ReplaceExpressionVisitor(Expression oldValue, Expression newValue)
            {
                _oldValue = oldValue;
                _newValue = newValue;
            }

            public override Expression? Visit(Expression? node)
            {
                return node == _oldValue ? _newValue : base.Visit(node);
            }
        }
    }
}