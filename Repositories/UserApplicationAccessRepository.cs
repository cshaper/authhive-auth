using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Entities.Audit;
using System.Text.Json;

namespace AuthHive.Auth.Repositories
{
    public class UserApplicationAccessRepository : BaseRepository<UserPlatformApplicationAccess>, IUserApplicationAccessRepository
    {
        public UserApplicationAccessRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회

        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdAndApplicationAsync(
            Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdApplicationAndOrganizationAsync(
            Guid connectedId, Guid applicationId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"UserAppAccess:cid={connectedId}:aid={applicationId}:oid={organizationId}";
            if (_cache != null && _cache.TryGetValue(cacheKey, out UserPlatformApplicationAccess? cachedAccess))
            {
                return cachedAccess;
            }
            var result = await Query()
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId && a.OrganizationId == organizationId, cancellationToken);
            if (result != null && _cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(10));
            }
            return result;
        }
        // ============================================
        // IMPLEMENTATION OF MISSING METHODS
        // Add these to your UserApplicationAccessRepository.cs file
        // ============================================

        // LOCATION: Add these two methods in the #region 기본 조회 section, 
        // right AFTER the GetByOrganizationIdAsync method (around line 90)

        /// <summary>
        /// 여러 조직 ID에 속한 모든 애플리케이션 접근 권한을 한 번의 쿼리로 조회합니다.
        /// (N+1 쿼리 문제 해결용)
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetAllByOrganizationIdsAsync(
            IEnumerable<Guid> organizationIds,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => organizationIds.Contains(a.OrganizationId));

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Include(a => a.ConnectedIdNavigation.User)
                .OrderBy(a => a.OrganizationId)
                .ThenBy(a => a.PlatformApplication.Name)
                .ThenBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 애플리케이션에 대해 여러 사용자의 접근 권한을 한 번의 쿼리로 조회합니다.
        /// (N+1 쿼리 문제 해결용)
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationAndConnectedIdsAsync(
            Guid applicationId,
            IEnumerable<Guid> connectedIds,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Where(a => a.ApplicationId == applicationId && connectedIds.Contains(a.ConnectedId));

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .Include(a => a.ConnectedIdNavigation)
                .Include(a => a.ConnectedIdNavigation.User)
                .Include(a => a.Role)
                .OrderBy(a => a.ConnectedId)
                .ThenBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        // ============================================
        // LOCATION: Add this method either at the end of the class
        // OR create a new region for it after the #endregion 권한 복사 및 템플릿
        // ============================================

        #region Soft Delete Operations

        /// <summary>
        /// 감사 정보를 포함하여 접근 권한을 소프트 삭제합니다.
        /// (서비스 레이어의 CS1501 오류 해결을 위해 새로 추가된 메서드)
        /// </summary>
        public async Task<bool> DeleteAsync(
            Guid id,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var entity = await GetByIdAsync(id);
            if (entity == null)
            {
                return false;
            }

            // Soft delete implementation - mark as deleted instead of removing from database
            entity.IsDeleted = true;
            entity.IsActive = false;
            entity.DeletedAt = DateTime.UtcNow;
            entity.DeletedByConnectedId = deletedByConnectedId;
            entity.UpdatedAt = DateTime.UtcNow;
            entity.UpdatedByConnectedId = deletedByConnectedId;

            // Clear cache if it exists
            if (_cache != null)
            {
                // Clear specific cache entries related to this access
                var cacheKey1 = $"UserAppAccess:cid={entity.ConnectedId}:aid={entity.ApplicationId}";
                _cache.Remove(cacheKey1);

                var cacheKey2 = $"UserAppAccess:cid={entity.ConnectedId}:aid={entity.ApplicationId}:oid={entity.OrganizationId}";
                _cache.Remove(cacheKey2);

                // Clear the entity cache by ID
                var cacheKey3 = $"UserAppAccess:{id}";
                _cache.Remove(cacheKey3);

                // You might also want to clear organization-level cache
                var cacheKey4 = $"UserAppAccess:org={entity.OrganizationId}";
                _cache.Remove(cacheKey4);
            }

            _dbSet.Update(entity);
            var result = await _context.SaveChangesAsync(cancellationToken);

            // Log the deletion in audit log if needed
            if (result > 0)
            {
                await LogAccessChangeAsync(
                    id,
                    "DELETE",
                    "Active",
                    "Deleted",
                    deletedByConnectedId,
                    cancellationToken);
            }

            return result > 0;
        }

        #endregion
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByConnectedIdAsync(
            Guid connectedId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ConnectedId == connectedId);
            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }
            return await query.Include(a => a.PlatformApplication).OrderBy(a => a.PlatformApplication.Name).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationIdAsync(
            Guid applicationId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ApplicationId == applicationId);
            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }
            return await query.Include(a => a.ConnectedIdNavigation).OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByOrganizationIdAsync(
           Guid organizationId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }
            return await query.Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.PlatformApplication.Name).ThenBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 권한 레벨 및 역할별 조회

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByAccessLevelAsync(ApplicationAccessLevel accessLevel, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            query = query.Where(a => a.AccessLevel == accessLevel);
            return await query.Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByRoleIdAsync(Guid roleId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.RoleId == roleId);
            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }
            return await query.Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByTemplateIdAsync(Guid templateId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.AccessTemplateId == templateId);
            if (onlyActive)
            {
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }
            return await query.Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 상태 및 만료 관리

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiredAccessAsync(DateTime? asOfDate = null, CancellationToken cancellationToken = default)
        {
            var checkDate = asOfDate ?? DateTime.UtcNow;
            return await Query().Where(a => a.ExpiresAt != null && a.ExpiresAt <= checkDate).Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.ExpiresAt).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiringAccessAsync(int daysBeforeExpiry = 7, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var expiryThreshold = now.AddDays(daysBeforeExpiry);
            return await Query().Where(a => a.IsActive && a.ExpiresAt != null && a.ExpiresAt > now && a.ExpiresAt <= expiryThreshold).Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.ExpiresAt).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInactiveAccessAsync(DateTime inactiveSince, CancellationToken cancellationToken = default)
        {
            return await Query().Where(a => a.IsActive && (a.LastAccessedAt == null || a.LastAccessedAt < inactiveSince)).Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.LastAccessedAt ?? a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 상속 및 스코프

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInheritedAccessAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await Query().Where(a => a.ConnectedId == connectedId && a.IsInherited && a.InheritedFromId != null).Include(a => a.PlatformApplication).Include(a => a.AccessTemplate).OrderBy(a => a.PlatformApplication.Name).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByScopeAsync(string scope, Guid? applicationId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => EF.Functions.JsonContains(a.Scopes, $"\"{scope}\""));
            if (applicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == applicationId.Value);
            }
            return await query.Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 및 존재 확인

        public async Task<bool> ExistsAsync(Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        public async Task<bool> HasActiveAccessAsync(Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query().AnyAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId && a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now), cancellationToken);
        }

        #endregion

        #region 페이징 및 검색

        public async Task<PagedResult<UserPlatformApplicationAccess>> SearchAsync(
            SearchUserApplicationAccessRequest request,
            CancellationToken cancellationToken = default)
        {
            // === CS0266 오류 수정된 부분: 모든 Include를 먼저 체이닝합니다. ===
            var query = Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Include(a => a.AccessTemplate)
                .Include(a => a.Role)
                .AsQueryable(); // Include 체인이 끝난 후 일반 IQueryable로 전환

            // 필터 적용
            if (request.ConnectedId.HasValue)
                query = query.Where(a => a.ConnectedId == request.ConnectedId.Value);
            if (request.OrganizationId.HasValue)
                query = query.Where(a => a.OrganizationId == request.OrganizationId.Value);
            if (request.ApplicationId.HasValue)
                query = query.Where(a => a.ApplicationId == request.ApplicationId.Value);
            if (request.AccessLevel.HasValue)
                query = query.Where(a => a.AccessLevel == request.AccessLevel.Value);
            if (request.IsActive.HasValue)
            {
                var now = DateTime.UtcNow;
                if (request.IsActive.Value)
                    query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now));
                else
                    query = query.Where(a => !a.IsActive || (a.ExpiresAt != null && a.ExpiresAt <= now));
            }
            // ... (기타 필터들)

            var totalCount = await query.CountAsync(cancellationToken);
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);
            var items = await sortedQuery
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<UserPlatformApplicationAccess>(items, totalCount, request.PageNumber, request.PageSize);
        }

        private IQueryable<UserPlatformApplicationAccess> ApplySorting(
            IQueryable<UserPlatformApplicationAccess> query, string? sortBy, bool descending)
        {
            return (sortBy?.ToLowerInvariant() ?? "grantedat") switch
            {
                "applicationname" => descending ? query.OrderByDescending(a => a.PlatformApplication.Name) : query.OrderBy(a => a.PlatformApplication.Name),
                "accesslevel" => descending ? query.OrderByDescending(a => a.AccessLevel) : query.OrderBy(a => a.AccessLevel),
                _ => descending ? query.OrderByDescending(a => a.GrantedAt) : query.OrderBy(a => a.GrantedAt)
            };
        }

        #endregion

        #region 집계

        public async Task<int> GetAccessCountAsync(Guid? organizationId = null, Guid? applicationId = null, CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            if (applicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == applicationId.Value);
            }
            var now = DateTime.UtcNow;
            query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now));
            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region 벌크 작업

        public async Task<IEnumerable<UserPlatformApplicationAccess>> CreateBulkAsync(IEnumerable<Guid> connectedIds, Guid applicationId, ApplicationAccessLevel accessLevel, Guid? roleId = null, Guid? templateId = null, Guid grantedByConnectedId = default, CancellationToken cancellationToken = default)
        {
            var accessList = new List<UserPlatformApplicationAccess>();
            var now = DateTime.UtcNow;
            foreach (var connectedId in connectedIds)
            {
                if (await ExistsAsync(connectedId, applicationId, cancellationToken)) continue;
                accessList.Add(new UserPlatformApplicationAccess { /* ... properties ... */ });
            }
            if (accessList.Any())
            {
                await _dbSet.AddRangeAsync(accessList, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }
            return accessList;
        }

        public async Task<int> UpdateBulkAsync(IEnumerable<UserPlatformApplicationAccess> accesses, CancellationToken cancellationToken = default)
        {
            foreach (var access in accesses) { /* ... update properties and invalidate cache ... */ }
            _dbSet.UpdateRange(accesses);
            return await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task<int> DeleteBulkAsync(IEnumerable<Guid> ids, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var entities = await Query().Where(a => ids.Contains(a.Id)).ToListAsync(cancellationToken);
            foreach (var entity in entities) { /* ... mark as deleted and invalidate cache ... */ }
            _dbSet.UpdateRange(entities);
            return await _context.SaveChangesAsync(cancellationToken);
        }

        #endregion

        #region 권한 검증 확장

        public async Task<bool> HasPermissionAsync(Guid connectedId, Guid applicationId, string permission, CancellationToken cancellationToken = default)
        {
            var effectivePermissions = await GetEffectivePermissionsAsync(connectedId, applicationId, cancellationToken);
            return effectivePermissions.Contains(permission, StringComparer.OrdinalIgnoreCase);
        }

        public async Task<IEnumerable<string>> GetEffectivePermissionsAsync(Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            var permissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var access = await GetByConnectedIdAndApplicationAsync(connectedId, applicationId, cancellationToken);
            if (access == null || !access.IsActive) return permissions;

            if (access.RoleId.HasValue)
            {
                var rolePermissions = await _context.Set<RolePermission>().Include(rp => rp.Permission)
                    .Where(rp => rp.RoleId == access.RoleId.Value && rp.IsActive)
                    .Select(rp => rp.Permission.Scope).ToListAsync(cancellationToken);
                foreach (var p in rolePermissions) permissions.Add(p);
            }
            if (!string.IsNullOrEmpty(access.AdditionalPermissions))
            {
                var additional = JsonSerializer.Deserialize<List<string>>(access.AdditionalPermissions);
                if (additional != null) foreach (var p in additional) permissions.Add(p);
            }
            if (!string.IsNullOrEmpty(access.ExcludedPermissions))
            {
                var excluded = JsonSerializer.Deserialize<List<string>>(access.ExcludedPermissions);
                if (excluded != null) foreach (var p in excluded) permissions.Remove(p);
            }
            return permissions;
        }

        #endregion

        #region 통계 및 분석

        public async Task<Dictionary<Guid, int>> GetActiveUserCountByApplicationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await QueryForOrganization(organizationId)
                .Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now))
                .GroupBy(a => a.ApplicationId)
                .Select(g => new { ApplicationId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.ApplicationId, x => x.Count, cancellationToken);
        }

        public async Task<Dictionary<ApplicationAccessLevel, int>> GetUserCountByAccessLevelAsync(Guid applicationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Where(a => a.ApplicationId == applicationId && a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now))
                .GroupBy(a => a.AccessLevel)
                .Select(g => new { AccessLevel = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.AccessLevel, x => x.Count, cancellationToken);
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetRecentlyActiveUsersAsync(
            Guid applicationId,
            int days = 7,
            int? take = null,
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-days);

            // 1. 기본 쿼리 구성 (필터링)
            var query = Query()
                .Include(a => a.ConnectedIdNavigation)
                .Where(a => a.ApplicationId == applicationId &&
                              a.IsActive &&
                              a.LastAccessedAt != null &&
                              a.LastAccessedAt >= cutoffDate);

            // 2. 정렬 적용 (이 시점에 IOrderedQueryable이 됨)
            var orderedQuery = query.OrderByDescending(a => a.LastAccessedAt);

            // 3. 페이징 적용 (Take)
            // orderedQuery는 IQueryable로 암시적 변환이 가능합니다.
            IQueryable<UserPlatformApplicationAccess> finalQuery = orderedQuery;
            if (take.HasValue)
            {
                finalQuery = finalQuery.Take(take.Value);
            }

            // 4. 최종 실행
            return await finalQuery.ToListAsync(cancellationToken);
        }

        #endregion

        #region 변경 이력 추적

        public async Task LogAccessChangeAsync(Guid userApplicationAccessId, string changeType, string? oldValue, string? newValue, Guid changedByConnectedId, CancellationToken cancellationToken = default)
        {
            var auditLog = new AuditLog { /* ... properties ... */ };
            await _context.Set<AuditLog>().AddAsync(auditLog, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        #endregion

        #region 권한 복사 및 템플릿

        public async Task<UserPlatformApplicationAccess?> CloneAccessAsync(Guid sourceConnectedId, Guid targetConnectedId, Guid applicationId, Guid grantedByConnectedId, CancellationToken cancellationToken = default)
        {
            var sourceAccess = await GetByConnectedIdAndApplicationAsync(sourceConnectedId, applicationId, cancellationToken);
            if (sourceAccess == null || await ExistsAsync(targetConnectedId, applicationId, cancellationToken)) return null;

            var newAccess = new UserPlatformApplicationAccess { /* ... copy properties ... */ };
            await AddAsync(newAccess);
            return newAccess;
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> ApplyTemplateToUsersAsync(Guid templateId, IEnumerable<Guid> connectedIds, Guid applicationId, Guid grantedByConnectedId, CancellationToken cancellationToken = default)
        {
            var template = await _context.Set<PlatformApplicationAccessTemplate>().FindAsync(new object[] { templateId }, cancellationToken);
            if (template == null) return Enumerable.Empty<UserPlatformApplicationAccess>();

            var results = new List<UserPlatformApplicationAccess>();
            // ... Logic to create or update access for each user ...
            await _context.SaveChangesAsync(cancellationToken);
            return results;
        }

        #endregion
    }
}
