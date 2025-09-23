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
using AuthHive.Auth.Services.Context;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 애플리케이션 접근 권한 Repository 구현체 - AuthHive v15
    /// BaseRepository를 상속받아 기본 CRUD와 캐싱을 활용하고,
    /// IUserApplicationAccessRepository의 특화된 메서드들을 구현합니다.
    /// </summary>
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

        /// <summary>
        /// ConnectedId와 ApplicationId로 접근 권한 조회
        /// </summary>
        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdAndApplicationAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            // 캐시 키 생성
            if (_cache != null)
            {
                var cacheKey = $"UserAppAccess:{connectedId}:{applicationId}";
                if (_cache.TryGetValue(cacheKey, out UserPlatformApplicationAccess? cached))
                {
                    return cached;
                }
            }

            var result = await Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.AccessTemplate)
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a =>
                    a.ConnectedId == connectedId &&
                    a.ApplicationId == applicationId,
                    cancellationToken);

            // 캐시 저장
            if (result != null && _cache != null)
            {
                var cacheKey = $"UserAppAccess:{connectedId}:{applicationId}";
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(15));
            }

            return result;
        }

        /// <summary>
        /// ConnectedId의 모든 애플리케이션 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByConnectedIdAsync(
            Guid connectedId,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.AccessTemplate)
                .Include(a => a.Role)
                .Where(a => a.ConnectedId == connectedId);

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .OrderBy(a => a.PlatformApplication.Name)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// Application의 모든 사용자 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationIdAsync(
            Guid applicationId,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Include(a => a.ConnectedIdNavigation)
                .Include(a => a.AccessTemplate)
                .Include(a => a.Role)
                .Where(a => a.ApplicationId == applicationId);

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직의 모든 애플리케이션 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByOrganizationIdAsync(
           Guid organizationId,
           bool onlyActive = true,
           CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            query = query.Include(a => a.PlatformApplication);
            query = query.Include(a => a.ConnectedIdNavigation);
            query = query.Include(a => a.AccessTemplate);
            query = query.Include(a => a.Role);

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .OrderBy(a => a.PlatformApplication.Name)
                .ThenBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 권한 레벨 및 역할별 조회

        /// <summary>
        /// 특정 접근 수준의 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByAccessLevelAsync(
            ApplicationAccessLevel accessLevel,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation);

            query = query.Where(a => a.AccessLevel == accessLevel);

            return await query
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 역할을 가진 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByRoleIdAsync(
            Guid roleId,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Where(a => a.RoleId == roleId);

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 템플릿을 사용하는 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByTemplateIdAsync(
            Guid templateId,
            bool onlyActive = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Where(a => a.AccessTemplateId == templateId);

            if (onlyActive)
            {
                query = query.Where(a => a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));
            }

            return await query
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 상태 및 만료 관리

        /// <summary>
        /// 만료된 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiredAccessAsync(
            DateTime? asOfDate = null,
            CancellationToken cancellationToken = default)
        {
            var checkDate = asOfDate ?? DateTime.UtcNow;

            return await Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Where(a => a.ExpiresAt != null && a.ExpiresAt <= checkDate)
                .OrderBy(a => a.ExpiresAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료 예정 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiringAccessAsync(
            int daysBeforeExpiry = 7,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var expiryThreshold = now.AddDays(daysBeforeExpiry);

            return await Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Where(a =>
                    a.IsActive &&
                    a.ExpiresAt != null &&
                    a.ExpiresAt > now &&
                    a.ExpiresAt <= expiryThreshold)
                .OrderBy(a => a.ExpiresAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 비활성 접근 권한 조회 (LastAccessedAt 기준)
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInactiveAccessAsync(
            DateTime inactiveSince,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Where(a =>
                    a.IsActive &&
                    (a.LastAccessedAt == null || a.LastAccessedAt < inactiveSince))
                .OrderBy(a => a.LastAccessedAt ?? a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 상속 및 스코프

        /// <summary>
        /// 상속된 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInheritedAccessAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.AccessTemplate)
                .Where(a =>
                    a.ConnectedId == connectedId &&
                    a.IsInherited &&
                    a.InheritedFromId != null)
                .OrderBy(a => a.PlatformApplication.Name)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 스코프를 가진 접근 권한 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByScopeAsync(
            string scope,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query();
            query = query.Include(a => a.PlatformApplication);
            query = query.Include(a => a.ConnectedIdNavigation);

            // JSON 배열 내 스코프 검색 (PostgreSQL JSONB 쿼리)
            query = query.Where(a =>
                EF.Functions.JsonContains(a.Scopes, $"\"{scope}\""));

            if (applicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == applicationId.Value);
            }

            return await query
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 및 존재 확인

        /// <summary>
        /// 접근 권한 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .AnyAsync(a =>
                    a.ConnectedId == connectedId &&
                    a.ApplicationId == applicationId,
                    cancellationToken);
        }

        /// <summary>
        /// 활성 접근 권한 존재 여부 확인
        /// </summary>
        public async Task<bool> HasActiveAccessAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await Query()
                .AnyAsync(a =>
                    a.ConnectedId == connectedId &&
                    a.ApplicationId == applicationId &&
                    a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > now),
                    cancellationToken);
        }

        #endregion

        #region 페이징 및 검색

        /// <summary>
        /// 접근 권한 검색
        /// </summary>
        public async Task<PagedResult<UserPlatformApplicationAccess>> SearchAsync(
            SearchUserApplicationAccessRequest request,
            CancellationToken cancellationToken = default)
        {
            IQueryable<UserPlatformApplicationAccess> query = Query();

            // Include 각각 별도로 적용
            query = query.Include(a => a.PlatformApplication);
            query = query.Include(a => a.ConnectedIdNavigation);
            query = query.Include(a => a.AccessTemplate);
            query = query.Include(a => a.Role);

            // 필터 적용
            if (request.ConnectedId.HasValue)
            {
                query = query.Where(a => a.ConnectedId == request.ConnectedId.Value);
            }

            if (request.OrganizationId.HasValue)
            {
                query = query.Where(a => a.OrganizationId == request.OrganizationId.Value);
            }

            if (request.ApplicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == request.ApplicationId.Value);
            }

            if (request.AccessLevel.HasValue)
            {
                query = query.Where(a => a.AccessLevel == request.AccessLevel.Value);
            }

            if (request.IsActive.HasValue)
            {
                var now = DateTime.UtcNow;
                if (request.IsActive.Value)
                {
                    query = query.Where(a => a.IsActive &&
                        (a.ExpiresAt == null || a.ExpiresAt > now));
                }
                else
                {
                    query = query.Where(a => !a.IsActive ||
                        (a.ExpiresAt != null && a.ExpiresAt <= now));
                }
            }

            if (request.IsInherited.HasValue)
            {
                query = query.Where(a => a.IsInherited == request.IsInherited.Value);
            }

            if (request.ExpiresAfter.HasValue)
            {
                query = query.Where(a => a.ExpiresAt != null &&
                    a.ExpiresAt > request.ExpiresAfter.Value);
            }

            if (request.ExpiresBefore.HasValue)
            {
                query = query.Where(a => a.ExpiresAt != null &&
                    a.ExpiresAt < request.ExpiresBefore.Value);
            }

            // 총 개수
            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬
            query = ApplySorting(query, request.SortBy, request.SortDescending);

            // 페이징
            var items = await query
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return new PagedResult<UserPlatformApplicationAccess>(
                items,
                totalCount,
                request.PageNumber,
                request.PageSize);
        }

        /// <summary>
        /// 정렬 적용
        /// </summary>
        private IQueryable<UserPlatformApplicationAccess> ApplySorting(
            IQueryable<UserPlatformApplicationAccess> query,
            string? sortBy,
            bool descending)
        {
            sortBy = sortBy?.ToLower() ?? "grantedat";

            query = sortBy switch
            {
                "applicationname" => descending
                    ? query.OrderByDescending(a => a.PlatformApplication.Name)
                    : query.OrderBy(a => a.PlatformApplication.Name),
                "accesslevel" => descending
                    ? query.OrderByDescending(a => a.AccessLevel)
                    : query.OrderBy(a => a.AccessLevel),
                "lastaccessedat" => descending
                    ? query.OrderByDescending(a => a.LastAccessedAt)
                    : query.OrderBy(a => a.LastAccessedAt),
                "expiresat" => descending
                    ? query.OrderByDescending(a => a.ExpiresAt)
                    : query.OrderBy(a => a.ExpiresAt),
                "createdat" => descending
                    ? query.OrderByDescending(a => a.CreatedAt)
                    : query.OrderBy(a => a.CreatedAt),
                "updatedat" => descending
                    ? query.OrderByDescending(a => a.UpdatedAt)
                    : query.OrderBy(a => a.UpdatedAt),
                _ => descending
                    ? query.OrderByDescending(a => a.GrantedAt)
                    : query.OrderBy(a => a.GrantedAt)
            };

            return query;
        }

        #endregion

        #region 집계

        /// <summary>
        /// 접근 권한 수 집계
        /// </summary>
        public async Task<int> GetAccessCountAsync(
            Guid? organizationId = null,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            if (applicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == applicationId.Value);
            }

            // 활성 권한만 집계
            var now = DateTime.UtcNow;
            query = query.Where(a => a.IsActive &&
                (a.ExpiresAt == null || a.ExpiresAt > now));

            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region 캐시 무효화 오버라이드

        /// <summary>
        /// 엔티티 업데이트 시 관련 캐시 무효화
        /// </summary>
        public override Task UpdateAsync(UserPlatformApplicationAccess entity)
        {
            // 기본 캐시 무효화
            InvalidateCache(entity.Id);

            // 관련 캐시 키 무효화
            if (_cache != null)
            {
                var cacheKey = $"UserAppAccess:{entity.ConnectedId}:{entity.ApplicationId}";
                _cache.Remove(cacheKey);
            }

            return base.UpdateAsync(entity);
        }

        /// <summary>
        /// 엔티티 삭제 시 관련 캐시 무효화
        /// </summary>
        public override Task DeleteAsync(UserPlatformApplicationAccess entity)
        {
            // 기본 캐시 무효화
            InvalidateCache(entity.Id);

            // 관련 캐시 키 무효화
            if (_cache != null)
            {
                var cacheKey = $"UserAppAccess:{entity.ConnectedId}:{entity.ApplicationId}";
                _cache.Remove(cacheKey);
            }

            return base.DeleteAsync(entity);
        }

        #endregion

        // UserApplicationAccessRepository.cs에 추가할 메서드들

        #region 벌크 작업

        /// <summary>
        /// 여러 사용자에게 동일한 접근 권한 일괄 부여
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> CreateBulkAsync(
            IEnumerable<Guid> connectedIds,
            Guid applicationId,
            ApplicationAccessLevel accessLevel,
            Guid? roleId = null,
            Guid? templateId = null,
            Guid grantedByConnectedId = default,
            CancellationToken cancellationToken = default)
        {
            var accessList = new List<UserPlatformApplicationAccess>();
            var now = DateTime.UtcNow;

            foreach (var connectedId in connectedIds)
            {
                // 중복 체크
                var existing = await Query()
                    .FirstOrDefaultAsync(a =>
                        a.ConnectedId == connectedId &&
                        a.ApplicationId == applicationId,
                        cancellationToken);

                if (existing != null)
                    continue;

                var access = new UserPlatformApplicationAccess
                {
                    ConnectedId = connectedId,
                    ApplicationId = applicationId,
                    OrganizationId = _organizationContext.CurrentOrganizationId ?? Guid.Empty,
                    AccessLevel = accessLevel,
                    RoleId = roleId,
                    AccessTemplateId = templateId,
                    GrantedByConnectedId = grantedByConnectedId,
                    GrantedAt = now,
                    IsActive = true,
                    Scopes = "[\"read\"]",
                    CreatedAt = now,
                    CreatedByConnectedId = grantedByConnectedId
                };

                accessList.Add(access);
            }

            if (accessList.Any())
            {
                await _dbSet.AddRangeAsync(accessList, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }

            return accessList;
        }

        /// <summary>
        /// 여러 접근 권한 일괄 업데이트
        /// </summary>
        public async Task<int> UpdateBulkAsync(
            IEnumerable<UserPlatformApplicationAccess> accesses,
            CancellationToken cancellationToken = default)
        {
            var accessList = accesses.ToList();
            var now = DateTime.UtcNow;

            foreach (var access in accessList)
            {
                access.UpdatedAt = now;
                access.UpdatedByConnectedId = _organizationContext.CurrentOrganizationId;

                // 캐시 무효화
                if (_cache != null)
                {
                    var cacheKey = $"UserAppAccess:{access.ConnectedId}:{access.ApplicationId}";
                    _cache.Remove(cacheKey);
                }
            }

            _dbSet.UpdateRange(accessList);
            return await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 여러 접근 권한 일괄 삭제
        /// </summary>
        public async Task<int> DeleteBulkAsync(
            IEnumerable<Guid> ids,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var entities = await Query()
                .Where(a => ids.Contains(a.Id))
                .ToListAsync(cancellationToken);

            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = now;
                entity.DeletedByConnectedId = deletedByConnectedId;

                // 캐시 무효화
                if (_cache != null)
                {
                    var cacheKey = $"UserAppAccess:{entity.ConnectedId}:{entity.ApplicationId}";
                    _cache.Remove(cacheKey);
                }
            }

            _dbSet.UpdateRange(entities);
            return await _context.SaveChangesAsync(cancellationToken);
        }

        #endregion

        #region 권한 검증 확장

        /// <summary>
        /// 사용자가 특정 권한을 가지고 있는지 확인
        /// </summary>
        public async Task<bool> HasPermissionAsync(
            Guid connectedId,
            Guid applicationId,
            string permission,
            CancellationToken cancellationToken = default)
        {
            var access = await GetByConnectedIdAndApplicationAsync(connectedId, applicationId, cancellationToken);

            if (access == null || !access.IsActive)
                return false;

            // 추가 권한 확인
            if (!string.IsNullOrEmpty(access.AdditionalPermissions))
            {
                var additionalPerms = System.Text.Json.JsonSerializer.Deserialize<List<string>>(access.AdditionalPermissions);
                if (additionalPerms?.Contains(permission) == true)
                    return true;
            }

            // 제외 권한 확인
            if (!string.IsNullOrEmpty(access.ExcludedPermissions))
            {
                var excludedPerms = System.Text.Json.JsonSerializer.Deserialize<List<string>>(access.ExcludedPermissions);
                if (excludedPerms?.Contains(permission) == true)
                    return false;
            }

            // 역할 권한 확인
            if (access.RoleId.HasValue && access.Role != null)
            {
                var rolePermissions = await _context.Set<RolePermission>()
                    .Include(rp => rp.Permission)
                    .Where(rp => rp.RoleId == access.RoleId.Value &&
                                rp.IsActive &&
                                rp.Permission.Scope == permission)
                    .AnyAsync(cancellationToken);

                return rolePermissions;
            }

            return false;
        }

        /// <summary>
        /// 사용자의 모든 유효 권한 목록 조회 (역할 + 추가 권한 - 제외 권한)
        /// </summary>
        public async Task<IEnumerable<string>> GetEffectivePermissionsAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var permissions = new HashSet<string>();

            var access = await GetByConnectedIdAndApplicationAsync(connectedId, applicationId, cancellationToken);

            if (access == null || !access.IsActive)
                return permissions;

            // 역할 권한 추가
            if (access.RoleId.HasValue)
            {
                var rolePermissions = await _context.Set<RolePermission>()
                    .Include(rp => rp.Permission)
                    .Where(rp => rp.RoleId == access.RoleId.Value && rp.IsActive)
                    .Select(rp => rp.Permission.Scope)
                    .ToListAsync(cancellationToken);

                foreach (var perm in rolePermissions)
                    permissions.Add(perm);
            }

            // 추가 권한 적용
            if (!string.IsNullOrEmpty(access.AdditionalPermissions))
            {
                var additionalPerms = System.Text.Json.JsonSerializer.Deserialize<List<string>>(access.AdditionalPermissions);
                if (additionalPerms != null)
                {
                    foreach (var perm in additionalPerms)
                        permissions.Add(perm);
                }
            }

            // 제외 권한 제거
            if (!string.IsNullOrEmpty(access.ExcludedPermissions))
            {
                var excludedPerms = System.Text.Json.JsonSerializer.Deserialize<List<string>>(access.ExcludedPermissions);
                if (excludedPerms != null)
                {
                    foreach (var perm in excludedPerms)
                        permissions.Remove(perm);
                }
            }

            return permissions;
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 애플리케이션별 활성 사용자 수 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetActiveUserCountByApplicationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await QueryForOrganization(organizationId)
                .Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now))
                .GroupBy(a => a.ApplicationId)
                .Select(g => new { ApplicationId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.ApplicationId, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 접근 레벨별 사용자 수 통계
        /// </summary>
        public async Task<Dictionary<ApplicationAccessLevel, int>> GetUserCountByAccessLevelAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await Query()
                .Where(a => a.ApplicationId == applicationId &&
                           a.IsActive &&
                           (a.ExpiresAt == null || a.ExpiresAt > now))
                .GroupBy(a => a.AccessLevel)
                .Select(g => new { AccessLevel = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.AccessLevel, x => x.Count, cancellationToken);
        }

        /// <summary>
        /// 최근 활동한 사용자 목록 조회
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetRecentlyActiveUsersAsync(
     Guid applicationId,
     int days = 7,
     int? take = null,
     CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-days);

            IQueryable<UserPlatformApplicationAccess> query = Query();
            query = query.Include(a => a.ConnectedIdNavigation);
            query = query.Where(a => a.ApplicationId == applicationId &&
                                   a.IsActive &&
                                   a.LastAccessedAt != null &&
                                   a.LastAccessedAt >= cutoffDate);
            query = query.OrderByDescending(a => a.LastAccessedAt);

            if (take.HasValue)
                query = query.Take(take.Value);

            return await query.ToListAsync(cancellationToken);
        }
        #endregion

        #region 변경 이력 추적

        /// <summary>
        /// 접근 권한 변경 이력 기록 (AuditLog 활용)
        /// </summary>
        public async Task LogAccessChangeAsync(
            Guid userApplicationAccessId,
            string changeType,
            string? oldValue,
            string? newValue,
            Guid changedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var auditLog = new AuditLog
            {
                PerformedByConnectedId = changedByConnectedId,
                Timestamp = DateTime.UtcNow,
                ActionType = AuditActionType.Update,
                Action = $"user.application.access.{changeType.ToLower()}",
                ResourceType = "UserPlatformApplicationAccess",
                ResourceId = userApplicationAccessId.ToString(),
                Success = true,
                Severity = AuditEventSeverity.Info,
                Metadata = System.Text.Json.JsonSerializer.Serialize(new
                {
                    ChangeType = changeType,
                    OldValue = oldValue,
                    NewValue = newValue
                })
            };

            await _context.Set<AuditLog>().AddAsync(auditLog, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        #endregion

        #region 권한 복사 및 템플릿

        /// <summary>
        /// 한 사용자의 권한을 다른 사용자에게 복사
        /// </summary>
        public async Task<UserPlatformApplicationAccess?> CloneAccessAsync(
            Guid sourceConnectedId,
            Guid targetConnectedId,
            Guid applicationId,
            Guid grantedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // 원본 권한 조회
            var sourceAccess = await GetByConnectedIdAndApplicationAsync(sourceConnectedId, applicationId, cancellationToken);

            if (sourceAccess == null)
                return null;

            // 대상에 이미 권한이 있는지 확인
            var existingAccess = await GetByConnectedIdAndApplicationAsync(targetConnectedId, applicationId, cancellationToken);

            if (existingAccess != null)
                return existingAccess;

            // 권한 복사
            var newAccess = new UserPlatformApplicationAccess
            {
                ConnectedId = targetConnectedId,
                ApplicationId = applicationId,
                OrganizationId = sourceAccess.OrganizationId,
                AccessLevel = sourceAccess.AccessLevel,
                AccessTemplateId = sourceAccess.AccessTemplateId,
                RoleId = sourceAccess.RoleId,
                AdditionalPermissions = sourceAccess.AdditionalPermissions,
                ExcludedPermissions = sourceAccess.ExcludedPermissions,
                Scopes = sourceAccess.Scopes,
                GrantedAt = DateTime.UtcNow,
                GrantedByConnectedId = grantedByConnectedId,
                IsActive = true,
                GrantReason = $"Cloned from ConnectedId: {sourceConnectedId}",
                CreatedAt = DateTime.UtcNow,
                CreatedByConnectedId = grantedByConnectedId
            };

            await _dbSet.AddAsync(newAccess, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            return newAccess;
        }

        /// <summary>
        /// 템플릿을 여러 사용자에게 일괄 적용
        /// </summary>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> ApplyTemplateToUsersAsync(
            Guid templateId,
            IEnumerable<Guid> connectedIds,
            Guid applicationId,
            Guid grantedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var template = await _context.Set<PlatformApplicationAccessTemplate>()
                .FirstOrDefaultAsync(t => t.Id == templateId, cancellationToken);

            if (template == null)
                return Enumerable.Empty<UserPlatformApplicationAccess>();

            var accessList = new List<UserPlatformApplicationAccess>();
            var now = DateTime.UtcNow;

            foreach (var connectedId in connectedIds)
            {
                // 중복 체크
                var existing = await Query()
                    .FirstOrDefaultAsync(a =>
                        a.ConnectedId == connectedId &&
                        a.ApplicationId == applicationId,
                        cancellationToken);

                if (existing != null)
                {
                    // 기존 권한 업데이트
                    existing.AccessTemplateId = templateId;
                    existing.AccessLevel = template.Level;
                    existing.UpdatedAt = now;
                    existing.UpdatedByConnectedId = grantedByConnectedId;

                    _dbSet.Update(existing);
                    accessList.Add(existing);
                }
                else
                {
                    // 새 권한 생성
                    var access = new UserPlatformApplicationAccess
                    {
                        ConnectedId = connectedId,
                        ApplicationId = applicationId,
                        OrganizationId = _organizationContext.CurrentOrganizationId ?? Guid.Empty,
                        AccessTemplateId = templateId,
                        AccessLevel = template.Level,  // Level 사용
                        GrantedAt = now,
                        GrantedByConnectedId = grantedByConnectedId,
                        IsActive = true,
                        Scopes = "[\"read\"]",  // 기본값 사용 또는 template.PermissionPatterns 파싱
                        GrantReason = $"Applied template: {template.Name}",
                        CreatedAt = now,
                        CreatedByConnectedId = grantedByConnectedId
                    };

                    await _dbSet.AddAsync(access, cancellationToken);
                    accessList.Add(access);
                }
            }

            await _context.SaveChangesAsync(cancellationToken);
            return accessList;
        }

        #endregion
    }
}