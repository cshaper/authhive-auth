using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // Replaced IMemoryCache with ICacheService
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Audit;
using System.Text.Json;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// UserPlatformApplicationAccess 엔티티의 데이터 접근을 담당하는 리포지토리입니다. (AuthHive v16 기준)
    /// BaseRepository의 v16 원칙에 따라 ICacheService를 사용하며, IOrganizationContext에 대한 의존성이 제거되었습니다.
    /// </summary>
    public class UserApplicationAccessRepository : BaseRepository<UserPlatformApplicationAccess>, IUserApplicationAccessRepository
    {
        /// <summary>
        /// 생성자에서 IOrganizationContext를 제거하고 ICacheService를 주입받도록 수정되었습니다.
        /// 이는 리포지토리가 외부 컨텍스트에 의존하지 않고 명시적인 파라미터로만 동작하도록 하는 v16 아키텍처 원칙을 따릅니다.
        /// </summary>
        public UserApplicationAccessRepository(
            AuthDbContext context,
            ICacheService? cacheService = null) // IMemoryCache -> ICacheService
            : base(context)
        {
        }

        /// <summary>
        /// BaseRepository의 추상 메서드를 구현합니다.
        /// UserPlatformApplicationAccess 엔티티는 OrganizationId를 포함하므로, 조직 범위 엔티티가 맞습니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

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
            // 캐싱 로직을 ICacheService를 사용하도록 수정
            var cacheKey = GetCacheKey($"cid={connectedId}:aid={applicationId}:oid={organizationId}");
            if (_cacheService != null)
            {
                var cachedAccess = await _cacheService.GetAsync<UserPlatformApplicationAccess>(cacheKey, cancellationToken);
                if (cachedAccess != null)
                {
                    return cachedAccess;
                }
            }

            var result = await Query()
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId && a.OrganizationId == organizationId, cancellationToken);

            if (result != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(10), cancellationToken);
            }

            return result;
        }

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
                .ThenInclude(c => c.User)
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
                .ThenInclude(c => c.User)
                .Include(a => a.Role)
                .OrderBy(a => a.ConnectedId)
                .ThenBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
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

        #region Soft Delete Operations

        /// <summary>
        /// 감사 정보를 포함하여 접근 권한을 소프트 삭제합니다.
        /// 캐시 무효화 로직이 ICacheService를 사용하도록 업데이트되었습니다.
        /// </summary>
        public async Task<bool> DeleteAsync(
            Guid id,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var entity = await GetByIdAsync(id, cancellationToken);
            if (entity == null || entity.IsDeleted)
            {
                return false;
            }

            // Soft delete: 엔티티 상태 변경
            entity.IsDeleted = true;
            entity.IsActive = false; // 비활성화
            entity.DeletedAt = DateTime.UtcNow;
            entity.DeletedByConnectedId = deletedByConnectedId;
            entity.UpdatedAt = DateTime.UtcNow;
            entity.UpdatedByConnectedId = deletedByConnectedId;

            // 관련 캐시를 비동기적으로 모두 무효화
            if (_cacheService != null)
            {
                var tasks = new List<Task>
                {
                    _cacheService.RemoveAsync(GetCacheKey($"cid={entity.ConnectedId}:aid={entity.ApplicationId}"), cancellationToken),
                    _cacheService.RemoveAsync(GetCacheKey($"cid={entity.ConnectedId}:aid={entity.ApplicationId}:oid={entity.OrganizationId}"), cancellationToken),
                    _cacheService.RemoveAsync(GetCacheKey(id), cancellationToken),
                    _cacheService.RemoveAsync(GetCacheKey($"org={entity.OrganizationId}"), cancellationToken)
                };
                await Task.WhenAll(tasks);
            }

            _dbSet.Update(entity);
            var result = await _context.SaveChangesAsync(cancellationToken);

            // 변경 사항 감사 로그 기록
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

        #region 상태 및 만료 관리

        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiredAccessAsync(DateTime? asOfDate = null, CancellationToken cancellationToken = default)
        {
            var checkDate = asOfDate ?? DateTime.UtcNow;
            return await Query().Where(a => a.IsActive && a.ExpiresAt != null && a.ExpiresAt <= checkDate).Include(a => a.PlatformApplication).Include(a => a.ConnectedIdNavigation).OrderBy(a => a.ExpiresAt).ToListAsync(cancellationToken);
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
            // EF Core 6+에서는 JSON 컬럼 쿼리에 EF.Functions.JsonContains를 사용할 수 있습니다.
            // a.AdditionalPermissions가 null이 아닌 경우에만 JsonContains를 실행하도록 수정
            // JSON 배열에 특정 값이 포함되어 있는지 확인할 때 예를 들어, "permissions"라는 JSON 배열 컬럼에 "admin"이라는 권한이 포함된 사용자를 찾고 싶을 때 사용할 수 있습니다.
            // 이건 scope라는 변수에 담긴값을 찾는 코드임
            var query = Query().Where(a => a.AdditionalPermissions != null &&
                                           EF.Functions.JsonContains(a.AdditionalPermissions, $"\"{scope}\""));
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
            var query = Query()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .Include(a => a.AccessTemplate)
                .Include(a => a.Role)
                .AsQueryable();

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
                "lastaccessedat" => descending ? query.OrderByDescending(a => a.LastAccessedAt) : query.OrderBy(a => a.LastAccessedAt),
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

        // 참고: 벌크 작업은 일반적으로 성능 최적화를 위해 캐시를 우회하거나,
        // 작업 완료 후 관련 캐시 목록을 무효화하는 별도 로직이 필요합니다.

        public async Task<IEnumerable<UserPlatformApplicationAccess>> CreateBulkAsync(IEnumerable<Guid> connectedIds, Guid applicationId, ApplicationAccessLevel accessLevel, Guid? roleId = null, Guid? templateId = null, Guid grantedByConnectedId = default, CancellationToken cancellationToken = default)
        {
            var accessList = new List<UserPlatformApplicationAccess>();
            var now = DateTime.UtcNow;
            // TODO: CreateBulkAsync 로직을 완성해야 합니다.
            // Placeholder for bulk creation logic
            await Task.CompletedTask;
            return accessList;
        }

        public async Task<int> UpdateBulkAsync(IEnumerable<UserPlatformApplicationAccess> accesses, CancellationToken cancellationToken = default)
        {
            // TODO: UpdateBulkAsync 로직을 완성하고 캐시 무효화를 처리해야 합니다.
            _dbSet.UpdateRange(accesses);
            return await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task<int> DeleteBulkAsync(IEnumerable<Guid> ids, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            // TODO: DeleteBulkAsync 로직을 완성하고 캐시 무효화를 처리해야 합니다.
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

            var query = Query()
                .Include(a => a.ConnectedIdNavigation)
                .Where(a => a.ApplicationId == applicationId &&
                              a.IsActive &&
                              a.LastAccessedAt != null &&
                              a.LastAccessedAt >= cutoffDate)
                .OrderByDescending(a => a.LastAccessedAt);

            if (take.HasValue)
            {
                query = (IOrderedQueryable<UserPlatformApplicationAccess>)query.Take(take.Value);
            }

            return await query.ToListAsync(cancellationToken);
        }

        #endregion

        #region 변경 이력 추적

        public async Task LogAccessChangeAsync(Guid userApplicationAccessId, string changeType, string? oldValue, string? newValue, Guid changedByConnectedId, CancellationToken cancellationToken = default)
        {
            // IgnoreQueryFilters를 사용하여 소프트 삭제된 엔티티도 조회하여 OrganizationId를 확보합니다.
            var accessEntity = await _dbSet.IgnoreQueryFilters()
                                     .FirstOrDefaultAsync(e => e.Id == userApplicationAccessId, cancellationToken);

            if (accessEntity == null) return; // 또는 예외 처리

            if (!Enum.TryParse<AuditActionType>(changeType, true, out var actionType))
            {
                // 변환 실패 시 기본값 또는 오류 처리
                actionType = AuditActionType.Update; // 혹은 예외를 던집니다.
            }

            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                PerformedByConnectedId = changedByConnectedId,
                TargetOrganizationId = accessEntity.OrganizationId, // 'OrganizationId' -> 'TargetOrganizationId'
                ApplicationId = accessEntity.ApplicationId,
                Timestamp = DateTime.UtcNow,
                ActionType = actionType, // Enum 타입으로 설정
                Action = $"ACCESS_{changeType.ToUpper()}", // 예: "ACCESS_DELETE"
                ResourceType = nameof(UserPlatformApplicationAccess), // 'EntityType' -> 'ResourceType'
                ResourceId = userApplicationAccessId.ToString(), // 'EntityId' -> 'ResourceId'
                Success = true,
                IpAddress = "N/A", // 서비스 계층에서 HttpContext로부터 주입 필요
                UserAgent = "N/A",  // 서비스 계층에서 HttpContext로부터 주입 필요
                Severity = AuditEventSeverity.Info,
                // 변경 전/후 데이터를 Metadata에 JSON 형식으로 저장
                Metadata = JsonSerializer.Serialize(new { OldValue = oldValue, NewValue = newValue })
            };

            await _context.Set<AuditLog>().AddAsync(auditLog, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken); // 변경사항 즉시 저장
        }

        #endregion

        #region 권한 복사 및 템플릿

        public async Task<UserPlatformApplicationAccess?> CloneAccessAsync(Guid sourceConnectedId, Guid targetConnectedId, Guid applicationId, Guid grantedByConnectedId, CancellationToken cancellationToken = default)
        {
            var sourceAccess = await GetByConnectedIdAndApplicationAsync(sourceConnectedId, applicationId, cancellationToken);
            if (sourceAccess == null || await ExistsAsync(targetConnectedId, applicationId, cancellationToken)) return null;

            var newAccess = new UserPlatformApplicationAccess
            {
                // ... 속성 복사 로직 ...
            };
            await AddAsync(newAccess, cancellationToken);
            return newAccess;
        }

        public async Task<IEnumerable<UserPlatformApplicationAccess>> ApplyTemplateToUsersAsync(Guid templateId, IEnumerable<Guid> connectedIds, Guid applicationId, Guid grantedByConnectedId, CancellationToken cancellationToken = default)
        {
            var template = await _context.Set<PlatformApplicationAccessTemplate>().FindAsync(new object[] { templateId }, cancellationToken);
            if (template == null) return Enumerable.Empty<UserPlatformApplicationAccess>();

            var results = new List<UserPlatformApplicationAccess>();
            // ... 템플릿 기반으로 권한을 생성 또는 업데이트하는 로직 ...
            await _context.SaveChangesAsync(cancellationToken);
            return results;
        }

        #endregion
    }
}