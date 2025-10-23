using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
// 💡 [v16.1] 인터페이스 네임스페이스 수정 (IUserApplicationAccessRepository 위치)
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Entities.Auth;
using System.Linq.Expressions;
// 💡 [v16.1] 서비스 로직(AuditLog) 분리를 위해 참조 제거
// using AuthHive.Core.Entities.Audit;
// using System.Text.Json;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// UserPlatformApplicationAccess 엔티티의 데이터 접근을 담당하는 리포지토리입니다. (AuthHive v16.1)
    /// 
    /// [v16.1 변경 사항]
    /// 1. (버그) 생성자에서 ICacheService를 base()로 전달하도록 수정
    /// 2. (UoW) 모든 _context.SaveChangesAsync() 호출 제거
    /// 3. (서비스 로직) 감사 로깅, 권한 계산 등 비즈니스 로직 메서드 제거
    /// 4. (최적화) 모든 읽기 전용 쿼리에 AsNoTracking() 적용
    /// 5. (TODO) 미완성 벌크(Bulk) 메서드를 UoW 원칙에 맞게 구현
    /// </summary>
    // 💡 [v16.1] 인터페이스 경로 수정
    public class UserApplicationAccessRepository : BaseRepository<UserPlatformApplicationAccess>, IUserPlatformApplicationAccessRepository
    {
        public UserApplicationAccessRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            // 💡 [v16.1 수정] cacheService를 base()로 전달해야 캐시가 동작합니다.
            : base(context, cacheService)
        {
        }

        /// <summary>
        /// 이 엔티티는 OrganizationId를 포함하므로, 조직 범위 엔티티가 맞습니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 조회 (AsNoTracking 적용)

        // 💡 [v16.1] 인터페이스(prompt 26)에 있는 FindSingleAsync 구현
        public async Task<UserPlatformApplicationAccess?> FindSingleAsync(
         Expression<Func<UserPlatformApplicationAccess, bool>> predicate,
         CancellationToken cancellationToken = default) // <-- 1. 여기 추가
        {
            return await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(predicate, cancellationToken); // <-- 2. 여기 전달
        }

        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdAndApplicationAsync(
            Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            // 이 메서드는 조회 후 수정될 수 있으므로 AsNoTracking() 생략
            return await Query()
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 사용자 정의 캐시 메서드
        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdApplicationAndOrganizationAsync(
            Guid connectedId, Guid applicationId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var cacheKey = GetCacheKey($"cid={connectedId}:aid={applicationId}:oid={organizationId}");
            if (_cacheService != null)
            {
                var cachedAccess = await _cacheService.GetAsync<UserPlatformApplicationAccess>(cacheKey, cancellationToken);
                if (cachedAccess != null) return cachedAccess;
            }

            // 💡 [v16.1] AsNoTracking() 추가
            var result = await Query()
                .AsNoTracking()
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId && a.OrganizationId == organizationId, cancellationToken);

            if (result != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(10), cancellationToken);
            }
            return result;
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (onlyActive 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByConnectedIdAsync(
            Guid connectedId, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ConnectedId == connectedId);

            // 💡 [v16.1] AsNoTracking() 추가
            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .OrderBy(a => a.PlatformApplication.Name)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (onlyActive 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationIdAsync(
            Guid applicationId, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ApplicationId == applicationId);

            // 💡 [v16.1] AsNoTracking() 추가
            return await query
                .AsNoTracking()
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (onlyActive 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByOrganizationIdAsync(
           Guid organizationId, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);

            // 💡 [v16.1] AsNoTracking() 추가
            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.PlatformApplication.Name)
                .ThenBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 N+1 방지용 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetAllByOrganizationIdsAsync(
            IEnumerable<Guid> organizationIds, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => organizationIds.Contains(a.OrganizationId));
            if (onlyActive)
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));

            return await query.AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation).ThenInclude(c => c.User)
                .OrderBy(a => a.OrganizationId)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 N+1 방지용 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationAndConnectedIdsAsync(
            Guid applicationId, IEnumerable<Guid> connectedIds, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ApplicationId == applicationId && connectedIds.Contains(a.ConnectedId));
            if (onlyActive)
                query = query.Where(a => a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow));

            return await query.AsNoTracking()
                .Include(a => a.ConnectedIdNavigation).ThenInclude(c => c.User)
                .Include(a => a.Role)
                .OrderBy(a => a.ConnectedId)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 권한 레벨 및 역할별 조회 (AsNoTracking 적용)

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (organizationId 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByAccessLevelAsync(
            Guid applicationId, ApplicationAccessLevel accessLevel, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.ApplicationId == applicationId && a.AccessLevel == accessLevel);

            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (onlyActive 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByRoleIdAsync(
            Guid roleId, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.RoleId == roleId);

            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 시그니처와 맞춤 (onlyActive 파라미터 제거)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByTemplateIdAsync(
            Guid templateId, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.AccessTemplateId == templateId);

            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region CUD 작업 (UoW 적용)

        /// <summary>
        /// [v16.1] SoftDeleteAsync 인터페이스 구현
        /// 감사 정보를 포함하여 접근 권한을 소프트 삭제합니다.
        /// UoW 원칙에 따라 SaveChangesAsync() 및 감사 로깅 로직을 제거했습니다.
        /// </summary>
        public async Task<bool> SoftDeleteAsync(
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

            // [v16.1] BaseRepository의 UpdateAsync 호출 (캐시 무효화 포함)
            await UpdateAsync(entity, cancellationToken);

            // [v16.1] 사용자 정의 캐시 키 무효화
            // 복잡한 캐시 무효화는 서비스 레이어 또는 이벤트 버스에서 처리하는 것이 이상적입니다.
            if (_cacheService != null)
            {
                await _cacheService.RemoveAsync(GetCacheKey($"cid={entity.ConnectedId}:aid={entity.ApplicationId}:oid={entity.OrganizationId}"), cancellationToken);
            }


            return true; // UoW 커밋을 가정하고 true 반환
        }

        // 💡 [v16.1] 인터페이스(prompt 26) 구현
        public async Task<bool> RemoveAllByApplicationAsync(Guid applicationId, CancellationToken cancellationToken = default)
        {
            var entities = await Query().Where(a => a.ApplicationId == applicationId).ToListAsync(cancellationToken);
            if (!entities.Any()) return true;

            // 💡 [v16.1] BaseRepository의 DeleteRangeAsync 사용
            await DeleteRangeAsync(entities, cancellationToken);
            return true;
        }

        // 💡 [v16.1] 인터페이스(prompt 26) 구현
        public async Task<bool> RemoveAllByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            var entities = await Query().Where(a => a.ConnectedId == connectedId).ToListAsync(cancellationToken);
            if (!entities.Any()) return true;

            // 💡 [v16.1] BaseRepository의 DeleteRangeAsync 사용
            await DeleteRangeAsync(entities, cancellationToken);
            return true;
        }

        #endregion

        #region 상태 및 만료 관리 (AsNoTracking 적용)

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiredAccessAsync(DateTime? asOfDate = null, CancellationToken cancellationToken = default)
        {
            var checkDate = asOfDate ?? DateTime.UtcNow;
            return await Query()
                .Where(a => a.IsActive && a.ExpiresAt != null && a.ExpiresAt <= checkDate)
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.ExpiresAt).ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetExpiringAccessAsync(int daysBeforeExpiry = 7, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var expiryThreshold = now.AddDays(daysBeforeExpiry);
            return await Query()
                .Where(a => a.IsActive && a.ExpiresAt != null && a.ExpiresAt > now && a.ExpiresAt <= expiryThreshold)
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.ExpiresAt).ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInactiveAccessAsync(DateTime inactiveSince, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(a => a.IsActive && (a.LastAccessedAt == null || a.LastAccessedAt < inactiveSince))
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.LastAccessedAt ?? a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 상속 및 스코프 (AsNoTracking 적용)

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetInheritedAccessAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(a => a.ConnectedId == connectedId && a.IsInherited && a.InheritedFromId != null)
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.AccessTemplate)
                .OrderBy(a => a.PlatformApplication.Name).ToListAsync(cancellationToken);
        }

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByScopeAsync(string scope, Guid? applicationId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(a => a.AdditionalPermissions != null &&
                                            EF.Functions.JsonContains(a.AdditionalPermissions, $"\"{scope}\""));
            if (applicationId.HasValue)
            {
                query = query.Where(a => a.ApplicationId == applicationId.Value);
            }
            return await query
                .AsNoTracking()
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt).ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 및 존재 확인

        public async Task<bool> ExistsAsync(Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 HasAccessLevelAsync 구현
        public async Task<bool> HasAccessLevelAsync(Guid connectedId, Guid applicationId, ApplicationAccessLevel minLevel, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query().AnyAsync(a =>
                a.ConnectedId == connectedId &&
                a.ApplicationId == applicationId &&
                a.AccessLevel >= minLevel && // 접근 레벨 비교
                a.IsActive &&
                (a.ExpiresAt == null || a.ExpiresAt > now),
                cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 IsActiveAsync 구현
        public async Task<bool> IsActiveAsync(Guid connectedId, Guid applicationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query().AnyAsync(a =>
                a.ConnectedId == connectedId &&
                a.ApplicationId == applicationId &&
                a.IsActive &&
                (a.ExpiresAt == null || a.ExpiresAt > now),
                cancellationToken);
        }

        #endregion

        #region 페이징 및 검색 (AsNoTracking 적용)

        // 💡 [v16.1] 원본 파일에만 있던 헬퍼 (AsNoTracking 추가)
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
            // ... (기타 필터들)

            var totalCount = await query.CountAsync(cancellationToken);
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);

            var items = await sortedQuery
                .AsNoTracking() // 💡 [v16.1] AsNoTracking() 추가
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

        // 💡 [v16.1] 인터페이스(prompt 26)의 GetCountByApplicationAsync 구현
        public async Task<int> GetCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default) // <-- 1. 시그니처에 잘 추가됨
        {
            return await Query().CountAsync(
                a => a.ApplicationId == applicationId,
                cancellationToken); // <-- 2. 내부 호출에 잘 전달됨
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 GetActiveCountByApplicationAsync 구현
        public async Task<int> GetActiveCountByApplicationAsync(Guid applicationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query().CountAsync(a =>
                a.ApplicationId == applicationId &&
                a.IsActive &&
                (a.ExpiresAt == null || a.ExpiresAt > now),
                cancellationToken);
        }

        // 💡 [v16.1] 인터페이스(prompt 26)의 GetCountByAccessLevelAsync (dictionary) 구현
        public async Task<Dictionary<ApplicationAccessLevel, int>> GetCountByAccessLevelAsync(Guid applicationId, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .Where(a => a.ApplicationId == applicationId && a.IsActive && (a.ExpiresAt == null || a.ExpiresAt > now))
                .GroupBy(a => a.AccessLevel)
                .Select(g => new { AccessLevel = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.AccessLevel, x => x.Count, cancellationToken);
        }
        /// <summary>
        /// (중복 서명) 특정 애플리케이션의 특정 접근 레벨 사용자 수를 계산합니다.
        /// </summary>
        public async Task<int> GetCountByAccessLevelAsync(
            Guid applicationId,
            ApplicationAccessLevel accessLevel,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .CountAsync(a =>
                    a.ApplicationId == applicationId &&
                    a.AccessLevel == accessLevel && // 💡 특정 레벨 필터 추가
                    a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > now),
                    cancellationToken);
        }
        // 💡 [v16.1] 인터페이스(prompt 26)의 GetQueryable 구현
        public IQueryable<UserPlatformApplicationAccess> GetQueryable()
        {
            return Query();
        }

        #endregion

        // 💡 [v16.1] 원본 파일에 있던 벌크 메서드들 (UoW 원칙 적용)
        // 참고: 이 메서드들은 인터페이스(prompt 26)에 정의되어 있지 않아 외부에서 호출이 불가능할 수 있습니다.
        // 캐시 무효화는 서비스 레이어 또는 이벤트 버스에서 처리해야 합니다.

        public async Task<IEnumerable<UserPlatformApplicationAccess>> CreateBulkAsync(IEnumerable<Guid> connectedIds, Guid applicationId, ApplicationAccessLevel accessLevel, Guid organizationId, Guid? roleId = null, Guid? templateId = null, Guid grantedByConnectedId = default, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var accessList = connectedIds.Select(cid => new UserPlatformApplicationAccess
            {
                Id = Guid.NewGuid(),
                ConnectedId = cid,
                OrganizationId = organizationId, // 💡 [v16.1] 조직 ID 추가
                ApplicationId = applicationId,
                AccessLevel = accessLevel,
                RoleId = roleId,
                AccessTemplateId = templateId,
                IsActive = true,
                GrantedAt = now,
                GrantedByConnectedId = grantedByConnectedId,
                CreatedAt = now,
                CreatedByConnectedId = grantedByConnectedId
            }).ToList();

            await AddRangeAsync(accessList, cancellationToken);
            return accessList;
        }

        public async Task UpdateBulkAsync(IEnumerable<UserPlatformApplicationAccess> accesses, CancellationToken cancellationToken = default)
        {
            // 💡 [v16.1] BaseRepository의 UpdateRangeAsync 호출
            await UpdateRangeAsync(accesses, cancellationToken);
            // 💡 [v16.1 삭제] UoW 원칙 위반
            // return await _context.SaveChangesAsync(cancellationToken);
        }


        public async Task DeleteBulkAsync(IEnumerable<Guid> ids, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var entities = await Query().Where(a => ids.Contains(a.Id)).ToListAsync(cancellationToken);
            if (!entities.Any()) return;

            var now = DateTime.UtcNow;
            foreach (var entity in entities)
            {
                // 💡 [v16.1] 수동으로 감사 속성 설정
                entity.DeletedByConnectedId = deletedByConnectedId;
                entity.UpdatedByConnectedId = deletedByConnectedId;
                entity.UpdatedAt = now;
                entity.IsActive = false;
            }

            // 💡 [v16.1] BaseRepository의 DeleteRangeAsync 호출 (IsDeleted, DeletedAt 설정)
            await DeleteRangeAsync(entities, cancellationToken);

            // 💡 [v16.1 삭제] UoW 원칙 위반
            // return await _context.SaveChangesAsync(cancellationToken);
        }

    }
}