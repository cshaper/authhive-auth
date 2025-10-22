using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Base; // AuditableEntity
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging; // ILogger 추가
// 엔티티 별칭 사용
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;
using AuthHive.Core.Enums.Core; 

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// PlatformApplication 엔티티의 데이터 접근을 담당하는 리포지토리입니다. (v16 리팩토링 적용)
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class PlatformApplicationRepository : BaseRepository<PlatformApplicationEntity>, IPlatformApplicationRepository
    {
         private readonly ILogger<PlatformApplicationRepository> _logger; // 로거 추가

        /// <summary>
        /// PlatformApplicationRepository의 생성자입니다.
        /// [FIXED] IOrganizationContext 제거, ICacheService 사용
        /// </summary>
        public PlatformApplicationRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<PlatformApplicationRepository> logger) // 로거 주입
            : base(context, cacheService)
        {
             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 PlatformApplicationEntity가 조직 범위 엔티티임을 명시합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region IPlatformApplicationRepository 구현 (CancellationToken 추가)

        public async Task<PlatformApplicationEntity?> GetByIdNoTrackingAsync(Guid id, CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 기본적으로 추적하지만, 여기서는 NoTracking 명시
            // Query() 사용 (IsDeleted = false 포함)
            // TODO: 캐싱 고려 (ID 기반 조회)
            return await Query().AsNoTracking().FirstOrDefaultAsync(app => app.Id == id, cancellationToken);
        }

        public async Task<PlatformApplicationEntity?> GetByApplicationKeyAsync(string applicationKey, CancellationToken cancellationToken = default)
        {
            // ApplicationKey는 고유하므로 캐싱 가능
            string cacheKey = GetCacheKey($"AppKey:{applicationKey.ToLowerInvariant()}");
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<PlatformApplicationEntity>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var app = await Query()
                .Include(a => a.Organization) // 필요 시 조직 정보 포함
                .FirstOrDefaultAsync(app => app.ApplicationKey == applicationKey, cancellationToken);

            if (app != null && _cacheService != null)
            {
                 // 캐시 TTL 설정 (예: 1시간)
                await _cacheService.SetAsync(cacheKey, app, TimeSpan.FromHours(1), cancellationToken);
            }
            return app;
        }

        public async Task<IEnumerable<PlatformApplicationEntity>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 조직 범위 쿼리 헬퍼 활용
             // TODO: 캐싱 고려 (조직별 앱 목록)
            return await QueryForOrganization(organizationId)
                .Include(a => a.Organization) // 조직 정보 포함
                .AsNoTracking()
                .OrderBy(app => app.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var entity = await GetByIdAsync(id, cancellationToken); // GetByIdAsync 사용 (캐시 활용 가능)
            if (entity == null || entity.IsDeleted) return false;

             // 삭제 주체 설정 (AuditableEntity 가정)
             if (entity is AuditableEntity auditableEntity)
             {
                 auditableEntity.DeletedByConnectedId = deletedByConnectedId;
             }
             else {
                 _logger.LogWarning("Entity {EntityId} is not AuditableEntity, cannot set DeletedByConnectedId.", id);
             }

            // BaseRepository의 DeleteAsync 호출 (Soft Delete + 캐시 무효화)
            await DeleteAsync(entity, cancellationToken);
             _logger.LogInformation("Soft deleted PlatformApplication {AppId} by {DeletedBy}", id, deletedByConnectedId);
            return true;
        }

        public async Task<PlatformApplicationEntity?> FindSingleAsync(Expression<Func<PlatformApplicationEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 FirstOrDefaultAsync 사용 (NoTracking 포함)
            return await FirstOrDefaultAsync(predicate, cancellationToken);
        }

        public async Task<PaginationResponse<PlatformApplicationEntity>> GetPagedAsync(
            Expression<Func<PlatformApplicationEntity, bool>>? predicate,
            PaginationRequest pagination,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationEntity, object>>[] includes)
        {
             // BaseRepository의 GetPagedAsync 활용 + Include 적용
             IQueryable<PlatformApplicationEntity> query = Query(); // IsDeleted=false 포함

             if (predicate != null) query = query.Where(predicate);

             if (includes != null)
             {
                 query = includes.Aggregate(query, (current, include) => current.Include(include));
             }

             var totalCount = await query.CountAsync(cancellationToken);
             var items = await query
                 // BaseRepository GetPagedAsync와 일관성을 위해 Id로 정렬 또는 Name 정렬 명시
                 .OrderBy(app => app.Name)
                 .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                 .Take(pagination.PageSize)
                 .AsNoTracking()
                 .ToListAsync(cancellationToken);

            return PaginationResponse<PlatformApplicationEntity>.Create(items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        public async Task<bool> ExistsByApplicationKeyAsync(string applicationKey, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(app => app.ApplicationKey == applicationKey);
            if (excludeId.HasValue) query = query.Where(app => app.Id != excludeId.Value);
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsDuplicateNameAsync(Guid organizationId, string name, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(app => app.Name == name);
            if (excludeId.HasValue) query = query.Where(app => app.Id != excludeId.Value);
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> DeleteRangeAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
        {
            var idList = ids?.ToList();
            if (idList == null || !idList.Any()) return false;

            // TODO: [성능] ExecuteUpdateAsync (EF Core 7+) 사용 고려
            var entities = await Query().Where(e => idList.Contains(e.Id)).ToListAsync(cancellationToken);
            if (!entities.Any()) return false;

            await base.DeleteRangeAsync(entities, cancellationToken); // Soft Delete + 캐시 무효화
             _logger.LogWarning("Bulk soft deleted {Count} PlatformApplications by IDs", entities.Count);
            return true;
        }

        public async Task<int> GetCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository CountAsync 사용 (QueryForOrganization 조건 사용)
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId, cancellationToken);
        }

        public async Task<int> GetActiveCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository CountAsync 사용 (QueryForOrganization 조건 + IsActive)
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId && app.IsActive, cancellationToken);
        }

        public async Task<Dictionary<ApplicationType, int>> GetCountByTypeAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository GetGroupCountAsync 사용
            return await GetGroupCountAsync(
                app => app.ApplicationType, // Key Selector (Enum)
                app => EF.Property<Guid>(app, "OrganizationId") == organizationId, // Predicate
                cancellationToken);
        }

        #endregion

        #region Override BaseRepository Methods (Caching)

        // AddAsync, UpdateAsync, DeleteAsync, DeleteRangeAsync는 BaseRepository 것을 사용하되,
        // 필요 시 캐시 무효화 로직을 추가하기 위해 override 할 수 있음.
        // 여기서는 AppKey 기반 캐시 무효화를 위해 override.

        public override async Task<PlatformApplicationEntity> AddAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
        {
            // OrganizationId 설정
             if (entity.OrganizationId == Guid.Empty)
             {
                 // OrganizationId를 설정할 방법 필요 (예: 상위 컨텍스트 또는 추가 정보)
                 _logger.LogWarning("OrganizationId is empty for new PlatformApplication {AppName}.", entity.Name);
                 // throw new InvalidOperationException("OrganizationId must be set for PlatformApplication.");
             }
            var result = await base.AddAsync(entity, cancellationToken);
            await InvalidateAppCachesAsync(result, cancellationToken); // 캐시 무효화
            return result;
        }

        public override async Task UpdateAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
        {
             // 변경 전 키 값 저장 (필요 시)
             // var originalKey = await Query().Where(a => a.Id == entity.Id).Select(a => a.ApplicationKey).FirstOrDefaultAsync(cancellationToken);

            await base.UpdateAsync(entity, cancellationToken); // 기본 캐시 무효화 (ID 기반) 포함
            await InvalidateAppCachesAsync(entity, cancellationToken); // AppKey 등 추가 캐시 무효화

             // 키 값이 변경되었다면 이전 키 캐시도 무효화
             // if (originalKey != entity.ApplicationKey && !string.IsNullOrEmpty(originalKey)) {
             //     await _cacheService?.RemoveAsync(GetCacheKey($"AppKey:{originalKey.ToLowerInvariant()}"), cancellationToken);
             // }
        }

         // DeleteAsync, DeleteRangeAsync는 BaseRepository 것을 사용하고,
         // 내부적으로 InvalidateCacheAsync(id)를 호출하므로 추가 캐시 무효화 필요 시 override.
         // 여기서는 AppKey 캐시 무효화를 위해 추가.
        public override async Task DeleteAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
        {
            await base.DeleteAsync(entity, cancellationToken);
            await InvalidateAppCachesAsync(entity, cancellationToken);
        }

        // base.DeleteRangeAsync는 각 엔티티에 대해 InvalidateCacheAsync(id)를 호출함.
        // AppKey 등 추가 캐시 무효화가 필요하면 override 필요.
        public override async Task DeleteRangeAsync(IEnumerable<PlatformApplicationEntity> entities, CancellationToken cancellationToken = default)
        {
             var entityList = entities?.ToList();
             if (entityList == null || !entityList.Any()) return;

            await base.DeleteRangeAsync(entityList, cancellationToken);
            foreach (var entity in entityList)
            {
                await InvalidateAppCachesAsync(entity, cancellationToken);
            }
        }


        #endregion

        #region Helper Methods

        // 애플리케이션 관련 캐시 무효화 (AppKey 등)
        private async Task InvalidateAppCachesAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken)
        {
            if (_cacheService == null || entity == null) return;

            var tasks = new List<Task>();

            // AppKey 기반 캐시
            if (!string.IsNullOrEmpty(entity.ApplicationKey))
            {
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey($"AppKey:{entity.ApplicationKey.ToLowerInvariant()}"), cancellationToken));
            }
            // 조직별 앱 목록 캐시
            if (entity.OrganizationId != Guid.Empty)
            {
                // 조직별 캐시 키 정의 필요 (예: "Apps:Org:{orgId}")
                tasks.Add(_cacheService.RemoveAsync($"Apps:Org:{entity.OrganizationId}", cancellationToken));
            }

            // ID 기반 캐시는 BaseRepository의 Update/Delete에서 처리

            await Task.WhenAll(tasks);
             _logger.LogDebug("Invalidated specific caches for PlatformApplication {AppId}", entity.Id);
        }

        #endregion
    }
}