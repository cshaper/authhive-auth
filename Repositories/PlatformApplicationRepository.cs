// Path: AuthHive.Auth/Repositories/PlatformApplicationRepository.cs
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Base;
using AuthHive.Core.Entities.PlatformApplications; // 네임스페이스 포함
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.PlatformApplication.Responses;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging; 
// ✅ 별칭 사용 (PlatformApplicationEntity = DB 엔티티임을 명확히 함)
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication; 
using AuthHive.Core.Enums.Core; 

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// PlatformApplication 엔티티의 데이터 접근을 담당하는 리포지토리입니다. (v17 리팩토링 적용)
    /// </summary>
    // 1. BaseRepository에 별칭 사용
    public class PlatformApplicationRepository : BaseRepository<PlatformApplicationEntity>, IPlatformApplicationRepository
    {
         private readonly ILogger<PlatformApplicationRepository> _logger; 

        /// <summary>
        /// PlatformApplicationRepository의 생성자입니다.
        /// </summary>
        public PlatformApplicationRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<PlatformApplicationRepository> logger) 
            : base(context, cacheService)
        {
             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 PlatformApplicationEntity가 조직 범위 엔티티임을 명시합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region IPlatformApplicationRepository 구현 (CancellationToken 추가)

        // 2. PlatformApplicationEntity 별칭 사용
        public async Task<PlatformApplicationEntity?> GetByIdNoTrackingAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await Query().AsNoTracking().FirstOrDefaultAsync(app => app.Id == id, cancellationToken);
        }

        public async Task<PlatformApplicationEntity?> GetByApplicationKeyAsync(string applicationKey, CancellationToken cancellationToken = default)
        {
            string cacheKey = GetCacheKey($"AppKey:{applicationKey.ToLowerInvariant()}");
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<PlatformApplicationEntity>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var app = await Query()
                .Include(a => a.Organization) 
                .FirstOrDefaultAsync(app => app.ApplicationKey == applicationKey, cancellationToken);

            if (app != null && _cacheService != null)
            {
                 await _cacheService.SetAsync(cacheKey, app, TimeSpan.FromHours(1), cancellationToken);
            }
            return app;
        }

        public async Task<IEnumerable<PlatformApplicationEntity>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(a => a.Organization) 
                .AsNoTracking()
                .OrderBy(app => app.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var entity = await GetByIdAsync(id, cancellationToken); 
            if (entity == null || entity.IsDeleted) return false;

             if (entity is GlobalBaseEntity GlobalBaseEntity)
             {
                 GlobalBaseEntity.DeletedByConnectedId = deletedByConnectedId;
             }
             else {
                 _logger.LogWarning("Entity {EntityId} is not GlobalBaseEntity, cannot set DeletedByConnectedId.", id);
             }

            await DeleteAsync(entity, cancellationToken);
             _logger.LogInformation("Soft deleted PlatformApplication {AppId} by {DeletedBy}", id, deletedByConnectedId);
            return true;
        }

        public async Task<PlatformApplicationEntity?> FindSingleAsync(Expression<Func<PlatformApplicationEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await FirstOrDefaultAsync(predicate, cancellationToken);
        }

        // 3. 인터페이스 시그니처와 일치
        public async Task<ApplicationListResponse> GetPagedAsync(
            Expression<Func<PlatformApplicationEntity, bool>>? predicate,
            int pageNumber,
            int pageSize,
            string? sortBy = null, 
            bool sortDescending = true,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationEntity, object>>[] includes)
        {
             IQueryable<PlatformApplicationEntity> query = Query(); 

             if (predicate != null) query = query.Where(predicate);

             if (includes != null)
             {
                 query = includes.Aggregate(query, (current, include) => current.Include(include));
             }

             var totalCount = await query.CountAsync(cancellationToken);
             
             if (string.IsNullOrEmpty(sortBy))
             {
                query = sortDescending ? 
                        query.OrderByDescending(app => app.Name) : 
                        query.OrderBy(app => app.Name);
             }
             // TODO: sortBy 문자열을 기반으로 동적 정렬(Dynamic Linq) 구현 필요

             var items = await query
                 .Skip((pageNumber - 1) * pageSize)
                 .Take(pageSize)
                 .AsNoTracking()
                 .ToListAsync(cancellationToken);
            
            // v17 표준 수정: 엔티티 -> DTO로 매핑
             var dtoItems = items.Select(app => new ApplicationResponse 
             {
                Id = app.Id,
                OrganizationId = app.OrganizationId,
                Name = app.Name,
                ApplicationKey = app.ApplicationKey,
                ApplicationType = app.ApplicationType,
                IsActive = app.IsActive,
                CreatedAt = app.CreatedAt
                // (ApplicationResponse DTO에 필요한 다른 속성들 매핑...)
             }).ToList();

             return new ApplicationListResponse
             {
                 Items = dtoItems,
                 TotalCount = totalCount
             };
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

            var entities = await Query().Where(e => idList.Contains(e.Id)).ToListAsync(cancellationToken);
            if (!entities.Any()) return false;

            await base.DeleteRangeAsync(entities, cancellationToken); 
             _logger.LogWarning("Bulk soft deleted {Count} PlatformApplications by IDs", entities.Count);
            return true;
        }

        public async Task<int> GetCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId, cancellationToken);
        }

        public async Task<int> GetActiveCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId && app.IsActive, cancellationToken);
        }

        public async Task<Dictionary<ApplicationType, int>> GetCountByTypeAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await GetGroupCountAsync(
                app => app.ApplicationType, 
                app => EF.Property<Guid>(app, "OrganizationId") == organizationId, 
                cancellationToken);
        }

        #endregion

        #region Override BaseRepository Methods (Caching)
        
        public override async Task<PlatformApplicationEntity> AddAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
        {
             if (entity.OrganizationId == Guid.Empty)
             {
                 _logger.LogWarning("OrganizationId is empty for new PlatformApplication {AppName}.", entity.Name);
             }
            var result = await base.AddAsync(entity, cancellationToken);
            await InvalidateAppCachesAsync(result, cancellationToken); // 캐시 무효화
            return result;
        }

        public override async Task UpdateAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
        {
            await base.UpdateAsync(entity, cancellationToken); 
            await InvalidateAppCachesAsync(entity, cancellationToken); 
        }

       public override async Task DeleteAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken = default)
       {
            await base.DeleteAsync(entity, cancellationToken);
            await InvalidateAppCachesAsync(entity, cancellationToken);
       }

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

        private async Task InvalidateAppCachesAsync(PlatformApplicationEntity entity, CancellationToken cancellationToken)
        {
            if (_cacheService == null || entity == null) return;

            var tasks = new List<Task>();

            if (!string.IsNullOrEmpty(entity.ApplicationKey))
            {
                tasks.Add(_cacheService.RemoveAsync(GetCacheKey($"AppKey:{entity.ApplicationKey.ToLowerInvariant()}"), cancellationToken));
            }
            if (entity.OrganizationId != Guid.Empty)
            {
                tasks.Add(_cacheService.RemoveAsync($"Apps:Org:{entity.OrganizationId}", cancellationToken));
            }

            await Task.WhenAll(tasks);
             _logger.LogDebug("Invalidated specific caches for PlatformApplication {AppId}", entity.Id);
        }

        #endregion
    }
}