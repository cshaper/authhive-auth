using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Base;
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
// 엔티티 별칭 사용
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// PlatformApplication 엔티티의 데이터 접근을 담당하는 리포지토리입니다. (v16 리팩토링 적용)
    /// BaseRepository를 상속받아 공통 CRUD, 캐싱, 통계 기능을 재사용하며, PlatformApplication 고유의 조회 로직을 구현합니다.
    /// Unit of Work 패턴을 준수하며, 데이터베이스 저장은 서비스 계층의 IUnitOfWork가 담당합니다.
    /// </summary>
    public class PlatformApplicationRepository : BaseRepository<PlatformApplicationEntity>, IPlatformApplicationRepository
    {
        /// <summary>
        /// PlatformApplicationRepository의 생성자입니다.
        /// IOrganizationContext에 대한 의존성을 제거하고 ICacheService를 통한 캐싱을 사용합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="cacheService">하이브리드 캐시 서비스</param>
        public PlatformApplicationRepository(AuthDbContext context, ICacheService? cacheService)
            : base(context, cacheService)
        {
        }

        /// <summary>
        /// 이 리포지토리가 다루는 PlatformApplicationEntity가 조직 범위 엔티티임을 명시합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region IPlatformApplicationRepository 구현

        public async Task<PlatformApplicationEntity?> GetByIdNoTrackingAsync(Guid id, CancellationToken cancellationToken = default)
        {
            // Query() 메서드를 사용하여 IsDeleted = false 조건을 항상 보장합니다.
            return await Query().AsNoTracking().FirstOrDefaultAsync(app => app.Id == id, cancellationToken);
        }

        public async Task<PlatformApplicationEntity?> GetByApplicationKeyAsync(string applicationKey, CancellationToken cancellationToken = default)
        {
            return await Query().FirstOrDefaultAsync(app => app.ApplicationKey == applicationKey, cancellationToken);
        }

        public async Task<IEnumerable<PlatformApplicationEntity>> GetByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 조직 범위 쿼리 헬퍼를 활용합니다.
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .OrderBy(app => app.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var entity = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (entity == null || entity.IsDeleted) return false;

            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;

            // 엔티티가 AuditableEntity를 상속받는 경우, 삭제 주체를 기록합니다.
            if (entity is AuditableEntity auditableEntity)
            {
                auditableEntity.DeletedByConnectedId = deletedByConnectedId;
            }

            // UpdateAsync는 내부적으로 캐시를 무효화하며, DB 변경은 UnitOfWork가 담당합니다.
            await UpdateAsync(entity, cancellationToken);
            return true;
        }

        public async Task<PlatformApplicationEntity?> FindSingleAsync(Expression<Func<PlatformApplicationEntity, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await Query().AsNoTracking().FirstOrDefaultAsync(predicate, cancellationToken);
        }

        public async Task<PaginationResponse<PlatformApplicationEntity>> GetPagedAsync(
            Expression<Func<PlatformApplicationEntity, bool>>? predicate,
            PaginationRequest pagination,
            CancellationToken cancellationToken = default,
            params Expression<Func<PlatformApplicationEntity, object>>[] includes)
        {
            var query = Query().AsNoTracking();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            foreach (var include in includes)
            {
                query = query.Include(include);
            }

            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query
                .OrderBy(app => app.Name) // 기본 정렬 기준 추가
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize)
                .ToListAsync(cancellationToken);

            return PaginationResponse<PlatformApplicationEntity>.Create(items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        public async Task<bool> ExistsByApplicationKeyAsync(string applicationKey, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(app => app.ApplicationKey == applicationKey);
            if (excludeId.HasValue)
            {
                query = query.Where(app => app.Id != excludeId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> IsDuplicateNameAsync(Guid organizationId, string name, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(app => app.Name == name);
            if (excludeId.HasValue)
            {
                query = query.Where(app => app.Id != excludeId.Value);
            }
            return await query.AnyAsync(cancellationToken);
        }

        public async Task<bool> DeleteRangeAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
        {
            var entities = await _dbSet.Where(e => ids.Contains(e.Id) && !e.IsDeleted).ToListAsync(cancellationToken);
            if (!entities.Any()) return false;
            
            // BaseRepository의 DeleteRangeAsync(IEnumerable<TEntity>)를 호출하여 로직을 재사용합니다.
            await base.DeleteRangeAsync(entities, cancellationToken); 
            return true;
        }

        public async Task<int> GetCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId, cancellationToken);
        }

        public async Task<int> GetActiveCountByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // PlatformApplicationEntity에 IsActive 속성이 있다고 가정합니다.
            return await CountAsync(app => EF.Property<Guid>(app, "OrganizationId") == organizationId && app.IsActive, cancellationToken);
        }

        public async Task<Dictionary<string, int>> GetCountByTypeAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // PlatformApplicationEntity에 ApplicationType 속성이 있다고 가정합니다.
            // .NET 8 / EF Core 8 환경에서는 Enum.ToString() 변환을 지원합니다.
            return await GetGroupCountAsync(
                app => app.ApplicationType.ToString(),
                app => EF.Property<Guid>(app, "OrganizationId") == organizationId,
                cancellationToken);
        }

        #endregion
    }
}