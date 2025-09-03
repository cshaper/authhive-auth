using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

// 엔티티 별칭
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;
// 인터페이스 네임스페이스 (프로젝트에 맞게 확인)
using AuthHive.Core.Interfaces.PlatformApplication.Repository;

namespace AuthHive.Auth.Repositories
{
    public class PlatformApplicationRepository : BaseRepository<PlatformApplicationEntity>, IPlatformApplicationRepository
    {
        public PlatformApplicationRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region IPlatformApplicationRepository 구현

        // BaseRepository의 GetByIdAsync를 그대로 사용
        // 인터페이스에서 요구하는 GetByIdAsync는 BaseRepository에서 구현됨

        public async Task<PlatformApplicationEntity?> GetByIdNoTrackingAsync(Guid id)
        {
            return await Query().AsNoTracking().FirstOrDefaultAsync(app => app.Id == id);
        }

        public async Task<PlatformApplicationEntity?> GetByApplicationKeyAsync(string applicationKey)
        {
            return await Query().FirstOrDefaultAsync(app => app.ApplicationKey == applicationKey);
        }

        // BaseRepository에서 이미 구현된 GetByOrganizationIdAsync를 override로 재정의하거나
        // 다른 이름으로 메서드를 만들어야 함. 여기서는 BaseRepository 것을 사용하되 명시적으로 override
        public override async Task<IEnumerable<PlatformApplicationEntity>> GetByOrganizationIdAsync(Guid organizationId)
        {
            // BaseRepository의 기본 구현을 활용
            return await base.GetByOrganizationIdAsync(organizationId);
        }

        // 추가적인 조직별 조회가 필요하다면 새로운 이름으로 메서드 생성
        public async Task<IEnumerable<PlatformApplicationEntity>> GetApplicationsByOrganizationAsync(Guid organizationId)
        {
            return await Query()
                .Where(app => app.OrganizationId == organizationId)
                .OrderBy(app => app.Name)
                .ToListAsync();
        }

        // 인터페이스 요구사항: AddAsync(PlatformApplication) 구현
        // BaseRepository의 AddAsync를 확장하여 SaveChanges까지 처리
        async Task<PlatformApplicationEntity> IPlatformApplicationRepository.AddAsync(PlatformApplicationEntity application)
        {
            var result = await base.AddAsync(application);
            await SaveChangesAsync();
            return result;
        }

        // 인터페이스 요구사항: UpdateAsync(PlatformApplication) 구현
        // BaseRepository의 UpdateAsync를 확장하여 SaveChanges까지 처리 및 반환값 추가
        async Task<PlatformApplicationEntity> IPlatformApplicationRepository.UpdateAsync(PlatformApplicationEntity application)
        {
            await base.UpdateAsync(application);
            await SaveChangesAsync();
            return application;
        }

        // 인터페이스 요구사항: DeleteAsync(Guid) 구현
        // BaseRepository에는 DeleteAsync(TEntity)만 있으므로 새로운 기능으로 구현
        async Task<bool> IPlatformApplicationRepository.DeleteAsync(Guid id)
        {
            var entity = await GetByIdAsync(id);
            if (entity == null) return false;

            await base.DeleteAsync(entity);
            return await SaveChangesAsync() > 0;
        }

        // 인터페이스 요구사항: SoftDeleteAsync(Guid, Guid) 구현
        // BaseRepository에는 SoftDeleteAsync(Guid)만 있으므로 새로운 기능으로 구현
        async Task<bool> IPlatformApplicationRepository.SoftDeleteAsync(Guid id, Guid deletedByConnectedId)
        {
            var entity = await GetByIdAsync(id);
            if (entity == null) return false;

            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            // deletedByConnectedId 속성이 있다면 설정 (엔티티 구조에 따라)
            // entity.DeletedBy = deletedByConnectedId;

            await base.UpdateAsync(entity);
            return await SaveChangesAsync() > 0;
        }

        // BaseRepository의 FindAsync를 그대로 사용
        // 인터페이스에서 요구하는 FindAsync는 BaseRepository에서 구현됨

        public async Task<PlatformApplicationEntity?> FindSingleAsync(Expression<Func<PlatformApplicationEntity, bool>> predicate)
        {
            return await Query().FirstOrDefaultAsync(predicate);
        }

        // 인터페이스 요구사항: GetPagedAsync with includes 구현
        // BaseRepository의 GetPagedAsync와 다른 시그니처이므로 새로운 기능으로 구현
        async Task<PaginationResponse<PlatformApplicationEntity>> IPlatformApplicationRepository.GetPagedAsync(
            Expression<Func<PlatformApplicationEntity, bool>>? predicate,
            PaginationRequest pagination,
            params Expression<Func<PlatformApplicationEntity, object>>[] includes)
        {
            var query = Query();

            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            foreach (var include in includes)
            {
                query = query.Include(include);
            }

            var totalCount = await query.CountAsync();
            var items = await query
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize)
                .ToListAsync();

            // PaginationResponse.Create 메서드가 없다면 생성자 사용
            return PaginationResponse<PlatformApplicationEntity>.Create(items, totalCount, pagination.PageNumber, pagination.PageSize);
        }

        public IQueryable<PlatformApplicationEntity> GetQueryable()
        {
            return Query();
        }

        // BaseRepository의 ExistsAsync(Guid)를 그대로 사용
        // 인터페이스에서 요구하는 ExistsAsync는 BaseRepository에서 구현됨

        public async Task<bool> ExistsByApplicationKeyAsync(string applicationKey, Guid? excludeId = null)
        {
            var query = Query().Where(app => app.ApplicationKey == applicationKey);
            if (excludeId.HasValue)
            {
                query = query.Where(app => app.Id != excludeId.Value);
            }
            return await query.AnyAsync();
        }

        public async Task<bool> IsDuplicateNameAsync(Guid organizationId, string name, Guid? excludeId = null)
        {
            var query = Query().Where(app => app.OrganizationId == organizationId && app.Name == name);
            if (excludeId.HasValue)
            {
                query = query.Where(app => app.Id != excludeId.Value);
            }
            return await query.AnyAsync();
        }

        // 인터페이스 요구사항: AddRangeAsync 구현
        // BaseRepository의 AddRangeAsync를 확장하여 SaveChanges까지 처리 및 반환값 추가
        async Task<IEnumerable<PlatformApplicationEntity>> IPlatformApplicationRepository.AddRangeAsync(IEnumerable<PlatformApplicationEntity> applications)
        {
            await base.AddRangeAsync(applications);
            await SaveChangesAsync();
            return applications;
        }

        // 인터페이스 요구사항: UpdateRangeAsync 구현  
        // BaseRepository의 UpdateRangeAsync를 확장하여 SaveChanges까지 처리 및 반환값 추가
        async Task<IEnumerable<PlatformApplicationEntity>> IPlatformApplicationRepository.UpdateRangeAsync(IEnumerable<PlatformApplicationEntity> applications)
        {
            await base.UpdateRangeAsync(applications);
            await SaveChangesAsync();
            return applications;
        }

        // 인터페이스 요구사항: DeleteRangeAsync(IEnumerable<Guid>) 구현
        // BaseRepository에는 DeleteRangeAsync(IEnumerable<TEntity>)만 있으므로 새로운 기능으로 구현
        async Task<bool> IPlatformApplicationRepository.DeleteRangeAsync(IEnumerable<Guid> ids)
        {
            var entities = await Query().Where(e => ids.Contains(e.Id)).ToListAsync();
            if (!entities.Any()) return false;

            await base.DeleteRangeAsync(entities);
            return await SaveChangesAsync() > 0;
        }

        public async Task<int> GetCountByOrganizationAsync(Guid organizationId)
        {
            // BaseRepository의 CountByOrganizationAsync가 있다면 활용
            return await CountByOrganizationAsync(organizationId);
        }

        public async Task<int> GetActiveCountByOrganizationAsync(Guid organizationId)
        {
            return await CountByOrganizationAsync(organizationId, app => app.IsActive);
        }

        public async Task<Dictionary<string, int>> GetCountByTypeAsync(Guid organizationId)
        {
            // BaseRepository의 GetGroupCountAsync 활용
            return await GetGroupCountAsync(
                app => app.ApplicationType.ToString(),
                app => app.OrganizationId == organizationId);
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }

        #endregion

        #region BaseRepository 메서드 활용 예시

        /// <summary>
        /// BaseRepository의 페이징 기능을 활용한 조직별 애플리케이션 조회
        /// </summary>
        public async Task<(IEnumerable<PlatformApplicationEntity> Items, int TotalCount)> GetPagedByOrganizationAsync(
            Guid organizationId,
            int pageNumber = 1,
            int pageSize = 10,
            bool activeOnly = false)
        {
            Expression<Func<PlatformApplicationEntity, bool>> predicate = app => app.OrganizationId == organizationId;

            if (activeOnly)
            {
                predicate = app => app.OrganizationId == organizationId && app.IsActive;
            }

            return await GetPagedAsync(
                pageNumber,
                pageSize,
                predicate,
                app => app.Name); // 이름순 정렬
        }

        /// <summary>
        /// BaseRepository의 통계 기능을 활용한 애플리케이션 상태별 통계
        /// </summary>
        public async Task<Dictionary<bool, int>> GetStatusStatisticsAsync(Guid organizationId)
        {
            return await GetGroupCountAsync(
                app => app.IsActive,
                app => app.OrganizationId == organizationId);
        }

        /// <summary>
        /// BaseRepository의 날짜별 통계 기능 활용
        /// </summary>
        public async Task<Dictionary<DateTime, int>> GetDailyCreationStatsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            return await GetDailyCountAsync(
                app => app.CreatedAt,
                startDate,
                endDate,
                app => app.OrganizationId == organizationId);
        }

        #endregion
    }
}