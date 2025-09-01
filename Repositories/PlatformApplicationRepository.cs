using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Common;
using AuthHive.Auth.Data.Context;

namespace AuthHive.Auth.Repositories.PlatformApplication;

/// <summary>
/// 플랫폼 애플리케이션 저장소 구현체 - AuthHive v15
/// v15 핵심: API 소비 및 자원 사용의 주체, 포인트 차감의 컨텍스트
/// </summary>
public class PlatformApplicationRepository : IPlatformApplicationRepository, IOrganizationScopedRepository<Core.Entities.PlatformApplications.PlatformApplication>
{
    private readonly AuthDbContext _context;
    private readonly DbSet<Core.Entities.PlatformApplications.PlatformApplication> _dbSet;

    public PlatformApplicationRepository(AuthDbContext context)
    {
        _context = context;
        _dbSet = context.Set<Core.Entities.PlatformApplications.PlatformApplication>();
    }

    #region IRepository<T> 기본 구현

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> GetByIdAsync(Guid id)
    {
        return await _dbSet
            .Include(x => x.Organization)
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .FirstOrDefaultAsync(x => x.Id == id && !x.IsDeleted);
    }

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> GetByIdNoTrackingAsync(Guid id)
    {
        return await _dbSet
            .AsNoTracking()
            .Include(x => x.Organization)
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .FirstOrDefaultAsync(x => x.Id == id && !x.IsDeleted);
    }

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> GetAllAsync()
    {
        return await _dbSet
            .Where(x => !x.IsDeleted)
            .ToListAsync();
    }

    public async Task<Core.Entities.PlatformApplications.PlatformApplication> AddAsync(Core.Entities.PlatformApplications.PlatformApplication entity)
    {
        await _dbSet.AddAsync(entity);
        await _context.SaveChangesAsync();
        return entity;
    }

    public async Task UpdateAsync(Core.Entities.PlatformApplications.PlatformApplication entity)
    {
        _dbSet.Update(entity);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(Guid id)
    {
        var entity = await GetByIdAsync(id);
        if (entity == null) return;

        entity.IsDeleted = true;
        entity.DeletedAt = DateTime.UtcNow;
        _dbSet.Update(entity);
        await _context.SaveChangesAsync();
    }

    public async Task<bool> SoftDeleteAsync(Guid id, Guid deletedByConnectedId)
    {
        var entity = await GetByIdAsync(id);
        if (entity == null) return false;

        entity.IsDeleted = true;
        entity.DeletedAt = DateTime.UtcNow;
        // deletedByConnectedId는 AuditableEntity의 감사 필드로 설정됨
        _dbSet.Update(entity);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> ExistsAsync(Guid id)
    {
        return await _dbSet.AnyAsync(x => x.Id == id && !x.IsDeleted);
    }

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> FindAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet
            .Where(predicate)
            .Where(x => !x.IsDeleted)
            .ToListAsync();
    }

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> FirstOrDefaultAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet
            .Where(predicate)
            .Where(x => !x.IsDeleted)
            .FirstOrDefaultAsync();
    }

    public async Task<bool> AnyAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet
            .Where(predicate)
            .Where(x => !x.IsDeleted)
            .AnyAsync();
    }

    public async Task<int> CountAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>>? predicate = null)
    {
        var query = _dbSet.Where(x => !x.IsDeleted);
        if (predicate != null)
            query = query.Where(predicate);
        return await query.CountAsync();
    }

    public async Task AddRangeAsync(IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> entities)
    {
        await _dbSet.AddRangeAsync(entities);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateRangeAsync(IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> entities)
    {
        _dbSet.UpdateRange(entities);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(Core.Entities.PlatformApplications.PlatformApplication entity)
    {
        await DeleteAsync(entity.Id);
    }

    public async Task DeleteRangeAsync(IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> entities)
    {
        foreach (var entity in entities)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
        }
        _dbSet.UpdateRange(entities);
        await _context.SaveChangesAsync();
    }

    public async Task SoftDeleteAsync(Guid id)
    {
        await DeleteAsync(id);
    }

    public async Task<bool> ExistsAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet.Where(predicate).Where(x => !x.IsDeleted).AnyAsync();
    }

    public async Task<(IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> Items, int TotalCount)> GetPagedAsync(
        int pageNumber,
        int pageSize,
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>>? predicate = null,
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, object>>? orderBy = null,
        bool isDescending = false)
    {
        var query = _dbSet.Where(x => !x.IsDeleted);

        if (predicate != null)
            query = query.Where(predicate);

        var totalCount = await query.CountAsync();

        if (orderBy != null)
        {
            query = isDescending 
                ? query.OrderByDescending(orderBy) 
                : query.OrderBy(orderBy);
        }

        var items = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (items, totalCount);
    }

    #endregion

    #region IOrganizationScopedRepository<T> 구현

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> GetByOrganizationIdAsync(Guid organizationId)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId && !x.IsDeleted)
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .ToListAsync();
    }

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
    {
        return await _dbSet
            .Include(x => x.Organization)
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .FirstOrDefaultAsync(x => x.Id == id && x.OrganizationId == organizationId && !x.IsDeleted);
    }

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> FindByOrganizationAsync(
        Guid organizationId, 
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId && !x.IsDeleted)
            .Where(predicate)
            .ToListAsync();
    }

    public async Task<(IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> Items, int TotalCount)> GetPagedByOrganizationAsync(
        Guid organizationId,
        int pageNumber,
        int pageSize,
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>>? additionalPredicate = null,
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, object>>? orderBy = null,
        bool isDescending = false)
    {
        var query = _dbSet.Where(x => x.OrganizationId == organizationId && !x.IsDeleted);

        if (additionalPredicate != null)
            query = query.Where(additionalPredicate);

        var totalCount = await query.CountAsync();

        if (orderBy != null)
        {
            query = isDescending 
                ? query.OrderByDescending(orderBy) 
                : query.OrderBy(orderBy);
        }

        var items = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (items, totalCount);
    }

    public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
    {
        return await _dbSet.AnyAsync(x => x.Id == id && x.OrganizationId == organizationId && !x.IsDeleted);
    }

    public async Task<int> CountByOrganizationAsync(
        Guid organizationId, 
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>>? predicate = null)
    {
        var query = _dbSet.Where(x => x.OrganizationId == organizationId && !x.IsDeleted);
        
        if (predicate != null)
            query = query.Where(predicate);
            
        return await query.CountAsync();
    }

    public async Task DeleteAllByOrganizationAsync(Guid organizationId)
    {
        var entities = await GetByOrganizationIdAsync(organizationId);
        
        foreach (var entity in entities)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
        }
        
        _dbSet.UpdateRange(entities);
        await _context.SaveChangesAsync();
    }

    #endregion

    #region IApplicationRepository 구현

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> GetByApplicationKeyAsync(string applicationKey)
    {
        return await _dbSet
            .Include(x => x.Organization)
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .FirstOrDefaultAsync(x => x.ApplicationKey == applicationKey && !x.IsDeleted);
    }

    public async Task<Core.Entities.PlatformApplications.PlatformApplication?> FindSingleAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>> predicate)
    {
        return await _dbSet
            .Where(predicate)
            .Where(x => !x.IsDeleted)
            .FirstOrDefaultAsync();
    }

    public async Task<PaginationResponse<Core.Entities.PlatformApplications.PlatformApplication>> GetPagedAsync(
        Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, bool>>? predicate,
        PaginationRequest pagination,
        params Expression<Func<Core.Entities.PlatformApplications.PlatformApplication, object>>[] includes)
    {
        var query = _dbSet.Where(x => !x.IsDeleted);

        if (predicate != null)
            query = query.Where(predicate);

        // Include 처리
        foreach (var include in includes)
        {
            query = query.Include(include);
        }

        var totalCount = await query.CountAsync();
        var items = await query
            .Skip((pagination.PageNumber - 1) * pagination.PageSize)
            .Take(pagination.PageSize)
            .ToListAsync();

        return new PaginationResponse<Core.Entities.PlatformApplications.PlatformApplication>
        {
            Items = items,
            TotalCount = totalCount,
            PageNumber = pagination.PageNumber,
            PageSize = pagination.PageSize
        };
    }

    public IQueryable<Core.Entities.PlatformApplications.PlatformApplication> GetQueryable()
    {
        return _dbSet.Where(x => !x.IsDeleted);
    }

    public async Task<bool> ExistsByApplicationKeyAsync(string applicationKey, Guid? excludeId = null)
    {
        var query = _dbSet.Where(x => x.ApplicationKey == applicationKey && !x.IsDeleted);

        if (excludeId.HasValue)
            query = query.Where(x => x.Id != excludeId.Value);

        return await query.AnyAsync();
    }

    public async Task<bool> IsDuplicateNameAsync(Guid organizationId, string name, Guid? excludeId = null)
    {
        var query = _dbSet.Where(x => x.OrganizationId == organizationId && 
                                     x.Name == name && 
                                     !x.IsDeleted);

        if (excludeId.HasValue)
            query = query.Where(x => x.Id != excludeId.Value);

        return await query.AnyAsync();
    }

    public async Task<bool> DeleteRangeAsync(IEnumerable<Guid> ids)
    {
        var applications = await _dbSet
            .Where(x => ids.Contains(x.Id) && !x.IsDeleted)
            .ToListAsync();

        foreach (var app in applications)
        {
            app.IsDeleted = true;
            app.DeletedAt = DateTime.UtcNow;
        }

        _dbSet.UpdateRange(applications);
        await _context.SaveChangesAsync();
        return applications.Any();
    }

    public async Task<int> GetCountByOrganizationAsync(Guid organizationId)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId && !x.IsDeleted)
            .CountAsync();
    }

    public async Task<int> GetActiveCountByOrganizationAsync(Guid organizationId)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId && 
                       x.Status == ApplicationStatus.Active && 
                       !x.IsDeleted)
            .CountAsync();
    }

    public async Task<Dictionary<string, int>> GetCountByTypeAsync(Guid organizationId)
    {
        return await _dbSet
            .Where(x => x.OrganizationId == organizationId && !x.IsDeleted)
            .GroupBy(x => x.ApplicationType)
            .ToDictionaryAsync(g => g.Key.ToString(), g => g.Count());
    }

    public async Task<int> SaveChangesAsync()
    {
        return await _context.SaveChangesAsync();
    }

    // IApplicationRepository에서 요구하는 특별한 반환 타입을 가진 메서드들
    async Task<Core.Entities.PlatformApplications.PlatformApplication> IPlatformApplicationRepository.AddAsync(Core.Entities.PlatformApplications.PlatformApplication application)
    {
        await _dbSet.AddAsync(application);
        await _context.SaveChangesAsync();
        return application;
    }

    async Task<Core.Entities.PlatformApplications.PlatformApplication> IPlatformApplicationRepository.UpdateAsync(Core.Entities.PlatformApplications.PlatformApplication application)
    {
        _dbSet.Update(application);
        await _context.SaveChangesAsync();
        return application;
    }

    async Task<bool> IPlatformApplicationRepository.DeleteAsync(Guid id)
    {
        var entity = await GetByIdAsync(id);
        if (entity == null) return false;

        entity.IsDeleted = true;
        entity.DeletedAt = DateTime.UtcNow;
        _dbSet.Update(entity);
        await _context.SaveChangesAsync();
        return true;
    }

    async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> IPlatformApplicationRepository.AddRangeAsync(
        IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> applications)
    {
        await _dbSet.AddRangeAsync(applications);
        await _context.SaveChangesAsync();
        return applications;
    }

    async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> IPlatformApplicationRepository.UpdateRangeAsync(
        IEnumerable<Core.Entities.PlatformApplications.PlatformApplication> applications)
    {
        _dbSet.UpdateRange(applications);
        await _context.SaveChangesAsync();
        return applications;
    }

    #endregion

    #region 비즈니스 메서드들

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> GetActiveApplicationsByOrganizationAsync(
        Guid organizationId,
        ApplicationEnvironment? environment = null)
    {
        var query = _dbSet
            .Where(x => x.OrganizationId == organizationId && 
                       x.Status == ApplicationStatus.Active &&
                       !x.IsDeleted);

        if (environment.HasValue)
        {
            query = query.Where(x => x.Environment == environment.Value);
        }

        return await query
            .Include(x => x.ApiKeys.Where(k => !k.IsDeleted))
            .OrderBy(x => x.Name)
            .ToListAsync();
    }

    public async Task<IEnumerable<Core.Entities.PlatformApplications.PlatformApplication>> GetQuotaExceededApplicationsAsync(
        Guid? organizationId = null,
        double thresholdPercentage = 80.0)
    {
        var query = _dbSet.Where(x => !x.IsDeleted && x.Status == ApplicationStatus.Active);

        if (organizationId.HasValue)
        {
            query = query.Where(x => x.OrganizationId == organizationId.Value);
        }

        return await query
            .Where(x => 
                // API 할당량 초과
                (x.MonthlyApiQuota > 0 && 
                 (x.CurrentMonthlyApiUsage * 100m / (decimal)x.MonthlyApiQuota) >= (decimal)thresholdPercentage) ||
                // 스토리지 할당량 초과
                (x.StorageQuotaGB > 0 && 
                 (x.CurrentStorageUsageGB * 100m / x.StorageQuotaGB) >= (decimal)thresholdPercentage))
            .Include(x => x.Organization)
            .OrderByDescending(x => x.CurrentMonthlyApiUsage)
            .ToListAsync();
    }

    public async Task UpdateApiUsageAsync(
        Guid applicationId,
        long dailyIncrement = 0,
        long monthlyIncrement = 0)
    {
        var application = await GetByIdAsync(applicationId);
        if (application == null) return;

        if (dailyIncrement > 0)
            application.CurrentDailyApiUsage += dailyIncrement;

        if (monthlyIncrement > 0)
            application.CurrentMonthlyApiUsage += monthlyIncrement;

        application.LastActivityAt = DateTime.UtcNow;
        
        _dbSet.Update(application);
        await _context.SaveChangesAsync();
    }

    #endregion
}

/*
TODO: DbContext OnModelCreating에서 설정
- ApplicationKey 유니크 인덱스
- (OrganizationId, ApplicationKey) 복합 유니크 인덱스
- (OrganizationId, Status) 복합 인덱스
- Status, ApplicationType, Environment 인덱스
- LastActivityAt 인덱스 (사용량 정렬용)
*/