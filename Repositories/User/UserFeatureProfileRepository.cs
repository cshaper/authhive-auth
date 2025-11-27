using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// [Base]
using AuthHive.Core.Entities.User; // UserFeatureProfile
using AuthHive.Core.Interfaces.User.Repository; // Interface
using AuthHive.Infra.Persistence.Repositories.Base; // BaseRepository
using AuthHive.Auth.Data.Context; // DbContext
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.User.Queries; // Search Query DTO
using AuthHive.Core.Models.Base;
using AuthHive.Infra.Persistence.Context; // PaginationResponse

namespace AuthHive.Auth.Repositories.User;

public class UserFeatureProfileRepository : BaseRepository<UserFeatureProfile>, IUserFeatureProfileRepository
{
    private readonly ILogger<UserFeatureProfileRepository> _logger;

    public UserFeatureProfileRepository(
        AuthDbContext context, 
        ILogger<UserFeatureProfileRepository> logger,
        ICacheService? cacheService = null)
        : base(context, cacheService) 
    {
        _logger = logger;
    }

    protected override bool IsOrganizationBaseEntity() => false;

    #region 특화 조회 (Domain Specific Query)

    public async Task<UserFeatureProfile?> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        // 캐시 키: UserFeatureProfile:UserId:{guid}
        // BaseRepository GetByIdAsync는 ID 기준이므로, 여기서는 UserId로 조회 (FK)
        // UserFeatureProfile은 PK가 없거나 Id가 있어도 UserId로 조회하는 게 핵심.
        // 여기서는 FK인 UserId로 조회.
        
        return await _dbSet
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.UserId == userId, cancellationToken);
    }

    public async Task<IEnumerable<UserFeatureProfile>> GetByUserIdsAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default)
    {
        return await _dbSet
            .AsNoTracking()
            .Where(p => userIds.Contains(p.UserId))
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 검색 및 통계 (Reporting)

    public async Task<(IEnumerable<UserFeatureProfile> Items, int TotalCount)> SearchAsync(
        SearchUserFeatureProfileQuery query,
        CancellationToken cancellationToken = default)
    {
        var dbQuery = Query().AsNoTracking();

        // 필터링 (예시: 프로필 완성도)
        if (query.MinCompleteness.HasValue)
        {
            dbQuery = dbQuery.Where(p => p.ProfileCompleteness >= query.MinCompleteness.Value);
        }

        // FeaturePreferences JSON 내부 검색은 성능상 지양하거나, 
        // PostgreSQL의 jsonb 연산자를 써야 함 (EF.Functions.JsonContains 등)
        // 여기서는 생략.

        var totalCount = await dbQuery.CountAsync(cancellationToken);

        var items = await dbQuery
            .OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
            .Skip((query.PageNumber - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToListAsync(cancellationToken);

        return (items, totalCount);
    }

    public async Task<IEnumerable<UserFeatureProfile>> GetInactiveProfilesAsync(
        DateTime cutoffDate,
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        return await Query()
            .AsNoTracking()
            .Where(p => (p.LastActivityAt == null && p.CreatedAt < cutoffDate) || (p.LastActivityAt < cutoffDate))
            .OrderBy(p => p.LastActivityAt)
            .Take(limit)
            .ToListAsync(cancellationToken);
    }

    #endregion
}