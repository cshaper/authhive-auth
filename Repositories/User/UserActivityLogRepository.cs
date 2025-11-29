using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// [Base]
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Infra.Persistence.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Queries; // SearchUserActivityLogsQuery
using AuthHive.Core.Models.Base; // PaginationResponse
using AuthHive.Core.Models.User.Responses;
using AuthHive.Infra.Persistence.Context;
using AuthHive.Core.Models.User.Queries.Activity; // UserActivityLogResponse

namespace AuthHive.Auth.Repositories.User;

public class UserActivityLogRepository : BaseRepository<UserActivityLog>, IUserActivityLogRepository
{
    private readonly ILogger<UserActivityLogRepository> _logger;

    public UserActivityLogRepository(
        AuthDbContext context, 
        ILogger<UserActivityLogRepository> logger,
        ICacheService? cacheService = null)
        : base(context, cacheService) 
    {
        _logger = logger;
    }

    protected override bool IsOrganizationBaseEntity() => false; // GlobalBaseEntity 상속

    #region 특화 조회 (Recent Logs)

    public async Task<IEnumerable<UserActivityLog>> GetRecentByUserIdAsync(Guid userId, int count = 20, CancellationToken cancellationToken = default)
    {
        return await _dbSet
            .AsNoTracking()
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.CreatedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<UserActivityLog>> GetRecentByConnectedIdAsync(Guid connectedId, int count = 20, CancellationToken cancellationToken = default)
    {
        return await _dbSet
            .AsNoTracking()
            .Where(l => l.ConnectedId == connectedId)
            .OrderByDescending(l => l.CreatedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region 검색 (Search)

    public async Task<(IEnumerable<UserActivityLog> Items, int TotalCount)> SearchAsync(
        SearchUserActivityLogsQuery query, 
        CancellationToken cancellationToken = default)
    {
        var dbQuery = Query().AsNoTracking();

        // 동적 필터링
        if (query.UserId.HasValue) 
            dbQuery = dbQuery.Where(l => l.UserId == query.UserId.Value);
            
        if (query.ConnectedId.HasValue) 
            dbQuery = dbQuery.Where(l => l.ConnectedId == query.ConnectedId.Value);
            
        if (query.ActivityType.HasValue) 
            dbQuery = dbQuery.Where(l => l.ActivityType == query.ActivityType.Value);
            
        if (query.IsSuccessful.HasValue) 
            dbQuery = dbQuery.Where(l => l.IsSuccessful == query.IsSuccessful.Value);

        if (query.FromDate.HasValue) 
            dbQuery = dbQuery.Where(l => l.CreatedAt >= query.FromDate.Value);
            
        if (query.ToDate.HasValue) 
            dbQuery = dbQuery.Where(l => l.CreatedAt <= query.ToDate.Value);

        var totalCount = await dbQuery.CountAsync(cancellationToken);

        var items = await dbQuery
            .OrderByDescending(l => l.CreatedAt)
            .Skip((query.PageNumber - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToListAsync(cancellationToken);

        return (items, totalCount);
    }

    #endregion
}