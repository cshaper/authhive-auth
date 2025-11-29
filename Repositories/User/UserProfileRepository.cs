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
using AuthHive.Infra.Persistence.Context;

namespace AuthHive.Auth.Repositories.User;

public class UserProfileRepository : BaseRepository<UserProfile>, IUserProfileRepository
{
    public UserProfileRepository(
        AuthDbContext context, 
        ILogger<UserProfileRepository> logger,
        ICacheService? cacheService = null)
        : base(context, cacheService) 
    {
    }

    protected override bool IsOrganizationBaseEntity() => false;

    #region 특화 조회

    public async Task<UserProfile?> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        // PK가 UserId인 경우 GetByIdAsync와 동일하지만, 명시적으로 구현
        return await _dbSet
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.UserId == userId, cancellationToken);
    }

    public async Task<IEnumerable<UserProfile>> GetByUserIdsAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default)
    {
        return await _dbSet
            .AsNoTracking()
            .Where(p => userIds.Contains(p.UserId))
            .ToListAsync(cancellationToken);
    }

    #endregion
}