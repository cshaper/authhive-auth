using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Infra.Persistence.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Infra.Persistence.Context;

namespace AuthHive.Auth.Repositories.User;

public class UserRepository : BaseRepository<AuthHive.Core.Entities.User.User>, IUserRepository
{
    public UserRepository(
        AuthDbContext context, 
        ILogger<UserRepository> logger,
        ICacheService? cacheService = null)
        : base(context, cacheService) 
    {
    }

    protected override bool IsOrganizationBaseEntity() => false;

    // 인터페이스에 정의된 특화 메서드만 구현 (나머지는 BaseRepository가 처리)

    public async Task<AuthHive.Core.Entities.User.User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        return await _dbSet.AsNoTracking()
            .FirstOrDefaultAsync(u => u.NormalizedEmail == email.ToUpperInvariant(), cancellationToken);
    }

    public async Task<AuthHive.Core.Entities.User.User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        return await _dbSet.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username == username, cancellationToken);
    }

    public async Task<bool> ExistsByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        return await _dbSet.AnyAsync(u => u.NormalizedEmail == email.ToUpperInvariant(), cancellationToken);
    }

    public async Task<bool> ExistsByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        return await _dbSet.AnyAsync(u => u.Username == username, cancellationToken);
    }
}