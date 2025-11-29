using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// [Base]
using AuthHive.Core.Entities.User; // UserSuspension Entity
using AuthHive.Core.Interfaces.User.Repositories; // Interface
using AuthHive.Infra.Persistence.Repositories.Base; // BaseRepository
using AuthHive.Auth.Data.Context; // DbContext
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Enums.Core;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Infra.Persistence.Context; // UserStatus, UserEnums

namespace AuthHive.Auth.Repositories.User;

/// <summary>
/// [Identity Core] 사용자 정지 이력 저장소 구현체 - v18 Standard
/// </summary>
public class UserSuspensionRepository : BaseRepository<UserSuspension>, IUserSuspensionRepository
{
    private readonly ILogger<UserSuspensionRepository> _logger;

    public UserSuspensionRepository(
        AuthDbContext context, 
        ILogger<UserSuspensionRepository> logger,
        ICacheService? cacheService = null)
        : base(context, cacheService) 
    {
        _logger = logger;
    }

    protected override bool IsOrganizationBaseEntity() => false;

    #region 특화 조회 (Clean Interface Implementation)

    /// <summary>
    /// 현재 활성화된(아직 만료되지 않은) 정지 내역 조회
    /// </summary>
    public async Task<UserSuspension?> GetActiveByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        
        return await _dbSet
            .AsNoTracking()
            .Where(s => s.UserId == userId)
            // 조건: 영구 정지이거나, 만료 예정일이 현재 시각보다 미래인 경우
            .Where(s => s.SuspendedUntil == null || s.SuspendedUntil > now)
            .OrderByDescending(s => s.SuspendedAt)
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// 특정 사용자의 모든 정지 이력 조회 (감사용)
    /// </summary>
    public async Task<IEnumerable<UserSuspension>> GetHistoryByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _dbSet
            .AsNoTracking()
            .Where(s => s.UserId == userId)
            .OrderByDescending(s => s.SuspendedAt)
            .ToListAsync(cancellationToken);
    }

    // [New] 정지 기간이 만료되었으나 User 상태가 아직 Suspended인 내역을 조회 (Background Job용)
    public async Task<IEnumerable<UserSuspension>> GetExpiredSuspensionsAsync(
        DateTime referenceTime, 
        CancellationToken cancellationToken = default)
    {
        // 1. 만료 기간이 지난 레코드 조회
        return await _dbSet
            .AsNoTracking()
            .Include(s => s.User) // User 상태 확인을 위해 Eager Loading
            .Where(s => s.SuspendedUntil != null && s.SuspendedUntil <= referenceTime)
            // 2. 해당 User의 현재 상태가 아직 정지(Suspended)인 경우만 반환
            .Where(s => s.User.Status == UserStatus.Suspended) 
            .ToListAsync(cancellationToken);
    }

    #endregion
}