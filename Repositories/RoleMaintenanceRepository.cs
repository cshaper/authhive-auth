using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Memory; // IMemoryCache 제거
using Microsoft.Extensions.Logging; // ILogger 추가
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
// using AuthHive.Auth.Services.Context; // IOrganizationContext 제거
// using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationContext 제거
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 추가
using System.Text.Json; // JsonSerializer 추가

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 역할 할당의 유지보수(만료, 정리 등)를 위한 Repository 구현체 - AuthHive v16
    /// [FIXED] BaseRepository 상속, ICacheService 사용, CancellationToken 적용
    /// </summary>
    public class RoleMaintenanceRepository : BaseRepository<ConnectedIdRole>, IRoleMaintenanceRepository
    {
         private readonly ILogger<RoleMaintenanceRepository> _logger;

        public RoleMaintenanceRepository(
            AuthDbContext context,
            // IOrganizationContext organizationContext, // 제거됨
            ICacheService? cacheService, // IMemoryCache -> ICacheService?
            ILogger<RoleMaintenanceRepository> logger) // 로거 주입
            : base(context, cacheService) // BaseRepository 생성자 호출 수정
        {
             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] BaseRepository 추상 메서드 구현. 역할 할당은 조직 범위에 속함 (true).
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;


        /// <summary>
        /// 만료된 역할 조회
        /// [FIXED] CancellationToken 추가, IQueryable 타입 명시
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiredRolesAsync(
            Guid? organizationId = null,
            // bool includeInactive = false, // 만료된 것은 비활성이어야 하므로 제거됨
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // 명시적 타입 IQueryable<ConnectedIdRole> 사용
            IQueryable<ConnectedIdRole> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query(); // Query()는 IsDeleted=false 포함

            query = query.Include(r => r.Role);
            query = query.Include(r => r.InheritedFrom); // Connected -> ConnectedUser (엔티티 이름 확인 필요)
            query = query.Include(r => r.PlatformApplication);

            // 만료 시간이 설정되어 있고 현재 시간보다 과거이며, 아직 활성 상태인 것 (정리 대상)
            // 또는 이미 비활성 상태인 만료된 역할도 포함 (단순 조회 목적)
            query = query.Where(r => r.ExpiresAt != null && r.ExpiresAt <= now);

            // if (!includeInactive) // 이 옵션은 의미가 모호하므로 제거함. 만료 조회는 보통 상태 무관.
            // {
            //     query = query.Where(r => r.IsActive);
            // }

            return await query
                .OrderBy(r => r.ExpiresAt)
                .ThenBy(r => r.AssignedAt)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료 예정 역할 조회
        /// [FIXED] CancellationToken 추가, IQueryable 타입 명시
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiringRolesAsync(
            int daysUntilExpiry,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var expiryThreshold = now.AddDays(daysUntilExpiry);

            IQueryable<ConnectedIdRole> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Include(r => r.Role);
            query = query.Include(r => r.InheritedFrom); // Connected -> ConnectedUser
            query = query.Include(r => r.PlatformApplication);

            // 활성 상태이고, 만료 예정인 역할
            query = query.Where(r =>
                r.IsActive && // 활성 상태
                r.ExpiresAt != null &&
                r.ExpiresAt > now && // 아직 만료되지 않았고
                r.ExpiresAt <= expiryThreshold); // 만료 예정일 이내

            return await query
                .OrderBy(r => r.ExpiresAt)
                .ThenBy(r => r.ConnectedId)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료된 역할 일괄 정리 (비활성화 처리)
        /// [FIXED] CancellationToken 추가, ExecuteUpdateAsync 사용 최적화
        /// </summary>
        public async Task<int> CleanupExpiredRolesAsync(int batchSize = 100, CancellationToken cancellationToken = default)
        {
            // TODO: 대량 업데이트는 DB 부하 고려하여 백그라운드 작업으로 실행 권장
            var now = DateTime.UtcNow;
            int totalProcessed = 0;

            // ExecuteUpdateAsync 사용 (EF Core 7+)
            // 만료되었지만 아직 활성 상태인 역할들을 대상으로 비활성화 처리
            totalProcessed = await Query()
                 .Where(r => r.IsActive && r.ExpiresAt != null && r.ExpiresAt <= now)
                 .ExecuteUpdateAsync(updates => updates
                     .SetProperty(r => r.IsActive, false)
                     .SetProperty(r => r.UpdatedAt, now)
                     .SetProperty(r => r.LastVerifiedAt, now) // 검증 시간도 업데이트
                     // .SetProperty(r => r.Metadata, ...) // 필요 시 메타데이터 업데이트
                     , cancellationToken);

            if (totalProcessed > 0)
            {
                _logger.LogInformation("Cleaned up (deactivated) {Count} expired roles.", totalProcessed);
                // TODO: 관련 캐시 무효화 필요 (영향받는 ConnectedId의 역할 캐시 등)
                // 캐시 무효화는 범위가 넓을 수 있으므로 서비스 계층에서 처리하는 것이 나을 수 있음
            }

            return totalProcessed;
        }

        /// <summary>
        /// 특정 역할 할당 만료 처리 (즉시 비활성화)
        /// [FIXED] CancellationToken 추가, ExecuteUpdateAsync 사용 최적화
        /// </summary>
        public async Task<bool> ExpireRoleAsync(Guid roleAssignmentId, string? reason = "Manually expired", CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // ExecuteUpdateAsync 사용
            int affectedRows = await Query()
                .Where(r => r.Id == roleAssignmentId && r.IsActive) // 활성 상태인 역할만 대상
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(r => r.ExpiresAt, now) // 만료 시간 설정
                    .SetProperty(r => r.IsActive, false) // 비활성화
                    .SetProperty(r => r.UpdatedAt, now)
                    .SetProperty(r => r.LastVerifiedAt, now)
                    // TODO: Metadata 업데이트 로직은 ExecuteUpdateAsync에서 직접 처리하기 어려움
                    // 필요 시 GetByIdAsync -> 수정 -> UpdateAsync 방식 사용 또는 Raw SQL 사용
                    // .SetProperty(r => r.Metadata, ...)
                    , cancellationToken);

            if (affectedRows > 0)
            {
                _logger.LogInformation("Expired role assignment {RoleAssignmentId}. Reason: {Reason}", roleAssignmentId, reason);
                await InvalidateCacheAsync(roleAssignmentId, cancellationToken); // BaseRepository 캐시 무효화
                // TODO: 추가 캐시 무효화 (예: 해당 ConnectedId의 역할 목록 캐시)
                return true;
            }
            else
            {
                _logger.LogWarning("Role assignment {RoleAssignmentId} not found or already inactive.", roleAssignmentId);
                return false;
            }
        }

        #region 추가 조회 메서드 (CancellationToken 추가)

        /// <summary>
        /// 조건부 역할 중 검증이 필요한 역할 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetRolesNeedingVerificationAsync(
            int hoursThreshold = 24,
            int batchSize = 100,
            CancellationToken cancellationToken = default)
        {
            var verificationThreshold = DateTime.UtcNow.AddHours(-hoursThreshold);

            return await Query()
                .Where(r =>
                    r.IsActive &&
                    r.IsConditional && // IsConditional 속성 필요
                    (r.LastVerifiedAt == null || r.LastVerifiedAt < verificationThreshold)) // LastVerified -> LastVerifiedAt
                .OrderBy(r => r.LastVerifiedAt ?? DateTime.MinValue)
                .Take(batchSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

/// <summary>
        /// 상속된 역할 중 원본이 없거나 비활성인 역할 조회 (고아 역할)
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetOrphanedInheritedRolesAsync(CancellationToken cancellationToken = default)
        {
            return await Query()
                // [FIXED] InheritedFromRoleAssignment -> InheritedFrom
                .Include(r => r.InheritedFrom)
                .Where(r =>
                    r.IsActive &&
                    r.InheritedFromId != null &&
                    (r.InheritedFrom == null || !r.InheritedFrom.IsActive))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }
        /// <summary>
        /// 특정 ConnectedId의 만료된 역할 할당 이력 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiredRoleHistoryAsync(
            Guid connectedId,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            // Query()는 IsDeleted=false 포함, 여기서는 만료된 비활성 역할을 찾음
            IQueryable<ConnectedIdRole> query = _dbSet // Query() 대신 _dbSet 사용 (IsDeleted 포함 가능성)
                 .IgnoreQueryFilters() // IsDeleted 필터 무시 (필요 시)
                 .Where(r => r.ConnectedId == connectedId &&
                             r.ExpiresAt != null &&
                             r.ExpiresAt <= DateTime.UtcNow); // 만료된 역할

            query = query.Include(r => r.Role);
            query = query.Include(r => r.PlatformApplication);
            query = query.OrderByDescending(r => r.ExpiresAt);

            if (limit.HasValue) query = query.Take(limit.Value);

            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 역할 검증 시간 업데이트
        /// [FIXED] CancellationToken 추가, ExecuteUpdateAsync 사용 최적화
        /// </summary>
        public async Task UpdateVerificationTimeAsync(
            IEnumerable<Guid> roleAssignmentIds, // roleIds -> roleAssignmentIds
            CancellationToken cancellationToken = default)
        {
            var idList = roleAssignmentIds?.ToList();
            if (idList == null || !idList.Any()) return;

            var now = DateTime.UtcNow;

            // ExecuteUpdateAsync 사용
            int updatedCount = await Query()
                .Where(r => idList.Contains(r.Id))
                .ExecuteUpdateAsync(updates => updates
                    // .SetProperty(r => r.LastVerified, now) // LastVerified 속성 확인 필요
                    .SetProperty(r => r.LastVerifiedAt, now) // LastVerified -> LastVerifiedAt
                    .SetProperty(r => r.UpdatedAt, now),
                    cancellationToken);

            if (updatedCount > 0)
            {
                _logger.LogInformation("Updated verification time for {Count} role assignments.", updatedCount);
                // TODO: 관련 캐시 무효화 (업데이트된 역할 할당 ID 기반)
                foreach(var id in idList) await InvalidateCacheAsync(id, cancellationToken);
            }
        }

        #endregion

        // [FIXED] SaveChangesAsync 제거 (Unit of Work 패턴 사용)
    }
}