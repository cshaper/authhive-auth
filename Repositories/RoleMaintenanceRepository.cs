using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 역할 할당의 유지보수(만료, 정리 등)를 위한 Repository 구현체
    /// 데이터 접근 계층으로서 ConnectedIdRole의 조회와 업데이트만 담당합니다.
    /// 실제 비즈니스 로직은 Service 계층에서 처리해야 합니다.
    /// </summary>
    public class RoleMaintenanceRepository : BaseRepository<ConnectedIdRole>, IRoleMaintenanceRepository
    {
        public RoleMaintenanceRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        /// <summary>
        /// 만료된 역할 조회
        /// ExpiresAt이 현재 시간보다 과거인 역할들을 반환
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiredRolesAsync(
            Guid? organizationId = null,
            bool includeInactive = false)
        {
            var now = DateTime.UtcNow;

            IQueryable<ConnectedIdRole> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Include(r => r.Role);
            query = query.Include(r => r.Connected);
            query = query.Include(r => r.PlatformApplication);

            // 만료 시간이 설정되어 있고 현재 시간보다 과거인 경우
            query = query.Where(r => r.ExpiresAt != null && r.ExpiresAt <= now);

            // includeInactive가 false면 활성 역할만
            if (!includeInactive)
            {
                query = query.Where(r => r.IsActive);
            }

            return await query
                .OrderBy(r => r.ExpiresAt)
                .ThenBy(r => r.AssignedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 만료 예정 역할 조회
        /// 지정된 일수 내에 만료될 역할들을 반환
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiringRolesAsync(
            int daysUntilExpiry,
            Guid? organizationId = null)
        {
            var now = DateTime.UtcNow;
            var expiryThreshold = now.AddDays(daysUntilExpiry);

            IQueryable<ConnectedIdRole> query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Include(r => r.Role);
            query = query.Include(r => r.Connected);
            query = query.Include(r => r.PlatformApplication);

            // 활성 상태이고, 만료 예정인 역할
            query = query.Where(r =>
                r.IsActive &&
                r.ExpiresAt != null &&
                r.ExpiresAt > now &&
                r.ExpiresAt <= expiryThreshold);

            return await query
                .OrderBy(r => r.ExpiresAt)
                .ThenBy(r => r.ConnectedId)
                .ToListAsync();
        }

        /// <summary>
        /// 만료된 역할 일괄 정리
        /// 만료되었지만 아직 활성 상태인 역할들을 비활성화
        /// 실제 정리 로직은 Service 계층에서 처리하고, 여기서는 데이터 업데이트만 수행
        /// </summary>
        public async Task<int> CleanupExpiredRolesAsync(int batchSize = 100)
        {
            var now = DateTime.UtcNow;
            var totalProcessed = 0;

            while (true)
            {
                // 만료되었지만 아직 활성인 역할들을 배치로 가져오기
                var expiredRoles = await Query()
                    .Where(r =>
                        r.IsActive &&
                        r.ExpiresAt != null &&
                        r.ExpiresAt <= now)
                    .Take(batchSize)
                    .ToListAsync();

                if (!expiredRoles.Any())
                    break;

                // 역할 비활성화
                foreach (var role in expiredRoles)
                {
                    role.IsActive = false;
                    role.UpdatedAt = now;
                    role.LastVerifiedAt = now;

                    // 캐시 무효화
                    InvalidateCache(role.Id);
                }

                _dbSet.UpdateRange(expiredRoles);
                var processed = await _context.SaveChangesAsync();
                totalProcessed += processed;

                // 배치 간 짧은 지연
                if (expiredRoles.Count == batchSize)
                    await Task.Delay(100);
            }

            return totalProcessed;
        }

        /// <summary>
        /// 특정 역할 할당 만료 처리
        /// 지정된 역할을 즉시 만료시킴
        /// </summary>
        public async Task<bool> ExpireRoleAsync(Guid roleAssignmentId, string? reason = null)
        {
            var role = await GetByIdAsync(roleAssignmentId);

            if (role == null || !role.IsActive)
                return false;

            var now = DateTime.UtcNow;

            // 역할 만료 처리
            role.ExpiresAt = now;
            role.IsActive = false;
            role.UpdatedAt = now;
            role.LastVerifiedAt = now;

            // 사유가 있으면 메타데이터에 기록
            if (!string.IsNullOrEmpty(reason))
            {
                var metadata = new Dictionary<string, object>
                {
                    ["ManualExpiration"] = true,
                    ["ExpiredAt"] = now,
                    ["Reason"] = reason
                };

                // 기존 메타데이터가 있으면 병합
                if (!string.IsNullOrEmpty(role.Metadata))
                {
                    try
                    {
                        var existing = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(role.Metadata);
                        if (existing != null)
                        {
                            foreach (var kvp in existing)
                            {
                                metadata.TryAdd(kvp.Key, kvp.Value);
                            }
                        }
                    }
                    catch
                    {
                        // 파싱 실패 시 무시
                    }
                }

                role.Metadata = System.Text.Json.JsonSerializer.Serialize(metadata);
            }

            await UpdateAsync(role);
            var result = await _context.SaveChangesAsync();

            // 캐시 무효화
            InvalidateCache(roleAssignmentId);

            return result > 0;
        }

        #region 추가 조회 메서드

        /// <summary>
        /// 조건부 역할 중 검증이 필요한 역할 조회
        /// LastVerified가 null이거나 지정된 시간보다 오래된 역할들
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetRolesNeedingVerificationAsync(
            int hoursThreshold = 24,
            int batchSize = 100)
        {
            var verificationThreshold = DateTime.UtcNow.AddHours(-hoursThreshold);

            return await Query()
                .Where(r =>
                    r.IsActive &&
                    r.IsConditional &&
                    (r.LastVerified == null || r.LastVerified < verificationThreshold))
                .OrderBy(r => r.LastVerified ?? DateTime.MinValue)
                .Take(batchSize)
                .ToListAsync();
        }

        /// <summary>
        /// 상속된 역할 중 원본이 없거나 비활성인 역할 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetOrphanedInheritedRolesAsync()
        {
            return await Query()
                .Include(r => r.InheritedFrom)
                .Where(r =>
                    r.IsActive &&
                    r.InheritedFromId != null &&
                    (r.InheritedFrom == null || !r.InheritedFrom.IsActive))
                .ToListAsync();
        }

        /// <summary>
        /// 특정 ConnectedId의 만료된 역할 이력 조회
        /// </summary>
        public async Task<IEnumerable<ConnectedIdRole>> GetExpiredRoleHistoryAsync(
            Guid connectedId,
            int? limit = null)
        {
            IQueryable<ConnectedIdRole> query = Query();
            query = query.Include(r => r.Role);
            query = query.Include(r => r.PlatformApplication);
            query = query.Where(r =>
                r.ConnectedId == connectedId &&
                !r.IsActive &&
                r.ExpiresAt != null &&
                r.ExpiresAt <= DateTime.UtcNow);
            query = query.OrderByDescending(r => r.ExpiresAt);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync();
        }

        /// <summary>
        /// 역할 검증 시간 업데이트
        /// </summary>
        public async Task UpdateVerificationTimeAsync(IEnumerable<Guid> roleIds)
        {
            var now = DateTime.UtcNow;
            var roles = await Query()
                .Where(r => roleIds.Contains(r.Id))
                .ToListAsync();

            foreach (var role in roles)
            {
                role.LastVerified = now;
                role.LastVerifiedAt = now;
                role.UpdatedAt = now;
            }

            if (roles.Any())
            {
                _dbSet.UpdateRange(roles);
                await _context.SaveChangesAsync();
            }
        }

        #endregion
    }
}