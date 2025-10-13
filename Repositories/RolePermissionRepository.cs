using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading; // 💡 CancellationToken을 위해 추가
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging; // ILogger를 위해 필요
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// RolePermission Repository - 역할-권한 관계 관리 Repository
    /// AuthHive v15 역할 권한 시스템의 핵심 저장소
    /// </summary>
    public class RolePermissionRepository :
        BaseRepository<RolePermission>,
        IRolePermissionRepository
    {
        private readonly ILogger<RolePermissionRepository> _logger;
        // BaseRepository를 상속받으므로 _organizationContext는 필요없지만,
        // 생성자 시그니처 유지를 위해 필드만 남겨둡니다.
        private readonly IOrganizationContext _organizationContext; 

        public RolePermissionRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<RolePermissionRepository> logger)
            : base(context) // ICacheService가 주입되지 않으므로 base(context)만 사용
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
        }
        
        /// <summary>
        /// RolePermission 엔티티는 특정 조직에 속하므로, 멀티테넌시 필터링을 위해 true를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
        }

        #region 기본 조회

        /// <summary>
        /// 역할의 모든 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByRoleAsync(
            Guid roleId,
            bool activeOnly = true,
            bool includeInherited = true,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var query = Query().Where(rp => rp.RoleId == roleId);

            if (activeOnly)
            {
                query = query.Where(rp => rp.IsActive);
            }

            if (!includeInherited)
            {
                query = query.Where(rp => !rp.IsInherited);
            }

            return await query
                .Include(rp => rp.Permission!) // 널 허용 경고 억제를 위해 '!' 추가
                .OrderBy(rp => rp.Priority)
                .ThenBy(rp => rp.PermissionScope)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 특정 권한을 가진 역할들 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByPermissionAsync(
            Guid permissionId,
            Guid? organizationId = null,
            bool activeOnly = true,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var query = Query().Where(rp => rp.PermissionId == permissionId);

            // 특정 조직 필터링 (선택적)
            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value)
                    .Where(rp => rp.PermissionId == permissionId);
            }

            if (activeOnly)
            {
                query = query.Where(rp => rp.IsActive);
            }

            return await query
                .Include(rp => rp.Role!) // 널 허용 경고 억제를 위해 '!' 추가
                .OrderBy(rp => rp.Priority)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 스코프로 권한 조회
        /// </summary>
        public async Task<RolePermission?> GetByScopeAsync(
            Guid roleId, 
            string permissionScope,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .FirstOrDefaultAsync(rp =>
                    rp.RoleId == roleId &&
                    rp.PermissionScope == permissionScope,
                    cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 역할-권한 관계 존재 확인
        /// </summary>
        public async Task<bool> ExistsAsync(
            Guid roleId, 
            Guid permissionId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId,
                    cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 권한 할당 관리

        /// <summary>
        /// 역할에 권한 할당
        /// </summary>
        public async Task<RolePermission> AssignPermissionAsync(
            Guid roleId,
            Guid permissionId,
            Guid grantedBy,
            string? reason = null,
            DateTime? expiresAt = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            // 중복 체크
            var existing = await Query()
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId,
                    cancellationToken); // 👈 CancellationToken 전달

            if (existing != null)
            {
                throw new InvalidOperationException("Permission already assigned to role");
            }

            // Permission 정보 조회
            var permission = await _context.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Id == permissionId,
                    cancellationToken); // 👈 CancellationToken 전달

            if (permission == null)
            {
                throw new ArgumentException("Permission not found", nameof(permissionId));
            }

            // Role 정보 조회 (조직 정보 포함)
            var role = await _context.Set<Role>()
                .FirstOrDefaultAsync(r => r.Id == roleId,
                    cancellationToken); // 👈 CancellationToken 전달

            if (role == null)
            {
                throw new ArgumentException("Role not found", nameof(roleId));
            }
            
            // role.OrganizationId는 Guid? 일 수 있으나, RolePermission 엔티티가
            // OrganizationId를 Guid?로 정의했을 경우 안전합니다.
            var organizationId = role.OrganizationId; 

            var rolePermission = new RolePermission
            {
                Id = Guid.NewGuid(),
                RoleId = roleId,
                PermissionId = permissionId,
                PermissionScope = permission.Scope,
                GrantedByConnectedId = grantedBy,
                GrantedAt = DateTime.UtcNow,
                ExpiresAt = expiresAt,
                Reason = reason,
                IsActive = true,
                OrganizationId = organizationId, // 👈 Guid? 타입 사용 가정
                CreatedAt = DateTime.UtcNow
            };

            var result = await AddAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Assigned permission {PermissionId} to role {RoleId} by {GrantedBy}", 
                permissionId, roleId, grantedBy);
            
            return result;
        }

        /// <summary>
        /// 조건부 권한 할당
        /// </summary>
        public async Task<RolePermission> AssignConditionalPermissionAsync(
            Guid roleId,
            Guid permissionId,
            string conditions,
            Guid grantedBy,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            // AssignPermissionAsync도 CancellationToken을 받도록 수정했으므로 전달
            var rolePermission = await AssignPermissionAsync(roleId, permissionId, grantedBy, cancellationToken: cancellationToken);
            rolePermission.Conditions = conditions;
            await UpdateAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Assigned conditional permission {PermissionId} to role {RoleId}", 
                permissionId, roleId);
            
            return rolePermission;
        }

        /// <summary>
        /// 역할에서 권한 제거
        /// </summary>
        public async Task<bool> RemovePermissionAsync(
            Guid roleId,
            Guid permissionId,
            string? reason = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await Query()
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId,
                    cancellationToken); // 👈 CancellationToken 전달

            if (rolePermission == null) return false;

            await SoftDeleteAsync(rolePermission.Id, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogWarning("Removed permission {PermissionId} from role {RoleId}. Reason: {Reason}", 
                permissionId, roleId, reason ?? "Not specified");
            
            return true;
        }

        /// <summary>
        /// 권한 활성화/비활성화
        /// </summary>
        public async Task<bool> SetActiveStatusAsync(
            Guid rolePermissionId, 
            bool isActive,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (rolePermission == null) return false;

            rolePermission.IsActive = isActive;
            await UpdateAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Set permission {RolePermissionId} active status to {IsActive}", 
                rolePermissionId, isActive);
            
            return true;
        }

        /// <summary>
        /// 권한 갱신
        /// </summary>
        public async Task<bool> RenewPermissionAsync(
            Guid rolePermissionId, 
            DateTime newExpiresAt,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (rolePermission == null) return false;

            rolePermission.ExpiresAt = newExpiresAt;
            await UpdateAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Renewed permission {RolePermissionId} until {ExpiresAt}", 
                rolePermissionId, newExpiresAt);
            
            return true;
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 역할에 여러 권한 일괄 할당
        /// </summary>
        public async Task<PermissionAssignmentSummary> BulkAssignPermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> permissionIds,
            Guid grantedBy,
            string? reason = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var permissionIdList = permissionIds.ToList();
            var summary = new PermissionAssignmentSummary();

            // 기존 권한 체크
            var existingPermissions = await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdList.Contains(rp.PermissionId))
                .Select(rp => rp.PermissionId)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            var newPermissionIds = permissionIdList.Except(existingPermissions).ToList();

            if (!newPermissionIds.Any())
            {
                summary.TotalRequested = permissionIdList.Count;
                summary.AlreadyExists = existingPermissions.Count;
                return summary;
            }

            // Permission 및 Role 정보 조회
            var permissions = await _context.Set<Permission>()
                .Where(p => newPermissionIds.Contains(p.Id))
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            var role = await _context.Set<Role>()
                .FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken); // 👈 CancellationToken 전달

            if (role == null)
            {
                throw new ArgumentException("Role not found", nameof(roleId));
            }

            var rolePermissions = permissions.Select(p => new RolePermission
            {
                Id = Guid.NewGuid(),
                RoleId = roleId,
                PermissionId = p.Id,
                PermissionScope = p.Scope,
                GrantedByConnectedId = grantedBy,
                GrantedAt = DateTime.UtcNow,
                Reason = reason,
                IsActive = true,
                OrganizationId = role.OrganizationId,
                CreatedAt = DateTime.UtcNow
            }).ToList();

            await AddRangeAsync(rolePermissions, cancellationToken); // 👈 CancellationToken 전달

            summary.TotalRequested = permissionIdList.Count;
            summary.SuccessfullyAssigned = rolePermissions.Count;
            summary.AlreadyExists = existingPermissions.Count;
            summary.Failed = permissionIdList.Count - summary.SuccessfullyAssigned - summary.AlreadyExists;

            _logger.LogInformation("Bulk assigned {Count} permissions to role {RoleId}", 
                rolePermissions.Count, roleId);

            return summary;
        }

        /// <summary>
        /// 역할에서 여러 권한 일괄 제거
        /// </summary>
        public async Task<int> BulkRemovePermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> permissionIds,
            string? reason = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var permissionIdList = permissionIds.ToList();
            var rolePermissions = await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdList.Contains(rp.PermissionId))
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            if (!rolePermissions.Any()) return 0;

            await DeleteRangeAsync(rolePermissions, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogWarning("Bulk removed {Count} permissions from role {RoleId}. Reason: {Reason}", 
                rolePermissions.Count, roleId, reason ?? "Not specified");
            
            return rolePermissions.Count;
        }

        /// <summary>
        /// 역할의 모든 권한 제거
        /// </summary>
        public async Task<int> RemoveAllPermissionsAsync(
            Guid roleId, 
            string? reason = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermissions = await Query()
                .Where(rp => rp.RoleId == roleId)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            if (!rolePermissions.Any()) return 0;

            await DeleteRangeAsync(rolePermissions, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogWarning("Removed all {Count} permissions from role {RoleId}. Reason: {Reason}", 
                rolePermissions.Count, roleId, reason ?? "Not specified");
            
            return rolePermissions.Count;
        }

        /// <summary>
        /// 권한 교체
        /// </summary>
        public async Task<PermissionAssignmentSummary> ReplacePermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> newPermissionIds,
            Guid grantedBy,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var summary = new PermissionAssignmentSummary();

            // 기존 권한 모두 제거
            var removedCount = await RemoveAllPermissionsAsync(roleId, "Replacing permissions", cancellationToken); // 👈 CancellationToken 전달

            // 새 권한 할당
            var assignSummary = await BulkAssignPermissionsAsync(roleId, newPermissionIds, grantedBy, cancellationToken: cancellationToken); // 👈 CancellationToken 전달

            summary.TotalRequested = assignSummary.TotalRequested;
            summary.SuccessfullyAssigned = assignSummary.SuccessfullyAssigned;
            summary.PreviouslyRemoved = removedCount;

            _logger.LogInformation("Replaced permissions for role {RoleId}. Removed: {Removed}, Added: {Added}", 
                roleId, removedCount, assignSummary.SuccessfullyAssigned);

            return summary;
        }

        #endregion

        #region 상속 관리

        /// <summary>
        /// 상속된 권한 생성
        /// </summary>
        public async Task<RolePermission> CreateInheritedPermissionAsync(
            Guid sourceRolePermissionId,
            Guid targetRoleId,
            Guid grantedBy,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var sourceRolePermission = await GetByIdAsync(sourceRolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (sourceRolePermission == null)
            {
                throw new ArgumentException("Source role permission not found", nameof(sourceRolePermissionId));
            }

            var targetRole = await _context.Set<Role>()
                .FirstOrDefaultAsync(r => r.Id == targetRoleId, cancellationToken); // 👈 CancellationToken 전달
            
            if (targetRole == null)
            {
                throw new ArgumentException("Target role not found", nameof(targetRoleId));
            }

            var inheritedPermission = new RolePermission
            {
                Id = Guid.NewGuid(),
                RoleId = targetRoleId,
                PermissionId = sourceRolePermission.PermissionId,
                PermissionScope = sourceRolePermission.PermissionScope,
                GrantedByConnectedId = grantedBy,
                GrantedAt = DateTime.UtcNow,
                IsActive = sourceRolePermission.IsActive,
                IsInherited = true,
                InheritedFromId = sourceRolePermissionId,
                OrganizationId = targetRole.OrganizationId,
                CreatedAt = DateTime.UtcNow
            };

            var result = await AddAsync(inheritedPermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Created inherited permission from {SourceId} to role {TargetRoleId}", 
                sourceRolePermissionId, targetRoleId);
            
            return result;
        }

        /// <summary>
        /// 상속된 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetInheritedPermissionsAsync(
            Guid inheritedFromId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.InheritedFromId == inheritedFromId)
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 상속 체인 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetInheritanceChainAsync(
            Guid rolePermissionId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var chain = new List<RolePermission>();
            var current = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달

            while (current != null)
            {
                chain.Add(current);

                if (current.InheritedFromId.HasValue)
                {
                    // 재귀적인 호출이 아니므로 GetByIdAsync에 CancellationToken 전달
                    current = await GetByIdAsync(current.InheritedFromId.Value, cancellationToken); 
                }
                else
                {
                    current = null;
                }
            }

            return chain;
        }

        /// <summary>
        /// 상속된 권한 동기화
        /// </summary>
        public async Task<int> SyncInheritedPermissionsAsync(
            Guid sourceRoleId, 
            Guid targetRoleId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            // GetByRoleAsync에 CancellationToken 전달
            var sourcePermissions = await GetByRoleAsync(sourceRoleId, activeOnly: true, includeInherited: false, cancellationToken);
            var targetPermissions = await GetByRoleAsync(targetRoleId, activeOnly: true, includeInherited: true, cancellationToken);

            var syncCount = 0;
            // TODO: 실제 동기화 로직 구현
            
            _logger.LogInformation("Synced {Count} inherited permissions from role {SourceId} to {TargetId}", 
                syncCount, sourceRoleId, targetRoleId);

            return syncCount;
        }

        #endregion

        #region 만료 관리

        /// <summary>
        /// 만료된 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetExpiredPermissionsAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var query = Query()
                .Where(rp => rp.ExpiresAt.HasValue && rp.ExpiresAt <= DateTime.UtcNow);

            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value)
                    .Where(rp => rp.ExpiresAt.HasValue && rp.ExpiresAt <= DateTime.UtcNow);
            }

            return await query
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.ExpiresAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 만료 예정 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetExpiringPermissionsAsync(
            int daysUntilExpiry,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var expiryThreshold = DateTime.UtcNow.AddDays(daysUntilExpiry);

            var query = Query()
                .Where(rp => rp.ExpiresAt.HasValue &&
                            rp.ExpiresAt <= expiryThreshold &&
                            rp.ExpiresAt > DateTime.UtcNow);

            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value)
                    .Where(rp => rp.ExpiresAt.HasValue &&
                                 rp.ExpiresAt <= expiryThreshold &&
                                 rp.ExpiresAt > DateTime.UtcNow);
            }

            return await query
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.ExpiresAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 만료된 권한 정리
        /// </summary>
        public async Task<int> CleanupExpiredPermissionsAsync(
            int batchSize = 100,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var expiredPermissions = await Query()
                .Where(rp => rp.ExpiresAt.HasValue && rp.ExpiresAt <= DateTime.UtcNow)
                .Take(batchSize)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            if (!expiredPermissions.Any()) return 0;

            await DeleteRangeAsync(expiredPermissions, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Cleaned up {Count} expired permissions", expiredPermissions.Count);
            
            return expiredPermissions.Count;
        }

        #endregion

        #region 우선순위 관리

        /// <summary>
        /// 우선순위별 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByPriorityAsync(
            Guid roleId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId && rp.IsActive)
                .OrderBy(rp => rp.Priority)
                .ThenBy(rp => rp.PermissionScope)
                .Include(rp => rp.Permission!)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 우선순위 업데이트
        /// </summary>
        public async Task<bool> UpdatePriorityAsync(
            Guid rolePermissionId, 
            int newPriority,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (rolePermission == null) return false;

            rolePermission.Priority = newPriority;
            await UpdateAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Updated priority for permission {RolePermissionId} to {Priority}", 
                rolePermissionId, newPriority);
            
            return true;
        }

        /// <summary>
        /// 우선순위 재정렬
        /// </summary>
        public async Task<int> ReorderPrioritiesAsync(
            Guid roleId, 
            IEnumerable<Guid> orderedPermissionIds,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var permissionIdsList = orderedPermissionIds.ToList();
            var rolePermissions = await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdsList.Contains(rp.PermissionId))
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            int priority = 1;
            int updatedCount = 0;

            foreach (var permissionId in permissionIdsList)
            {
                var rolePermission = rolePermissions.FirstOrDefault(rp => rp.PermissionId == permissionId);
                if (rolePermission != null)
                {
                    rolePermission.Priority = priority++;
                    updatedCount++;
                }
            }

            if (updatedCount > 0)
            {
                await UpdateRangeAsync(rolePermissions, cancellationToken); // 👈 CancellationToken 전달
                _logger.LogInformation("Reordered {Count} permission priorities for role {RoleId}", 
                    updatedCount, roleId);
            }

            return updatedCount;
        }

        #endregion

        #region 조건부 권한

        /// <summary>
        /// 조건부 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetConditionalPermissionsAsync(
            Guid roleId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId &&
                            !string.IsNullOrEmpty(rp.Conditions) &&
                            rp.IsActive)
                .Include(rp => rp.Permission!)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 조건 평가
        /// </summary>
        public async Task<bool> EvaluateConditionsAsync(
            Guid rolePermissionId, 
            string context,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (rolePermission?.Conditions == null) return true;

            // TODO: 실제 조건 평가 로직 구현
            return true;
        }

        /// <summary>
        /// 조건 업데이트
        /// </summary>
        public async Task<bool> UpdateConditionsAsync(
            Guid rolePermissionId, 
            string newConditions,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 👈 CancellationToken 전달
            if (rolePermission == null) return false;

            rolePermission.Conditions = newConditions;
            await UpdateAsync(rolePermission, cancellationToken); // 👈 CancellationToken 전달
            
            _logger.LogInformation("Updated conditions for permission {RolePermissionId}", rolePermissionId);
            
            return true;
        }

        #endregion

        #region 충돌 검증

        /// <summary>
        /// 권한 충돌 확인
        /// </summary>
        public async Task<IEnumerable<RolePermission>> CheckPermissionConflictsAsync(
            Guid roleId, 
            Guid permissionId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId && rp.PermissionId == permissionId)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 중복 권한 확인
        /// </summary>
        public async Task<IEnumerable<RolePermission>> FindDuplicatePermissionsAsync(
            Guid roleId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId)
                .GroupBy(rp => rp.PermissionId)
                .Where(g => g.Count() > 1)
                .SelectMany(g => g)
                .Include(rp => rp.Permission!)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 순환 참조 확인
        /// </summary>
        public async Task<bool> CheckCircularReferenceAsync(
            Guid roleId, 
            Guid permissionId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            // 직접적인 순환 참조 확인
            var directCircular = await Query()
                .AnyAsync(rp => rp.RoleId == roleId &&
                                 rp.PermissionId == permissionId &&
                                 rp.InheritedFromId != null,
                                 cancellationToken); // 👈 CancellationToken 전달

            if (directCircular) return true;

            // 상속 체인을 통한 순환 참조 확인
            var visited = new HashSet<Guid>();
            // 재귀 호출 메서드에 CancellationToken 추가
            return await CheckCircularReferenceRecursiveAsync(roleId, permissionId, visited, cancellationToken); 
        }

        private async Task<bool> CheckCircularReferenceRecursiveAsync(
            Guid roleId,
            Guid permissionId,
            HashSet<Guid> visited,
            CancellationToken cancellationToken) // 👈 CancellationToken 추가
        {
            if (visited.Contains(roleId)) return true;
            visited.Add(roleId);

            var inheritedPermissions = await Query()
                .Where(rp => rp.RoleId == roleId && rp.IsInherited)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            foreach (var rp in inheritedPermissions)
            {
                if (rp.PermissionId == permissionId) return true;

                if (rp.InheritedFromId.HasValue)
                {
                    var sourceRolePermission = await GetByIdAsync(rp.InheritedFromId.Value, cancellationToken); // 👈 CancellationToken 전달
                    if (sourceRolePermission != null)
                    {
                        var hasCircular = await CheckCircularReferenceRecursiveAsync(
                            sourceRolePermission.RoleId, permissionId, new HashSet<Guid>(visited), cancellationToken); // 👈 CancellationToken 전달
                        if (hasCircular) return true;
                    }
                }
            }

            return false;
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 역할별 권한 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetPermissionCountByRoleAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.RoleId)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 권한별 할당 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetRoleCountByPermissionAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.PermissionId)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 가장 많이 할당된 권한
        /// </summary>
        public async Task<IEnumerable<(Guid PermissionId, int Count)>> GetMostAssignedPermissionsAsync(
            Guid organizationId,
            int limit = 10,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.PermissionId)
                .Select(g => new { PermissionId = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(limit)
                .Select(x => ValueTuple.Create(x.PermissionId, x.Count))
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 사용되지 않는 권한 찾기
        /// </summary>
        public async Task<IEnumerable<RolePermission>> FindUnusedPermissionsAsync(
            Guid organizationId,
            int inactiveDays = 90,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            return await QueryForOrganization(organizationId)
                .Where(rp => rp.CreatedAt < cutoffDate && !rp.IsActive)
                .Include(rp => rp.Permission!)
                .Include(rp => rp.Role!)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 감사 및 이력

        /// <summary>
        /// 권한 할당 이력 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetAssignmentHistoryAsync(
            Guid roleId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var query = Query().Where(rp => rp.RoleId == roleId);

            if (startDate.HasValue)
            {
                query = query.Where(rp => rp.GrantedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(rp => rp.GrantedAt <= endDate.Value);
            }

            return await query
                .Include(rp => rp.Permission!)
                .OrderByDescending(rp => rp.GrantedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 부여자별 권한 할당 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByGrantedByAsync(
            Guid grantedByConnectedId, 
            int limit = 100,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            return await Query()
                .Where(rp => rp.GrantedByConnectedId == grantedByConnectedId)
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderByDescending(rp => rp.GrantedAt)
                .Take(limit)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 고급 검색
        /// </summary>
        public async Task<PagedResult<RolePermission>> SearchAsync(
            Expression<Func<RolePermission, bool>> criteria,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var query = Query().Where(criteria);
            var totalCount = await query.CountAsync(cancellationToken); // 👈 CancellationToken 전달

            var items = await query
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            return PagedResult<RolePermission>.Create(items, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 스코프 패턴으로 검색
        /// </summary>
        public async Task<IEnumerable<RolePermission>> SearchByScopePatternAsync(
            string scopePattern,
            Guid organizationId,
            CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            var likePattern = scopePattern.Replace("*", "%");

            return await QueryForOrganization(organizationId)
                .Where(rp => EF.Functions.Like(rp.PermissionScope, likePattern))
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.PermissionScope)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region Unit of Work

        /// <summary>
        /// 변경사항 저장
        /// </summary>
        public async Task<int> SaveChangesAsync(
            CancellationToken cancellationToken = default)
        {
            return await _context.SaveChangesAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion
    }
}