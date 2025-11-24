using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;

using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Interfaces.Infra.Cache; // 💡 ICacheService 네임스페이스 추가


namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// RolePermission Repository - 역할-권한 관계 관리 Repository (v16 Refactored)
    /// AuthHive v16 역할 권한 시스템의 핵심 저장소. BaseRepository<T>를 상속받아 캐싱 및 기본 CRUD 활용.
    /// </summary>
    public class RolePermissionRepository :
        BaseRepository<RolePermission>,
        IRolePermissionRepository
    {
        private readonly ILogger<RolePermissionRepository> _logger;
        // AuthDbContext와 ICacheService는 BaseRepository에서 관리합니다.

        // 생성자에서 IOrganizationContext 제거, ICacheService 주입 추가
        public RolePermissionRepository(
            AuthDbContext context,
            ICacheService cacheService, // 💡 ICacheService 주입
            ILogger<RolePermissionRepository> logger)
            : base(context, cacheService) // 💡 base 생성자에 cacheService 전달
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        }

        /// <summary>
        /// RolePermission 엔티티는 특정 조직에 속하므로, 멀티테넌시 필터링 및 조직별 캐싱을 위해 true를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity()
        {
            return true;
        }
        #region 캐시 무효화 (조직 범위 엔티티 오버라이드)

        // 조직 범위 엔티티이므로, CUD 작업 시 조직 ID를 포함하는
        // BaseRepository.InvalidateCacheAsync(Guid id, Guid organizationId, ...)를 호출하도록 오버라이드합니다.

        public override async Task UpdateAsync(RolePermission entity, CancellationToken cancellationToken = default)
        {
            _context.Entry(entity).State = EntityState.Modified;
            // 수정: 올바른 base 메서드 호출
            await base.InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken);
        }

        public override async Task UpdateRangeAsync(IEnumerable<RolePermission> entities, CancellationToken cancellationToken = default)
        {
            _dbSet.UpdateRange(entities);
            // 수정: 올바른 base 메서드 호출
            var tasks = entities.Select(e => base.InvalidateCacheAsync(e.Id, e.OrganizationId, cancellationToken));
            await Task.WhenAll(tasks);
        }

        public override async Task DeleteAsync(RolePermission entity, CancellationToken cancellationToken = default)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            _context.Entry(entity).State = EntityState.Modified;
            // 수정: 올바른 base 메서드 호출
            await base.InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken);
        }
        public override async Task SoftDeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var entity = await _dbSet.FindAsync(new object[] { id }, cancellationToken);
            if (entity != null)
            {
                // DeleteAsync는 이미 수정된 InvalidateCacheAsync를 호출합니다.
                await DeleteAsync(entity, cancellationToken);
            }
        }


        public override async Task DeleteRangeAsync(IEnumerable<RolePermission> entities, CancellationToken cancellationToken = default)
        {
            var timestamp = DateTime.UtcNow;
            var tasks = new List<Task>();
            foreach (var entity in entities)
            {
                entity.IsDeleted = true;
                entity.DeletedAt = timestamp;
                // 수정: 올바른 base 메서드 호출
                tasks.Add(base.InvalidateCacheAsync(entity.Id, entity.OrganizationId, cancellationToken));
            }
            _dbSet.UpdateRange(entities);
            await Task.WhenAll(tasks);
        }

        #endregion

        #region 기본 조회

        /// <summary>
        /// 역할의 모든 권한 조회 (활성, 상속 여부 필터링 가능)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByRoleAsync(
            Guid roleId,
            bool activeOnly = true,
            bool includeInherited = true,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query() 메서드를 사용하여 기본 필터링(IsDeleted = false) 적용
            var query = Query().Where(rp => rp.RoleId == roleId);

            if (activeOnly)
            {
                query = query.Where(rp => rp.IsActive);
            }

            if (!includeInherited)
            {
                query = query.Where(rp => !rp.IsInherited);
            }

            // AsNoTracking()을 사용하여 성능 최적화 (조회 전용)
            return await query
                .Include(rp => rp.Permission!) // Nullable 참조 타입 로딩
                .OrderBy(rp => rp.Priority)
                .ThenBy(rp => rp.PermissionScope)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 권한 ID를 가진 역할-권한 관계 조회 (조직 필터링 가능)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByPermissionAsync(
            Guid permissionId,
            Guid? organizationId = null, // 명시적 organizationId 파라미터 사용
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            IQueryable<RolePermission> query;

            // organizationId가 제공되면 해당 조직으로 필터링, 아니면 전체 조직에서 검색 (IsOrganizationBaseEntity 활용)
            if (organizationId.HasValue && IsOrganizationBaseEntity())
            {
                query = QueryForOrganization(organizationId.Value) // BaseRepository의 헬퍼 메서드 사용
                        .Where(rp => rp.PermissionId == permissionId);
            }
            else
            {
                // IsOrganizationBaseEntity()가 false이거나 organizationId가 null이면,
                // 기본 Query() (IsDeleted=false만 필터링) 사용
                query = Query().Where(rp => rp.PermissionId == permissionId);
            }


            if (activeOnly)
            {
                query = query.Where(rp => rp.IsActive);
            }

            return await query
                .Include(rp => rp.Role!) // Nullable 참조 타입 로딩
                .OrderBy(rp => rp.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 역할 ID와 권한 스코프 문자열로 특정 역할-권한 관계 조회
        /// </summary>
        public async Task<RolePermission?> GetByScopeAsync(
            Guid roleId,
            string permissionScope,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 FirstOrDefaultAsync 사용 가능 (AsNoTracking 내장)
            return await FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionScope == permissionScope, cancellationToken);

            /* 위 FirstOrDefaultAsync 사용으로 대체 가능
             return await Query()
                 .AsNoTracking() // 성능 최적화
                 .FirstOrDefaultAsync(rp =>
                     rp.RoleId == roleId &&
                     rp.PermissionScope == permissionScope,
                     cancellationToken);
            */
        }

        /// <summary>
        /// 역할 ID와 권한 ID로 관계 존재 여부 확인
        /// </summary>
        public async Task<bool> ExistsAsync(
            Guid roleId,
            Guid permissionId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 AnyAsync 사용
            return await AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, cancellationToken);
        }

        #endregion

        #region 권한 할당 관리 (Repository 책임: 데이터 생성/수정/삭제)

        /// <summary>
        /// 역할에 권한 할당 (데이터 생성)
        /// </summary>
        public async Task<RolePermission> AssignPermissionAsync(
            Guid roleId,
            Guid permissionId,
            Guid grantedBy, // ConnectedId
            string? reason = null,
            DateTime? expiresAt = null,
            CancellationToken cancellationToken = default)
        {
            // 1. 중복 체크 (DB 조회)
            // AnyAsync 사용이 더 효율적
            bool exists = await AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, cancellationToken);
            if (exists)
            {
                // 중복 시 예외 발생 (서비스 레벨에서 처리할 수도 있음)
                throw new InvalidOperationException($"Permission '{permissionId}' is already assigned to role '{roleId}'.");
            }


            // 2. 관련 엔티티 조회 (Permission, Role) - 새 RolePermission 생성을 위함
            // AsNoTracking 사용: 상태 추적이 필요 없으므로 성능 향상
            var permission = await _context.Set<Permission>()
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == permissionId, cancellationToken);

            if (permission == null)
            {
                throw new ArgumentException($"Permission with ID '{permissionId}' not found.", nameof(permissionId));
            }

            // Role 조회 시 OrganizationId도 필요하므로 추적 필요 없음
            var role = await _context.Set<Role>()
                 .AsNoTracking() // Role 정보만 필요하므로 NoTracking
                .FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken);

            if (role == null)
            {
                throw new ArgumentException($"Role with ID '{roleId}' not found.", nameof(roleId));
            }

            // RolePermission 엔티티가 OrganizationBaseEntity를 상속받으므로 OrganizationId는 필수
            if (role.OrganizationId == Guid.Empty)
            {
                // Role에 OrganizationId가 없는 경우 (시스템 Role 등) 처리 방안 필요
                // 여기서는 예외를 발생시키거나 로깅 후 null을 반환하는 등의 처리가 가능
                // 여기서는 예외 발생
                throw new InvalidOperationException($"Role '{roleId}' must belong to an organization to assign permissions.");
            }


            // 3. 새 RolePermission 엔티티 생성
            var rolePermission = new RolePermission
            {
                // Id = Guid.NewGuid(), // BaseEntity에서 처리하거나 DB에서 자동 생성될 수 있음
                RoleId = roleId,
                PermissionId = permissionId,
                PermissionScope = permission.Scope, // Permission에서 가져옴
                GrantedByConnectedId = grantedBy,
                GrantedAt = DateTime.UtcNow, // IDateTimeProvider 사용 고려
                ExpiresAt = expiresAt,
                Reason = reason,
                IsActive = true,
                OrganizationId = role.OrganizationId, // Role에서 가져옴 (Nullable 체크 후)
                                                      // CreatedAt, CreatedBy 등은 GlobalBaseEntity/SaveChangesAsync에서 처리될 수 있음
                                                      // 여기서는 명시적으로 설정 (GlobalBaseEntity 설정에 따라 달라질 수 있음)
                CreatedAt = DateTime.UtcNow, // IDateTimeProvider 사용 고려
                                             // CreatedByConnectedId = grantedBy // GlobalBaseEntity가 자동으로 처리한다면 생략 가능
            };

            // 4. 엔티티 추가 (DB Context에 등록)
            var result = await AddAsync(rolePermission, cancellationToken); // BaseRepository AddAsync 사용

            // 5. 로깅 (성공 정보)
            _logger.LogInformation("Assigned permission {PermissionId} ({PermissionScope}) to role {RoleId} in organization {OrganizationId} by {GrantedBy}",
                permissionId, permission.Scope, roleId, role.OrganizationId, grantedBy);

            return result; // 추가된 엔티티 반환
        }


        /// <summary>
        /// 조건부 권한 할당 (기존 할당 후 조건 추가)
        /// </summary>
        public async Task<RolePermission> AssignConditionalPermissionAsync(
            Guid roleId,
            Guid permissionId,
            string conditions, // 조건 문자열 (JSON, OData 등)
            Guid grantedBy, // ConnectedId
            CancellationToken cancellationToken = default)
        {
            // 1. 기본 권한 할당 시도
            var rolePermission = await AssignPermissionAsync(roleId, permissionId, grantedBy, cancellationToken: cancellationToken);

            // 2. 조건 추가 및 업데이트
            rolePermission.Conditions = conditions;
            // UpdateAsync 호출 시 변경 추적 및 캐시 무효화 발생
            await UpdateAsync(rolePermission, cancellationToken);

            _logger.LogInformation("Added conditions to permission assignment {RolePermissionId} for role {RoleId}",
                rolePermission.Id, roleId);

            return rolePermission; // 업데이트된 엔티티 반환 (UpdateAsync는 void)
                                   // 필요시 GetByIdAsync로 다시 조회하여 반환할 수 있음
        }

        /// <summary>
        /// 역할에서 권한 제거 (Soft Delete)
        /// </summary>
        public async Task<bool> RemovePermissionAsync(
            Guid roleId,
            Guid permissionId,
            string? reason = null, // 제거 사유 (감사 목적)
            CancellationToken cancellationToken = default)
        {
            // 1. 제거할 RolePermission 조회 (추적 필요 O - 상태 변경해야 하므로)
            var rolePermission = await Query() // Query() 사용 (IsDeleted=false 필터링)
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId && !rp.IsInherited, cancellationToken); // 직접 할당된 것만 제거

            if (rolePermission == null)
            {
                _logger.LogWarning("Attempted to remove non-existent or inherited permission {PermissionId} from role {RoleId}. Reason: {Reason}",
                    permissionId, roleId, reason ?? "Not specified");
                return false; // 제거할 대상 없음
            }

            // SoftDeleteAsync 사용 (내부적으로 IsDeleted=true, DeletedAt 설정 및 Update, 캐시 무효화 수행)
            await SoftDeleteAsync(rolePermission.Id, cancellationToken);


            _logger.LogWarning("Soft-removed permission {PermissionId} from role {RoleId}. Reason: {Reason}",
                permissionId, roleId, reason ?? "Not specified");

            return true;
        }

        /// <summary>
        /// 특정 역할-권한 관계의 활성 상태 변경
        /// </summary>
        public async Task<bool> SetActiveStatusAsync(
            Guid rolePermissionId,
            bool isActive,
            CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 기본적으로 NoTracking이 아님 (상황 따라 다름)
            // 상태 변경이 필요하므로 추적 가능한 엔티티를 가져와야 함.
            // FindAsync 또는 추적 쿼리 사용
            var rolePermission = await _dbSet.FindAsync(new object[] { rolePermissionId }, cancellationToken);

            if (rolePermission == null || rolePermission.IsDeleted) // 삭제된 것은 상태 변경 불가
            {
                _logger.LogWarning("Attempted to set active status for non-existent or deleted role permission {RolePermissionId}", rolePermissionId);
                return false;
            }

            // 상태 변경 및 UpdateAsync 호출 (캐시 무효화 포함)
            rolePermission.IsActive = isActive;
            // UpdatedAt, UpdatedBy 등은 GlobalBaseEntity/SaveChangesAsync에서 처리될 수 있음
            // 여기서는 명시적 설정
            rolePermission.UpdatedAt = DateTime.UtcNow; // IDateTimeProvider 사용 고려
                                                        // UpdatedByConnectedId 설정 필요 (현재 호출자 정보 필요 - 서비스 레이어에서 주입받아야 함)

            await UpdateAsync(rolePermission, cancellationToken);


            _logger.LogInformation("Set RolePermission {RolePermissionId} active status to {IsActive}",
                rolePermissionId, isActive);

            return true;
        }

        /// <summary>
        /// 특정 역할-권한 관계의 만료일 갱신
        /// </summary>
        public async Task<bool> RenewPermissionAsync(
            Guid rolePermissionId,
            DateTime newExpiresAt,
            CancellationToken cancellationToken = default)
        {
            // 상태 변경 필요 -> 추적 가능한 엔티티 조회
            var rolePermission = await _dbSet.FindAsync(new object[] { rolePermissionId }, cancellationToken);

            if (rolePermission == null || rolePermission.IsDeleted)
            {
                _logger.LogWarning("Attempted to renew non-existent or deleted role permission {RolePermissionId}", rolePermissionId);
                return false;
            }

            // 만료일 변경 및 UpdateAsync 호출
            rolePermission.ExpiresAt = newExpiresAt;
            rolePermission.UpdatedAt = DateTime.UtcNow; // IDateTimeProvider 사용 고려
                                                        // UpdatedByConnectedId 설정 필요

            await UpdateAsync(rolePermission, cancellationToken);

            _logger.LogInformation("Renewed RolePermission {RolePermissionId} until {ExpiresAt}",
                rolePermissionId, newExpiresAt);

            return true;
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 역할에 여러 권한 일괄 할당
        /// </summary>
        /// <summary>
        /// 역할에 여러 권한 일괄 할당
        /// </summary>
        public async Task<PermissionAssignmentSummary> BulkAssignPermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> permissionIds,
            Guid grantedBy, // ConnectedId
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            var permissionIdList = permissionIds.Distinct().ToList(); // 중복 제거
            var summary = new PermissionAssignmentSummary { TotalRequested = permissionIdList.Count };

            if (!permissionIdList.Any()) return summary;

            // 1. 대상 Role 조회 (OrganizationId 확인용)
            var role = await _context.Set<Role>()
                .AsNoTracking()
                .Select(r => new { r.Id, r.OrganizationId }) // 필요한 정보만 선택
                .FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken);

            if (role == null) throw new ArgumentException($"Role with ID '{roleId}' not found.", nameof(roleId));

            // 💡 수정: 'Guid'에 .HasValue 대신 Guid.Empty와 비교
            if (role.OrganizationId == Guid.Empty)
            {
                throw new InvalidOperationException($"Role '{roleId}' must belong to an organization.");
            }

            // 💡 수정: .Value 없이 Guid 값을 직접 할당
            var organizationId = role.OrganizationId;


            // 2. 이미 할당된 권한 ID 조회 (최적화: Set 사용)
            // 💡 수정: ToHashSetAsync() 대신 ToListAsync() 후 ToHashSet() 사용
            var existingPermissionIds = (await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdList.Contains(rp.PermissionId))
                 .Select(rp => rp.PermissionId) // ID만 선택
                 .Distinct() // 중복 제거
                .ToListAsync(cancellationToken)) // 1. 리스트로 변환
                .ToHashSet(); // 2. 메모리에서 HashSet으로 변환

            summary.AlreadyExists = existingPermissionIds.Count;

            // 3. 새로 할당할 권한 ID 목록 생성
            var newPermissionIds = permissionIdList.Except(existingPermissionIds).ToList();

            if (!newPermissionIds.Any()) return summary; // 새로 할당할 것 없음

            // 4. 새로 할당할 권한 정보 조회 (Scope 확인용)
            var permissionsToAssign = await _context.Set<Permission>()
                .AsNoTracking()
                .Where(p => newPermissionIds.Contains(p.Id))
                .Select(p => new { p.Id, p.Scope }) // 필요한 정보만 선택
                .ToListAsync(cancellationToken);


            // 유효하지 않은 Permission ID 처리 (요청된 ID 중 DB에 없는 경우)
            var foundPermissionIds = permissionsToAssign.Select(p => p.Id).ToHashSet();
            var missingPermissionIds = newPermissionIds.Except(foundPermissionIds).ToList();
            summary.Failed = missingPermissionIds.Count; // 실패 수 기록
            if (missingPermissionIds.Any())
            {
                _logger.LogWarning("Attempted to assign non-existent permissions to role {RoleId}: {MissingPermissionIds}",
                    roleId, string.Join(", ", missingPermissionIds));
            }


            // 5. 새 RolePermission 엔티티 생성
            var currentTime = DateTime.UtcNow; // IDateTimeProvider 사용 고려
            var newRolePermissions = permissionsToAssign.Select(p => new RolePermission
            {
                RoleId = roleId,
                PermissionId = p.Id,
                PermissionScope = p.Scope,
                GrantedByConnectedId = grantedBy,
                GrantedAt = currentTime,
                Reason = reason,
                IsActive = true,
                OrganizationId = organizationId, // 💡 수정된 organizationId 변수 사용
                CreatedAt = currentTime,
                // CreatedByConnectedId = grantedBy // GlobalBaseEntity 처리 여부 확인
            }).ToList();

            // 6. 일괄 추가 (DB Context에 등록)
            if (newRolePermissions.Any())
            {
                await AddRangeAsync(newRolePermissions, cancellationToken); // BaseRepository AddRangeAsync
                summary.SuccessfullyAssigned = newRolePermissions.Count;

                _logger.LogInformation("Bulk assigned {Count} new permissions to role {RoleId} in organization {OrganizationId} by {GrantedBy}",
                    summary.SuccessfullyAssigned, roleId, organizationId, grantedBy);
            }

            return summary;
        }
        /// <summary>
        /// 역할에서 여러 권한 일괄 제거 (Soft Delete)
        /// </summary>
        public async Task<int> BulkRemovePermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> permissionIds,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            var permissionIdList = permissionIds.Distinct().ToList(); // 중복 제거
            if (!permissionIdList.Any()) return 0;

            // 1. 제거 대상 RolePermission 조회 (추적 필요 O - 상태 변경)
            // 직접 할당된 것만 제거 (IsInherited = false)
            var rolePermissionsToRemove = await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdList.Contains(rp.PermissionId) && !rp.IsInherited)
                .ToListAsync(cancellationToken);

            if (!rolePermissionsToRemove.Any())
            {
                _logger.LogWarning("No directly assigned permissions found to remove for role {RoleId} matching IDs: {PermissionIds}. Reason: {Reason}",
                    roleId, string.Join(", ", permissionIdList), reason ?? "Not specified");
                return 0; // 제거할 대상 없음
            }

            // 2. 일괄 Soft Delete (BaseRepository DeleteRangeAsync 사용)
            await DeleteRangeAsync(rolePermissionsToRemove, cancellationToken);


            _logger.LogWarning("Bulk soft-removed {Count} permissions from role {RoleId}. Reason: {Reason}",
                rolePermissionsToRemove.Count, roleId, reason ?? "Not specified");

            return rolePermissionsToRemove.Count; // 제거된 개수 반환
        }


        /// <summary>
        /// 역할의 모든 *직접 할당된* 권한 제거 (Soft Delete)
        /// </summary>
        public async Task<int> RemoveAllPermissionsAsync(
            Guid roleId,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            // 1. 제거 대상 조회 (직접 할당된 것만, 추적 필요 O)
            var rolePermissionsToRemove = await Query()
                .Where(rp => rp.RoleId == roleId && !rp.IsInherited)
                .ToListAsync(cancellationToken);

            if (!rolePermissionsToRemove.Any())
            {
                _logger.LogInformation("No directly assigned permissions found to remove for role {RoleId}. Reason: {Reason}",
                    roleId, reason ?? "Not specified");
                return 0;
            }

            // 2. 일괄 Soft Delete
            await DeleteRangeAsync(rolePermissionsToRemove, cancellationToken);

            _logger.LogWarning("Removed all {Count} directly assigned permissions from role {RoleId}. Reason: {Reason}",
                rolePermissionsToRemove.Count, roleId, reason ?? "Not specified");

            return rolePermissionsToRemove.Count;
        }

        /// <summary>
        /// 역할의 모든 *직접 할당된* 권한을 새 권한 목록으로 교체
        /// </summary>
        public async Task<PermissionAssignmentSummary> ReplacePermissionsAsync(
            Guid roleId,
            IEnumerable<Guid> newPermissionIds,
            Guid grantedBy, // ConnectedId
            CancellationToken cancellationToken = default)
        {
            // 이 작업은 트랜잭션으로 묶는 것이 좋습니다 (서비스 레이어에서 IUnitOfWork 사용).
            // Repository는 개별 작업만 수행합니다.

            // 1. 기존 직접 할당 권한 모두 제거
            int removedCount = await RemoveAllPermissionsAsync(roleId, "Replacing permissions", cancellationToken);

            // 2. 새 권한 목록 일괄 할당
            var assignSummary = await BulkAssignPermissionsAsync(roleId, newPermissionIds, grantedBy, "Replacing permissions", cancellationToken);

            // 3. 결과 조합 (Remove 결과는 assignSummary에 반영되지 않으므로 별도 처리)
            assignSummary.PreviouslyRemoved = removedCount; // 제거된 개수 추가

            _logger.LogInformation("Replaced permissions for role {RoleId}. Removed: {RemovedCount}, Assigned: {AssignedCount}, Failed: {FailedCount}, Already Existed (in new set): {AlreadyExistsCount}",
                roleId, removedCount, assignSummary.SuccessfullyAssigned, assignSummary.Failed, assignSummary.AlreadyExists);

            return assignSummary;
        }

        #endregion

        #region 상속 관리 (상속 로직은 복잡하며 서비스 레이어 역할일 수 있음)

        /// <summary>
        /// 상속된 권한 생성 (데이터 생성)
        /// </summary>
        public async Task<RolePermission> CreateInheritedPermissionAsync(
            Guid sourceRolePermissionId, // 원본 RolePermission ID
            Guid targetRoleId,           // 상속받을 대상 Role ID
            Guid grantedBy,             // 작업 수행자 ConnectedId
            CancellationToken cancellationToken = default)
        {
            // 1. 원본 RolePermission 조회 (NoTracking)
            var sourceRolePermission = await GetByIdAsync(sourceRolePermissionId, cancellationToken);
            if (sourceRolePermission == null)
            {
                throw new ArgumentException($"Source RolePermission with ID '{sourceRolePermissionId}' not found.", nameof(sourceRolePermissionId));
            }

            // 2. 대상 Role 조회 (OrganizationId 확인용, NoTracking)
            var targetRole = await _context.Set<Role>()
                .AsNoTracking()
                .Select(r => new { r.Id, r.OrganizationId })
                .FirstOrDefaultAsync(r => r.Id == targetRoleId, cancellationToken);

            if (targetRole == null) throw new ArgumentException($"Target role with ID '{targetRoleId}' not found.", nameof(targetRoleId));

            // 💡 수정: .HasValue 대신 Guid.Empty와 비교
            if (targetRole.OrganizationId == Guid.Empty)
            {
                throw new InvalidOperationException($"Target role '{targetRoleId}' must belong to an organization.");
            }
            // 3. 중복 상속 체크 (이미 대상 Role에 동일한 원본으로부터 상속된 권한이 있는지)
            bool alreadyInherited = await AnyAsync(rp =>
                rp.RoleId == targetRoleId &&
                rp.PermissionId == sourceRolePermission.PermissionId && // 동일 권한
                rp.IsInherited &&
                rp.InheritedFromId == sourceRolePermissionId, // 동일 출처
                cancellationToken);

            if (alreadyInherited)
            {
                // 이미 존재하면 예외 또는 기존 엔티티 반환 (정책에 따라 결정)
                throw new InvalidOperationException($"Permission {sourceRolePermission.PermissionId} from source {sourceRolePermissionId} is already inherited by role {targetRoleId}.");
            }


            // 4. 새 상속 RolePermission 엔티티 생성
            var inheritedPermission = new RolePermission
            {
                RoleId = targetRoleId,
                PermissionId = sourceRolePermission.PermissionId,
                PermissionScope = sourceRolePermission.PermissionScope, // 원본에서 복사
                GrantedByConnectedId = grantedBy, // 상속 작업을 수행한 주체
                GrantedAt = DateTime.UtcNow,      // 상속 시점 기록
                IsActive = sourceRolePermission.IsActive, // 원본의 활성 상태 따름
                IsInherited = true,                     // 상속 플래그 설정
                InheritedFromId = sourceRolePermissionId, // 원본 ID 기록
                OrganizationId = targetRole.OrganizationId, // 대상 Role의 조직 ID
                CreatedAt = DateTime.UtcNow,
                // CreatedByConnectedId = grantedBy
                // 상속된 권한의 Priority, ExpiresAt, Reason, Conditions 등은 원본을 따를지,
                // 별도 정책을 가질지 결정 필요. 여기서는 기본값 또는 null로 둠.
                Priority = sourceRolePermission.Priority, // 예: 원본 우선순위 따름
                                                          // ExpiresAt = sourceRolePermission.ExpiresAt // 예: 원본 만료일 따름
            };

            // 5. 엔티티 추가
            var result = await AddAsync(inheritedPermission, cancellationToken);

            _logger.LogInformation("Created inherited permission link from source {SourceRolePermissionId} (Permission: {PermissionId}) to target role {TargetRoleId} by {GrantedBy}",
                sourceRolePermissionId, sourceRolePermission.PermissionId, targetRoleId, grantedBy);

            return result;
        }

        /// <summary>
        /// 특정 원본 RolePermission으로부터 상속받은 모든 관계 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetInheritedPermissionsAsync(
            Guid inheritedFromId, // 원본 RolePermission ID
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(rp => rp.InheritedFromId == inheritedFromId && rp.IsInherited)
                .Include(rp => rp.Role!)        // 상속받은 Role 정보 포함
                .Include(rp => rp.Permission!)  // 권한 정보 포함
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 RolePermission의 상속 체인 조회 (자신부터 최상위 원본까지)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetInheritanceChainAsync(
            Guid rolePermissionId,
            CancellationToken cancellationToken = default)
        {
            var chain = new List<RolePermission>();
            var currentId = (Guid?)rolePermissionId; // Nullable로 시작

            // 최대 깊이 제한 (무한 루프 방지)
            int maxDepth = 10;
            int currentDepth = 0;

            while (currentId.HasValue && currentDepth < maxDepth)
            {
                // GetByIdAsync는 캐시를 활용할 수 있음 (NoTracking 아님)
                // 단, 여기서는 Include가 필요할 수 있으므로 직접 조회
                var current = await Query()
                    .Include(rp => rp.Permission) // 필요 시 정보 포함
                    .Include(rp => rp.Role)       // 필요 시 정보 포함
                    .AsNoTracking()               // 체인 조회는 읽기 전용
                    .FirstOrDefaultAsync(rp => rp.Id == currentId.Value, cancellationToken);


                if (current == null) break; // 중간에 끊어진 경우

                chain.Add(current);

                // 다음 상위 ID 설정
                currentId = current.InheritedFromId;
                currentDepth++;

                if (currentDepth == maxDepth && currentId.HasValue)
                {
                    _logger.LogWarning("Inheritance chain for RolePermission {StartId} exceeded max depth {MaxDepth}. Chain might be circular or too deep.", rolePermissionId, maxDepth);
                }

            }

            return chain; // 최하위 -> 최상위 순서
        }


        /// <summary>
        /// 상속된 권한 동기화 (구현 복잡 - 서비스 레이어 로직 가능성 높음)
        /// </summary>
        public Task<int> SyncInheritedPermissionsAsync(
            Guid sourceRoleId,
            Guid targetRoleId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 실제 동기화 로직 구현 필요.
            // 1. sourceRole의 직접 할당된 권한 (A) 조회
            // 2. targetRole의 직접 할당된 권한 (B) 조회
            // 3. targetRole의 현재 상속된 권한 중 sourceRole에서 온 것들 (C) 조회
            // 4. (A)에는 있고 (C)에는 없는 권한 -> targetRole에 상속 생성 (CreateInheritedPermissionAsync 사용)
            // 5. (C)에는 있고 (A)에는 없는 권한 -> targetRole의 상속 관계 제거 (SoftDeleteAsync 사용)
            // 6. (A)와 (C) 모두에 있는 권한 -> 속성 동기화 (예: IsActive, Priority 등) (UpdateAsync 사용)
            // 이 로직은 복잡하고 여러 DB 작업을 포함하므로 서비스 레이어에서 트랜잭션과 함께 처리하는 것이 더 적합할 수 있습니다.
            _logger.LogWarning("SyncInheritedPermissionsAsync is not fully implemented in the repository layer. Complex synchronization logic might belong in the service layer.");
            return Task.FromResult(0); // 임시 반환
        }


        #endregion

        #region 만료 관리

        /// <summary>
        /// 만료된 역할-권한 관계 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetExpiredPermissionsAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var utcNow = DateTime.UtcNow; // IDateTimeProvider 사용 고려
            IQueryable<RolePermission> query = organizationId.HasValue && IsOrganizationBaseEntity()
                ? QueryForOrganization(organizationId.Value)
                : Query();


            return await query
                .Where(rp => rp.ExpiresAt.HasValue && rp.ExpiresAt <= utcNow)
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.ExpiresAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 기간 내에 만료 예정인 역할-권한 관계 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetExpiringPermissionsAsync(
            int daysUntilExpiry,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var utcNow = DateTime.UtcNow; // IDateTimeProvider 사용 고려
            var expiryThreshold = utcNow.AddDays(daysUntilExpiry);

            IQueryable<RolePermission> query = organizationId.HasValue && IsOrganizationBaseEntity()
                ? QueryForOrganization(organizationId.Value)
                : Query();


            return await query
                .Where(rp => rp.ExpiresAt.HasValue &&
                              rp.ExpiresAt > utcNow &&          // 아직 만료되지 않았고
                              rp.ExpiresAt <= expiryThreshold) // 만료 임계값 이전
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.ExpiresAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료된 역할-권한 관계 일괄 정리 (Soft Delete)
        /// </summary>
        public async Task<int> CleanupExpiredPermissionsAsync(
            int batchSize = 100, // 한 번에 처리할 개수 제한
            CancellationToken cancellationToken = default)
        {
            var utcNow = DateTime.UtcNow; // IDateTimeProvider 사용 고려

            // 1. 제거 대상 조회 (추적 필요 O)
            // Take()를 사용하여 과도한 메모리 사용 방지
            var expiredPermissions = await Query()
                .Where(rp => rp.ExpiresAt.HasValue && rp.ExpiresAt <= utcNow)
                .OrderBy(rp => rp.ExpiresAt) // 오래된 것부터 처리
                .Take(batchSize)
                .ToListAsync(cancellationToken);

            if (!expiredPermissions.Any()) return 0;

            // 2. 일괄 Soft Delete
            await DeleteRangeAsync(expiredPermissions, cancellationToken);

            _logger.LogInformation("Cleaned up {Count} expired RolePermissions (soft delete).", expiredPermissions.Count);

            return expiredPermissions.Count;
        }

        #endregion

        #region 우선순위 관리

        /// <summary>
        /// 역할의 활성 권한을 우선순위 순으로 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByPriorityAsync(
            Guid roleId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId && rp.IsActive) // 활성 권한만
                .OrderBy(rp => rp.Priority)                     // 우선순위 오름차순
                .ThenBy(rp => rp.PermissionScope)              // 우선순위 같으면 스코프 순
                .Include(rp => rp.Permission!)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 역할-권한 관계의 우선순위 업데이트
        /// </summary>
        public async Task<bool> UpdatePriorityAsync(
            Guid rolePermissionId,
            int newPriority,
            CancellationToken cancellationToken = default)
        {
            // 상태 변경 필요 -> 추적
            var rolePermission = await _dbSet.FindAsync(new object[] { rolePermissionId }, cancellationToken);

            if (rolePermission == null || rolePermission.IsDeleted)
            {
                _logger.LogWarning("Attempted to update priority for non-existent or deleted role permission {RolePermissionId}", rolePermissionId);
                return false;
            }

            rolePermission.Priority = newPriority;
            rolePermission.UpdatedAt = DateTime.UtcNow; // IDateTimeProvider
                                                        // UpdatedByConnectedId 설정

            await UpdateAsync(rolePermission, cancellationToken); // 캐시 무효화 포함

            _logger.LogInformation("Updated priority for RolePermission {RolePermissionId} to {Priority}",
                rolePermissionId, newPriority);

            return true;
        }

        /// <summary>
        /// 역할 내 권한들의 우선순위 일괄 재정렬
        /// </summary>
        public async Task<int> ReorderPrioritiesAsync(
            Guid roleId,
            IEnumerable<Guid> orderedPermissionIds, // 새 순서대로 정렬된 Permission ID 목록
            CancellationToken cancellationToken = default)
        {
            var permissionIdsList = orderedPermissionIds.ToList();
            if (!permissionIdsList.Any()) return 0;

            // 1. 대상 RolePermissions 조회 (추적 필요 O)
            // IsInherited = false 조건 추가: 직접 할당된 권한의 순서만 변경하는 것이 일반적
            var rolePermissions = await Query()
                .Where(rp => rp.RoleId == roleId && permissionIdsList.Contains(rp.PermissionId) && !rp.IsInherited)
                .ToListAsync(cancellationToken);


            // 2. 새 우선순위 할당
            int priority = 1; // 1부터 시작 (또는 0부터 시작 - 정책 결정 필요)
            int updatedCount = 0;
            var currentTime = DateTime.UtcNow; // IDateTimeProvider
                                               // UpdatedBy 설정 필요

            // 요청된 순서대로 루프
            foreach (var permissionId in permissionIdsList)
            {
                // 해당 Permission ID를 가진 RolePermission 찾기
                var rolePermission = rolePermissions.FirstOrDefault(rp => rp.PermissionId == permissionId);
                if (rolePermission != null)
                {
                    // 우선순위가 변경되었는지 확인 후 업데이트
                    if (rolePermission.Priority != priority)
                    {
                        rolePermission.Priority = priority;
                        rolePermission.UpdatedAt = currentTime;
                        // rolePermission.UpdatedByConnectedId = ... ; // 설정 필요
                        updatedCount++;
                    }
                    priority++; // 다음 우선순위
                }
                else
                {
                    // 요청된 ID 목록에 있지만 DB에 없는 경우 (또는 상속된 경우) 로그
                    _logger.LogWarning("Permission ID {PermissionId} provided for reordering role {RoleId} was not found among directly assigned permissions.", permissionId, roleId);
                }
            }


            // 3. 변경된 엔티티 일괄 업데이트 (UpdateRangeAsync는 캐시 무효화 포함)
            if (updatedCount > 0)
            {
                // UpdateRangeAsync는 변경된 엔티티만 Update하도록 EF Core가 처리할 수 있음
                // 또는 변경된 엔티티만 필터링하여 전달
                var updatedEntities = rolePermissions.Where(rp => _context.Entry(rp).State == EntityState.Modified).ToList();
                if (updatedEntities.Any())
                {
                    await UpdateRangeAsync(updatedEntities, cancellationToken);
                    _logger.LogInformation("Reordered {Count} permission priorities for role {RoleId}",
                        updatedCount, roleId);
                }
            }

            return updatedCount;
        }

        #endregion

        #region 조건부 권한

        /// <summary>
        /// 역할의 활성 조건부 권한 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetConditionalPermissionsAsync(
            Guid roleId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(rp => rp.RoleId == roleId &&
                              rp.IsActive &&                      // 활성 상태이고
                              !string.IsNullOrEmpty(rp.Conditions)) // Conditions 필드가 비어있지 않은 경우
                .Include(rp => rp.Permission!)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조건 평가 (구현 복잡 - 서비스 레이어 로직 가능성 높음)
        /// </summary>
        public async Task<bool> EvaluateConditionsAsync(
            Guid rolePermissionId,
            string context, // 조건을 평가하는 데 필요한 컨텍스트 정보 (JSON 등)
            CancellationToken cancellationToken = default)
        {
            var rolePermission = await GetByIdAsync(rolePermissionId, cancellationToken); // 캐시 활용 가능

            // 조건이 없거나 비활성이면 항상 true (조건 통과)
            if (rolePermission == null || !rolePermission.IsActive || string.IsNullOrEmpty(rolePermission.Conditions))
            {
                return true;
            }

            // TODO: 실제 조건 평가 로직 구현 필요.
            // rolePermission.Conditions 문자열을 파싱하고, 제공된 context 정보를 기반으로 평가.
            // 예: JSON 기반 규칙 엔진 사용 (NRules, JsonLogic.Net 등)
            // 이 로직은 Repository의 책임 범위를 벗어날 수 있으며, 별도의 조건 평가 서비스에서 처리하는 것이 더 적합할 수 있습니다.
            _logger.LogWarning("EvaluateConditionsAsync is not fully implemented in the repository layer. Complex condition evaluation logic might belong in a dedicated service.");
            return true; // 임시 반환
        }


        /// <summary>
        /// 특정 역할-권한 관계의 조건 업데이트
        /// </summary>
        public async Task<bool> UpdateConditionsAsync(
            Guid rolePermissionId,
            string newConditions, // 새로운 조건 문자열
            CancellationToken cancellationToken = default)
        {
            // 상태 변경 필요 -> 추적
            var rolePermission = await _dbSet.FindAsync(new object[] { rolePermissionId }, cancellationToken);

            if (rolePermission == null || rolePermission.IsDeleted)
            {
                _logger.LogWarning("Attempted to update conditions for non-existent or deleted role permission {RolePermissionId}", rolePermissionId);
                return false;
            }

            rolePermission.Conditions = newConditions;
            rolePermission.UpdatedAt = DateTime.UtcNow; // IDateTimeProvider
                                                        // UpdatedByConnectedId 설정

            await UpdateAsync(rolePermission, cancellationToken); // 캐시 무효화 포함

            _logger.LogInformation("Updated conditions for RolePermission {RolePermissionId}", rolePermissionId);

            return true;
        }

        #endregion

        #region 충돌 검증 (조회 기반)

        /// <summary>
        /// 특정 역할 내에서 주어진 권한 ID를 가진 모든 관계 조회 (충돌 확인용)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> CheckPermissionConflictsAsync(
            Guid roleId,
            Guid permissionId,
            CancellationToken cancellationToken = default)
        {
            // 직접 할당된 것과 상속된 것 모두 조회
            return await Query()
                .Where(rp => rp.RoleId == roleId && rp.PermissionId == permissionId)
                 .Include(rp => rp.Permission) // 권한 정보 포함하여 비교 용이하게
                 .AsNoTracking()
                .ToListAsync(cancellationToken);
            // 결과가 2개 이상이면 충돌 가능성 (예: 직접 할당 + 상속, 다른 우선순위 등)
            // 실제 충돌 해결 로직은 서비스 레이어에서 처리
        }


        /// <summary>
        /// 역할 내에서 중복 할당된 권한 찾기 (동일 PermissionId가 여러 번 할당된 경우)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> FindDuplicatePermissionsAsync(
            Guid roleId,
            CancellationToken cancellationToken = default)
        {
            // 동일 PermissionId를 가진 RolePermission 그룹 찾기
            var duplicateGroups = await Query()
                .Where(rp => rp.RoleId == roleId)
                .GroupBy(rp => rp.PermissionId) // 권한 ID로 그룹화
                .Where(g => g.Count() > 1)      // 그룹 크기가 1보다 큰 경우 (중복)
                .Select(g => g.Key)             // 중복된 권한 ID만 선택
                .ToListAsync(cancellationToken);

            if (!duplicateGroups.Any())
            {
                return Enumerable.Empty<RolePermission>(); // 중복 없음
            }

            // 중복된 권한 ID를 가진 모든 RolePermission 상세 정보 조회
            return await Query()
                .Where(rp => rp.RoleId == roleId && duplicateGroups.Contains(rp.PermissionId))
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.PermissionId).ThenBy(rp => rp.IsInherited) // 정렬하여 보기 쉽게
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 상속 관계에서의 순환 참조 확인 (구현 복잡 - 서비스 레이어 로직 가능성 높음)
        /// </summary>
        public async Task<bool> CheckCircularReferenceAsync(
            Guid roleId,
            Guid permissionId, // 이 권한을 추가/상속하려 할 때 순환이 발생하는지 확인
            CancellationToken cancellationToken = default)
        {
            // 순환 참조 확인은 그래프 탐색 문제로, Repository보다는 서비스 레이어나
            // 별도의 그래프 순회 로직으로 구현하는 것이 더 적합할 수 있습니다.
            // 간단한 직접 참조 확인 정도는 가능합니다.

            // 1. roleId가 가진 권한 중 permissionId를 상속받은 것이 있는지 확인
            bool alreadyInheritsTarget = await Query()
                .AnyAsync(rp => rp.RoleId == roleId && rp.IsInherited && rp.PermissionId == permissionId, cancellationToken);
            if (alreadyInheritsTarget) return true; // 이미 상속 중이면 더 깊게 들어갈 필요 없음


            // 2. 깊은 순환 참조 확인 (재귀 또는 반복) - Repository에는 부적합할 수 있음
            // 아래는 재귀 방식 예시 (성능 및 스택 오버플로우 위험 고려 필요)
            var visited = new HashSet<Guid>(); // 방문한 RolePermission ID 추적
                                               // 시작점: permissionId를 직접 가진 RolePermission 조회 (상속 체인의 시작점 찾기)
            var startingPermissions = await Query()
                .Where(rp => rp.PermissionId == permissionId && !rp.IsInherited) // 직접 할당된 것부터 시작
                .ToListAsync(cancellationToken);

            foreach (var startPerm in startingPermissions)
            {
                if (await CheckCircularReferenceRecursiveAsync(startPerm.Id, roleId, visited, cancellationToken))
                {
                    return true; // 순환 발견
                }
            }

            return false; // 순환 없음
        }

        // 재귀 함수 (스택 오버플로우 위험, 성능 이슈 가능성 -> 반복 방식으로 개선 고려)
        private async Task<bool> CheckCircularReferenceRecursiveAsync(
            Guid currentRolePermissionId, // 현재 탐색 중인 RolePermission ID
            Guid targetRoleId,            // 최종적으로 도달하면 순환이 발생하는 Role ID
            HashSet<Guid> visited,         // 방문 기록
            CancellationToken cancellationToken)
        {
            if (!visited.Add(currentRolePermissionId)) // 이미 방문했으면 순환 (기저 사례 1)
            {
                return true;
            }

            // 현재 RolePermission으로부터 상속받는 하위 RolePermission들 조회
            var children = await Query()
                .Where(rp => rp.InheritedFromId == currentRolePermissionId && rp.IsInherited)
                .ToListAsync(cancellationToken);

            foreach (var child in children)
            {
                if (child.RoleId == targetRoleId) // 목표 Role에 도달하면 순환 (기저 사례 2)
                {
                    return true;
                }

                // 재귀 호출
                if (await CheckCircularReferenceRecursiveAsync(child.Id, targetRoleId, new HashSet<Guid>(visited), cancellationToken)) // 방문 기록 복사 전달
                {
                    return true;
                }
            }

            return false; // 현재 경로에서는 순환 없음
        }


        #endregion

        #region 통계 및 분석 (조회 기반)

        /// <summary>
        /// 특정 조직 내 역할별 활성 권한 수 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetPermissionCountByRoleAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            if (!IsOrganizationBaseEntity()) // 방어 코드
            {
                _logger.LogWarning("GetPermissionCountByRoleAsync called for a non-organization-scoped entity repository: {EntityType}", typeof(RolePermission).Name);
                // 또는 organizationId 무시하고 전체 통계 반환? 여기서는 빈 Dictionary 반환
                return new Dictionary<Guid, int>();
            }

            // BaseRepository의 GetGroupCountAsync 활용 가능
            return await GetGroupCountAsync(
                keySelector: rp => rp.RoleId, // RoleId로 그룹화
                predicate: rp => rp.OrganizationId == organizationId && rp.IsActive, // 해당 조직 & 활성 권한
                cancellationToken: cancellationToken);

            /* 위 GetGroupCountAsync 사용으로 대체 가능
            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.RoleId)
                .Select(g => new { RoleId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.RoleId, x => x.Count, cancellationToken);
            */
        }

        /// <summary>
        /// 특정 조직 내 권한별 할당된 역할 수 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetRoleCountByPermissionAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            if (!IsOrganizationBaseEntity())
            {
                _logger.LogWarning("GetRoleCountByPermissionAsync called for a non-organization-scoped entity repository: {EntityType}", typeof(RolePermission).Name);
                return new Dictionary<Guid, int>();
            }

            return await GetGroupCountAsync(
                keySelector: rp => rp.PermissionId, // PermissionId로 그룹화
                predicate: rp => rp.OrganizationId == organizationId && rp.IsActive, // 해당 조직 & 활성 권한
                cancellationToken: cancellationToken);

            /* 위 GetGroupCountAsync 사용으로 대체 가능
            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.PermissionId)
                .Select(g => new { PermissionId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.PermissionId, x => x.Count, cancellationToken);
            */
        }

        /// <summary>
        /// 특정 조직 내 가장 많이 할당된 활성 권한 TOP N 조회
        /// </summary>
        public async Task<IEnumerable<(Guid PermissionId, int Count)>> GetMostAssignedPermissionsAsync(
            Guid organizationId,
            int limit = 10,
            CancellationToken cancellationToken = default)
        {
            if (!IsOrganizationBaseEntity())
            {
                _logger.LogWarning("GetMostAssignedPermissionsAsync called for a non-organization-scoped entity repository: {EntityType}", typeof(RolePermission).Name);
                return Enumerable.Empty<(Guid, int)>();
            }

            return await QueryForOrganization(organizationId)
                .Where(rp => rp.IsActive)
                .GroupBy(rp => rp.PermissionId)
                .Select(g => new { PermissionId = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count) // 할당 횟수 내림차순
                .Take(limit)                     // 상위 N개 선택
                 .AsNoTracking()                  // 조회 전용
                                                  // ValueTuple을 직접 Select하는 것이 EF Core 버전에 따라 지원되지 않을 수 있음
                                                  // .Select(x => (x.PermissionId, x.Count)) // C# 7.0 이상
                 .ToListAsync(cancellationToken) // 익명 타입으로 가져온 후 변환
                 .ContinueWith(t => t.Result.Select(x => (x.PermissionId, x.Count)), TaskContinuationOptions.OnlyOnRanToCompletion);
        }

        /// <summary>
        /// 특정 조직 내 장기간 사용되지 않는(비활성 상태가 오래된) 권한 할당 관계 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> FindUnusedPermissionsAsync(
            Guid organizationId,
            int inactiveDays = 90, // 비활성 기준일
            CancellationToken cancellationToken = default)
        {
            if (!IsOrganizationBaseEntity())
            {
                _logger.LogWarning("FindUnusedPermissionsAsync called for a non-organization-scoped entity repository: {EntityType}", typeof(RolePermission).Name);
                return Enumerable.Empty<RolePermission>();
            }

            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays); // IDateTimeProvider

            return await QueryForOrganization(organizationId)
                // 언제 비활성화되었는지 추적하는 필드가 있다면 더 정확함 (예: DeactivatedAt)
                // 여기서는 CreatedAt을 기준으로 오래전에 생성되었지만 현재 비활성인 것을 찾음
                .Where(rp => !rp.IsActive && rp.CreatedAt < cutoffDate) // 현재 비활성이며, 생성된 지 오래된 것
                .Include(rp => rp.Permission!)
                .Include(rp => rp.Role!)
                .OrderBy(rp => rp.CreatedAt) // 오래된 순으로 정렬
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 감사 및 이력 (조회 기반)

        /// <summary>
        /// 특정 역할의 권한 할당/제거 이력 조회 (기간 필터링 가능)
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetAssignmentHistoryAsync(
            Guid roleId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            // IsDeleted 포함 여부 결정 필요. 여기서는 포함하여 '제거' 이력도 볼 수 있게 함.
            var query = _dbSet // IsDeleted 필터링 없이 전체 _dbSet 사용
                .IgnoreQueryFilters() // 만약 전역 필터가 있다면 무시
                .Where(rp => rp.RoleId == roleId);


            if (startDate.HasValue)
            {
                // GrantedAt 또는 CreatedAt 기준? 여기서는 GrantedAt 사용
                query = query.Where(rp => rp.GrantedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                // 종료일은 해당 날짜의 끝까지 포함 (23:59:59)
                var endOfDay = endDate.Value.Date.AddDays(1);
                query = query.Where(rp => rp.GrantedAt < endOfDay);
            }

            return await query
                .Include(rp => rp.Permission!)
                // CreatedBy/UpdatedBy/DeletedBy 정보도 Include 고려
                .OrderByDescending(rp => rp.GrantedAt) // 최신 이력부터
                 .ThenByDescending(rp => rp.CreatedAt) // GrantedAt이 같으면 생성 시간
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 부여자가 수행한 권한 할당 이력 조회
        /// </summary>
        public async Task<IEnumerable<RolePermission>> GetByGrantedByAsync(
            Guid grantedByConnectedId,
            int limit = 100, // 결과 개수 제한
            CancellationToken cancellationToken = default)
        {
            // 여기서는 IsDeleted=false인 활성 할당만 조회할지, 전체 이력을 볼지 결정 필요
            // 여기서는 현재 유효한 할당(IsDeleted=false)만 조회
            return await Query()
                .Where(rp => rp.GrantedByConnectedId == grantedByConnectedId)
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderByDescending(rp => rp.GrantedAt) // 최신 할당부터
                .Take(limit)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }


        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 다양한 조건으로 역할-권한 관계 페이징 검색
        /// </summary>
        public async Task<PagedResult<RolePermission>> SearchAsync(
            Expression<Func<RolePermission, bool>> criteria, // 동적 검색 조건
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetPagedAsync 활용
            var (items, totalCount) = await GetPagedAsync(
                 pageNumber: pageNumber,
                 pageSize: pageSize,
                 predicate: criteria, // 검색 조건 적용
                 orderBy: rp => rp.CreatedAt, // 기본 정렬 (필요시 파라미터 추가)
                 isDescending: true,         // 기본 정렬 방향
                 cancellationToken: cancellationToken
             );


            // GetPagedAsync는 AsNoTracking을 사용하지만, Include가 필요하면 별도 처리 필요
            // 여기서는 GetPagedAsync 내부 로직 수정 대신, 결과를 받아 Include 수행 (비효율적일 수 있음)
            // 또는 GetPagedAsync에 Include 로직 추가 고려
            // 현재 BaseRepository<T>.GetPagedAsync 는 Include를 지원하지 않음.
            // 따라서 여기서 직접 구현하거나 BaseRepository 수정 필요.

            // 여기서는 직접 구현하는 방식으로 수정:
            var query = Query().Where(criteria); // 기본 쿼리 + 검색 조건
            var totalCountManual = await query.CountAsync(cancellationToken);

            var itemsManual = await query
                .Include(rp => rp.Role!)       // Include 추가
                .Include(rp => rp.Permission!) // Include 추가
                .OrderByDescending(rp => rp.CreatedAt) // 정렬
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking()                // NoTracking 적용
                .ToListAsync(cancellationToken);

            return PagedResult<RolePermission>.Create(itemsManual, totalCountManual, pageNumber, pageSize);
        }

        /// <summary>
        /// 권한 스코프 패턴(와일드카드 포함)으로 검색
        /// </summary>
        public async Task<IEnumerable<RolePermission>> SearchByScopePatternAsync(
            string scopePattern, // 예: "organization:app:resource:*"
            Guid organizationId, // 검색 범위 조직
            CancellationToken cancellationToken = default)
        {
            if (!IsOrganizationBaseEntity())
            {
                _logger.LogWarning("SearchByScopePatternAsync called for a non-organization-scoped entity repository: {EntityType}", typeof(RolePermission).Name);
                return Enumerable.Empty<RolePermission>();
            }

            // SQL LIKE 연산자를 위한 패턴 변환 ('*' -> '%', 필요시 다른 와일드카드 처리)
            var likePattern = scopePattern.Replace("*", "%");

            return await QueryForOrganization(organizationId)
                // EF.Functions.Like 사용 (DB 의존적일 수 있음 - 대부분 지원)
                .Where(rp => EF.Functions.Like(rp.PermissionScope, likePattern))
                .Include(rp => rp.Role!)
                .Include(rp => rp.Permission!)
                .OrderBy(rp => rp.PermissionScope) // 스코프 순 정렬
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Unit of Work (제거됨)
        // SaveChangesAsync는 IUnitOfWork 패턴의 일부로, 서비스 레이어에서 호출됩니다.
        // Repository는 개별 엔티티의 상태 변경만 담당합니다.
        /*
        /// <summary>
        /// 변경사항 저장 (Unit of Work 패턴의 일부) - 서비스 레이어로 이동
        /// </summary>
        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            // return _context.SaveChangesAsync(cancellationToken);
            throw new NotSupportedException("SaveChangesAsync should be called from the Unit of Work in the service layer.");
        }
        */
        #endregion
    }
}