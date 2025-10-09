// Path: AuthHive.Auth/Services/Authentication/RoleAdminService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Common;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Auth.Role.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Models.Auth.Role.Events;
using AuthHive.Core.Models.Auth.Role;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Constants.Business;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 역할의 관리, 유지보수, 데이터 마이그레이션 작업을 담당하는 서비스
    /// </summary>
    public class RoleAdminService : IRoleAdminService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IOrganizationSettingsQueryRepository _orgSettingsQueryRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly ILogger<RoleAdminService> _logger;

        public RoleAdminService(
            IRoleRepository roleRepository,
            IRolePermissionRepository rolePermissionRepository,
            IOrganizationSettingsQueryRepository orgSettingsQueryRepository,
            IUnitOfWork unitOfWork,
            IEventBus eventBus,
            IAuditService auditService,
            ILogger<RoleAdminService> logger)
        {
            _roleRepository = roleRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _orgSettingsQueryRepository = orgSettingsQueryRepository;
            _unitOfWork = unitOfWork;
            _eventBus = eventBus;
            _auditService = auditService;
            _logger = logger;
        }
        #region IService Implementation

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("RoleAdminService initializing...");

                // async 없이 Task.CompletedTask를 반환하여 최적화
                _logger.LogInformation("RoleAdminService initialized successfully");
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize RoleAdminService");
                throw;
            }
        }

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Repository 연결 상태 확인
                // AnyAsync에 CancellationToken을 전달합니다.
                var testQuery = await _roleRepository.AnyAsync(r => true, cancellationToken);

                return true;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleAdminService health check failed");
                return false;
            }
        }

        #endregion
        #region 상태 관리

        /// <summary>
        /// 역할 만료 일시 설정
        /// </summary>
        public async Task<ServiceResult> SetExpirationAsync(Guid roleId, DateTime? expiresAt, Guid actorId)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return ServiceResult.NotFound("역할을 찾을 수 없습니다.");
                }

                if (expiresAt.HasValue && expiresAt.Value < DateTime.UtcNow)
                {
                    return ServiceResult.Failure(
                        "만료 일시는 현재 시간 이후여야 합니다.",
                        "INVALID_EXPIRATION_DATE");
                }

                role.ExpiresAt = expiresAt;

                await _roleRepository.UpdateAsync(role);
                await _unitOfWork.SaveChangesAsync();

                // 이벤트 발행으로 캐시 무효화 처리 위임
                await _eventBus.PublishAsync(new RoleUpdatedEvent(role.Id, role.OrganizationId));

                await _auditService.LogActionAsync(
                    actorId,
                    "SetRoleExpiration",
                    AuditActionType.StatusChange,
                    $"Role {role.Id} expiration set to {expiresAt}",
                    System.Text.Json.JsonSerializer.Serialize(new { roleId, expiresAt }) // 2. 객체를 JSON 문자열로 변환
  );

                return ServiceResult.Success("역할 만료 일시가 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error setting expiration for role {roleId}");
                return ServiceResult.Failure("역할 만료 일시 설정 중 오류가 발생했습니다.", "INTERNAL_ERROR");
            }
        }

        /// <summary>
        /// 만료된 역할 정리
        /// </summary>

        public async Task<ServiceResult<BulkRoleCreateResponse>> BulkCreateRolesAsync(List<CreateRoleRequest> requests, Guid actorId)
        {
            var response = new BulkRoleCreateResponse();

            // 성능 최적화: 기존 RoleKey들을 한 번에 조회
            var orgIds = requests.Select(r => r.OrganizationId).Distinct();
            var existingRoles = await _roleRepository.GetByOrganizationIdsAsync(orgIds);
            var existingRoleKeys = existingRoles.ToLookup(r => r.OrganizationId, r => r.RoleKey);

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var request in requests)
                {
                    if (existingRoleKeys[request.OrganizationId].Contains(request.RoleKey))
                    {
                        response.Failed.Add(new FailedRoleCreate
                        {
                            Request = request,
                            Reason = $"역할 키 '{request.RoleKey}'가 이미 존재합니다.",
                            ErrorCode = "DUPLICATE_ROLE_KEY"
                        });
                        continue;
                    }

                    var role = new Role { /* ... 매핑 ... */ };
                    var createdRole = await _roleRepository.AddAsync(role);

                    // 초기 권한 할당
                    if (request.InitialPermissionIds?.Any() == true)
                    {
                        foreach (var permissionId in request.InitialPermissionIds)
                        {
                            await _rolePermissionRepository.AssignPermissionAsync(createdRole.Id, permissionId, actorId, "Initial permission assignment");
                        }
                    }
                    response.Succeeded.Add(new RoleDto { Id = createdRole.Id, Name = createdRole.Name, RoleKey = createdRole.RoleKey });
                }

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                // 각 조직별 캐시 무효화
                foreach (var orgId in orgIds)
                {
                    await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(orgId));
                }

                await _auditService.LogActionAsync(
                  actorId,
                  "BulkCreateRoles",
                  AuditActionType.BulkCreate, // 1. "PartialSuccess" 대신 Enum 타입 사용
                  $"Succeeded: {response.Succeeded.Count}, Failed: {response.Failed.Count}",
                  System.Text.Json.JsonSerializer.Serialize(response) // 2. response 객체 전체를 JSON으로 기록
              );
                return ServiceResult<BulkRoleCreateResponse>.Success(
                    response,
                    $"{response.Succeeded.Count} roles created, {response.Failed.Count} failed");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk role creation");
                return ServiceResult<BulkRoleCreateResponse>.Failure(
                    "An error occurred during bulk role creation.",
                    "BULK_CREATE_ERROR");
            }
        }
        #endregion

        #region 일괄 작업 (Bulk Operations)

        /// <summary>
        /// 역할 일괄 활성/비활성 설정
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkSetActiveStateAsync(List<Guid> roleIds, bool isActive, Guid actorId)
        {
            var result = new BulkOperationResult();
            var updatedRoles = new List<Role>();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 성능 최적화: ID 목록으로 역할을 한 번에 조회합니다.
                var roles = await _roleRepository.GetByIdsAsync(roleIds);
                var rolesById = roles.ToDictionary(r => r.Id);

                foreach (var roleId in roleIds)
                {
                    if (rolesById.TryGetValue(roleId, out var role))
                    {
                        // 역할 상태 업데이트
                        role.IsActive = isActive;
                        role.UpdatedAt = DateTime.UtcNow;
                        await _roleRepository.UpdateAsync(role);

                        updatedRoles.Add(role);
                        result.SuccessCount++;
                    }
                    else
                    {
                        // 찾을 수 없는 역할 처리
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = roleId,
                            Reason = "Role not found.", // 영문화
                            ErrorCode = "NOT_FOUND"
                        });
                        result.FailureCount++;
                    }
                }

                if (result.SuccessCount > 0)
                {
                    await _unitOfWork.SaveChangesAsync();
                }

                await _unitOfWork.CommitTransactionAsync();

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actorId,
                    "BulkSetActiveState",
                    AuditActionType.BulkUpdate,
                    $"{result.SuccessCount} roles updated to IsActive={isActive}. {result.FailureCount} failed.",
                    System.Text.Json.JsonSerializer.Serialize(new { SucceededIds = updatedRoles.Select(r => r.Id), FailedIds = result.Errors.Select(e => e.EntityId) })
                );

                // 이벤트 발행: 영향을 받은 각 조직에 대해 이벤트를 발행합니다.
                var affectedOrgIds = updatedRoles.Select(r => r.OrganizationId).Distinct();
                foreach (var orgId in affectedOrgIds)
                {
                    await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(orgId));
                }

                return ServiceResult<BulkOperationResult>.Success(
                    result,
                    $"{result.SuccessCount} succeeded, {result.FailureCount} failed"); // 영문화
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk set active state");

                return ServiceResult<BulkOperationResult>.Failure(
                    "An error occurred during bulk state update.", // 영문화
                    "BULK_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 역할 일괄 삭제
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkDeleteRolesAsync(List<Guid> roleIds, Guid actorId)
        {
            var result = new BulkOperationResult();
            var deletedRoles = new List<Role>();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 성능 최적화: 삭제할 역할들을 한 번의 쿼리로 조회합니다.
                var rolesToDelete = await _roleRepository.GetByIdsAsync(roleIds);
                var foundRoleIds = rolesToDelete.Select(r => r.Id).ToHashSet();

                // DB에 존재하지 않는 ID들을 실패 처리합니다.
                var notFoundIds = roleIds.Where(id => !foundRoleIds.Contains(id));
                foreach (var notFoundId in notFoundIds)
                {
                    result.Errors.Add(new BulkOperationError
                    {
                        EntityId = notFoundId,
                        Reason = "Role not found.",
                        ErrorCode = "NOT_FOUND"
                    });
                    result.FailureCount++;
                }

                // 찾은 역할들에 대해 Soft Delete를 수행합니다.
                foreach (var role in rolesToDelete)
                {
                    try
                    {
                        await _roleRepository.SoftDeleteAsync(role.Id);
                        deletedRoles.Add(role);
                        result.SuccessCount++;
                    }
                    catch (Exception ex)
                    {
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = role.Id,
                            Reason = ex.Message,
                            ErrorCode = "DELETE_ERROR"
                        });
                        result.FailureCount++;
                    }
                }

                if (result.SuccessCount > 0)
                {
                    await _unitOfWork.SaveChangesAsync();
                }

                await _unitOfWork.CommitTransactionAsync();

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actorId,
                    "BulkDeleteRoles",
                    AuditActionType.BulkDelete,
                    $"{result.SuccessCount} roles deleted. {result.FailureCount} failed.",
                    System.Text.Json.JsonSerializer.Serialize(new { SucceededIds = deletedRoles.Select(r => r.Id), FailedIds = result.Errors.Select(e => e.EntityId) })
                );

                // 이벤트 발행
                var affectedOrgIds = deletedRoles.Select(r => r.OrganizationId).Distinct();
                foreach (var orgId in affectedOrgIds)
                {
                    await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(orgId));
                }

                return ServiceResult<BulkOperationResult>.Success(
                    result,
                    $"{result.SuccessCount} deleted, {result.FailureCount} failed");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk delete roles");

                return ServiceResult<BulkOperationResult>.Failure(
                    "An error occurred during bulk role deletion.",
                    "BULK_DELETE_ERROR");
            }
        }

        #endregion

        #region 복제 및 복사

        /// <summary>
        /// 역할 복제
        /// </summary>
        public async Task<ServiceResult<RoleResponse>> CloneRoleAsync(Guid sourceRoleId, string newRoleName, string newRoleKey, Guid actorId)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var sourceRole = await _roleRepository.GetWithRelatedDataAsync(
                    sourceRoleId,
                    includePermissions: true);

                if (sourceRole == null)
                {
                    return ServiceResult<RoleResponse>.NotFound("Source role not found.");
                }

                // Validate if the new RoleKey already exists in the organization
                if (await _roleRepository.RoleKeyExistsAsync(sourceRole.OrganizationId, newRoleKey))
                {
                    return ServiceResult<RoleResponse>.Failure($"Role key '{newRoleKey}' already exists.", "DUPLICATE_ROLE_KEY");
                }

                // Create the new role
                var clonedRole = new Role
                {
                    OrganizationId = sourceRole.OrganizationId,
                    Name = newRoleName,
                    Description = sourceRole.Description + " (Copied)",
                    RoleKey = newRoleKey,
                    Scope = sourceRole.Scope,
                    ApplicationId = sourceRole.ApplicationId,
                    Level = sourceRole.Level,
                    Priority = sourceRole.Priority,
                    MaxAssignments = sourceRole.MaxAssignments,
                    IsActive = true, // Cloned roles are active by default
                    Tags = sourceRole.Tags,
                    Metadata = sourceRole.Metadata,
                    CreatedAt = DateTime.UtcNow
                };

                var created = await _roleRepository.AddAsync(clonedRole);

                // Copy permissions
                if (sourceRole.RolePermissions.Any())
                {
                    foreach (var rolePermission in sourceRole.RolePermissions)
                    {
                        await _rolePermissionRepository.AssignPermissionAsync(
                            created.Id,
                            rolePermission.PermissionId,
                            actorId, // Use the actorId for the audit trail
                            $"Cloned from role '{sourceRole.Name}' ({sourceRole.Id})");
                    }
                }

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                // Add Audit Log
                await _auditService.LogActionAsync(
                    actorId,
                    "CloneRole",
                    AuditActionType.Create,
                    $"Role '{sourceRole.Name}' ({sourceRoleId}) cloned to new role '{created.Name}' ({created.Id})",
                    System.Text.Json.JsonSerializer.Serialize(new { sourceRoleId, ClonedRoleId = created.Id, NewRoleKey = newRoleKey })
                );

                // Publish event for cache invalidation
                await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(created.OrganizationId));

                var response = new RoleResponse
                {
                    Id = created.Id,
                    OrganizationId = created.OrganizationId,
                    Name = created.Name,
                    RoleKey = created.RoleKey,
                    Scope = created.Scope,
                    IsActive = created.IsActive,
                    CreatedAt = created.CreatedAt
                };

                return ServiceResult<RoleResponse>.Success(
                    response,
                    "Role cloned successfully.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error cloning role {sourceRoleId}");

                return ServiceResult<RoleResponse>.Failure(
                    "An error occurred while cloning the role.",
                    "CLONE_ERROR");
            }
        }

        /// <summary>
        /// 권한 복사
        /// </summary>
        public async Task<ServiceResult> CopyPermissionsAsync(
          Guid sourceRoleId,
          Guid targetRoleId,
          Guid actorId,
          bool overwrite = false,
          CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                // Validate that both roles exist and are in the same organization
                var sourceRole = await _roleRepository.GetByIdAsync(sourceRoleId, cancellationToken);
                var targetRole = await _roleRepository.GetByIdAsync(targetRoleId, cancellationToken);

                if (sourceRole == null) return ServiceResult.NotFound("Source role not found.");
                if (targetRole == null) return ServiceResult.NotFound("Target role not found.");
                if (sourceRole.OrganizationId != targetRole.OrganizationId)
                {
                    return ServiceResult.Failure("Roles must be in the same organization.", "ORGANIZATION_MISMATCH");
                }

                // Get permissions from the source role
                var sourcePermissions = await _rolePermissionRepository.GetByRoleAsync(sourceRoleId, cancellationToken: cancellationToken);
                if (!sourcePermissions.Any())
                {
                    return ServiceResult.Failure("Source role has no permissions to copy.", "NO_PERMISSIONS");
                }

                // If in overwrite mode, remove all existing permissions from the target role
                if (overwrite)
                {
                    await _rolePermissionRepository.RemoveAllPermissionsAsync(targetRoleId, $"Overwrite by {actorId} for permission copy", cancellationToken);
                }

                // Performance Optimization: Get target permissions once to avoid N+1 queries
                var targetPermissionIds = overwrite
                    ? new HashSet<Guid>()
                    : (await _rolePermissionRepository.GetByRoleAsync(targetRoleId, cancellationToken: cancellationToken)).Select(p => p.PermissionId).ToHashSet();

                var permissionsAdded = 0;
                // Copy permissions
                foreach (var permission in sourcePermissions)
                {
                    // Check in memory instead of hitting the database in a loop
                    if (!targetPermissionIds.Contains(permission.PermissionId))
                    {
                        await _rolePermissionRepository.AssignPermissionAsync(
             targetRoleId,
             permission.PermissionId,
             actorId,
             reason: $"Copied from role '{sourceRole.Name}' ({sourceRoleId})",
             expiresAt: null,
             cancellationToken: cancellationToken);
                        permissionsAdded++;
                    }
                }

                if (permissionsAdded > 0 || overwrite)
                {
                    await _unitOfWork.SaveChangesAsync(cancellationToken);
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // Add Audit Log
                await _auditService.LogActionAsync(
             actorId,                    // performedByConnectedId
             "CopyRolePermissions",      // action
             AuditActionType.Update,     // actionType
             "Role",                     // resourceType ← 빠짐
             targetRoleId.ToString(),    // resourceId ← 빠짐
             success: true,              // success
             metadata: System.Text.Json.JsonSerializer.Serialize(new { sourceRoleId, targetRoleId, actorId, overwrite, permissionsAdded })
         );

                // Publish event for cache invalidation on the target role
                await _eventBus.PublishAsync(new RoleUpdatedEvent(targetRoleId, targetRole.OrganizationId), cancellationToken);

                return ServiceResult.Success("Permissions copied successfully.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, $"Error copying permissions from {sourceRoleId} to {targetRoleId}");

                return ServiceResult.Failure(
                    "An error occurred while copying permissions.",
                    "COPY_ERROR");
            }
        }
        #endregion

        #region 내보내기/가져오기

        /// <summary>
        /// 역할 내보내기
        /// </summary>
        public async Task<ServiceResult<RoleExportData>> ExportRolesAsync(Guid organizationId, Guid actorId, string format = "json")
        {
            try
            {
                var roles = await _roleRepository.GetByOrganizationAsync(organizationId, includeInactive: true);
                var exportData = new RoleExportData
                {
                    Format = format,
                    RoleCount = roles.Count(),
                    ExportedAt = DateTime.UtcNow,
                    ExportedByConnectedId = actorId // Use the actorId
                };

                switch (format.ToLower())
                {
                    case "json":
                        var jsonContent = System.Text.Json.JsonSerializer.Serialize(roles, new System.Text.Json.JsonSerializerOptions
                        {
                            WriteIndented = true
                        });
                        exportData.Content = jsonContent;
                        exportData.FileSizeInBytes = Encoding.UTF8.GetByteCount(jsonContent);
                        break;

                    case "csv":
                        // CSV conversion logic
                        var csvBuilder = new StringBuilder();
                        csvBuilder.AppendLine("Id,Name,RoleKey,Scope,Level,IsActive");
                        foreach (var role in roles)
                        {
                            csvBuilder.AppendLine($"{role.Id},{role.Name},{role.RoleKey},{role.Scope},{role.Level},{role.IsActive}");
                        }
                        exportData.Content = csvBuilder.ToString();
                        exportData.FileSizeInBytes = Encoding.UTF8.GetByteCount(exportData.Content);
                        break;

                    default:
                        return ServiceResult<RoleExportData>.Failure(
                            "Unsupported format.",
                            "UNSUPPORTED_FORMAT");
                }

                // Add Audit Log
                await _auditService.LogActionAsync(
                    actorId,
                    "ExportRoles",
                    AuditActionType.Export,
                    $"Exported {exportData.RoleCount} roles from organization {organizationId} in {format} format.",
                    System.Text.Json.JsonSerializer.Serialize(new { organizationId, format, roleCount = exportData.RoleCount })
                );

                return ServiceResult<RoleExportData>.Success(
                    exportData,
                    "Roles exported successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error exporting roles for organization {organizationId}");

                return ServiceResult<RoleExportData>.Failure(
                    "An error occurred while exporting roles.",
                    "EXPORT_ERROR");
            }
        }

        /// <summary>
        /// 역할 가져오기
        /// </summary>
        public async Task<ServiceResult<RoleImportResult>> ImportRolesAsync(RoleImportData importData, Guid actorId, bool overwrite = false)
        {
            var result = new RoleImportResult
            {
                ImportedAt = DateTime.UtcNow,
                ImportedByConnectedId = actorId
            };

            try
            {
                // 데이터 파싱
                var content = Encoding.UTF8.GetString(importData.Data);
                List<Role> rolesToImport;

                switch (importData.Format.ToLower())
                {
                    case "json":
                        rolesToImport = JsonSerializer.Deserialize<List<Role>>(content) ?? new List<Role>();
                        break;
                    default:
                        return ServiceResult<RoleImportResult>.Failure(
                            "Unsupported format.",
                            "UNSUPPORTED_FORMAT");
                }

                if (!rolesToImport.Any())
                {
                    return ServiceResult<RoleImportResult>.Success(result, "Import file was empty. No roles were processed.");
                }

                await _unitOfWork.BeginTransactionAsync();

                // 성능 최적화: 조직의 모든 기존 역할을 한 번에 조회
                var existingRoles = await _roleRepository.GetByOrganizationAsync(importData.OrganizationId, includeInactive: true);
                var existingRolesMap = existingRoles.ToDictionary(r => r.RoleKey, r => r);

                // SaaS 원칙: 새 역할을 만들기 전 가격 정책 제한 확인
                var rolesToCreateCount = rolesToImport.Count(r => !existingRolesMap.ContainsKey(r.RoleKey));
                if (rolesToCreateCount > 0)
                {
                    // 1. "PricingPlanId" 설정을 직접 조회합니다.
                    var pricingPlanSetting = await _orgSettingsQueryRepository.GetSettingAsync(
                        importData.OrganizationId,
                        "Billing", // 카테고리는 "Billing" 또는 유사한 표준 이름이어야 합니다.
                        "PricingPlanId"
                    );

                    // 2. 설정 값이 없거나 비어있으면 기본 플랜 키를 사용합니다.
                    var pricingPlanId = !string.IsNullOrEmpty(pricingPlanSetting?.SettingValue)
                        ? pricingPlanSetting.SettingValue
                        : PricingConstants.DefaultPlanKey;

                    // 3. GetPlan 메서드 호출
                    var plan = PricingConstants.GetPlan(pricingPlanId);
                    var currentRoleCount = existingRoles.Count();

                    // 4. 'plan' 객체를 사용한 한도 검사 (-1은 무제한을 의미)
                    if (plan.MaxRoles != -1 && (currentRoleCount + rolesToCreateCount > plan.MaxRoles))
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult<RoleImportResult>.Failure(
                            $"Importing {rolesToCreateCount} new roles would exceed your plan's limit of {plan.MaxRoles} roles. " +
                            $"You currently have {currentRoleCount} roles.",
                            "PLAN_LIMIT_EXCEEDED");
                    }
                }

                // 각 역할 처리
                foreach (var role in rolesToImport)
                {
                    // ... (이하 로직은 이전 답변과 동일) ...
                    try
                    {
                        if (existingRolesMap.TryGetValue(role.RoleKey, out var existingRole))
                        {
                            if (overwrite)
                            {
                                existingRole.Name = role.Name;
                                existingRole.Description = role.Description;
                                existingRole.UpdatedAt = DateTime.UtcNow;
                                await _roleRepository.UpdateAsync(existingRole);
                                result.Updated++;
                            }
                            else
                            {
                                result.Skipped++;
                            }
                        }
                        else
                        {
                            role.OrganizationId = importData.OrganizationId;
                            role.Id = Guid.NewGuid();
                            role.CreatedAt = DateTime.UtcNow;
                            await _roleRepository.AddAsync(role);
                            result.Created++;
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Failed++;
                        result.Errors.Add(new ImportError { RoleKey = role.RoleKey, Reason = ex.Message });
                    }
                }

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                // 감사 로그 및 이벤트 발행
                await _auditService.LogActionAsync(
                    actorId,
                    "ImportRoles",
                    AuditActionType.BulkUpdate, // 생성과 수정을 모두 포함할 수 있으므로 BulkUpdate가 적합
                    $"Import completed: {result.Created} created, {result.Updated} updated, {result.Skipped} skipped, {result.Failed} failed.",
                    JsonSerializer.Serialize(result)
                );
                await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(importData.OrganizationId));

                return ServiceResult<RoleImportResult>.Success(result, $"Import completed: {result.Created} created, {result.Updated} updated, {result.Skipped} skipped, {result.Failed} failed.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error importing roles");
                return ServiceResult<RoleImportResult>.Failure("An error occurred while importing roles.", "IMPORT_ERROR");
            }
        }
        #endregion
        public async Task<ServiceResult<int>> CleanupExpiredRolesAsync(Guid organizationId, Guid actorId)
        {
            try
            {
                // 1. Begin a transaction for data consistency.
                await _unitOfWork.BeginTransactionAsync();

                var expiredRoles = await _roleRepository.GetExpiredRolesAsync(organizationId, DateTime.UtcNow);
                var cleanupCount = 0;
                var roleIdsToDeactivate = new List<Guid>();

                if (expiredRoles.Any())
                {
                    foreach (var role in expiredRoles)
                    {
                        role.IsActive = false;
                        await _roleRepository.UpdateAsync(role);
                        cleanupCount++;
                        roleIdsToDeactivate.Add(role.Id);
                    }
                    await _unitOfWork.SaveChangesAsync();
                }

                // 2. Commit all changes to the DB at once.
                await _unitOfWork.CommitTransactionAsync();

                if (cleanupCount > 0)
                {
                    // 3. Publish an event for cache invalidation.
                    await _eventBus.PublishAsync(new OrganizationRolesChangedEvent(organizationId));

                    // 4. Record an audit log for traceability.
                    await _auditService.LogActionAsync(
                        actorId,
                        "CleanupExpiredRoles",
                        AuditActionType.BulkUpdate,
                        $"{cleanupCount} expired roles were deactivated for organization {organizationId}.",
                        System.Text.Json.JsonSerializer.Serialize(new { organizationId, cleanupCount, DeactivatedRoleIds = roleIdsToDeactivate })
                    );
                }

                // This return statement is now outside the 'if' block to ensure a value is always returned.
                return ServiceResult<int>.Success(
                    cleanupCount,
                    $"{cleanupCount} expired roles were deactivated.");
            }
            catch (Exception ex)
            {
                // If an error occurs, rollback all changes.
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error cleaning up expired roles for organization {organizationId}");

                return ServiceResult<int>.Failure(
                    "An error occurred while cleaning up expired roles.",
                    "CLEANUP_ERROR");
            }
        }

    }
}