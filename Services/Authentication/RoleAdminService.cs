using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role;
using AuthHive.Core.Models.Auth.Role.Common;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Auth.Role.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 역할의 관리, 유지보수, 데이터 마이그레이션 작업을 담당하는 서비스
    /// </summary>
    public class RoleAdminService : IRoleAdminService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMemoryCache _cache;
        private readonly ILogger<RoleAdminService> _logger;

        public RoleAdminService(
            IRoleRepository roleRepository,
            IRolePermissionRepository rolePermissionRepository,
            IUnitOfWork unitOfWork,
            IMemoryCache cache,
            ILogger<RoleAdminService> logger)
        {
            _roleRepository = roleRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _unitOfWork = unitOfWork;
            _cache = cache;
            _logger = logger;
        }

        #region 상태 관리

        /// <summary>
        /// 역할 만료 일시 설정
        /// </summary>
        public async Task<ServiceResult> SetExpirationAsync(Guid roleId, DateTime? expiresAt)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return ServiceResult.Failure(
                        "역할을 찾을 수 없습니다.",
                        "ROLE_NOT_FOUND");
                }

                // 과거 날짜 검증
                if (expiresAt.HasValue && expiresAt.Value < DateTime.UtcNow)
                {
                    return ServiceResult.Failure(
                        "만료 일시는 현재 시간 이후여야 합니다.",
                        "INVALID_EXPIRATION_DATE");
                }

                role.ExpiresAt = expiresAt;
                role.UpdatedAt = DateTime.UtcNow;

                await _roleRepository.UpdateAsync(role);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await ClearRoleCacheAsync(roleId);

                _logger.LogInformation($"Role {roleId} expiration set to {expiresAt}");

                return ServiceResult.Success("역할 만료 일시가 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error setting expiration for role {roleId}");
                return ServiceResult.Failure(
                    "역할 만료 일시 설정 중 오류가 발생했습니다.",
                    "INTERNAL_ERROR");
            }
        }

        /// <summary>
        /// 만료된 역할 정리
        /// </summary>
        public async Task<ServiceResult<int>> CleanupExpiredRolesAsync(Guid organizationId)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var expiredRoles = await _roleRepository.GetExpiredRolesAsync(organizationId, DateTime.UtcNow);
                var cleanupCount = 0;

                foreach (var role in expiredRoles)
                {
                    role.IsActive = false;
                    role.UpdatedAt = DateTime.UtcNow;
                    await _roleRepository.UpdateAsync(role);
                    cleanupCount++;

                    _logger.LogInformation($"Deactivated expired role: {role.Id}");
                }

                await _unitOfWork.CommitTransactionAsync();

                // 조직 캐시 무효화
                await ClearOrganizationRoleCacheAsync(organizationId);

                return ServiceResult<int>.Success(
                    cleanupCount,
                    $"{cleanupCount}개의 만료된 역할이 비활성화되었습니다.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error cleaning up expired roles for organization {organizationId}");
                
                return ServiceResult<int>.Failure(
                    "만료된 역할 정리 중 오류가 발생했습니다.",
                    "CLEANUP_ERROR");
            }
        }

        #endregion

        #region 일괄 작업 (Bulk Operations)

        /// <summary>
        /// 역할 일괄 생성
        /// </summary>
        public async Task<ServiceResult<BulkRoleCreateResponse>> BulkCreateRolesAsync(List<CreateRoleRequest> requests)
        {
            var response = new BulkRoleCreateResponse();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var request in requests)
                {
                    try
                    {
                        // 중복 체크
                        var exists = await _roleRepository.RoleKeyExistsAsync(
                            request.OrganizationId, 
                            request.RoleKey);

                        if (exists)
                        {
                            response.Failed.Add(new FailedRoleCreate
                            {
                                Request = request,
                                Reason = $"역할 키 '{request.RoleKey}'가 이미 존재합니다.",
                                ErrorCode = "DUPLICATE_ROLE_KEY"
                            });
                            continue;
                        }

                        // 역할 생성
                        var role = new Role
                        {
                            OrganizationId = request.OrganizationId,
                            Name = request.Name,
                            Description = request.Description,
                            RoleKey = request.RoleKey,
                            Scope = request.Scope,
                            ApplicationId = request.ApplicationId,
                            Category = request.Category,
                            Level = (PermissionLevel)request.Level,
                            ParentRoleId = request.ParentRoleId,
                            Priority = request.Priority,
                            MaxAssignments = request.MaxAssignments,
                            ExpiresAt = request.ExpiresAt,
                            IsActive = request.IsActive,
                            Tags = request.Tags,
                            Metadata = request.Metadata,
                            CreatedAt = DateTime.UtcNow
                        };

                        var createdRole = await _roleRepository.AddAsync(role);

                        // 초기 권한 할당
                        if (request.InitialPermissionIds?.Any() == true)
                        {
                            foreach (var permissionId in request.InitialPermissionIds)
                            {
                                await _rolePermissionRepository.AssignPermissionAsync(
                                    createdRole.Id,
                                    permissionId,
                                    Guid.Empty, // TODO: 실제 사용자 ID 필요
                                    "Initial permission assignment");
                            }
                        }

                        response.Succeeded.Add(new RoleDto
                        {
                            Id = createdRole.Id,
                            Name = createdRole.Name,
                            RoleKey = createdRole.RoleKey
                        });
                    }
                    catch (Exception ex)
                    {
                        response.Failed.Add(new FailedRoleCreate
                        {
                            Request = request,
                            Reason = ex.Message,
                            ErrorCode = "CREATE_ERROR"
                        });
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation($"Bulk created {response.Succeeded.Count} roles, {response.Failed.Count} failed");

                return ServiceResult<BulkRoleCreateResponse>.Success(
                    response,
                    $"{response.Succeeded.Count}개 역할 생성, {response.Failed.Count}개 실패");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk role creation");
                
                return ServiceResult<BulkRoleCreateResponse>.Failure(
                    "역할 일괄 생성 중 오류가 발생했습니다.",
                    "BULK_CREATE_ERROR");
            }
        }

        /// <summary>
        /// 역할 일괄 활성/비활성 설정
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkSetActiveStateAsync(List<Guid> roleIds, bool isActive)
        {
            var result = new BulkOperationResult();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var roleId in roleIds)
                {
                    try
                    {
                        var role = await _roleRepository.GetByIdAsync(roleId);
                        if (role == null)
                        {
                            result.Errors.Add(new BulkOperationError
                            {
                                EntityId = roleId,
                                Reason = "역할을 찾을 수 없습니다.",
                                ErrorCode = "NOT_FOUND"
                            });
                            result.FailureCount++;
                            continue;
                        }

                        role.IsActive = isActive;
                        role.UpdatedAt = DateTime.UtcNow;
                        await _roleRepository.UpdateAsync(role);
                        
                        result.SuccessCount++;
                    }
                    catch (Exception ex)
                    {
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = roleId,
                            Reason = ex.Message,
                            ErrorCode = "UPDATE_ERROR"
                        });
                        result.FailureCount++;
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult<BulkOperationResult>.Success(
                    result,
                    $"{result.SuccessCount}개 성공, {result.FailureCount}개 실패");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk set active state");
                
                return ServiceResult<BulkOperationResult>.Failure(
                    "역할 상태 일괄 변경 중 오류가 발생했습니다.",
                    "BULK_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 역할 일괄 삭제
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkDeleteRolesAsync(List<Guid> roleIds)
        {
            var result = new BulkOperationResult();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var roleId in roleIds)
                {
                    try
                    {
                        // Soft delete
                        await _roleRepository.SoftDeleteAsync(roleId);
                        result.SuccessCount++;
                    }
                    catch (Exception ex)
                    {
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = roleId,
                            Reason = ex.Message,
                            ErrorCode = "DELETE_ERROR"
                        });
                        result.FailureCount++;
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult<BulkOperationResult>.Success(
                    result,
                    $"{result.SuccessCount}개 삭제 성공, {result.FailureCount}개 실패");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error in bulk delete roles");
                
                return ServiceResult<BulkOperationResult>.Failure(
                    "역할 일괄 삭제 중 오류가 발생했습니다.",
                    "BULK_DELETE_ERROR");
            }
        }

        #endregion

        #region 복제 및 복사

        /// <summary>
        /// 역할 복제
        /// </summary>
        public async Task<ServiceResult<RoleResponse>> CloneRoleAsync(Guid sourceRoleId, string newRoleName, string newRoleKey)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var sourceRole = await _roleRepository.GetWithRelatedDataAsync(
                    sourceRoleId, 
                    includePermissions: true);

                if (sourceRole == null)
                {
                    return ServiceResult<RoleResponse>.NotFound("원본 역할을 찾을 수 없습니다.");
                }

                // 새 역할 생성
                var clonedRole = new Role
                {
                    OrganizationId = sourceRole.OrganizationId,
                    Name = newRoleName,
                    Description = sourceRole.Description + " (복제됨)",
                    RoleKey = newRoleKey,
                    Scope = sourceRole.Scope,
                    ApplicationId = sourceRole.ApplicationId,
                    Category = sourceRole.Category,
                    Level = sourceRole.Level,
                    Priority = sourceRole.Priority,
                    MaxAssignments = sourceRole.MaxAssignments,
                    IsActive = true,
                    Tags = sourceRole.Tags,
                    Metadata = sourceRole.Metadata,
                    CreatedAt = DateTime.UtcNow
                };

                var created = await _roleRepository.AddAsync(clonedRole);

                // 권한 복사
                foreach (var rolePermission in sourceRole.RolePermissions)
                {
                    await _rolePermissionRepository.AssignPermissionAsync(
                        created.Id,
                        rolePermission.PermissionId,
                        Guid.Empty, // TODO: 실제 사용자 ID
                        $"Cloned from role {sourceRole.Name}");
                }

                await _unitOfWork.CommitTransactionAsync();

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
                    "역할이 성공적으로 복제되었습니다.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error cloning role {sourceRoleId}");
                
                return ServiceResult<RoleResponse>.Failure(
                    "역할 복제 중 오류가 발생했습니다.",
                    "CLONE_ERROR");
            }
        }

        /// <summary>
        /// 권한 복사
        /// </summary>
        public async Task<ServiceResult> CopyPermissionsAsync(Guid sourceRoleId, Guid targetRoleId, bool overwrite = false)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 원본 역할의 권한 조회
                var sourcePermissions = await _rolePermissionRepository.GetByRoleAsync(sourceRoleId);
                
                if (!sourcePermissions.Any())
                {
                    return ServiceResult.Failure(
                        "원본 역할에 권한이 없습니다.",
                        "NO_PERMISSIONS");
                }

                // 덮어쓰기 모드인 경우 기존 권한 제거
                if (overwrite)
                {
                    await _rolePermissionRepository.RemoveAllPermissionsAsync(targetRoleId, "Overwrite for permission copy");
                }

                // 권한 복사
                foreach (var permission in sourcePermissions)
                {
                    var exists = await _rolePermissionRepository.ExistsAsync(targetRoleId, permission.PermissionId);
                    if (!exists)
                    {
                        await _rolePermissionRepository.AssignPermissionAsync(
                            targetRoleId,
                            permission.PermissionId,
                            Guid.Empty, // TODO: 실제 사용자 ID
                            $"Copied from role {sourceRoleId}");
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult.Success("권한이 성공적으로 복사되었습니다.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error copying permissions from {sourceRoleId} to {targetRoleId}");
                
                return ServiceResult.Failure(
                    "권한 복사 중 오류가 발생했습니다.",
                    "COPY_ERROR");
            }
        }

        #endregion

        #region 내보내기/가져오기

        /// <summary>
        /// 역할 내보내기
        /// </summary>
        public async Task<ServiceResult<RoleExportData>> ExportRolesAsync(Guid organizationId, string format = "json")
        {
            try
            {
                var roles = await _roleRepository.GetByOrganizationAsync(organizationId, includeInactive: true);
                var exportData = new RoleExportData
                {
                    Format = format,
                    RoleCount = roles.Count(),
                    ExportedAt = DateTime.UtcNow,
                    ExportedByConnectedId = Guid.Empty // TODO: 실제 사용자 ID
                };

                switch (format.ToLower())
                {
                    case "json":
                        var jsonContent = JsonSerializer.Serialize(roles, new JsonSerializerOptions
                        {
                            WriteIndented = true
                        });
                        exportData.Content = jsonContent;
                        exportData.FileSizeInBytes = Encoding.UTF8.GetByteCount(jsonContent);
                        break;
                    
                    case "csv":
                        // CSV 변환 로직
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
                            "지원하지 않는 형식입니다.",
                            "UNSUPPORTED_FORMAT");
                }

                return ServiceResult<RoleExportData>.Success(
                    exportData,
                    "역할이 성공적으로 내보내졌습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error exporting roles for organization {organizationId}");
                
                return ServiceResult<RoleExportData>.Failure(
                    "역할 내보내기 중 오류가 발생했습니다.",
                    "EXPORT_ERROR");
            }
        }

        /// <summary>
        /// 역할 가져오기
        /// </summary>
        public async Task<ServiceResult<RoleImportResult>> ImportRolesAsync(RoleImportData importData, bool overwrite = false)
        {
            var result = new RoleImportResult
            {
                ImportedAt = DateTime.UtcNow,
                ImportedByConnectedId = Guid.Empty // TODO: 실제 사용자 ID
            };

            try
            {
                await _unitOfWork.BeginTransactionAsync();

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
                            "지원하지 않는 형식입니다.",
                            "UNSUPPORTED_FORMAT");
                }

                // 각 역할 처리
                foreach (var role in rolesToImport)
                {
                    try
                    {
                        var exists = await _roleRepository.RoleKeyExistsAsync(
                            importData.OrganizationId, 
                            role.RoleKey);

                        if (exists)
                        {
                            if (overwrite)
                            {
                                var existingRole = await _roleRepository.GetByRoleKeyAsync(
                                    importData.OrganizationId, 
                                    role.RoleKey);
                                
                                if (existingRole != null)
                                {
                                    existingRole.Name = role.Name;
                                    existingRole.Description = role.Description;
                                    existingRole.UpdatedAt = DateTime.UtcNow;
                                    
                                    await _roleRepository.UpdateAsync(existingRole);
                                    result.Updated++;
                                }
                            }
                            else
                            {
                                result.Skipped++;
                            }
                        }
                        else
                        {
                            role.OrganizationId = importData.OrganizationId;
                            role.CreatedAt = DateTime.UtcNow;
                            
                            await _roleRepository.AddAsync(role);
                            result.Created++;
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Failed++;
                        result.Errors.Add(new ImportError
                        {
                            RoleKey = role.RoleKey,
                            Reason = ex.Message
                        });
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult<RoleImportResult>.Success(
                    result,
                    $"가져오기 완료: {result.Created}개 생성, {result.Updated}개 업데이트, {result.Skipped}개 건너뜀, {result.Failed}개 실패");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error importing roles");
                
                return ServiceResult<RoleImportResult>.Failure(
                    "역할 가져오기 중 오류가 발생했습니다.",
                    "IMPORT_ERROR");
            }
        }

        #endregion

        #region 캐시 관리

        /// <summary>
        /// 역할 캐시 삭제
        /// </summary>
        public async Task<ServiceResult> ClearRoleCacheAsync(Guid roleId)
        {
            try
            {
                var cacheKeys = new[]
                {
                    $"role:{roleId}",
                    $"role:{roleId}:permissions",
                    $"role:{roleId}:users"
                };

                foreach (var key in cacheKeys)
                {
                    _cache.Remove(key);
                }

                await Task.CompletedTask;

                return ServiceResult.Success("역할 캐시가 삭제되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error clearing cache for role {roleId}");
                
                return ServiceResult.Failure(
                    "캐시 삭제 중 오류가 발생했습니다.",
                    "CACHE_ERROR");
            }
        }

        /// <summary>
        /// 조직 역할 캐시 삭제
        /// </summary>
        public async Task<ServiceResult> ClearOrganizationRoleCacheAsync(Guid organizationId)
        {
            try
            {
                // 조직의 모든 역할 조회
                var roles = await _roleRepository.GetByOrganizationAsync(organizationId);
                
                // 각 역할의 캐시 삭제
                foreach (var role in roles)
                {
                    await ClearRoleCacheAsync(role.Id);
                }

                // 조직 레벨 캐시 삭제
                _cache.Remove($"org:{organizationId}:roles");
                _cache.Remove($"org:{organizationId}:role:stats");

                return ServiceResult.Success("조직 역할 캐시가 삭제되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error clearing cache for organization {organizationId}");
                
                return ServiceResult.Failure(
                    "조직 캐시 삭제 중 오류가 발생했습니다.",
                    "CACHE_ERROR");
            }
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("RoleAdminService initializing...");
                
                // 캐시 워밍업이나 초기 설정이 필요한 경우 여기에 구현
                await Task.CompletedTask;
                
                _logger.LogInformation("RoleAdminService initialized successfully");
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
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository 연결 상태 확인
                var testQuery = await _roleRepository.AnyAsync(r => true);
                
                // 캐시 상태 확인
                _cache.Set("health_check", true, TimeSpan.FromSeconds(1));
                _cache.Remove("health_check");
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleAdminService health check failed");
                return false;
            }
        }

        #endregion
    }
}