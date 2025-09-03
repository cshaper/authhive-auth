using AutoMapper;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Common;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

namespace AuthHive.Auth.Services.Permission
{
    public class PermissionAdminService : IPermissionAdminService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPermissionRepository _permissionRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IPermissionCacheService _permissionCacheService;
        private readonly IMapper _mapper;
        private readonly ILogger<PermissionAdminService> _logger;

        public PermissionAdminService(
            IUnitOfWork unitOfWork,
            IPermissionRepository permissionRepository,
            IRolePermissionRepository rolePermissionRepository,
            IPermissionCacheService permissionCacheService,
            IMapper mapper,
            ILogger<PermissionAdminService> logger)
        {
            _unitOfWork = unitOfWork;
            _permissionRepository = permissionRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _permissionCacheService = permissionCacheService;
            _mapper = mapper;
            _logger = logger;
        }

        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task InitializeAsync() => Task.CompletedTask;

        #region 시스템 권한 관리

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetSystemPermissionsAsync()
        {
            try
            {
                var permissions = await _permissionRepository.Query().Where(p => p.IsSystemPermission).ToListAsync();
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);
                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get system permissions.");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("An error occurred while fetching system permissions.");
            }
        }

        public async Task<ServiceResult<PermissionSyncResult>> SyncSystemPermissionsAsync()
        {
            var result = new PermissionSyncResult { StartedAt = DateTime.UtcNow };
            var sourcePermissions = GetSourceSystemPermissions();

            try
            {
                await _unitOfWork.BeginTransactionAsync();
                var dbPermissions = await _permissionRepository.Query().Where(p => p.IsSystemPermission).ToListAsync();
                var dbPermissionMap = dbPermissions.ToDictionary(p => p.Scope);
                var sourcePermissionMap = sourcePermissions.ToDictionary(p => p.Scope);

                var toCreate = sourcePermissions.Where(sp => !dbPermissionMap.ContainsKey(sp.Scope));
                foreach (var perm in toCreate)
                {
                    var created = await _permissionRepository.AddAsync(perm);
                    result.Added++;
                    result.SyncedPermissions.Add(new SyncedPermission { PermissionId = created.Id, Scope = created.Scope, Action = "Created" });
                }

                foreach (var dbPerm in dbPermissions)
                {
                    if (sourcePermissionMap.TryGetValue(dbPerm.Scope, out var sourcePerm) &&
                        (dbPerm.Name != sourcePerm.Name || dbPerm.Description != sourcePerm.Description || dbPerm.Category != sourcePerm.Category))
                    {
                        dbPerm.Name = sourcePerm.Name;
                        dbPerm.Description = sourcePerm.Description;
                        dbPerm.Category = sourcePerm.Category;
                        await _permissionRepository.UpdateAsync(dbPerm);
                        result.Updated++;
                        result.SyncedPermissions.Add(new SyncedPermission { PermissionId = dbPerm.Id, Scope = dbPerm.Scope, Action = "Updated" });
                    }
                }
                
                var toDeactivate = dbPermissions.Where(dp => !sourcePermissionMap.ContainsKey(dp.Scope) && dp.IsActive);
                foreach (var perm in toDeactivate)
                {
                    perm.IsActive = false;
                    await _permissionRepository.UpdateAsync(perm);
                    result.Deactivated++;
                    result.SyncedPermissions.Add(new SyncedPermission { PermissionId = perm.Id, Scope = perm.Scope, Action = "Deactivated" });
                }
                
                await _unitOfWork.CommitTransactionAsync();
                
                if(result.Added > 0 || result.Updated > 0 || result.Deactivated > 0)
                {
                    await _permissionCacheService.RefreshAllAsync();
                }
                
                result.CompletedAt = DateTime.UtcNow;
                return ServiceResult<PermissionSyncResult>.Success(result);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Failed to sync system permissions.");
                result.Errors++;
                result.ErrorDetails.Add(ex.Message);
                result.CompletedAt = DateTime.UtcNow;
                return ServiceResult<PermissionSyncResult>.FailureWithData("An error occurred during system permission sync.", result);
            }
        }

        private static List<PermissionEntity> GetSourceSystemPermissions()
        {
            return new List<PermissionEntity>
            {
                new() { Scope = "system:admin", Name = "System Administration", Description = "Full access to system-level settings.", Category = PermissionCategory.System, IsSystemPermission = true, IsActive = true },
                new() { Scope = "organization:create", Name = "Create Organization", Description = "Allows creating new organizations.", Category = PermissionCategory.Organization, IsSystemPermission = true, IsActive = true },
            };
        }

        #endregion

        #region 데이터 마이그레이션

        public async Task<ServiceResult<PermissionExportData>> ExportAsync(string format = "json")
        {
            if (!format.Equals("json", StringComparison.OrdinalIgnoreCase))
                return ServiceResult<PermissionExportData>.Failure("Unsupported format. Only 'json' is supported.");

            try
            {
                var totalCount = await _permissionRepository.CountAsync();
                var allPermissions = await _permissionRepository.Query().ToListAsync();
                var exportDtos = _mapper.Map<IEnumerable<PermissionDto>>(allPermissions);
                var jsonContent = JsonSerializer.Serialize(exportDtos, new JsonSerializerOptions { WriteIndented = true });
                var dataBytes = System.Text.Encoding.UTF8.GetBytes(jsonContent);

                var exportData = new PermissionExportData
                {
                    Format = "json",
                    Data = dataBytes,
                    FileName = $"authhive_permissions_{DateTime.UtcNow:yyyyMMddHHmmss}.json",
                    MimeType = "application/json",
                    TotalPermissions = (int)totalCount,
                };
                return ServiceResult<PermissionExportData>.Success(exportData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export permissions.");
                return ServiceResult<PermissionExportData>.Failure("An error occurred during permission export.");
            }
        }

        public async Task<ServiceResult<PermissionImportResult>> ImportAsync(PermissionImportData importData, bool overwrite = false)
        {
            var result = new PermissionImportResult { StartedAt = DateTime.UtcNow };
            try
            {
                var importDtos = JsonSerializer.Deserialize<List<PermissionDto>>(importData.Content);
                if (importDtos == null)
                {
                    result.Errors++;
                    result.ErrorDetails.Add("Failed to deserialize import data.");
                    return ServiceResult<PermissionImportResult>.FailureWithData("Invalid import data content.", result);
                }
                
                await _unitOfWork.BeginTransactionAsync();
                foreach (var dto in importDtos)
                {
                    var importedItem = new ImportedPermission { Scope = dto.Scope };
                    try
                    {
                        var existing = await _permissionRepository.GetByScopeAsync(dto.Scope);
                        if (existing != null)
                        {
                            if (overwrite)
                            {
                                _mapper.Map(dto, existing);
                                await _permissionRepository.UpdateAsync(existing);
                                importedItem.Action = ImportAction.Updated;
                                importedItem.PermissionId = existing.Id;
                                result.Updated++;
                            }
                            else
                            {
                                importedItem.Action = ImportAction.Skipped;
                                importedItem.PermissionId = existing.Id;
                                result.Skipped++;
                            }
                        }
                        else
                        {
                            var newPermission = _mapper.Map<PermissionEntity>(dto);
                            var createdEntity = await _permissionRepository.AddAsync(newPermission);
                            importedItem.Action = ImportAction.Created;
                            importedItem.PermissionId = createdEntity.Id;
                            result.Imported++;
                        }
                    }
                    catch (Exception itemEx)
                    {
                        _logger.LogError(itemEx, "Failed to import permission item with scope {Scope}", dto.Scope);
                        importedItem.Action = ImportAction.Failed;
                        importedItem.Error = itemEx.Message;
                        result.Failed++;
                    }
                    result.ImportedPermissions.Add(importedItem);
                }

                await _unitOfWork.CommitTransactionAsync();
                await _permissionCacheService.RefreshAllAsync();
                
                result.IsSuccess = true;
                result.CompletedAt = DateTime.UtcNow;
                return ServiceResult<PermissionImportResult>.Success(result);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "A critical error occurred during permission import. Transaction rolled back.");
                result.IsSuccess = false;
                result.Errors++; 
                result.ErrorDetails.Add($"Critical error: {ex.Message}");
                result.CompletedAt = DateTime.UtcNow;
                return ServiceResult<PermissionImportResult>.FailureWithData("An error occurred during permission import.", result);
            }
        }

        #endregion

        #region 일괄 작업 (Bulk Operations)

        public async Task<ServiceResult<BulkPermissionOperationResult>> CreateBulkAsync(IEnumerable<CreatePermissionRequest> requests)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new BulkPermissionOperationResult { OperationType = "Create", TotalRequested = requests.Count(), StartedAt = DateTime.UtcNow };

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                foreach (var request in requests)
                {
                    var detail = new PermissionOperationDetail { Scope = request.Scope, Operation = "Create" };
                    try
                    {
                        var existing = await _permissionRepository.GetByScopeAsync(request.Scope);
                        if (existing != null) throw new InvalidOperationException($"Permission with scope '{request.Scope}' already exists.");

                        var newPermission = _mapper.Map<PermissionEntity>(request);
                        var createdEntity = await _permissionRepository.AddAsync(newPermission);
                        
                        detail.PermissionId = createdEntity.Id;
                        detail.Success = true;
                        result.Succeeded++;
                    }
                    catch (Exception ex)
                    {
                        detail.Success = false;
                        detail.ErrorMessage = ex.Message;
                        result.Failed++;
                    }
                    result.Details.Add(detail);
                }
                await _unitOfWork.CommitTransactionAsync();
                await _permissionCacheService.RefreshAllAsync();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during bulk permission creation. Transaction rolled back.");
                return ServiceResult<BulkPermissionOperationResult>.Failure("A critical error occurred during bulk creation.");
            }
            finally
            {
                stopwatch.Stop();
                result.CompletedAt = DateTime.UtcNow;
                result.TotalProcessingTimeMs = stopwatch.ElapsedMilliseconds;
            }
            return ServiceResult<BulkPermissionOperationResult>.Success(result);
        }

        public async Task<ServiceResult<BulkPermissionOperationResult>> UpdateBulkAsync(IEnumerable<(Guid Id, UpdatePermissionRequest Request)> updates)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new BulkPermissionOperationResult { OperationType = "Update", TotalRequested = updates.Count(), StartedAt = DateTime.UtcNow };

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                foreach (var (id, request) in updates)
                {
                    var detail = new PermissionOperationDetail { PermissionId = id, Scope = request.Scope, Operation = "Update" };
                    try
                    {
                        var permission = await _permissionRepository.GetByIdAsync(id);
                        if (permission == null) throw new KeyNotFoundException($"Permission with ID '{id}' not found.");

                        _mapper.Map(request, permission);
                        await _permissionRepository.UpdateAsync(permission);

                        detail.Success = true;
                        result.Succeeded++;
                    }
                    catch (Exception ex)
                    {
                        detail.Success = false;
                        detail.ErrorMessage = ex.Message;
                        result.Failed++;
                    }
                    result.Details.Add(detail);
                }
                await _unitOfWork.CommitTransactionAsync();
                foreach (var detail in result.Details.Where(d => d.Success))
                {
                    // [오류 수정] Nullable 경고 해결 (CS8629)
                    if (detail.PermissionId.HasValue)
                    {
                        await _permissionCacheService.InvalidatePermissionAsync(detail.PermissionId.Value);
                    }
                }
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during bulk permission update. Transaction rolled back.");
                return ServiceResult<BulkPermissionOperationResult>.Failure("A critical error occurred during bulk update.");
            }
            finally
            {
                stopwatch.Stop();
                result.CompletedAt = DateTime.UtcNow;
                result.TotalProcessingTimeMs = stopwatch.ElapsedMilliseconds;
            }
            return ServiceResult<BulkPermissionOperationResult>.Success(result);
        }

        public async Task<ServiceResult<BulkPermissionOperationResult>> DeleteBulkAsync(IEnumerable<Guid> ids)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new BulkPermissionOperationResult { OperationType = "Delete", TotalRequested = ids.Count(), StartedAt = DateTime.UtcNow };
            
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                foreach (var id in ids)
                {
                    var detail = new PermissionOperationDetail { PermissionId = id, Operation = "Delete" };
                    try
                    {
                        // [오류 수정] 잘못된 ExistsAsync 호출을 올바른 AnyAsync로 변경 (CS7036)
                        var isAssigned = await _rolePermissionRepository.AnyAsync(rp => rp.PermissionId == id);
                        if (isAssigned) throw new InvalidOperationException("Permission is assigned to one or more roles and cannot be deleted.");

                        var permission = await _permissionRepository.GetByIdAsync(id);
                        if (permission == null) throw new KeyNotFoundException("Permission not found.");
                        
                        await _permissionRepository.DeleteAsync(permission);
                        detail.Success = true;
                        result.Succeeded++;
                    }
                    catch (Exception ex)
                    {
                        detail.Success = false;
                        detail.ErrorMessage = ex.Message;
                        result.Failed++;
                    }
                    result.Details.Add(detail);
                }
                await _unitOfWork.CommitTransactionAsync();
                foreach (var detail in result.Details.Where(d => d.Success))
                {
                    // [오류 수정] Nullable 경고 해결 (CS8629)
                    if (detail.PermissionId.HasValue)
                    {
                        await _permissionCacheService.InvalidatePermissionAsync(detail.PermissionId.Value);
                    }
                }
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during bulk permission deletion. Transaction rolled back.");
                return ServiceResult<BulkPermissionOperationResult>.Failure("A critical error occurred during bulk deletion.");
            }
            finally
            {
                stopwatch.Stop();
                result.CompletedAt = DateTime.UtcNow;
                result.TotalProcessingTimeMs = stopwatch.ElapsedMilliseconds;
            }
            return ServiceResult<BulkPermissionOperationResult>.Success(result);
        }

        public async Task<ServiceResult<BulkPermissionOperationResult>> BulkSetActiveStateAsync(IEnumerable<Guid> ids, bool isActive)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new BulkPermissionOperationResult { OperationType = $"SetActiveState:{isActive}", TotalRequested = ids.Count(), StartedAt = DateTime.UtcNow };

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                 foreach (var id in ids)
                {
                    var detail = new PermissionOperationDetail { PermissionId = id, Operation = $"SetActiveState:{isActive}" };
                    try
                    {
                        var permission = await _permissionRepository.GetByIdAsync(id);
                        if (permission == null) throw new KeyNotFoundException($"Permission with ID '{id}' not found.");

                        permission.IsActive = isActive;
                        await _permissionRepository.UpdateAsync(permission);

                        detail.Success = true;
                        result.Succeeded++;
                    }
                    catch (Exception ex)
                    {
                        detail.Success = false;
                        detail.ErrorMessage = ex.Message;
                        result.Failed++;
                    }
                    result.Details.Add(detail);
                }
                await _unitOfWork.CommitTransactionAsync();
                foreach (var detail in result.Details.Where(d => d.Success))
                {
                    // [오류 수정] Nullable 경고 해결 (CS8629)
                    if (detail.PermissionId.HasValue)
                    {
                       await _permissionCacheService.InvalidatePermissionAsync(detail.PermissionId.Value);
                    }
                }
            }
            catch(Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during bulk set active state. Transaction rolled back.");
                return ServiceResult<BulkPermissionOperationResult>.Failure("A critical error occurred during bulk set active state.");
            }
            finally
            {
                stopwatch.Stop();
                result.CompletedAt = DateTime.UtcNow;
                result.TotalProcessingTimeMs = stopwatch.ElapsedMilliseconds;
            }
            return ServiceResult<BulkPermissionOperationResult>.Success(result);
        }

        #endregion

        #region 캐시 관리
        public async Task<ServiceResult> ClearPermissionCacheAsync(Guid permissionId)
        {
            try
            {
                await _permissionCacheService.InvalidatePermissionAsync(permissionId);
                return ServiceResult.Success("Permission cache cleared successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear cache for permission {PermissionId}", permissionId);
                return ServiceResult.Failure("Failed to clear permission cache.");
            }
        }

        public async Task<ServiceResult> ClearAllPermissionCacheAsync()
        {
            try
            {
                await _permissionCacheService.RefreshAllAsync();
                return ServiceResult.Success("All permission cache cleared successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear all permission cache.");
                return ServiceResult.Failure("Failed to clear all permission cache.");
            }
        }
        
        #endregion
    }
}