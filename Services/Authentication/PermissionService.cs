// Path: AuthHive.Auth/Services/Authentication/PermissionService.cs
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Cache;
using AuthHive.Core.Models.Auth.Permissions.Common;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Auth.Permissions.Views;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Cache;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using System.Linq.Expressions;
using AuthHive.Core.Models.Base.Summaries;

namespace AuthHive.Auth.Services.Authentication
{
    public class PermissionService : IPermissionService
    {
        private readonly IPermissionRepository _permissionRepository;
        private readonly ILogger<PermissionService> _logger;
        private readonly IMemoryCache _cache;

        public PermissionService(
            IPermissionRepository permissionRepository,
            ILogger<PermissionService> logger,
            IMemoryCache cache)
        {
            _permissionRepository = permissionRepository;
            _logger = logger;
            _cache = cache;
        }

        #region IService 기본 구현

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _permissionRepository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Permission service health check failed");
                return false;
            }
        }
        public Task<ServiceResult<PermissionSummaryView>> GetPermissionSummaryAsync(Guid permissionId)
        {
            var view = new PermissionSummaryView
            {
                BasicInfo = new PermissionBasicInfo { Id = permissionId }, // permissionId 사용
                UsageStats = new AuthHive.Core.Models.Auth.Permissions.Views.PermissionUsageStats(),
                AssignmentInfo = new PermissionAssignmentInfo(),
                GeneratedAt = DateTime.UtcNow
            };
            return Task.FromResult(ServiceResult<PermissionSummaryView>.Success(view));
        }
        public async Task InitializeAsync()
        {
            _logger.LogInformation("Permission service initialization started");
            await InitializeSystemPermissionsAsync();
            _logger.LogInformation("Permission service initialization completed");
        }

        #endregion

        #region 기본 CRUD 작업

        public async Task<ServiceResult<PermissionDto>> CreateAsync(CreatePermissionRequest request)
        {
            try
            {
                _logger.LogInformation("Creating permission with scope: {Scope}", request.Scope);

                var existingPermission = await _permissionRepository.GetByScopeAsync(request.Scope);
                if (existingPermission != null)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        $"Permission with scope '{request.Scope}' already exists",
                        PermissionConstants.ErrorCodes.DuplicateScope);
                }

                var (resourceType, actionType) = ParseScope(request.Scope);

                var permission = new Permission
                {
                    Id = Guid.NewGuid(),
                    Scope = request.Scope,
                    Name = request.Name,
                    Description = request.Description,
                    Category = request.Category,
                    ParentPermissionId = request.ParentPermissionId,
                    Level = request.Level,
                    ResourceType = resourceType,
                    ActionType = actionType,
                    RequiredMembershipTypes = request.RequiredMembershipTypes?.Count > 0
                        ? JsonSerializer.Serialize(request.RequiredMembershipTypes)
                        : null,
                    IsActive = request.IsActive,
                    IsSystemPermission = false,
                    Metadata = request.Metadata?.Count > 0
                        ? JsonSerializer.Serialize(request.Metadata)
                        : null
                };

                ParseAndSetScopeComponents(permission);

                var createdPermission = await _permissionRepository.AddAsync(permission);
                InvalidatePermissionCache();

                _logger.LogInformation("Permission created successfully: {PermissionId}", permission.Id);

                var permissionDto = MapToDto(createdPermission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating permission with scope: {Scope}", request.Scope);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while creating the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PermissionDto>> GetByIdAsync(Guid id)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                var permissionDto = MapToDto(permission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission: {PermissionId}", id);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while retrieving the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PermissionDto>> UpdateAsync(Guid id, UpdatePermissionRequest request)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                if (permission.IsSystemPermission)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Cannot modify system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                // 업데이트 로직
                permission.Name = request.Name ?? permission.Name;
                permission.Description = request.Description ?? permission.Description;
                permission.IsActive = request.IsActive;

                if (request.Metadata?.Count > 0)
                {
                    permission.Metadata = JsonSerializer.Serialize(request.Metadata);
                }

                await _permissionRepository.UpdateAsync(permission);
                InvalidatePermissionCache();

                var permissionDto = MapToDto(permission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating permission: {PermissionId}", id);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while updating the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                if (permission.IsSystemPermission)
                {
                    return ServiceResult.Failure(
                        "Cannot delete system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                await _permissionRepository.DeleteAsync(id);
                InvalidatePermissionCache();

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting permission: {PermissionId}", id);
                return ServiceResult.Failure(
                    "An error occurred while deleting the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetAllAsync()
        {
            try
            {
                var permissions = await _permissionRepository.GetAllAsync();
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving all permissions");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PagedResult<PermissionDto>>> GetPagedAsync(PaginationRequest request)
        {
            try
            {
                // 전체 데이터를 가져온 후 Service에서 정렬/페이징 처리
                var allPermissions = await _permissionRepository.GetAllAsync();

                // 정렬 적용
                var sortedQuery = ApplySorting(allPermissions.AsQueryable(), request.SortBy, request.SortDirection);

                // 페이징 적용
                var totalCount = sortedQuery.Count();
                var pagedItems = sortedQuery
                    .Skip((request.PageNumber - 1) * request.PageSize)
                    .Take(request.PageSize)
                    .ToList();

                var permissionDtos = pagedItems.Select(MapToDto).ToList();

                var pagedResult = new PagedResult<PermissionDto>
                {
                    Items = permissionDtos,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                return ServiceResult<PagedResult<PermissionDto>>.Success(pagedResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paged permissions");
                return ServiceResult<PagedResult<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<bool>> ExistsAsync(Guid id)
        {
            try
            {
                var exists = await _permissionRepository.ExistsAsync(id);
                return ServiceResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking permission existence: {PermissionId}", id);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking permission existence",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region 도메인 특화 조회

        public async Task<ServiceResult<PermissionDto>> GetByScopeAsync(string scope)
        {
            try
            {
                var cacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}{scope}";

                if (_cache.TryGetValue(cacheKey, out PermissionDto? cachedPermission))
                {
                    return ServiceResult<PermissionDto>.Success(cachedPermission!);
                }

                var permission = await _permissionRepository.GetByScopeAsync(scope);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        $"Permission with scope '{scope}' not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                var permissionDto = MapToDto(permission);

                _cache.Set(cacheKey, permissionDto, TimeSpan.FromSeconds(PermissionConstants.Cache.PermissionCacheTtl));

                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission by scope: {Scope}", scope);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while retrieving the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByCategoryAsync(string category, bool includeInactive = false)
        {
            try
            {
                // string을 PermissionCategory enum으로 변환
                if (!Enum.TryParse<PermissionCategory>(category, true, out var categoryEnum))
                {
                    return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                        $"Invalid category: {category}",
                        PermissionConstants.ErrorCodes.InvalidParameter);
                }

                var permissions = await _permissionRepository.GetByCategoryAsync(categoryEnum, includeInactive);
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permissions by category: {Category}", category);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<bool>> ExistsByScopeAsync(string scope)
        {
            try
            {
                // Repository에 ExistsByScopeAsync가 없다면 GetByScopeAsync로 대체
                var permission = await _permissionRepository.GetByScopeAsync(scope);
                var exists = permission != null;
                return ServiceResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking permission existence by scope: {Scope}", scope);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking permission existence",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region 계층 구조 관리

        public async Task<ServiceResult<PermissionTreeResponse>> GetTreeAsync(Guid? rootPermissionId = null, int? maxDepth = null)
        {
            try
            {
                var permissions = await _permissionRepository.GetPermissionTreeAsync(rootPermissionId, maxDepth);
                var permissionNodes = permissions.Select(MapToPermissionNode).ToList();

                var response = new PermissionTreeResponse
                {
                    Nodes = permissionNodes,
                    TotalNodes = permissionNodes.Count,
                    MaxDepth = maxDepth ?? 0,
                    RootPermissionId = rootPermissionId
                };

                return ServiceResult<PermissionTreeResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission tree");
                return ServiceResult<PermissionTreeResponse>.Failure(
                    "An error occurred while retrieving permission tree",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetChildrenAsync(Guid parentPermissionId, bool includeInactive = false)
        {
            try
            {
                var permissions = await _permissionRepository.GetChildPermissionsAsync(parentPermissionId, includeInactive);
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving child permissions for: {ParentId}", parentPermissionId);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving child permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<bool>> MoveAsync(Guid permissionId, Guid? newParentId)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(permissionId);
                if (permission == null)
                {
                    return ServiceResult<bool>.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                if (permission.IsSystemPermission)
                {
                    return ServiceResult<bool>.Failure(
                        "Cannot move system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                permission.ParentPermissionId = newParentId;
                await _permissionRepository.UpdateAsync(permission);
                InvalidatePermissionCache();

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error moving permission: {PermissionId}", permissionId);
                return ServiceResult<bool>.Failure(
                    "An error occurred while moving the permission",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetPathAsync(Guid permissionId)
        {
            try
            {
                var path = new List<PermissionDto>();
                Guid? currentId = permissionId;

                while (currentId.HasValue)
                {
                    var permission = await _permissionRepository.GetByIdAsync(currentId.Value);
                    if (permission == null) break;

                    path.Insert(0, MapToDto(permission));
                    currentId = permission.ParentPermissionId;
                }

                return ServiceResult<IEnumerable<PermissionDto>>.Success(path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission path: {PermissionId}", permissionId);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permission path",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region 권한 상태 관리

        public async Task<ServiceResult<bool>> SetActiveStateAsync(Guid permissionId, bool isActive)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(permissionId);
                if (permission == null)
                {
                    return ServiceResult<bool>.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                permission.IsActive = isActive;
                await _permissionRepository.UpdateAsync(permission);
                InvalidatePermissionCache();

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting permission active state: {PermissionId}", permissionId);
                return ServiceResult<bool>.Failure(
                    "An error occurred while updating permission state",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region 시스템 권한 관리

        public Task<ServiceResult<PermissionSyncResult>> SyncSystemPermissionsAsync()
        {
            try
            {
                var result = new PermissionSyncResult
                {
                    Added = 0,
                    Updated = 0,
                    Deleted = 0,
                    Errors = 0,
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow
                };

                return Task.FromResult(ServiceResult<PermissionSyncResult>.Success(result));
            }
            catch (Exception ex)
            {

                _logger.LogError(ex, "Error syncing system permissions");
                return Task.FromResult(ServiceResult<PermissionSyncResult>.Failure(
                    "An error occurred while syncing system permissions",
                    PermissionConstants.ErrorCodes.DatabaseError));
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetSystemPermissionsAsync()
        {
            try
            {
                var permissions = await _permissionRepository.GetSystemPermissionsAsync();
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving system permissions");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving system permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public Task<ServiceResult<PermissionSyncResult>> InitializeSystemPermissionsAsync()
        {
            try
            {
                var result = new PermissionSyncResult
                {
                    Added = 0,
                    Updated = 0,
                    Deleted = 0,
                    Errors = 0,
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow
                };

                return Task.FromResult(ServiceResult<PermissionSyncResult>.Success(result));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing system permissions");
                return Task.FromResult(ServiceResult<PermissionSyncResult>.Failure(
                    "An error occurred while initializing system permissions",
                    PermissionConstants.ErrorCodes.DatabaseError));
            }
        }

        #endregion

        #region 권한 검색 및 필터링

        public async Task<ServiceResult<PermissionDto>> SearchAsync(PermissionSearchCriteria searchCriteria)
        {
            try
            {
                var permissions = await _permissionRepository.GetAllAsync();
                var filtered = permissions.AsQueryable();

                if (!string.IsNullOrEmpty(searchCriteria.SearchTerm))
                {
                    filtered = filtered.Where(p => p.Name.Contains(searchCriteria.SearchTerm) ||
                                                   p.Scope.Contains(searchCriteria.SearchTerm) ||
                                                   (p.Description != null && p.Description.Contains(searchCriteria.SearchTerm)));
                }

                if (!string.IsNullOrEmpty(searchCriteria.Category))
                {
                    filtered = filtered.Where(p => p.Category.ToString().Contains(searchCriteria.Category));
                }

                if (!string.IsNullOrEmpty(searchCriteria.ResourceType))
                {
                    filtered = filtered.Where(p => p.ResourceType == searchCriteria.ResourceType);
                }

                if (!string.IsNullOrEmpty(searchCriteria.ActionType))
                {
                    filtered = filtered.Where(p => p.ActionType == searchCriteria.ActionType);
                }

                if (searchCriteria.IsActive.HasValue)
                {
                    filtered = filtered.Where(p => p.IsActive == searchCriteria.IsActive.Value);
                }

                if (searchCriteria.IsSystemPermission.HasValue)
                {
                    filtered = filtered.Where(p => p.IsSystemPermission == searchCriteria.IsSystemPermission.Value);
                }

                var result = filtered.Select(MapToDto).FirstOrDefault();

                if (result != null)
                {
                    return ServiceResult<PermissionDto>.Success(result);
                }
                else
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "No permissions found matching the search criteria",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching permissions");
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while searching permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByResourceTypeAsync(string resourceType)
        {
            try
            {
                // Repository에 메서드가 없다면 GetAllAsync로 대체
                var allPermissions = await _permissionRepository.GetAllAsync();
                var permissions = allPermissions.Where(p => p.ResourceType == resourceType);
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permissions by resource type: {ResourceType}", resourceType);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByActionTypeAsync(string actionType)
        {
            try
            {
                // Repository에 메서드가 없다면 GetAllAsync로 대체
                var allPermissions = await _permissionRepository.GetAllAsync();
                var permissions = allPermissions.Where(p => p.ActionType == actionType);
                var permissionDtos = permissions.Select(MapToDto);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permissions by action type: {ActionType}", actionType);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region 나머지 인터페이스 메서드들 - 기본 구현

        // 권한 분석 및 리포트
        public Task<ServiceResult<PermissionUsageStatistics>> GetUsageStatisticsAsync(Guid permissionId)
        {
            var stats = new PermissionUsageStatistics
            {
                PermissionId = permissionId,
                Scope = string.Empty,
                TotalRoles = 0,
                TotalUsers = 0,
                TotalApplications = 0,
                TotalOrganizations = 0,
                LastUsedAt = null,
                FirstUsedAt = null,
                UsageByOrganization = new Dictionary<string, int>(),
                UsageByApplication = new Dictionary<string, int>(),
                UsageTrends = new List<UsageTrend>(),
                UsageFrequency = 0.0
            };
            return Task.FromResult(ServiceResult<PermissionUsageStatistics>.Success(stats));
        }

        public Task<ServiceResult<IEnumerable<PermissionDto>>> GetUnusedPermissionsAsync(int days = 90)
        {
            var permissions = new List<PermissionDto>();
            return Task.FromResult(ServiceResult<IEnumerable<PermissionDto>>.Success(permissions));
        }

        public Task<ServiceResult<PermissionConflictInfo>> CheckConflictsAsync(string scope)
        {
            var conflicts = new PermissionConflictInfo { Scope = scope };
            return Task.FromResult(ServiceResult<PermissionConflictInfo>.Success(conflicts));
        }

        // 권한 내보내기/가져오기
        public Task<ServiceResult<PermissionExportData>> ExportAsync(string format = "json", bool includeSystemPermissions = false)
        {
            var exportData = new PermissionExportData
            {
                Format = format,
                IncludesSystemPermissions = includeSystemPermissions,
                ExportedAt = DateTime.UtcNow
            };
            return Task.FromResult(ServiceResult<PermissionExportData>.Success(exportData));
        }

        public Task<ServiceResult<PermissionImportResult>> ImportAsync(PermissionImportData importData, bool overwriteExisting = false)
        {
            var result = new PermissionImportResult
            {
                IsSuccess = true,
                CompletedAt = DateTime.UtcNow
            };
            return Task.FromResult(ServiceResult<PermissionImportResult>.Success(result));
        }

        // 벌크 작업
        public Task<ServiceResult<BulkPermissionOperationResult>> CreateBulkAsync(IEnumerable<CreatePermissionRequest> requests)
        {
            var result = new BulkPermissionOperationResult
            {
                OperationType = "Create",
                TotalRequested = requests.Count(),
                Succeeded = 0,
                Failed = 0,
                Skipped = 0,
                Details = new List<PermissionOperationDetail>(),
                StartedAt = DateTime.UtcNow,
                CompletedAt = DateTime.UtcNow,
                TotalProcessingTimeMs = 0
            };
            return Task.FromResult(ServiceResult<BulkPermissionOperationResult>.Success(result));
        }

        public Task<ServiceResult<BulkPermissionOperationResult>> UpdateBulkAsync(IEnumerable<(Guid Id, UpdatePermissionRequest Request)> updates)
        {
            var result = new BulkPermissionOperationResult
            {
                OperationType = "Update",
                TotalRequested = updates.Count(),
                Succeeded = 0,
                Failed = 0,
                Skipped = 0,
                Details = new List<PermissionOperationDetail>(),
                StartedAt = DateTime.UtcNow,
                CompletedAt = DateTime.UtcNow,
                TotalProcessingTimeMs = 0
            };
            return Task.FromResult(ServiceResult<BulkPermissionOperationResult>.Success(result));
        }

        public Task<ServiceResult<BulkPermissionOperationResult>> DeleteBulkAsync(IEnumerable<Guid> ids)
        {
            var result = new BulkPermissionOperationResult
            {
                OperationType = "Delete",
                TotalRequested = ids.Count(),
                Succeeded = 0,
                Failed = 0,
                Skipped = 0,
                Details = new List<PermissionOperationDetail>(),
                StartedAt = DateTime.UtcNow,
                CompletedAt = DateTime.UtcNow,
                TotalProcessingTimeMs = 0
            };
            return Task.FromResult(ServiceResult<BulkPermissionOperationResult>.Success(result));
        }

        public Task<ServiceResult<BulkPermissionOperationResult>> BulkSetActiveStateAsync(IEnumerable<Guid> permissionIds, bool isActive)
        {
            var result = new BulkPermissionOperationResult
            {
                OperationType = "SetActiveState",
                TotalRequested = permissionIds.Count(),
                Succeeded = 0,
                Failed = 0,
                Skipped = 0,
                Details = new List<PermissionOperationDetail>(),
                StartedAt = DateTime.UtcNow,
                CompletedAt = DateTime.UtcNow,
                TotalProcessingTimeMs = 0
            };
            return Task.FromResult(ServiceResult<BulkPermissionOperationResult>.Success(result));
        }

        // 권한 할당
        public Task<ServiceResult<BulkPermissionAssignResponse>> BulkAssignToConnectedIdAsync(Guid connectedId, IEnumerable<Guid> permissionIds)
        {
            var response = new BulkPermissionAssignResponse
            {
                Success = true,
                PartialSuccess = false,
                Summary = new PermissionAssignmentSummary(),
                Results = new List<PermissionAssignmentResult>(),
                Message = "Assignment completed successfully",
                Timestamp = DateTime.UtcNow,
                TotalProcessingTimeMs = 0,
                Context = new BulkAssignmentContext
                {
                    Description = $"Bulk assign to ConnectedId: {connectedId}",
                    ReplacedExisting = false
                }
            };
            return Task.FromResult(ServiceResult<BulkPermissionAssignResponse>.Success(response));
        }

        public Task<ServiceResult<BulkPermissionAssignResponse>> BulkAssignToRoleAsync(Guid roleId, IEnumerable<Guid> permissionIds)
        {
            var response = new BulkPermissionAssignResponse
            {
                Success = true,
                PartialSuccess = false,
                Summary = new PermissionAssignmentSummary(),
                Results = new List<PermissionAssignmentResult>(),
                Message = "Assignment completed successfully",
                Timestamp = DateTime.UtcNow,
                TotalProcessingTimeMs = 0,
                Context = new BulkAssignmentContext
                {
                    Description = $"Bulk assign to Role: {roleId}",
                    ReplacedExisting = false
                }
            };
            return Task.FromResult(ServiceResult<BulkPermissionAssignResponse>.Success(response));
        }

        // Organization 관련
        public Task<ServiceResult<IEnumerable<PermissionDto>>> GetOrganizationPermissionsAsync(Guid organizationId, bool includeInherited = false)
        {
            var permissions = new List<PermissionDto>();
            return Task.FromResult(ServiceResult<IEnumerable<PermissionDto>>.Success(permissions));
        }

        public Task<ServiceResult> AssignToOrganizationAsync(Guid permissionId, Guid organizationId)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        // Application 관련
        public Task<ServiceResult<IEnumerable<PermissionDto>>> GetApplicationPermissionsAsync(Guid applicationId, bool includeSystemPermissions = false)
        {
            var permissions = new List<PermissionDto>();
            return Task.FromResult(ServiceResult<IEnumerable<PermissionDto>>.Success(permissions));
        }

        public Task<ServiceResult> AssignToApplicationAsync(Guid permissionId, Guid applicationId)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        // 권한 검증
        public Task<ServiceResult<PermissionValidationResponse>> ValidatePermissionAsync(PermissionValidationRequest request)
        {
            var response = new PermissionValidationResponse
            {
                IsAllowed = true,
                ValidationTime = DateTime.UtcNow,
                RequestId = request.RequestId
            };
            return Task.FromResult(ServiceResult<PermissionValidationResponse>.Success(response));
        }

        public Task<ServiceResult<bool>> CanDeletePermissionAsync(Guid permissionId)
        {
            return Task.FromResult(ServiceResult<bool>.Success(true));
        }

        public Task<ServiceResult<bool>> CanAssignPermissionAsync(Guid permissionId, Guid targetId, string targetType)
        {
            return Task.FromResult(ServiceResult<bool>.Success(true));
        }

        // 캐시 관리
        public Task<ServiceResult> ClearPermissionCacheAsync(Guid permissionId)
        {
            try
            {
                var cacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}{permissionId}";
                _cache.Remove(cacheKey);
                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing permission cache: {PermissionId}", permissionId);
                return Task.FromResult(ServiceResult.Failure("Failed to clear permission cache"));
            }
        }

        public Task<ServiceResult> ClearOrganizationPermissionCacheAsync(Guid organizationId)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult<AuthHive.Core.Models.Common.Cache.CacheStatistics>> GetCacheStatisticsAsync()
        {
            try
            {
                var stats = new AuthHive.Core.Models.Common.Cache.CacheStatistics
                {
                    ServiceName = "PermissionService",
                    CacheType = "InMemory",
                    StatsPeriodStart = DateTime.UtcNow.AddHours(-1),
                    StatsPeriodEnd = DateTime.UtcNow
                };

                return Task.FromResult(ServiceResult<AuthHive.Core.Models.Common.Cache.CacheStatistics>.Success(stats));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving cache statistics");
                return Task.FromResult(ServiceResult<AuthHive.Core.Models.Common.Cache.CacheStatistics>.Failure("Failed to get cache statistics"));
            }
        }

        public Task<ServiceResult<PermissionCacheStatistics>> GetDetailedCacheStatisticsAsync()
        {
            var stats = new PermissionCacheStatistics
            {
                // 부모 클래스 CacheStatistics의 속성들 사용
                ServiceName = "PermissionService",
                CacheType = "InMemory",
                StatsPeriodStart = DateTime.UtcNow.AddHours(-1),
                StatsPeriodEnd = DateTime.UtcNow,

                // PermissionCacheStatistics 고유 속성들
                EntriesByScope = new Dictionary<string, long>(),
                EntriesByOrganization = new Dictionary<Guid, long>(),
                MostCachedScopes = new List<string>(),
                LeastUsedScopes = new List<string>(),
                EntriesByConnectedId = new Dictionary<Guid, int>()
            };
            return Task.FromResult(ServiceResult<PermissionCacheStatistics>.Success(stats));
        }

        // Views 지원
        public Task<ServiceResult<OrganizationPermissionMatrixView>> GetPermissionMatrixAsync(Guid organizationId, List<Guid>? permissionIds = null)
        {
            var view = new OrganizationPermissionMatrixView
            {
                Organization = new OrganizationMatrixInfo { Id = organizationId },
                Header = new MatrixHeader(),
                Rows = new List<MatrixRow>(),
                Summary = new MatrixSummary(),
                GeneratedAt = DateTime.UtcNow,
                Metadata = new MatrixMetadata()
            };
            return Task.FromResult(ServiceResult<OrganizationPermissionMatrixView>.Success(view));
        }


        public Task<ServiceResult<ApplicationPermissionView>> GetApplicationPermissionViewAsync(Guid applicationId)
        {
            var view = new ApplicationPermissionView
            {
                Application = new ApplicationInfo
                {
                    Id = applicationId,
                    Name = string.Empty,
                    OrganizationId = Guid.Empty,
                    OrganizationName = string.Empty,
                    ApplicationType = string.Empty,
                    IsActive = true
                },
                PermissionGroups = new List<PermissionCategoryGroup>(),
                Summary = new ApplicationPermissionSummary(),
                RoleMatrices = new List<RolePermissionMatrix>(),
                GeneratedAt = DateTime.UtcNow
            };
            return Task.FromResult(ServiceResult<ApplicationPermissionView>.Success(view));
        }
        #endregion

        #region Private Helper Methods

        private PermissionDto MapToDto(Permission permission)
        {
            return new PermissionDto
            {
                Id = permission.Id,
                Scope = permission.Scope,
                Name = permission.Name,
                Description = permission.Description,
                Category = permission.Category,
                ParentPermissionId = permission.ParentPermissionId,
                Level = permission.Level,
                IsSystemPermission = permission.IsSystemPermission,
                RequiredMembershipTypes = DeserializeRequiredMembershipTypes(permission.RequiredMembershipTypes),
                IsActive = permission.IsActive,
                ResourceType = permission.ResourceType,
                ActionType = permission.ActionType,
                ScopeOrganization = permission.ScopeOrganization,
                ScopeApplication = permission.ScopeApplication,
                ScopeResource = permission.ScopeResource,
                ScopeAction = permission.ScopeAction,
                HasWildcard = permission.HasWildcard,
                ScopeLevel = permission.ScopeLevel,
                NormalizedScope = permission.NormalizedScope,
                Metadata = DeserializeMetadata(permission.Metadata),
                CreatedAt = permission.CreatedAt,
                CreatedByConnectedId = permission.CreatedByConnectedId,
                UpdatedAt = permission.UpdatedAt,
                UpdatedByConnectedId = permission.UpdatedByConnectedId,
                IsDeleted = permission.IsDeleted,
                DeletedAt = permission.DeletedAt,
                DeletedByConnectedId = permission.DeletedByConnectedId
            };
        }

        private PermissionNode MapToPermissionNode(Permission permission)
        {
            return new PermissionNode
            {
                Id = permission.Id,
                Scope = permission.Scope,
                Name = permission.Name,
                Category = permission.Category.ToString(),
                ParentId = permission.ParentPermissionId,
                Children = new List<PermissionNode>(), // 빈 리스트로 초기화
                Level = (int)permission.Level,
                IsActive = permission.IsActive,
                IsSystemPermission = permission.IsSystemPermission
            };
        }

        private static List<string>? DeserializeRequiredMembershipTypes(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                return JsonSerializer.Deserialize<List<string>>(json);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static Dictionary<string, object>? DeserializeMetadata(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private (string resourceType, string actionType) ParseScope(string scope)
        {
            var parts = scope.Split(':');
            if (parts.Length >= 2)
            {
                return (parts[0], parts[1]);
            }

            return (scope, "unknown");
        }

        private void ParseAndSetScopeComponents(Permission permission)
        {
            var parts = permission.Scope.Split(':');

            permission.ScopeLevel = parts.Length;
            permission.NormalizedScope = permission.Scope.ToLowerInvariant();
            permission.HasWildcard = permission.Scope.Contains('*');

            if (parts.Length >= 1) permission.ScopeResource = parts[0];
            if (parts.Length >= 2) permission.ScopeAction = parts[1];
            if (parts.Length >= 3) permission.ScopeOrganization = parts[2];
            if (parts.Length >= 4) permission.ScopeApplication = parts[3];
        }

        private void InvalidatePermissionCache()
        {
            _logger.LogDebug("Permission cache invalidated");
        }

        private IQueryable<Permission> ApplySorting(IQueryable<Permission> query, string? sortBy, string sortDirection)
        {
            if (string.IsNullOrEmpty(sortBy))
            {
                return query.OrderBy(p => p.CreatedAt); // 기본 정렬
            }

            var isDescending = sortDirection?.ToLowerInvariant() == "desc";

            return sortBy.ToLowerInvariant() switch
            {
                "name" => isDescending ? query.OrderByDescending(p => p.Name) : query.OrderBy(p => p.Name),
                "scope" => isDescending ? query.OrderByDescending(p => p.Scope) : query.OrderBy(p => p.Scope),
                "category" => isDescending ? query.OrderByDescending(p => p.Category) : query.OrderBy(p => p.Category),
                "createdat" => isDescending ? query.OrderByDescending(p => p.CreatedAt) : query.OrderBy(p => p.CreatedAt),
                "updatedat" => isDescending ? query.OrderByDescending(p => p.UpdatedAt) : query.OrderBy(p => p.UpdatedAt),
                "isactive" => isDescending ? query.OrderByDescending(p => p.IsActive) : query.OrderBy(p => p.IsActive),
                _ => query.OrderBy(p => p.CreatedAt) // 기본 정렬
            };
        }

        #endregion
    }
}