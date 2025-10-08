using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Auth.Role;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Auth.Role.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using System.Text.Json;
using AuthHive.Core.Models.Auth.Role.Common;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Enums.Core; // RoleConstants 사용

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 역할 관리의 핵심 비즈니스 로직을 담당하는 서비스
    /// </summary>
    public class RoleService : IRoleService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IPermissionRepository _permissionRepository;
        private readonly IConnectedIdRoleRepository _connectedIdRoleRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly ILogger<RoleService> _logger;

        public RoleService(
            IRoleRepository roleRepository,
            IRolePermissionRepository rolePermissionRepository,
            IPermissionRepository permissionRepository,
            IConnectedIdRoleRepository connectedIdRoleRepository,
            IUnitOfWork unitOfWork,
            IAuditService auditService,
            ICacheService cacheService,
            ILogger<RoleService> logger)
        {
            _roleRepository = roleRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _permissionRepository = permissionRepository;
            _connectedIdRoleRepository = connectedIdRoleRepository;
            _unitOfWork = unitOfWork;
            _auditService = auditService;
            _cacheService = cacheService;
            _logger = logger;
        }

        #region IService Implementation (InitializeAsync, IsHealthyAsync)

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("RoleService initializing...");
                await Task.CompletedTask;
                _logger.LogInformation("RoleService initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize RoleService");
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
                var testQuery = await _roleRepository.AnyAsync(r => true);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleService health check failed");
                return false;
            }
        }

        #endregion

        #region 역할 검증 (ConnectedIdContextStatisticsService에서 필요)

        /// <summary>
        /// 특정 ConnectedId가 특정 RoleKey를 가진 역할을 할당받았는지 확인합니다.
        /// </summary>
        /// <param name="connectedId">ConnectedId (사용자 또는 서비스 계정 ID)</param>
        /// <param name="roleKey">검증할 역할 키 (예: SUPER_ADMIN)</param>
        /// <returns>역할을 가지고 있으면 true</returns>
        public async Task<bool> IsConnectedIdInRoleAsync(Guid connectedId, string roleKey)
        {
            if (connectedId == Guid.Empty)
            {
                // 시스템 내부 호출에 대한 명시적 처리 (SaaS 원칙에 따라 명확히 처리되어야 함)
                // Guid.Empty가 SUPER_ADMIN 권한을 가져야 하는지 여부는 정책에 따라 결정됩니다.
                if (roleKey.Equals(RoleConstants.SystemReservedKeys.SUPER_ADMIN, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Implicitly granting SUPER_ADMIN role for System ConnectedId (Guid.Empty).");
                    return true;
                }
                return false;
            }

            var cacheKey = string.Format(RoleConstants.CacheKeys.UserRoles, connectedId);

            // 1. 캐시에서 ConnectedId의 활성 역할 연결 정보 조회 (ICacheService 대신 IMemoryCache 사용)
            var roleConnections = await _cacheService.GetOrSetAsync(cacheKey, async () =>
                    {
                        // CS1061 해결: IConnectedIdRoleRepository의 GetActiveRolesAsync를 사용
                        return (await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId)).ToList();
                    }, TimeSpan.FromMinutes(RoleConstants.Limits.CacheDurationMinutes)); // CacheDurationMinutes 사용


            if (roleConnections == null || !roleConnections.Any())
            {
                return false;
            }

            // 2. 연결된 역할 ID 목록 생성
            var roleIds = roleConnections.Select(cr => cr.RoleId).Distinct().ToList();

            // 3. 역할 ID 목록을 기반으로 RoleKey를 가진 역할이 있는지 확인
            // NOTE: _roleRepository에 RoleIds와 RoleKey를 동시에 쿼리하는 최적화된 메서드가 있어야 이상적입니다.
            var roles = await _roleRepository.GetByIdsAsync(roleIds); // List<Role>을 반환한다고 가정

            // 4. 역할 키를 비교합니다.
            return roles.Any(r => r.RoleKey.Equals(roleKey, StringComparison.OrdinalIgnoreCase) && r.IsActive);
        }

        #endregion

        #region 기본 CRUD 작업

        /// <summary>
        /// 역할 생성
        /// </summary>
        public async Task<ServiceResult<RoleResponse>> CreateAsync(CreateRoleRequest request)
        {
            try
            {
                // 유효성 검증 (Parameterized Error Messages 적용)
                if (await _roleRepository.RoleKeyExistsAsync(request.OrganizationId, request.RoleKey))
                {
                    return ServiceResult<RoleResponse>.Failure(
                        string.Format(RoleConstants.ValidationMessages.DUPLICATE_ROLE_KEY, request.RoleKey),
                        RoleConstants.ErrorCodes.DuplicateKey);
                }

                // 상위 역할 검증
                if (request.ParentRoleId.HasValue)
                {
                    var parentRole = await _roleRepository.GetByIdAsync(request.ParentRoleId.Value);
                    if (parentRole == null || parentRole.OrganizationId != request.OrganizationId)
                    {
                        return ServiceResult<RoleResponse>.Failure(
                            RoleConstants.ValidationMessages.PARENT_ROLE_NOT_FOUND,
                            RoleConstants.ErrorCodes.ParentNotFound);
                    }
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

                await _unitOfWork.BeginTransactionAsync();

                var createdRole = await _roleRepository.AddAsync(role);

                // 초기 권한 할당
                if (request.InitialPermissionIds?.Any() == true)
                {
                    foreach (var permissionId in request.InitialPermissionIds)
                    {
                        await _rolePermissionRepository.AssignPermissionAsync(
                            createdRole.Id,
                            permissionId,
                            Guid.Empty, // TODO: 실제 사용자 ID (Auditable 필드는 모두 채워져야 함)
                            "Initial permission assignment");
                    }
                }

                await _unitOfWork.CommitTransactionAsync();

                // 캐시 무효화
                await InvalidateOrganizationRoleCacheAsync(request.OrganizationId);

                _logger.LogInformation($"Role created: {createdRole.Id} ({createdRole.RoleKey})");

                var response = MapToRoleResponse(createdRole);
                return ServiceResult<RoleResponse>.Success(response, "Role created successfully.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error creating role");
                return ServiceResult<RoleResponse>.Failure(
                    "An error occurred while creating the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// ID로 역할 조회
        /// </summary>
        public async Task<ServiceResult<RoleDetailResponse>> GetByIdAsync(Guid roleId)
        {
            try
            {
                var cacheKey = $"role:detail:{roleId}";
                var cachedRole = await _cacheService.GetAsync<RoleDetailResponse>(cacheKey);
                if (cachedRole != null)
                {
                    return ServiceResult<RoleDetailResponse>.Success(cachedRole);
                }

                var role = await _roleRepository.GetWithRelatedDataAsync(
                    roleId,
                    includePermissions: true,
                    includeUsers: true);

                if (role == null)
                {
                    return ServiceResult<RoleDetailResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);
                }

                var response = await MapToRoleDetailResponse(role);

                // ⭐️ ICacheService.SetAsync 사용
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(RoleConstants.Limits.CacheDurationMinutes));

                return ServiceResult<RoleDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting role {roleId}");
                return ServiceResult<RoleDetailResponse>.Failure(
                    "An error occurred while retrieving the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        /// <summary>
        /// 역할 키로 조회
        /// </summary>
        public async Task<ServiceResult<RoleDetailResponse>> GetByRoleKeyAsync(Guid organizationId, string roleKey)
        {
            try
            {
                var role = await _roleRepository.GetByRoleKeyAsync(organizationId, roleKey);
                if (role == null)
                {
                    return ServiceResult<RoleDetailResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);
                }

                return await GetByIdAsync(role.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting role by key {roleKey}");
                return ServiceResult<RoleDetailResponse>.Failure(
                    "An error occurred while retrieving the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 역할 목록 조회
        /// </summary>
        public async Task<ServiceResult<RoleListResponse>> GetRolesAsync(SearchRolesRequest request)
        {
            try
            {
                IEnumerable<Role> roles;

                // Repository 최적화된 메서드 사용
                if (request.ConnectedId.HasValue)
                {
                    roles = await _roleRepository.GetByConnectedIdAsync(
                        request.ConnectedId.Value,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }
                else if (request.ApplicationId.HasValue)
                {
                    roles = await _roleRepository.GetByApplicationAsync(
                        request.ApplicationId.Value,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }
                else if (request.Scope.HasValue)
                {
                    roles = await _roleRepository.GetByScopeAsync(
                        request.OrganizationId,
                        request.Scope.Value,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }
                else if (request.Level.HasValue)
                {
                    roles = await _roleRepository.GetByLevelAsync(
                        request.OrganizationId,
                        request.Level.Value,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }
                else if (request.ParentRoleId.HasValue)
                {
                    roles = await _roleRepository.GetChildRolesAsync(
                        request.ParentRoleId.Value,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }
                else if (request.HasPermissionId.HasValue)
                {
                    roles = await _roleRepository.GetRolesWithPermissionAsync(
                        request.OrganizationId,
                        request.HasPermissionId.Value);
                }
                else
                {
                    // 기본: 조직의 모든 역할 조회
                    roles = await _roleRepository.GetByOrganizationAsync(
                        request.OrganizationId,
                        includeInactive: request.IsActive == null || !request.IsActive.Value);
                }

                // 추가 필터링 (메모리에서)
                var query = roles.AsQueryable();

                // 검색어 필터
                if (!string.IsNullOrEmpty(request.SearchTerm))
                {
                    var searchTerm = request.SearchTerm.ToLower();
                    query = query.Where(r =>
                        r.Name.ToLower().Contains(searchTerm) ||
                        r.RoleKey.ToLower().Contains(searchTerm) ||
                        (r.Description != null && r.Description.ToLower().Contains(searchTerm)));
                }

                // RoleKey 필터
                if (!string.IsNullOrEmpty(request.RoleKey))
                {
                    query = query.Where(r => r.RoleKey == request.RoleKey);
                }

                // IsActive 필터
                if (request.IsActive.HasValue)
                {
                    query = query.Where(r => r.IsActive == request.IsActive.Value);
                }

                // 만료되지 않은 역할만
                if (request.OnlyNonExpired == true)
                {
                    var now = DateTime.UtcNow;
                    // ExpiresAt이 HasValue이고, 만료되지 않은 역할만
                    query = query.Where(r => !r.ExpiresAt.HasValue || r.ExpiresAt.Value > now);
                }

                // 날짜 범위 필터
                if (request.CreatedFrom.HasValue)
                {
                    query = query.Where(r => r.CreatedAt >= request.CreatedFrom.Value);
                }

                if (request.CreatedTo.HasValue)
                {
                    query = query.Where(r => r.CreatedAt <= request.CreatedTo.Value);
                }

                // Tags 필터
                if (!string.IsNullOrEmpty(request.Tags))
                {
                    query = query.Where(r => r.Tags != null && r.Tags.Contains(request.Tags));
                }

                // 정렬
                query = request.SortBy?.ToLower() switch
                {
                    "name" => request.IsDescending ? query.OrderByDescending(r => r.Name) : query.OrderBy(r => r.Name),
                    "rolekey" => request.IsDescending ? query.OrderByDescending(r => r.RoleKey) : query.OrderBy(r => r.RoleKey),
                    "priority" => request.IsDescending ? query.OrderByDescending(r => r.Priority) : query.OrderBy(r => r.Priority),
                    "level" => request.IsDescending ? query.OrderByDescending(r => r.Level) : query.OrderBy(r => r.Level),
                    "createdat" => request.IsDescending ? query.OrderByDescending(r => r.CreatedAt) : query.OrderBy(r => r.CreatedAt),
                    "updatedat" => request.IsDescending ? query.OrderByDescending(r => r.UpdatedAt) : query.OrderBy(r => r.UpdatedAt),
                    _ => request.IsDescending ? query.OrderByDescending(r => r.Name) : query.OrderBy(r => r.Name)
                };

                // 전체 개수
                var totalCount = query.Count();

                // 페이징
                var pagedItems = query
                    .Skip((request.PageNumber - 1) * request.PageSize)
                    .Take(request.PageSize)
                    .ToList();

                // 각 역할에 대한 추가 정보 로드 (필요한 경우)
                if (request.IncludeOptions.HasFlag(RoleIncludeOptions.Permissions) ||
                    request.IncludeOptions.HasFlag(RoleIncludeOptions.AssignedUsers))
                {
                    foreach (var role in pagedItems)
                    {
                        if (request.IncludeOptions.HasFlag(RoleIncludeOptions.Permissions))
                        {
                            role.RolePermissions = (await _rolePermissionRepository.GetByRoleAsync(role.Id)).ToList();
                        }
                        if (request.IncludeOptions.HasFlag(RoleIncludeOptions.AssignedUsers))
                        {
                            role.ConnectedIdRoles = (await _connectedIdRoleRepository.GetByRoleAsync(role.Id)).ToList();
                        }
                    }
                }

                var response = new RoleListResponse
                {
                    Items = pagedItems.Select(MapToRoleResponse).ToList(),
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                // AssignedUserCount 추가 (필요시)
                foreach (var item in response.Items)
                {
                    item.AssignedUserCount = await _roleRepository.GetAssignedUserCountAsync(item.Id);
                    item.PermissionCount = await _roleRepository.GetPermissionCountAsync(item.Id);
                }

                // 통계 정보 추가
                response.Statistics = await GetRoleStatistics(request.OrganizationId);

                // 검색 요약 추가
                response.SearchSummary = new SearchSummary
                {
                    SearchTerm = request.SearchTerm,
                    SortBy = request.SortBy ?? "Name",
                    SortDirection = request.IsDescending ? "Descending" : "Ascending",
                    AppliedFilterCount = CountAppliedFilters(request)
                };

                // 필터 옵션 추가
                response.FilterOptions = await BuildFilterOptions(request.OrganizationId);

                return ServiceResult<RoleListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching roles");
                return ServiceResult<RoleListResponse>.Failure(
                    "An error occurred while searching roles.",
                    "SEARCH_ERROR");
            }
        }

        private int CountAppliedFilters(SearchRolesRequest request)
        {
            int count = 0;
            if (!string.IsNullOrEmpty(request.SearchTerm)) count++;
            if (!string.IsNullOrEmpty(request.RoleKey)) count++;
            if (request.Scope.HasValue) count++;
            if (request.ApplicationId.HasValue) count++;
            if (request.Level.HasValue) count++;
            if (request.ParentRoleId.HasValue) count++;
            if (request.IsActive.HasValue) count++;
            if (request.OnlyNonExpired == true) count++;
            if (request.ConnectedId.HasValue) count++;
            if (request.HasPermissionId.HasValue) count++;
            if (!string.IsNullOrEmpty(request.Tags)) count++;
            if (request.CreatedFrom.HasValue) count++;
            if (request.CreatedTo.HasValue) count++;
            return count;
        }

        private async Task<FilterOptions> BuildFilterOptions(Guid organizationId)
        {
            var statistics = await _roleRepository.GetStatisticsAsync(organizationId);

            return new FilterOptions
            {

                AvailableScopes = statistics.CountByScope
                    .Select(kvp => new FilterOption
                    {
                        Value = kvp.Key.ToString(),
                        DisplayText = kvp.Key.ToString(),
                        Count = kvp.Value
                    }).ToList(),

                AvailableLevels = statistics.CountByLevel
                    .Select(kvp => new FilterOption
                    {
                        Value = kvp.Key.ToString(),
                        DisplayText = $"Level {kvp.Key}",
                        Count = kvp.Value
                    }).ToList()
            };
        }

        /// <summary>
        /// 역할 업데이트
        /// </summary>
        public async Task<ServiceResult<RoleResponse>> UpdateAsync(Guid roleId, UpdateRoleRequest request)
        {
            try
            {
                // RoleId가 request에 있는 경우 검증
                if (request.RoleId != Guid.Empty && request.RoleId != roleId)
                {
                    return ServiceResult<RoleResponse>.Failure(
                        "Request ID does not match.",
                        "ID_MISMATCH");
                }

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return ServiceResult<RoleResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);
                }

                // 버전 충돌 검증 (있는 경우)
                if (request.RowVersion != null && role.RowVersion != null)
                {
                    if (!request.RowVersion.SequenceEqual(role.RowVersion))
                    {
                        return ServiceResult<RoleResponse>.Failure(
                            "Another user has already modified this. Please try again.",
                            "CONCURRENCY_ERROR");
                    }
                }

                // 업데이트
                if (!string.IsNullOrEmpty(request.Name))
                    role.Name = request.Name;

                if (request.Description != null)
                    role.Description = request.Description;

                if (request.Level.HasValue)
                    role.Level = (PermissionLevel)request.Level.Value;

                if (request.ParentRoleId.HasValue)
                {
                    // 순환 참조 검증
                    if (await IsCircularReference(roleId, request.ParentRoleId.Value))
                    {
                        return ServiceResult<RoleResponse>.Failure(
                            RoleConstants.ValidationMessages.CIRCULAR_REFERENCE,
                            RoleConstants.ErrorCodes.CircularReference);
                    }
                    role.ParentRoleId = request.ParentRoleId;
                }

                if (request.Priority.HasValue)
                    role.Priority = request.Priority.Value;

                if (request.MaxAssignments.HasValue)
                    role.MaxAssignments = request.MaxAssignments.Value;

                if (request.ExpiresAt.HasValue)
                    role.ExpiresAt = request.ExpiresAt;

                if (request.IsActive.HasValue)
                    role.IsActive = request.IsActive.Value;

                if (!string.IsNullOrEmpty(request.Tags))
                    role.Tags = request.Tags;

                if (!string.IsNullOrEmpty(request.Metadata))
                    role.Metadata = request.Metadata;

                role.UpdatedAt = DateTime.UtcNow;

                await _roleRepository.UpdateAsync(role);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                _logger.LogInformation($"Role updated: {roleId}. Reason: {request.UpdateReason}");

                var response = MapToRoleResponse(role);
                return ServiceResult<RoleResponse>.Success(response, "Role updated successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating role {roleId}");
                return ServiceResult<RoleResponse>.Failure(
                    "An error occurred while updating the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 역할 삭제
        /// </summary>
        public async Task<ServiceResult> DeleteAsync(Guid roleId)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 삭제 가능 여부 확인
                var canDelete = await CanDeleteRoleAsync(roleId);
                if (!canDelete.IsSuccess || !canDelete.Data)
                {
                    // Parameterized Error Message 적용
                    var errorMessage = canDelete.ErrorMessage ?? RoleConstants.ValidationMessages.ROLE_IN_USE;
                    var errorCode = canDelete.ErrorCode ?? RoleConstants.ErrorCodes.RoleInUse;

                    return ServiceResult.Failure(errorMessage, errorCode);
                }

                await _roleRepository.SoftDeleteAsync(roleId);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);
                await InvalidateOrganizationRoleCacheAsync(role.OrganizationId);
                _logger.LogInformation($"Role deleted: {roleId}");

                return ServiceResult.Success("Role deleted successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting role {roleId}");
                return ServiceResult.Failure(
                    "An error occurred while deleting the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region 계층 구조 관리

        /// <summary>
        /// 하위 역할 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<RoleDto>>> GetChildRolesAsync(Guid parentRoleId)
        {
            try
            {
                var childRoles = await _roleRepository.GetChildRolesAsync(parentRoleId);
                var roleDtos = childRoles.Select(r => new RoleDto
                {
                    Id = r.Id,
                    Name = r.Name,
                    RoleKey = r.RoleKey,
                    Description = r.Description,
                    Scope = r.Scope,
                    IsActive = r.IsActive
                });

                return ServiceResult<IEnumerable<RoleDto>>.Success(roleDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting child roles for {parentRoleId}");
                return ServiceResult<IEnumerable<RoleDto>>.Failure(
                    "An error occurred while retrieving child roles.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 역할 이동 (계층 구조 변경)
        /// </summary>
        public async Task<ServiceResult> MoveRoleAsync(Guid roleId, Guid? newParentId, Guid movedByConnectedId)
        {
            Role? role = null; //

            try
            {
                role = await _roleRepository.GetByIdAsync(roleId); // ⭐️ 외부 변수에 할당
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                Guid? oldParentId = role.ParentRoleId;

                // 순환 참조 검증
                if (newParentId.HasValue)
                {
                    if (await IsCircularReference(roleId, newParentId.Value))
                    {
                        // ⭐️ 감사 로그: 실패 기록 (순환 참조)
                        await LogRoleActionAsync(
                            movedByConnectedId, roleId, role.RoleKey, AuditActionType.Update, 
                            false, "Circular reference detected.", RoleConstants.ErrorCodes.CircularReference);

                        return ServiceResult.Failure(
                            RoleConstants.ValidationMessages.CIRCULAR_REFERENCE,
                            RoleConstants.ErrorCodes.CircularReference);
                    }
                }

                role.ParentRoleId = newParentId;
                role.UpdatedAt = DateTime.UtcNow;

                await _roleRepository.UpdateAsync(role);
                await _unitOfWork.SaveChangesAsync();

                await InvalidateRoleCacheAsync(roleId);

                // ⭐️ 감사 로그: 성공 기록
                await LogRoleActionAsync(
                    movedByConnectedId, roleId, role.RoleKey, AuditActionType.Update, 
                    true, $"ParentRoleId changed from {oldParentId} to {newParentId}.");

                _logger.LogInformation($"Role {roleId} moved to parent {newParentId}");

                return ServiceResult.Success("Role moved successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error moving role {roleId}");
                
                // ⭐️ 감사 로그: 시스템 에러 기록 (null 검사 후 호출)
                // role이 null이 아니거나, 시스템 에러 로그에 필요한 최소한의 정보가 있을 때만 호출
                if (role != null) 
                {
                    await LogRoleActionAsync(
                        movedByConnectedId, 
                        roleId, 
                        role.RoleKey, // ⭐️ 수정됨: role 객체 참조를 통해 접근
                        AuditActionType.Update, 
                        false, 
                        $"System error: {ex.Message}", 
                        RoleConstants.ErrorCodes.SystemError
                    );
                }
                
                return ServiceResult.Failure(
                    "An error occurred while moving the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region 권한 관리 (RolePermission)

        /// <summary>
        /// 단일 권한 할당
        /// </summary>
        public async Task<ServiceResult> AssignPermissionAsync(Guid roleId, Guid permissionId)
        {
            try
            {
                // 이미 할당되어 있는지 확인
                if (await _rolePermissionRepository.ExistsAsync(roleId, permissionId))
                {
                    return ServiceResult.Success("Permission is already assigned.");
                }

                await _rolePermissionRepository.AssignPermissionAsync(
                    roleId,
                    permissionId,
                    Guid.Empty, // TODO: 실제 사용자 ID
                    "Permission assigned");

                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                _logger.LogInformation($"Permission {permissionId} assigned to role {roleId}");

                return ServiceResult.Success("Permission assigned successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error assigning permission {permissionId} to role {roleId}");
                return ServiceResult.Failure(
                    "An error occurred while assigning the permission.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 권한 제거
        /// </summary>
        public async Task<ServiceResult> RemovePermissionAsync(Guid roleId, Guid permissionId)
        {
            try
            {
                var removed = await _rolePermissionRepository.RemovePermissionAsync(
                    roleId,
                    permissionId,
                    "Permission removed");

                if (!removed)
                {
                    return ServiceResult.Failure(
                        PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND,
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                _logger.LogInformation($"Permission {permissionId} removed from role {roleId}");

                return ServiceResult.Success("Permission removed successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error removing permission {permissionId} from role {roleId}");
                return ServiceResult.Failure(
                    "An error occurred while removing the permission.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 대량 권한 할당
        /// </summary>
        public async Task<ServiceResult<BulkPermissionAssignResponse>> AssignPermissionsBulkAsync(
            Guid roleId,
            List<Guid> permissionIds)
        {
            var response = new BulkPermissionAssignResponse
            {
                Summary = new PermissionAssignmentSummary(),
                Results = new List<PermissionAssignmentResult>()
            };

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var permissionId in permissionIds)
                {
                    var result = new PermissionAssignmentResult
                    {
                        PermissionId = permissionId
                    };

                    try
                    {
                        var permission = await _permissionRepository.GetByIdAsync(permissionId);
                        if (permission == null)
                        {
                            result.IsSuccess = false;
                            result.Status = AssignmentStatus.PermissionNotFound;
                            result.Reason = PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND;
                            result.ErrorCode = PermissionConstants.ErrorCodes.PermissionNotFound;
                            response.Summary.Failed++;
                        }
                        else
                        {
                            result.PermissionScope = permission.Scope;
                            result.PermissionName = permission.Name;

                            if (await _rolePermissionRepository.ExistsAsync(roleId, permissionId))
                            {
                                result.IsSuccess = true;
                                result.Status = AssignmentStatus.AlreadyAssigned;
                                result.Reason = "Already assigned.";
                                response.Summary.AlreadyExists++;
                            }
                            else
                            {
                                await _rolePermissionRepository.AssignPermissionAsync(
                                    roleId,
                                    permissionId,
                                    Guid.Empty, // TODO: 실제 사용자 ID
                                    "Bulk assignment");

                                result.IsSuccess = true;
                                result.Status = AssignmentStatus.Assigned;
                                response.Summary.SuccessfullyAssigned++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        result.IsSuccess = false;
                        result.Status = AssignmentStatus.SystemError;
                        result.Reason = ex.Message;
                        result.ErrorCode = RoleConstants.ErrorCodes.SystemError;
                        response.Summary.Failed++;
                    }

                    response.Results.Add(result);
                }

                await _unitOfWork.CommitTransactionAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                response.Success = response.Summary.Failed == 0;
                response.PartialSuccess = response.Summary.SuccessfullyAssigned > 0 && response.Summary.Failed > 0;
                response.Message = $"{response.Summary.SuccessfullyAssigned} succeeded, {response.Summary.AlreadyExists} skipped, {response.Summary.Failed} failed";
                response.Summary.TotalRequested = permissionIds.Count;

                return ServiceResult<BulkPermissionAssignResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error in bulk permission assignment for role {roleId}");
                return ServiceResult<BulkPermissionAssignResponse>.Failure(
                    "An error occurred during bulk permission assignment.",
                    RoleConstants.ErrorCodes.BulkLimitExceeded); // BULK_ASSIGN_ERROR 대신 명확한 에러 코드 사용
            }
        }

        /// <summary>
        /// 권한 교체
        /// </summary>
        public async Task<ServiceResult<RolePermissionReplaceResult>> ReplacePermissionsAsync(
            Guid roleId,
            List<Guid> permissionIds)
        {
            var result = new RolePermissionReplaceResult();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 기존 권한 조회
                var existingPermissions = await _rolePermissionRepository.GetByRoleAsync(roleId);
                var existingPermissionIds = existingPermissions.Select(rp => rp.PermissionId).ToHashSet();

                // 추가할 권한
                var toAdd = permissionIds.Where(id => !existingPermissionIds.Contains(id)).ToList();

                // 제거할 권한
                var toRemove = existingPermissionIds.Where(id => !permissionIds.Contains(id)).ToList();

                // 권한 제거
                foreach (var permissionId in toRemove)
                {
                    await _rolePermissionRepository.RemovePermissionAsync(roleId, permissionId, "Replace operation");
                    result.RemovedPermissionIds.Add(permissionId);
                }
                result.RemovedCount = toRemove.Count;

                // 권한 추가
                foreach (var permissionId in toAdd)
                {
                    await _rolePermissionRepository.AssignPermissionAsync(
                        roleId,
                        permissionId,
                        Guid.Empty, // TODO: 실제 사용자 ID
                        "Replace operation");
                    result.AddedPermissionIds.Add(permissionId);
                }
                result.AddedCount = toAdd.Count;

                result.UnchangedCount = existingPermissionIds.Intersect(permissionIds).Count();

                await _unitOfWork.CommitTransactionAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                result.Success = true;
                result.ProcessedAt = DateTime.UtcNow;

                return ServiceResult<RolePermissionReplaceResult>.Success(
                    result,
                    $"{result.AddedCount} added, {result.RemovedCount} removed, {result.UnchangedCount} unchanged");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, $"Error replacing permissions for role {roleId}");
                return ServiceResult<RolePermissionReplaceResult>.Failure(
                    "An error occurred while replacing permissions.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 역할의 권한 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetPermissionsAsync(
            Guid roleId,
            bool includeInherited = false)
        {
            try
            {
                var rolePermissions = await _rolePermissionRepository.GetByRoleAsync(
                    roleId,
                    activeOnly: true,
                    includeInherited: includeInherited);

                var permissionDtos = new List<PermissionDto>();

                foreach (var rp in rolePermissions)
                {
                    var permission = await _permissionRepository.GetByIdAsync(rp.PermissionId);
                    if (permission != null)
                    {
                        permissionDtos.Add(new PermissionDto
                        {
                            Id = permission.Id,
                            Scope = permission.Scope,
                            Name = permission.Name,
                            Description = permission.Description,
                            IsActive = permission.IsActive
                        });
                    }
                }

                return ServiceResult<IEnumerable<PermissionDto>>.Success(permissionDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting permissions for role {roleId}");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region 상태 및 유효성 검증

        /// <summary>
        /// 역할 활성/비활성 설정
        /// </summary>
        public async Task<ServiceResult> SetActiveStateAsync(Guid roleId, bool isActive)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                role.IsActive = isActive;
                role.UpdatedAt = DateTime.UtcNow;

                await _roleRepository.UpdateAsync(role);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId);

                _logger.LogInformation($"Role {roleId} active state set to {isActive}");

                return ServiceResult.Success($"Role {(isActive ? "activated" : "deactivated")} successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error setting active state for role {roleId}");
                return ServiceResult.Failure(
                    "An error occurred while changing role status.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 역할 키 유효성 검증
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateRoleKeyAsync(
            Guid organizationId,
            string roleKey,
            Guid? excludeRoleId = null)
        {
            try
            {
                var exists = await _roleRepository.RoleKeyExistsAsync(organizationId, roleKey);

                if (excludeRoleId.HasValue && exists)
                {
                    var existingRole = await _roleRepository.GetByRoleKeyAsync(organizationId, roleKey);
                    if (existingRole?.Id == excludeRoleId.Value)
                    {
                        exists = false;
                    }
                }

                return ServiceResult<bool>.Success(!exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating role key {roleKey}");
                return ServiceResult<bool>.Failure(
                    "An error occurred while validating the role key.",
                    RoleConstants.ErrorCodes.ValidationFailed);
            }
        }

        /// <summary>
        /// 역할 삭제 가능 여부 확인
        /// </summary>
        public async Task<ServiceResult<bool>> CanDeleteRoleAsync(Guid roleId)
        {
            try
            {
                // 하위 역할 확인
                var childRoles = await _roleRepository.GetChildRolesAsync(roleId);
                var hasChildRoles = childRoles.Any();
                if (hasChildRoles)
                {
                    return ServiceResult<bool>.Success(false, RoleConstants.ValidationMessages.HAS_CHILD_ROLES);
                }

                // 할당된 사용자 확인
                var assignedUsers = await _connectedIdRoleRepository.GetByRoleAsync(roleId);
                var userCount = assignedUsers.Count();
                if (userCount > 0)
                {
                    return ServiceResult<bool>.Success(false, RoleConstants.ValidationMessages.ROLE_IN_USE);
                }

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking if role {roleId} can be deleted");
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking deletion availability.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region Private Methods

        private RoleResponse MapToRoleResponse(Role role)
        {
            return new RoleResponse
            {
                Id = role.Id,
                OrganizationId = role.OrganizationId,
                Name = role.Name,
                Description = role.Description,
                RoleKey = role.RoleKey,
                Scope = role.Scope,
                ApplicationId = role.ApplicationId,
                IsActive = role.IsActive,
                Level = (int)role.Level,
                Priority = role.Priority,
                ExpiresAt = role.ExpiresAt,
                CreatedAt = role.CreatedAt,
                UpdatedAt = role.UpdatedAt
            };
        }

        private async Task<RoleDetailResponse> MapToRoleDetailResponse(Role role)
        {
            var response = new RoleDetailResponse
            {
                Id = role.Id,
                OrganizationId = role.OrganizationId,
                Name = role.Name,
                Description = role.Description,
                RoleKey = role.RoleKey,
                Scope = role.Scope,
                ApplicationId = role.ApplicationId,
                IsActive = role.IsActive,
                Level = (int)role.Level,
                Priority = role.Priority,
                ParentRoleId = role.ParentRoleId,
                MaxAssignments = role.MaxAssignments,
                ExpiresAt = role.ExpiresAt,
                CreatedInfo = new AuditInfo
                {
                    At = role.CreatedAt
                }
            };

            if (role.UpdatedAt.HasValue)
            {
                response.UpdatedInfo = new AuditInfo
                {
                    At = role.UpdatedAt.Value
                };
            }

            // Tags 파싱
            if (!string.IsNullOrEmpty(role.Tags))
            {
                try
                {
                    response.Tags = JsonSerializer.Deserialize<List<string>>(role.Tags) ?? new List<string>();
                }
                catch { }
            }

            // Metadata 파싱
            if (!string.IsNullOrEmpty(role.Metadata))
            {
                try
                {
                    response.Metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(role.Metadata);
                }
                catch { }
            }

            // 권한 정보
            if (role.RolePermissions?.Any() == true)
            {
                foreach (var rp in role.RolePermissions)
                {
                    var permission = await _permissionRepository.GetByIdAsync(rp.PermissionId);
                    if (permission != null)
                    {
                        response.Permissions.Add(new PermissionInfo
                        {
                            Id = permission.Id,
                            Scope = permission.Scope,
                            Name = permission.Name,
                            Description = permission.Description,
                            IsInherited = rp.InheritedFromId.HasValue,
                            InheritedFromRoleId = rp.InheritedFromId,
                            ExpiresAt = rp.ExpiresAt
                        });
                    }
                }
            }

            // 통계
            response.Statistics = new RoleDetailStatistics
            {
                TotalPermissions = response.Permissions.Count,
                DirectPermissions = response.Permissions.Count(p => !p.IsInherited),
                InheritedPermissions = response.Permissions.Count(p => p.IsInherited),
                ChildRoleCount = role.ChildRoles?.Count ?? 0
            };

            // 현재 할당 수
            var assignedUsers = await _connectedIdRoleRepository.GetByRoleAsync(role.Id);
            response.CurrentAssignments = assignedUsers.Count();

            return response;
        }

        private async Task<RoleListStatistics> GetRoleStatistics(Guid organizationId)
        {
            var allRoles = await _roleRepository.GetByOrganizationAsync(organizationId, includeInactive: true);
            var rolesList = allRoles.ToList();

            return new RoleListStatistics
            {
                TotalRoles = rolesList.Count,
                ActiveRoles = rolesList.Count(r => r.IsActive),
                InactiveRoles = rolesList.Count(r => !r.IsActive),
                ExpiredRoles = rolesList.Count(r => r.ExpiresAt.HasValue && r.ExpiresAt.Value < DateTime.UtcNow),
                RolesByScope = rolesList.GroupBy(r => r.Scope.ToString())
                    .ToDictionary(g => g.Key, g => g.Count()),
                RolesByLevel = rolesList.GroupBy(r => (int)r.Level)
                    .ToDictionary(g => g.Key, g => g.Count())
            };
        }

        private async Task<bool> IsCircularReference(Guid roleId, Guid newParentId)
        {
            var current = newParentId;
            var visited = new HashSet<Guid>();

            while (current != Guid.Empty)
            {
                if (current == roleId || visited.Contains(current))
                    return true;

                visited.Add(current);
                var parent = await _roleRepository.GetByIdAsync(current);
                current = parent?.ParentRoleId ?? Guid.Empty;
            }

            return false;
        }

        private async Task InvalidateRoleCacheAsync(Guid roleId)
        {
            // ICacheService의 RemoveAsync 사용
            await _cacheService.RemoveAsync($"role:detail:{roleId}");
            await _cacheService.RemoveAsync($"role:{roleId}");
            await _cacheService.RemoveAsync($"role:{roleId}:permissions");
        }

        private async Task InvalidateOrganizationRoleCacheAsync(Guid organizationId)
        {
            // ICacheService의 RemoveAsync 사용
            await _cacheService.RemoveAsync($"org:{organizationId}:roles");
            await _cacheService.RemoveAsync($"org:{organizationId}:role:stats");
        }

        // RoleService.cs 내 Private Methods 영역에 추가된 메서드

        /// <summary>
        /// 역할 관련 활동을 감사 로그에 기록하는 헬퍼 메서드
        /// IAuditService의 Dictionary<string, object>? metadata를 받는 오버로드를 사용합니다.
        /// </summary>
        // Private Methods 영역에 정의된 최종 LogRoleActionAsync 헬퍼 메서드
        private async Task LogRoleActionAsync(
            Guid connectedId,
            Guid roleId,
            string? roleKey, // ⭐️ 이 값을 사용합니다.
            AuditActionType actionType,
            bool success,
            string message,
            string? errorCode = null)
        {
            var metadata = new Dictionary<string, object>
    {
        { "RoleId", roleId },
        { "RoleKey", roleKey ?? "N/A" }, // 💡 roleKey를 참조하여 오류를 해결함
        { "Details", message }
    };

            if (!success && errorCode != null)
            {
                metadata.Add("ErrorCode", errorCode);
            }

            // IAuditService의 오버로드를 사용하여 감사 로그 기록
            await _auditService.LogActionAsync(
                actionType: actionType,
                action: $"{actionType.ToString()} Role",
                connectedId: connectedId,
                success: success,
                errorMessage: success ? null : message,
                resourceType: "Role",
                resourceId: roleId.ToString(),
                metadata: metadata
            );
        }

        #endregion
    }
}