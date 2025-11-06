using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.Extensions.Logging;

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.System; // IDateTimeProvider 추가
using AuthHive.Core.Interfaces.Organization.Service; // IPlanRestrictionService 추가

using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Auth.Role;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Auth.Role.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Auth.Role.Common;

using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Interfaces.Infra;


namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 역할 관리의 핵심 비즈니스 로직을 담당하는 서비스 (CancellationToken, IPrincipalAccessor, IDateTimeProvider 통합)
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
        private readonly IPrincipalAccessor _principalAccessor; // ⭐️ 작업 주체 (ConnectedId) 확보
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IPlanRestrictionService _planRestrictionService; // ⭐️ 조직 제한 사항
        private readonly ILogger<RoleService> _logger;

        public RoleService(
            IRoleRepository roleRepository,
            IRolePermissionRepository rolePermissionRepository,
            IPermissionRepository permissionRepository,
            IConnectedIdRoleRepository connectedIdRoleRepository,
            IUnitOfWork unitOfWork,
            IAuditService auditService,
            ICacheService cacheService,
            IPrincipalAccessor principalAccessor, // ⭐️ DI 추가
            IDateTimeProvider dateTimeProvider,     // ⭐️ DI 추가
            IPlanRestrictionService planRestrictionService, // ⭐️ DI 추가
            ILogger<RoleService> logger)
        {
            _roleRepository = roleRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _permissionRepository = permissionRepository;
            _connectedIdRoleRepository = connectedIdRoleRepository;
            _unitOfWork = unitOfWork;
            _auditService = auditService;
            _cacheService = cacheService;
            _principalAccessor = principalAccessor; // ⭐️ 할당
            _dateTimeProvider = dateTimeProvider;   // ⭐️ 할당
            _planRestrictionService = planRestrictionService; // ⭐️ 할당
            _logger = logger;
        }

        #region IService Implementation

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("RoleService initializing...");
            _logger.LogInformation("RoleService initialized successfully");
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _roleRepository.AnyAsync(r => true, cancellationToken);
                return true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleService health check failed");
                return false;
            }
        }

        #endregion

        #region 역할 검증 (IRoleService 계약)

        public async Task<ServiceResult<bool>> IsConnectedIdInRoleAsync(
            Guid connectedId,
            string roleKey,
            CancellationToken cancellationToken = default)
        {
            // Guid.Empty (시스템) 처리 로직
            if (connectedId == Guid.Empty)
            {
                if (roleKey.Equals(RoleConstants.SystemReservedKeys.SUPER_ADMIN, StringComparison.OrdinalIgnoreCase))
                {
                    return ServiceResult<bool>.Success(true);
                }
                return ServiceResult<bool>.Success(false);
            }

            var cacheKey = string.Format(RoleConstants.CacheKeys.UserRoles, connectedId);
            // 1. 캐시에서 ConnectedId의 활성 역할 연결 정보 조회 (ICacheService 대신 IMemoryCache 사용)
            var roleConnections = await _cacheService.GetOrSetAsync(
                     cacheKey,
                     async () =>
                     {
                         // ⭐️ [수정된 부분]: 세 번째 인자(bool)에 false를 위치 기반으로 추가하고,
                         // CancellationToken을 네 번째 인자로 올바르게 전달합니다.
                         return (await _connectedIdRoleRepository.GetActiveRolesAsync(
                             connectedId,
                             null,   // Argument 2: Guid? organizationId
                             false,  // 🚨 Argument 3: bool includeInactive (false = 활성 역할만)
                             cancellationToken)).ToList();
                     },
                     TimeSpan.FromMinutes(RoleConstants.Limits.CacheDurationMinutes),
                     cancellationToken);

            if (roleConnections == null || !roleConnections.Any())
            {
                return ServiceResult<bool>.Success(false);
            }

            var roleIds = roleConnections.Select(cr => cr.RoleId).Distinct().ToList();

            // CancellationToken 전달
            var roles = await _roleRepository.GetByIdsAsync(roleIds, cancellationToken);

            var isInRole = roles.Any(r => r.RoleKey.Equals(roleKey, StringComparison.OrdinalIgnoreCase) && r.IsActive);

            return ServiceResult<bool>.Success(isInRole);
        }

        #endregion

        #region 기본 CRUD 작업
        public async Task<ServiceResult<RoleResponse>> CreateAsync(CreateRoleRequest request, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var connectedId = _principalAccessor.ConnectedId; // ⭐️ 작업 주체 확보

                // [플랜 제한 검증]
                if (await _planRestrictionService.IsRoleLimitExceededAsync(request.OrganizationId, cancellationToken))
                {
                    return ServiceResult<RoleResponse>.Failure(
                        "Role creation failed. Organization limit reached.",
                        RoleConstants.ErrorCodes.PlanLimitExceeded);
                }

                if (await _roleRepository.RoleKeyExistsAsync(request.OrganizationId, request.RoleKey, excludeRoleId: null, cancellationToken))
                {
                    return ServiceResult<RoleResponse>.Failure(
                        string.Format(RoleConstants.ValidationMessages.DUPLICATE_ROLE_KEY, request.RoleKey),
                        RoleConstants.ErrorCodes.DuplicateKey);
                }

                if (request.ParentRoleId.HasValue)
                {
                    var parentRole = await _roleRepository.GetByIdAsync(request.ParentRoleId.Value, cancellationToken);
                    if (parentRole == null || parentRole.OrganizationId != request.OrganizationId)
                    {
                        return ServiceResult<RoleResponse>.Failure(
                            RoleConstants.ValidationMessages.PARENT_ROLE_NOT_FOUND,
                            RoleConstants.ErrorCodes.ParentNotFound);
                    }
                }

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
                    CreatedAt = _dateTimeProvider.UtcNow // ⭐️ IDateTimeProvider 사용
                };

                var createdRole = await _roleRepository.AddAsync(role, cancellationToken);

                // 초기 권한 할당 (CancellationToken 전달)
                if (request.InitialPermissionIds?.Any() == true)
                {
                    foreach (var permissionId in request.InitialPermissionIds)
                    {
                        // ⭐️ [오류 해결: CS1503] DateTime? expiresAt 인자에 null 명시
                        await _rolePermissionRepository.AssignPermissionAsync(
                            createdRole.Id, permissionId, connectedId,
                            reason: "Initial permission assignment",
                            expiresAt: null, // Arg 5: DateTime?
                            cancellationToken: cancellationToken);
                    }
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                await InvalidateOrganizationRoleCacheAsync(request.OrganizationId, cancellationToken);

                // 감사 로그 (CancellationToken 전달)
                await LogRoleActionAsync(
                    connectedId: connectedId, roleId: createdRole.Id, roleKey: createdRole.RoleKey,
                    actionType: AuditActionType.Create, success: true, message: "Role created successfully.",
                    cancellationToken: cancellationToken);


                _logger.LogInformation($"Role created: {createdRole.Id} ({createdRole.RoleKey}) by {connectedId}");

                var response = MapToRoleResponse(createdRole);
                return ServiceResult<RoleResponse>.Success(response, "Role created successfully.");
            }
            catch (OperationCanceledException)
            {
                await _unitOfWork.RollbackTransactionAsync(CancellationToken.None);
                throw;
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(CancellationToken.None);
                _logger.LogError(ex, "Error creating role");

                await LogRoleActionAsync(
                    connectedId: _principalAccessor.ConnectedId, roleId: Guid.Empty, roleKey: request.RoleKey,
                    actionType: AuditActionType.Create, success: false,
                    message: $"Error creating role: {ex.Message}", errorCode: RoleConstants.ErrorCodes.SystemError,
                    cancellationToken: CancellationToken.None);

                return ServiceResult<RoleResponse>.Failure("An error occurred while creating the role.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<RoleDetailResponse>> GetByIdAsync(Guid roleId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"role:detail:{roleId}";
                var cachedRole = await _cacheService.GetAsync<RoleDetailResponse>(cacheKey, cancellationToken);
                if (cachedRole != null) return ServiceResult<RoleDetailResponse>.Success(cachedRole);

                var role = await _roleRepository.GetWithRelatedDataAsync(roleId, includePermissions: true, includeUsers: true, cancellationToken: cancellationToken);
                if (role == null)
                    return ServiceResult<RoleDetailResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);

                var response = await MapToRoleDetailResponse(role, cancellationToken);

                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(RoleConstants.Limits.CacheDurationMinutes), cancellationToken);

                return ServiceResult<RoleDetailResponse>.Success(response);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting role {roleId}");
                return ServiceResult<RoleDetailResponse>.Failure("An error occurred while retrieving the role.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<RoleDetailResponse>> GetByRoleKeyAsync(Guid organizationId, string roleKey, CancellationToken cancellationToken = default)
        {
            try
            {
                var role = await _roleRepository.GetByRoleKeyAsync(organizationId, roleKey, cancellationToken);
                if (role == null)
                {
                    return ServiceResult<RoleDetailResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);
                }
                return await GetByIdAsync(role.Id, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting role by key {roleKey}");
                return ServiceResult<RoleDetailResponse>.Failure("An error occurred while retrieving the role.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<RoleListResponse>> GetRolesAsync(SearchRolesRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                IEnumerable<Role> roles;
                // Repository 메서드에 CancellationToken 전달
                if (request.ConnectedId.HasValue)
                {
                    roles = await _roleRepository.GetByConnectedIdAsync(request.ConnectedId.Value, includeInactive: request.IsActive == null || !request.IsActive.Value, cancellationToken);
                }
                else if (request.ApplicationId.HasValue)
                {
                    roles = await _roleRepository.GetByApplicationAsync(request.ApplicationId.Value, includeInactive: request.IsActive == null || !request.IsActive.Value, cancellationToken);
                }
                else if (request.Scope.HasValue)
                {
                    roles = await _roleRepository.GetByScopeAsync(request.OrganizationId, request.Scope.Value, includeInactive: request.IsActive == null || !request.IsActive.Value, cancellationToken);
                }
                else if (request.Level.HasValue)
                {
                    roles = await _roleRepository.GetByLevelAsync(request.OrganizationId, request.Level.Value, includeInactive: request.IsActive == null || !request.IsActive.Value, cancellationToken);
                }
                else if (request.ParentRoleId.HasValue)
                {
                    roles = await _roleRepository.GetChildRolesAsync(request.ParentRoleId.Value, includeInactive: request.IsActive == null || !request.IsActive.Value, cancellationToken);
                }
                else if (request.HasPermissionId.HasValue)
                {
                    roles = await _roleRepository.GetRolesWithPermissionAsync(request.OrganizationId, request.HasPermissionId.Value, cancellationToken);
                }
                else
                {
                    // ⭐️ [오류 해결: CS1061] GetByOrganizationAsync 대신 GetByOrganizationIdAsync 사용
                    roles = await _roleRepository.GetByOrganizationIdAsync(
                        organizationId: request.OrganizationId,
                        startDate: request.CreatedFrom,
                        endDate: request.CreatedTo,
                        limit: null,
                        cancellationToken: cancellationToken);
                }

                // ... (나머지 필터링 및 로직 유지) ...
                var query = roles.AsQueryable();
                var now = _dateTimeProvider.UtcNow;

                // 필터링 로직 유지
                if (!string.IsNullOrEmpty(request.SearchTerm))
                {
                    var searchTerm = request.SearchTerm.ToLower();
                    query = query.Where(r =>
                        r.Name.ToLower().Contains(searchTerm) || r.RoleKey.ToLower().Contains(searchTerm) ||
                        (r.Description != null && r.Description.ToLower().Contains(searchTerm)));
                }
                if (!string.IsNullOrEmpty(request.RoleKey)) query = query.Where(r => r.RoleKey == request.RoleKey);
                if (request.IsActive.HasValue) query = query.Where(r => r.IsActive == request.IsActive.Value);
                if (request.OnlyNonExpired == true) query = query.Where(r => !r.ExpiresAt.HasValue || r.ExpiresAt.Value > now);
                if (request.CreatedFrom.HasValue) query = query.Where(r => r.CreatedAt >= request.CreatedFrom.Value);
                if (request.CreatedTo.HasValue) query = query.Where(r => r.CreatedAt <= request.CreatedTo.Value);
                if (!string.IsNullOrEmpty(request.Tags)) query = query.Where(r => r.Tags != null && r.Tags.Contains(request.Tags));

                // 정렬 (메모리)
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

                var totalCount = query.Count();

                var pagedItems = query.Skip((request.PageNumber - 1) * request.PageSize).Take(request.PageSize).ToList();

                if (request.IncludeOptions.HasFlag(RoleIncludeOptions.Permissions) || request.IncludeOptions.HasFlag(RoleIncludeOptions.AssignedUsers))
                {
                    foreach (var role in pagedItems)
                    {
                        if (request.IncludeOptions.HasFlag(RoleIncludeOptions.Permissions))
                            role.RolePermissions = (await _rolePermissionRepository.GetByRoleAsync(role.Id, cancellationToken: cancellationToken)).ToList();
                        if (request.IncludeOptions.HasFlag(RoleIncludeOptions.AssignedUsers))
                            role.ConnectedIdRoles = (await _connectedIdRoleRepository.GetByRoleAsync(role.Id, cancellationToken: cancellationToken)).ToList();
                    }
                }

                var response = new RoleListResponse
                {
                    Items = pagedItems.Select(MapToRoleResponse).ToList(),
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                foreach (var item in response.Items)
                {
                    item.AssignedUserCount = await _roleRepository.GetAssignedUserCountAsync(item.Id, cancellationToken);
                    item.PermissionCount = await _roleRepository.GetPermissionCountAsync(item.Id, cancellationToken);
                }

                response.Statistics = await GetRoleStatistics(request.OrganizationId, cancellationToken);
                response.FilterOptions = await BuildFilterOptions(request.OrganizationId, cancellationToken);

                response.SearchSummary = new SearchSummary
                {
                    SearchTerm = request.SearchTerm,
                    SortBy = request.SortBy ?? "Name",
                    SortDirection = request.IsDescending ? "Descending" : "Ascending",
                    AppliedFilterCount = CountAppliedFilters(request)
                };

                return ServiceResult<RoleListResponse>.Success(response);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching roles");
                return ServiceResult<RoleListResponse>.Failure("An error occurred while searching roles.", "SEARCH_ERROR");
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

        private async Task<FilterOptions> BuildFilterOptions(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var statistics = await _roleRepository.GetStatisticsAsync(organizationId, cancellationToken);

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

        public async Task<ServiceResult<RoleResponse>> UpdateAsync(Guid roleId, UpdateRoleRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                if (request.RoleId != Guid.Empty && request.RoleId != roleId)
                {
                    return ServiceResult<RoleResponse>.Failure("Request ID does not match.", "ID_MISMATCH");
                }

                var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
                if (role == null)
                {
                    return ServiceResult<RoleResponse>.NotFound(RoleConstants.ValidationMessages.ROLE_NOT_FOUND);
                }

                // 버전 충돌 검증 (로직 유지)
                if (request.RowVersion != null && role.RowVersion != null)
                {
                    if (!request.RowVersion.SequenceEqual(role.RowVersion))
                    {
                        return ServiceResult<RoleResponse>.Failure("Another user has already modified this. Please try again.", "CONCURRENCY_ERROR");
                    }
                }

                // 업데이트
                if (!string.IsNullOrEmpty(request.Name)) role.Name = request.Name;
                if (request.Description != null) role.Description = request.Description;
                if (request.Level.HasValue) role.Level = (PermissionLevel)request.Level.Value;

                if (request.ParentRoleId.HasValue)
                {
                    // 순환 참조 검증 (CancellationToken 전달)
                    if (await IsCircularReference(roleId, request.ParentRoleId.Value, cancellationToken))
                    {
                        return ServiceResult<RoleResponse>.Failure(RoleConstants.ValidationMessages.CIRCULAR_REFERENCE, RoleConstants.ErrorCodes.CircularReference);
                    }
                    role.ParentRoleId = request.ParentRoleId;
                }

                if (request.Priority.HasValue) role.Priority = request.Priority.Value;
                if (request.MaxAssignments.HasValue) role.MaxAssignments = request.MaxAssignments.Value;
                if (request.ExpiresAt.HasValue) role.ExpiresAt = request.ExpiresAt;
                if (request.IsActive.HasValue) role.IsActive = request.IsActive.Value;
                if (!string.IsNullOrEmpty(request.Tags)) role.Tags = request.Tags;
                if (!string.IsNullOrEmpty(request.Metadata)) role.Metadata = request.Metadata;

                role.UpdatedAt = _dateTimeProvider.UtcNow; // ⭐️ IDateTimeProvider 사용

                await _roleRepository.UpdateAsync(role, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 캐시 무효화 (CancellationToken 전달)
                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                // 감사 로그 (CancellationToken 전달)
                await LogRoleActionAsync(
                    _principalAccessor.ConnectedId, roleId, role.RoleKey, AuditActionType.Update, true,
                    $"Role updated: {request.UpdateReason}", null, cancellationToken);

                _logger.LogInformation($"Role updated: {roleId}. Reason: {request.UpdateReason}");

                var response = MapToRoleResponse(role);
                return ServiceResult<RoleResponse>.Success(response, "Role updated successfully.");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating role {roleId}");
                return ServiceResult<RoleResponse>.Failure(
                    "An error occurred while updating the role.",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid roleId, CancellationToken cancellationToken = default)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 삭제 가능 여부 확인 (CancellationToken 전달)
                var canDelete = await CanDeleteRoleAsync(roleId, cancellationToken);
                if (!canDelete.IsSuccess || !canDelete.Data)
                {
                    var errorMessage = canDelete.ErrorMessage ?? RoleConstants.ValidationMessages.ROLE_IN_USE;
                    var errorCode = canDelete.ErrorCode ?? RoleConstants.ErrorCodes.RoleInUse;
                    return ServiceResult.Failure(errorMessage, errorCode);
                }

                await _roleRepository.SoftDeleteAsync(roleId, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 캐시 무효화 (CancellationToken 전달)
                await InvalidateRoleCacheAsync(roleId, cancellationToken);
                await InvalidateOrganizationRoleCacheAsync(role.OrganizationId, cancellationToken);

                // 감사 로그 (CancellationToken 전달)
                await LogRoleActionAsync(_principalAccessor.ConnectedId, roleId, role.RoleKey, AuditActionType.Delete, true,
                    "Role soft deleted successfully.", null, cancellationToken);

                _logger.LogInformation($"Role deleted: {roleId}");

                return ServiceResult.Success("Role deleted successfully.");
            }
            catch (OperationCanceledException)
            {
                throw;
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

        public async Task<ServiceResult<IEnumerable<RoleDto>>> GetChildRolesAsync(Guid parentRoleId, CancellationToken cancellationToken = default)
        {
            try
            {
                var childRoles = await _roleRepository.GetChildRolesAsync(parentRoleId, cancellationToken: cancellationToken);
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
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting child roles for {parentRoleId}");
                return ServiceResult<IEnumerable<RoleDto>>.Failure("An error occurred while retrieving child roles.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> MoveRoleAsync(Guid roleId, Guid? newParentId, Guid movedByConnectedId, CancellationToken cancellationToken = default)
        {
            Role? role = null;

            try
            {
                role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                Guid? oldParentId = role.ParentRoleId;

                // 순환 참조 검증 (CancellationToken 전달)
                if (newParentId.HasValue)
                {
                    if (await IsCircularReference(roleId, newParentId.Value, cancellationToken))
                    {
                        await LogRoleActionAsync(movedByConnectedId, roleId, role.RoleKey, AuditActionType.Update, false,
                            "Circular reference detected.", RoleConstants.ErrorCodes.CircularReference, cancellationToken);
                        return ServiceResult.Failure(RoleConstants.ValidationMessages.CIRCULAR_REFERENCE, RoleConstants.ErrorCodes.CircularReference);
                    }
                }

                role.ParentRoleId = newParentId;
                role.UpdatedAt = _dateTimeProvider.UtcNow; // ⭐️ IDateTimeProvider 사용

                await _roleRepository.UpdateAsync(role, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                // 감사 로그 (CancellationToken 전달)
                await LogRoleActionAsync(movedByConnectedId, roleId, role.RoleKey, AuditActionType.Update, true,
                    $"ParentRoleId changed from {oldParentId} to {newParentId}.", cancellationToken: cancellationToken);

                _logger.LogInformation($"Role {roleId} moved to parent {newParentId}");

                return ServiceResult.Success("Role moved successfully.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error moving role {roleId}");

                if (role != null)
                {
                    await LogRoleActionAsync(movedByConnectedId, roleId, role.RoleKey, AuditActionType.Update, false,
                        $"System error: {ex.Message}", RoleConstants.ErrorCodes.SystemError, CancellationToken.None);
                }

                return ServiceResult.Failure("An error occurred while moving the role.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region 권한 관리 (RolePermission)
        // RoleService.cs (AssignPermissionAsync 메서드 내부)

        /// <summary>
                /// 단일 권한 할당
                /// </summary>
        public async Task<ServiceResult> AssignPermissionAsync(Guid roleId, Guid permissionId, CancellationToken cancellationToken = default)
        {
            try
            {
                // 이미 할당되어 있는지 확인
                if (await _rolePermissionRepository.ExistsAsync(roleId, permissionId, cancellationToken))
                {
                    return ServiceResult.Success("Permission is already assigned.");
                }

                // ⭐️ 수정된 부분: expiresAt 인자(DateTime?)에 null을 명시적으로 전달
                await _rolePermissionRepository.AssignPermissionAsync(
                          roleId,
                          permissionId,
                          _principalAccessor.ConnectedId,
                          reason: "Permission assigned",
                          expiresAt: null, // 🚨 Argument 5: DateTime?
                                    cancellationToken: cancellationToken); // Argument 6: CancellationToken

                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 캐시 무효화
                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                _logger.LogInformation($"Permission {permissionId} assigned to role {roleId}");

                return ServiceResult.Success("Permission assigned successfully.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error assigning permission {permissionId} to role {roleId}");
                return ServiceResult.Failure(
                  "An error occurred while assigning the permission.",
                  RoleConstants.ErrorCodes.SystemError);
            }
        }
        // RoleService.cs (RemovePermissionAsync 메서드 내부)

        public async Task<ServiceResult> RemovePermissionAsync(Guid roleId, Guid permissionId, CancellationToken cancellationToken = default)
        {
            try
            {
                // ⭐️ 오류 해결: reason과 cancellationToken 사이에 누락된 DateTime? 인자(null)를 채워 넣습니다.
                var removed = await _rolePermissionRepository.RemovePermissionAsync(
                    roleId,
                    permissionId,
                    reason: "Permission removed",
                    cancellationToken: cancellationToken);

                if (!removed)
                    return ServiceResult.Failure(
                        PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND,
                        PermissionConstants.ErrorCodes.PermissionNotFound);

                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                _logger.LogInformation($"Permission {permissionId} removed from role {roleId}");
                return ServiceResult.Success("Permission removed successfully.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error removing permission {permissionId} from role {roleId}");
                return ServiceResult.Failure("An error occurred while removing the permission.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<BulkPermissionAssignResponse>> AssignPermissionsBulkAsync(Guid roleId, List<Guid> permissionIds, CancellationToken cancellationToken = default)
        {
            var response = new BulkPermissionAssignResponse
            {
                Summary = new PermissionAssignmentSummary(),
                Results = new List<PermissionAssignmentResult>()
            };

            await _unitOfWork.BeginTransactionAsync(cancellationToken);

            try
            {
                foreach (var permissionId in permissionIds)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var result = new PermissionAssignmentResult { PermissionId = permissionId };

                    try
                    {
                        var permission = await _permissionRepository.GetByIdAsync(permissionId, cancellationToken);
                        if (permission == null)
                        {
                            result.IsSuccess = false; result.Status = AssignmentStatus.PermissionNotFound; result.Reason = PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND;
                            result.ErrorCode = PermissionConstants.ErrorCodes.PermissionNotFound; response.Summary.Failed++;
                        }
                        else
                        {
                            result.PermissionScope = permission.Scope; result.PermissionName = permission.Name;

                            if (await _rolePermissionRepository.ExistsAsync(roleId, permissionId, cancellationToken))
                            {
                                result.IsSuccess = true; result.Status = AssignmentStatus.AlreadyAssigned; result.Reason = "Already assigned.";
                                response.Summary.AlreadyExists++;
                            }
                            else
                            {
                                await _rolePermissionRepository.AssignPermissionAsync(roleId, permissionId, _principalAccessor.ConnectedId, "Bulk assignment", null, cancellationToken); // ⭐️ PrincipalAccessor 사용
                                result.IsSuccess = true; result.Status = AssignmentStatus.Assigned;
                                response.Summary.SuccessfullyAssigned++;
                            }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        result.IsSuccess = false; result.Status = AssignmentStatus.SystemError; result.Reason = ex.Message;
                        result.ErrorCode = RoleConstants.ErrorCodes.SystemError; response.Summary.Failed++;
                    }

                    response.Results.Add(result);
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                response.Success = response.Summary.Failed == 0;
                response.PartialSuccess = response.Summary.SuccessfullyAssigned > 0 && response.Summary.Failed > 0;
                response.Message = $"{response.Summary.SuccessfullyAssigned} succeeded, {response.Summary.AlreadyExists} skipped, {response.Summary.Failed} failed";
                response.Summary.TotalRequested = permissionIds.Count;

                return ServiceResult<BulkPermissionAssignResponse>.Success(response);
            }
            catch (OperationCanceledException)
            {
                await _unitOfWork.RollbackTransactionAsync(CancellationToken.None); throw;
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(CancellationToken.None);
                _logger.LogError(ex, $"Error in bulk permission assignment for role {roleId}");
                return ServiceResult<BulkPermissionAssignResponse>.Failure("An error occurred during bulk permission assignment.", RoleConstants.ErrorCodes.BulkLimitExceeded);
            }
        }
        // RoleService.cs (ReplacePermissionsAsync 메서드 내부)

        public async Task<ServiceResult<RolePermissionReplaceResult>> ReplacePermissionsAsync(Guid roleId, List<Guid> permissionIds, CancellationToken cancellationToken = default)
        {
            var result = new RolePermissionReplaceResult();
            await _unitOfWork.BeginTransactionAsync(cancellationToken);

            try
            {
                var existingPermissions = await _rolePermissionRepository.GetByRoleAsync(roleId, cancellationToken: cancellationToken);
                var existingPermissionIds = existingPermissions.Select(rp => rp.PermissionId).ToHashSet();

                var toAdd = permissionIds.Where(id => !existingPermissionIds.Contains(id)).ToList();
                var toRemove = existingPermissionIds.Where(id => !permissionIds.Contains(id)).ToList();

                // ⭐️ [오류 해결: RemovePermissionAsync] (Line 802)
                foreach (var permissionId in toRemove)
                {
                    await _rolePermissionRepository.RemovePermissionAsync(
                        roleId,
                        permissionId,
                        reason: "Replace operation",
                        cancellationToken: cancellationToken);
                    result.RemovedPermissionIds.Add(permissionId);
                }
                result.RemovedCount = toRemove.Count;

                // ⭐️ [오류 해결: AssignPermissionAsync] (Line 862)
                foreach (var permissionId in toAdd)
                {
                    await _rolePermissionRepository.AssignPermissionAsync(
                        roleId,
                        permissionId,
                        _principalAccessor.ConnectedId,
                        reason: "Replace operation",
                        expiresAt: null, // DateTime? 인자 자리에 null 명시
                        cancellationToken: cancellationToken);
                    result.AddedPermissionIds.Add(permissionId);
                }
                result.AddedCount = toAdd.Count;

                result.UnchangedCount = existingPermissionIds.Intersect(permissionIds).Count();

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                result.Success = true;
                result.ProcessedAt = _dateTimeProvider.UtcNow;

                return ServiceResult<RolePermissionReplaceResult>.Success(result, $"{result.AddedCount} added, {result.RemovedCount} removed, {result.UnchangedCount} unchanged");
            }
            catch (OperationCanceledException) { await _unitOfWork.RollbackTransactionAsync(CancellationToken.None); throw; }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(CancellationToken.None);
                _logger.LogError(ex, $"Error replacing permissions for role {roleId}");
                return ServiceResult<RolePermissionReplaceResult>.Failure("An error occurred while replacing permissions.", RoleConstants.ErrorCodes.SystemError);
            }
        }
        public async Task<ServiceResult<IEnumerable<PermissionInfoResponse>>> GetPermissionsAsync(Guid roleId, bool includeInherited = false, CancellationToken cancellationToken = default)
        {
            try
            {
                var rolePermissions = await _rolePermissionRepository.GetByRoleAsync(roleId, activeOnly: true, includeInherited: includeInherited, cancellationToken: cancellationToken);
                var PermissionInfoResponses = new List<PermissionInfoResponse>();

                foreach (var rp in rolePermissions)
                {
                    var permission = await _permissionRepository.GetByIdAsync(rp.PermissionId, cancellationToken);
                    if (permission != null)
                    {
                        PermissionInfoResponses.Add(new PermissionInfoResponse
                        {
                            Id = permission.Id,
                            Scope = permission.Scope,
                            Name = permission.Name,
                            Description = permission.Description,
                            IsActive = permission.IsActive
                        });
                    }
                }
                return ServiceResult<IEnumerable<PermissionInfoResponse>>.Success(PermissionInfoResponses);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting permissions for role {roleId}");
                return ServiceResult<IEnumerable<PermissionInfoResponse>>.Failure("An error occurred while retrieving permissions.", RoleConstants.ErrorCodes.SystemError);
            }
        }
        #endregion

        #region 상태 및 유효성 검증

        public async Task<ServiceResult> SetActiveStateAsync(Guid roleId, bool isActive, CancellationToken cancellationToken = default)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
                if (role == null)
                {
                    return ServiceResult.Failure(RoleConstants.ValidationMessages.ROLE_NOT_FOUND, RoleConstants.ErrorCodes.RoleNotFound);
                }

                role.IsActive = isActive;
                role.UpdatedAt = _dateTimeProvider.UtcNow; // ⭐️ IDateTimeProvider 사용

                await _roleRepository.UpdateAsync(role, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await InvalidateRoleCacheAsync(roleId, cancellationToken);

                _logger.LogInformation($"Role {roleId} active state set to {isActive}");

                return ServiceResult.Success($"Role {(isActive ? "activated" : "deactivated")} successfully.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error setting active state for role {roleId}");
                return ServiceResult.Failure("An error occurred while changing role status.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<bool>> ValidateRoleKeyAsync(Guid organizationId, string roleKey, Guid? excludeRoleId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var exists = await _roleRepository.RoleKeyExistsAsync(organizationId, roleKey, cancellationToken: cancellationToken);

                if (excludeRoleId.HasValue && exists)
                {
                    var existingRole = await _roleRepository.GetByRoleKeyAsync(organizationId, roleKey, cancellationToken);
                    if (existingRole?.Id == excludeRoleId.Value)
                    {
                        exists = false;
                    }
                }
                return ServiceResult<bool>.Success(!exists);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating role key {roleKey}");
                return ServiceResult<bool>.Failure("An error occurred while validating the role key.", RoleConstants.ErrorCodes.ValidationFailed);
            }
        }

        public async Task<ServiceResult<bool>> CanDeleteRoleAsync(Guid roleId, CancellationToken cancellationToken = default)
        {
            try
            {
                // 하위 역할 확인 (CancellationToken 전달)
                var childRoles = await _roleRepository.GetChildRolesAsync(roleId, cancellationToken: cancellationToken);
                if (childRoles.Any())
                {
                    return ServiceResult<bool>.Success(false, RoleConstants.ValidationMessages.HAS_CHILD_ROLES);
                }

                // 할당된 사용자 확인 (CancellationToken 전달)
                var userCount = await _roleRepository.GetAssignedUserCountAsync(roleId, cancellationToken);

                if (userCount > 0)
                {
                    return ServiceResult<bool>.Success(false, RoleConstants.ValidationMessages.ROLE_IN_USE);
                }
                return ServiceResult<bool>.Success(true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking if role {roleId} can be deleted");
                return ServiceResult<bool>.Failure("An error occurred while checking deletion availability.", RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region Private Methods

        private RoleResponse MapToRoleResponse(Role role)
        {
            // ... (로직 유지)
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

        private async Task<RoleDetailResponse> MapToRoleDetailResponse(Role role, CancellationToken cancellationToken = default)
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
                CreatedInfo = new AuditInfo { At = role.CreatedAt },
                Permissions = new List<PermissionInfo>()
            };

            if (role.UpdatedAt.HasValue) response.UpdatedInfo = new AuditInfo { At = role.UpdatedAt.Value };

            // Tags/Metadata 파싱 (로직 유지)
            if (!string.IsNullOrEmpty(role.Tags))
                try { response.Tags = JsonSerializer.Deserialize<List<string>>(role.Tags) ?? new List<string>(); } catch { }
            if (!string.IsNullOrEmpty(role.Metadata))
                try { response.Metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(role.Metadata); } catch { }

            // 권한 정보 로드 (CancellationToken 전달)
            if (role.RolePermissions?.Any() == true)
            {
                foreach (var rp in role.RolePermissions)
                {
                    // ⭐️ 오류 해결: IPermissionRepository.GetByIdAsync의 5개 인자 시그니처 준수
                    var permission = await _permissionRepository.GetByIdAsync(
                      rp.PermissionId,
                      cancellationToken); // Argument 2: CancellationToken

                    if (permission != null)
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

            response.Statistics = new RoleDetailStatistics
            {
                TotalPermissions = response.Permissions.Count,
                DirectPermissions = response.Permissions.Count(p => !p.IsInherited),
                InheritedPermissions = response.Permissions.Count(p => p.IsInherited),
                ChildRoleCount = role.ChildRoles?.Count ?? 0
            };

            // 현재 할당 수 (CancellationToken 전달)
            response.CurrentAssignments = await _roleRepository.GetAssignedUserCountAsync(role.Id, cancellationToken);

            return response;
        }

        // RoleService.cs (GetRoleStatistics 메서드)

        private async Task<RoleListStatistics> GetRoleStatistics(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // ⭐️ [수정된 부분]: GetByOrganizationAsync 대신 GetByOrganizationIdAsync 사용
            var allRoles = await _roleRepository.GetByOrganizationIdAsync(
                organizationId: organizationId,
                startDate: null,
                endDate: null,
                limit: null,
                cancellationToken: cancellationToken);

            var rolesList = allRoles.ToList();
            var now = _dateTimeProvider.UtcNow;

            return new RoleListStatistics
            {
                TotalRoles = rolesList.Count,
                ActiveRoles = rolesList.Count(r => r.IsActive),
                InactiveRoles = rolesList.Count(r => !r.IsActive),
                ExpiredRoles = rolesList.Count(r => r.ExpiresAt.HasValue && r.ExpiresAt.Value < now),
                RolesByScope = rolesList.GroupBy(r => r.Scope.ToString()).ToDictionary(g => g.Key, g => g.Count()),
                RolesByLevel = rolesList.GroupBy(r => (int)r.Level).ToDictionary(g => g.Key, g => g.Count())
            };
        }

        private async Task<bool> IsCircularReference(Guid roleId, Guid newParentId, CancellationToken cancellationToken = default)
        {
            var current = newParentId;
            var visited = new HashSet<Guid>();

            while (current != Guid.Empty)
            {
                if (current == roleId || visited.Contains(current)) return true;
                visited.Add(current);
                var parent = await _roleRepository.GetByIdAsync(current, cancellationToken);
                current = parent?.ParentRoleId ?? Guid.Empty;
            }
            return false;
        }

        private async Task InvalidateRoleCacheAsync(Guid roleId, CancellationToken cancellationToken = default)
        {
            await _cacheService.RemoveAsync($"role:detail:{roleId}", cancellationToken);
            await _cacheService.RemoveAsync($"role:{roleId}", cancellationToken);
            await _cacheService.RemoveAsync($"role:{roleId}:permissions", cancellationToken);
        }

        private async Task InvalidateOrganizationRoleCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            await _cacheService.RemoveAsync($"org:{organizationId}:roles", cancellationToken);
            await _cacheService.RemoveAsync($"org:{organizationId}:role:stats", cancellationToken);
        }

        // Private Methods 영역에 정의된 최종 LogRoleActionAsync 헬퍼 메서드
        private async Task LogRoleActionAsync(
            Guid connectedId,
            Guid roleId,
            string? roleKey,
            AuditActionType actionType,
            bool success,
            string message,
            string? errorCode = null,
            CancellationToken cancellationToken = default)
        {
            var metadata = new Dictionary<string, object>
            {
                { "RoleId", roleId }, { "RoleKey", roleKey ?? "N/A" }, { "Details", message }
            };
            if (!success && errorCode != null) metadata.Add("ErrorCode", errorCode);

            await _auditService.LogActionAsync(
                actionType: actionType, action: $"{actionType.ToString()} Role", connectedId: connectedId,
                success: success, errorMessage: success ? null : message, resourceType: "Role",
                resourceId: roleId.ToString(), metadata: metadata, cancellationToken: cancellationToken
            );
        }

        #endregion
    }
}