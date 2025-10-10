using AutoMapper;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Audit.Requests;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Enums.Core;
// 최종 수정: Permission 관련 이벤트가 모여있는 정확한 네임스페이스를 사용합니다.
using AuthHive.Core.Models.Auth.Permissions.Events;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// Permission 서비스 - AuthHive v15 (완전 리팩토링)
    /// </summary>
    public class PermissionService : IPermissionService
    {
        private readonly IPermissionRepository _permissionRepository;
        private readonly IPermissionCacheService _cacheService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IMapper _mapper;
        private readonly ILogger<PermissionService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IConnectedIdService _connectedIdService;

        public PermissionService(
            IPermissionRepository permissionRepository,
            IPermissionCacheService cacheService,
            IUnitOfWork unitOfWork,
            IAuditService auditService,
            IEventBus eventBus,
            IMapper mapper,
            ILogger<PermissionService> logger,
            IDateTimeProvider dateTimeProvider,
            IConnectedIdService connectedIdService)
        {
            _permissionRepository = permissionRepository ?? throw new ArgumentNullException(nameof(permissionRepository));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
        }

        #region IService Implementation
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheHealthy = await _cacheService.IsHealthyAsync(cancellationToken);
                if (!cacheHealthy)
                {
                    _logger.LogWarning("Cache service is unhealthy, checking repository directly");
                }

                await _permissionRepository.AnyAsync(p => true, cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Permission service health check failed");
                return false;
            }
        }

        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("PermissionService initializing...");
            try
            {
                await _cacheService.InitializeAsync(cancellationToken);
                _logger.LogInformation("PermissionService initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PermissionService initialization failed");
                throw;
            }
        }



        #endregion

        #region Standard CRUD (from IService<T>)

        public async Task<ServiceResult<PermissionDto>> CreateAsync(CreatePermissionRequest request, CancellationToken cancellationToken = default)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (request == null)
            {
                return ServiceResult<PermissionDto>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }
            return await CreateAsync(request, null, null, null);
        }

        public async Task<ServiceResult<PermissionDto>> CreateAsync(
           CreatePermissionRequest request,
           Guid? connectedId = null,
           Guid? organizationId = null,
           string? subscriptionPlanKey = null)
        {
            if (request == null)
            {
                return ServiceResult<PermissionDto>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 이 호출이 경고를 발생시키지 않으려면, ValidateScopeDepthByPlan 메서드의 선언부도
                // 'string? subscriptionPlanKey'로 수정되어 있어야 합니다.
                var validationResult = await ValidateScopeDepthByPlan(request.Scope, subscriptionPlanKey);

                if (!validationResult.IsSuccess)
                {
                    // 수정됨: '??' 연산자를 사용해 validationResult.ErrorMessage가 null일 경우를 대비합니다.
                    return ServiceResult<PermissionDto>.Failure(
                        validationResult.ErrorMessage ?? "Scope depth validation failed.",
                        PermissionConstants.ErrorCodes.InvalidScope);
                }

                var existing = await _permissionRepository.FirstOrDefaultAsync(p => p.Scope == request.Scope);
                if (existing != null)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        $"Permission with scope '{request.Scope}' already exists.",
                        PermissionConstants.ErrorCodes.DuplicateScope);
                }

                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    var permission = _mapper.Map<PermissionEntity>(request);
                    permission.CreatedAt = _dateTimeProvider.UtcNow;
                    permission.UpdatedAt = _dateTimeProvider.UtcNow;

                    var createdPermission = await _permissionRepository.AddAsync(permission);
                    await _unitOfWork.SaveChangesAsync();

                    var domainEvent = new PermissionCreatedEvent(
                        createdPermission.Id,
                        createdPermission.Scope,
                        createdPermission.Name,
                        createdPermission.Category.ToString(),
                        connectedId,
                        organizationId);
                    await _eventBus.PublishAsync(domainEvent);

                    if (connectedId.HasValue)
                    {
                        await LogAuditAsync(
                            connectedId: connectedId.Value,
                            actionType: AuditActionType.Create,
                            resourceType: "Permission",
                            resourceId: createdPermission.Id,
                            description: $"Created permission: {createdPermission.Scope}",
                            organizationId: organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();

                    await _cacheService.RefreshAllAsync();

                    var permissionDto = _mapper.Map<PermissionDto>(createdPermission);
                    return ServiceResult<PermissionDto>.Success(permissionDto);
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating permission: {Scope}", request.Scope);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while creating permission.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }


        public async Task<ServiceResult<bool>> ValidateCreateAsync(CreatePermissionRequest request, CancellationToken cancellationToken = default)
        {
            var exists = await _permissionRepository.AnyAsync(p => p.Name == request.Name, cancellationToken);
            if (exists)
            {
                return ServiceResult<bool>.Conflict("A permission with the same name already exists.");
            }

            return ServiceResult<bool>.Success(true);
        }


        public async Task<ServiceResult<PermissionDto>> GetByScopeAsync(string scope)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                return ServiceResult<PermissionDto>.Failure("Scope cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }
            // 캐시 서비스가 모든 것을 처리합니다.
            return await _cacheService.GetByScopeAsync(scope);
        }

        public async Task<ServiceResult<PermissionTreeResponse>> GetTreeAsync(Guid? rootPermissionId = null, int? maxDepth = null)
        {
            // IPermissionCacheService의 GetTreeAsync는 파라미터가 없으므로,
            // 이 메서드도 파라미터 없이 호출하도록 단순화하거나,
            // 캐시 서비스의 인터페이스를 수정해야 합니다.
            // 여기서는 인터페이스에 맞춰 파라미터 없이 호출하는 것으로 가정합니다.
            if (rootPermissionId.HasValue || maxDepth.HasValue)
            {
                _logger.LogWarning("GetTreeAsync with parameters is not supported by the cache service, fetching the entire tree.");
            }
            return await _cacheService.GetTreeAsync();
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetChildrenAsync(Guid parentPermissionId, bool includeInactive = false)
        {
            // 1. 입력 값 유효성 검사
            if (parentPermissionId == Guid.Empty)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("ParentPermissionId cannot be an empty GUID.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 2. 데이터베이스 쿼리 생성
                var query = _permissionRepository.Query()
                    .Where(p => p.ParentPermissionId == parentPermissionId);

                // 비활성 권한 포함 여부 필터링
                if (!includeInactive)
                {
                    query = query.Where(p => p.IsActive);
                }

                var permissions = await query.ToListAsync();

                // 3. Entity 목록을 DTO 목록으로 매핑
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving child permissions for parent ID: {ParentId}", parentPermissionId);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving child permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<bool>> ExistsByScopeAsync(string scope)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                return ServiceResult<bool>.Failure("Scope cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 캐시 확인: ServiceResult 객체를 직접 받습니다.
                var cacheResult = await _cacheService.GetByScopeAsync(scope);

                // IsSuccess와 Data가 null이 아닌지로 캐시 존재 여부를 판단합니다.
                if (cacheResult.IsSuccess && cacheResult.Data != null)
                {
                    _logger.LogDebug("Existence check for scope '{Scope}' resolved from cache.", scope);
                    return ServiceResult<bool>.Success(true);
                }

                // 캐시에 없으면 데이터베이스에서 존재 여부 확인
                var exists = await _permissionRepository.AnyAsync(p => p.Scope == scope);
                return ServiceResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for scope existence: {Scope}", scope);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking for scope existence.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByResourceTypeAsync(string resourceType)
        {
            // 1. Input validation
            if (string.IsNullOrWhiteSpace(resourceType))
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("ResourceType cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 2. Find permissions from the database where the ResourceType matches
                var permissions = await _permissionRepository.FindAsync(p => p.ResourceType == resourceType);

                // 3. Map the list of entities to a list of DTOs
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permissions by resource type: {ResourceType}", resourceType);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions by resource type.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByCategoryAsync(string category, bool includeInactive = false)
        {
            // 1. 입력 값 유효성 검사
            if (string.IsNullOrWhiteSpace(category))
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("Category cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 2. 입력된 카테고리 문자열이 유효한 Enum 값인지 확인
                if (!Enum.TryParse<PermissionCategory>(category, true, out var categoryEnum))
                {
                    return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                        $"Invalid category: '{category}'. Valid categories are: {string.Join(", ", Enum.GetNames(typeof(PermissionCategory)))}",
                        PermissionConstants.ErrorCodes.InvalidParameter);
                }

                // 3. 데이터베이스 쿼리 생성
                var query = _permissionRepository.Query()
                    .Where(p => p.Category == categoryEnum);

                // 비활성 권한 포함 여부 필터링
                if (!includeInactive)
                {
                    query = query.Where(p => p.IsActive);
                }

                var permissions = await query.ToListAsync();
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permissions by category: {Category}", category);
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving permissions by category.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<PermissionDto>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            // 캐시 서비스가 캐시 확인, DB 조회를 모두 알아서 처리해줍니다.
            return await _cacheService.GetByIdAsync(id);
        }
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("Querying database for all permissions");

                // 데이터베이스에서 모든 권한을 직접 조회합니다.
                var permissions = await _permissionRepository.GetAllAsync();

                // 조회된 엔티티 목록을 DTO 목록으로 변환합니다.
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);

                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving all permissions");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while retrieving all permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PermissionDto>> UpdateAsync(Guid id, UpdatePermissionRequest request, CancellationToken cancellationToken = default)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (request == null)
            {
                return ServiceResult<PermissionDto>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }
            return await UpdateAsync(id, request, null, null);
        }

        public async Task<ServiceResult<PermissionDto>> UpdateAsync(
            Guid id,
            UpdatePermissionRequest request,
            Guid? connectedId = null,
            Guid? organizationId = null)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (request == null)
            {
                return ServiceResult<PermissionDto>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.NotFound("Permission not found");
                }

                if (permission.IsSystemPermission)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Cannot modify system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    var oldScope = permission.Scope;
                    _mapper.Map(request, permission);
                    permission.UpdatedAt = _dateTimeProvider.UtcNow;

                    await _permissionRepository.UpdateAsync(permission);
                    await _unitOfWork.SaveChangesAsync();

                    var domainEvent = new PermissionUpdatedEvent(
                        permission.Id,
                        permission.Scope,
                        connectedId,
                        organizationId);
                    await _eventBus.PublishAsync(domainEvent);

                    if (connectedId.HasValue)
                    {
                        await LogAuditAsync(
                            connectedId: connectedId.Value,
                            actionType: AuditActionType.Update,
                            resourceType: "Permission",
                            resourceId: permission.Id,
                            description: $"Updated permission: {permission.Scope}",
                            organizationId: organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();

                    // 수정됨: 역할에 맞는 캐시 무효화 메서드 이름으로 변경
                    await _cacheService.RefreshAllAsync();

                    var permissionDto = _mapper.Map<PermissionDto>(permission);
                    return ServiceResult<PermissionDto>.Success(permissionDto);
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating permission: {Id}", id);
                return ServiceResult<PermissionDto>.Failure(
                    "An error occurred while updating permission.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await DeleteAsync(id, null, null);
        }

        public async Task<ServiceResult> DeleteAsync(
            Guid id,
            Guid? connectedId = null,
            Guid? organizationId = null)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    // 최종 수정: 비제네릭 ServiceResult에 NotFound가 없으므로 Failure 사용
                    return ServiceResult.Failure("Permission not found", PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                if (permission.IsSystemPermission)
                {
                    return ServiceResult.Failure(
                        "Cannot delete system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                var hasChildPermissions = await _permissionRepository.AnyAsync(p => p.ParentPermissionId == id);
                if (hasChildPermissions)
                {
                    return ServiceResult.Failure(
                        "Cannot delete permission with child permissions. Delete or reassign child permissions first.",
                        PermissionConstants.ErrorCodes.PermissionHasDependencies);
                }

                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    await _permissionRepository.DeleteAsync(permission);
                    await _unitOfWork.SaveChangesAsync();

                    var domainEvent = new PermissionDeletedEvent(
                        permission.Id,
                        permission.Scope,
                        permission.IsSystemPermission,
                        connectedId,
                        organizationId);
                    await _eventBus.PublishAsync(domainEvent);

                    if (connectedId.HasValue)
                    {
                        await LogAuditAsync(
                            connectedId: connectedId.Value,
                            actionType: AuditActionType.Delete,
                            resourceType: "Permission",
                            resourceId: permission.Id,
                            description: $"Deleted permission: {permission.Scope}",
                            organizationId: organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();
                    await _cacheService.RefreshAllAsync();
                    return ServiceResult.Success();
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting permission: {Id}", id);
                return ServiceResult.Failure(
                    "An error occurred while deleting permission.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PagedResult<PermissionDto>>> GetPagedAsync(PaginationRequest request, CancellationToken cancellationToken = default)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (request == null)
            {
                return ServiceResult<PagedResult<PermissionDto>>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                var (items, totalCount) = await _permissionRepository.GetPagedAsync(
                    request.PageNumber, request.PageSize, null, p => p.Scope);

                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(items);
                var pagedResult = new PagedResult<PermissionDto>(
                    dtos, totalCount, request.PageNumber, request.PageSize);

                return ServiceResult<PagedResult<PermissionDto>>.Success(pagedResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paged permissions");
                return ServiceResult<PagedResult<PermissionDto>>.Failure(
                    "An error occurred while retrieving paged permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region Bulk Operations

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> CreateBulkAsync(IEnumerable<CreatePermissionRequest> requests, CancellationToken cancellationToken = default)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (requests == null)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }
            return await CreateBulkAsync(requests, null, null);
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> CreateBulkAsync(
            IEnumerable<CreatePermissionRequest> requests,
            Guid? connectedId = null,
            Guid? organizationId = null)
        {
            // 최종 수정: Null 안정성 강화를 위해 request null 체크 추가
            if (requests == null)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                var requestList = requests.ToList();

                if (requestList.Count > PermissionConstants.Limits.MaxBulkOperationSize)
                {
                    return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                        $"Bulk operation size ({requestList.Count}) exceeds limit of {PermissionConstants.Limits.MaxBulkOperationSize}. " +
                        $"Please split the operation into smaller batches.",
                        PermissionConstants.ErrorCodes.InvalidParameter);
                }

                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    var createdPermissions = new List<PermissionEntity>();

                    foreach (var request in requestList)
                    {
                        var permission = _mapper.Map<PermissionEntity>(request);
                        permission.CreatedAt = _dateTimeProvider.UtcNow;
                        permission.UpdatedAt = _dateTimeProvider.UtcNow;

                        var created = await _permissionRepository.AddAsync(permission);
                        createdPermissions.Add(created);
                    }

                    await _unitOfWork.SaveChangesAsync();

                    foreach (var permission in createdPermissions)
                    {
                        var domainEvent = new PermissionCreatedEvent(
                            permission.Id, permission.Scope, permission.Name,
                            permission.Category.ToString(), connectedId, organizationId);
                        await _eventBus.PublishAsync(domainEvent);
                    }

                    if (connectedId.HasValue)
                    {
                        // 수정됨: AuditActionType의 BulkCreate 멤버를 사용합니다.
                        await LogAuditAsync(
                            connectedId.Value, AuditActionType.BulkCreate, "Permission", null,
                            $"Bulk created {createdPermissions.Count} permissions", organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();

                    // 수정됨: 역할에 맞는 캐시 무효화 메서드 이름으로 변경
                    await _cacheService.RefreshAllAsync();

                    var dtos = _mapper.Map<IEnumerable<PermissionDto>>(createdPermissions);
                    return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk create permissions");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while bulk creating permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// ✅ PricingConstants 기반 스코프 깊이 검증
        /// SaaS 원칙: 플랜별로 스코프 깊이를 엄격하게 제한합니다.
        /// </summary>
        private Task<ServiceResult<bool>> ValidateScopeDepthByPlan(
            string scope,
            string? subscriptionPlanKey)
        {
            try
            {
                var scopeParts = scope.Split(PermissionConstants.ScopeFormat.Separator);
                var scopeDepth = scopeParts.Length;

                // 기본 플랜 사용 (null인 경우)
                var planKey = subscriptionPlanKey ?? PricingConstants.DefaultPlanKey;

                // PricingConstants에서 플랜별 제한 조회
                if (!PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits.TryGetValue(
                    planKey,
                    out var maxDepth))
                {
                    // 플랜 키가 없으면 기본 플랜 제한 사용
                    maxDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[
                        PricingConstants.DefaultPlanKey];

                    _logger.LogWarning(
                        "Unknown plan key '{PlanKey}', using default plan limit of {MaxDepth}",
                        planKey,
                        maxDepth);
                }

                // -1은 무제한 (Enterprise 플랜 등)
                if (maxDepth != -1 && scopeDepth > maxDepth)
                {
                    var errorMessage = $"Permission scope depth ({scopeDepth}) exceeds your plan limit ({maxDepth}). " +
                                     $"Current scope: '{scope}'. " +
                                     $"Upgrade to a higher plan for deeper permission scopes.";

                    _logger.LogWarning(
                        "Scope depth validation failed. Scope: {Scope}, Depth: {Depth}, Plan: {Plan}, Limit: {Limit}",
                        scope, scopeDepth, planKey, maxDepth);

                    return Task.FromResult(ServiceResult<bool>.Failure(
                        errorMessage,
                        PermissionConstants.ErrorCodes.InvalidScope));
                }

                return Task.FromResult(ServiceResult<bool>.Success(true));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating scope depth for scope: {Scope}", scope);
                return Task.FromResult(ServiceResult<bool>.Failure(
                    "An error occurred during scope depth validation",
                    PermissionConstants.ErrorCodes.SystemError));
            }
        }
        /// <summary>
        /// ✅ 감사 로그 기록 헬퍼 메서드
        /// </summary>
        // 최종 수정: 파라미터 타입을 'AuditAction'에서 올바른 'AuditActionType'으로 수정
        private async Task LogAuditAsync(
            Guid connectedId,
            AuditActionType actionType,
            string resourceType,
            Guid? resourceId,
            string description,
            Guid? organizationId)
        {
            try
            {
                var auditRequest = new CreateAuditLogRequest
                {
                    ActionType = actionType, // 수정된 타입으로 인해 이제 정상적으로 할당됩니다.
                    ResourceType = resourceType,
                    ResourceId = resourceId?.ToString(),
                    Action = description,
                    OrganizationId = organizationId,
                };

                await _auditService.CreateAuditLogAsync(auditRequest, connectedId);
            }
            catch (Exception ex)
            {
                // 중요: 감사 로그 실패는 메인 작업을 방해하지 않도록 경고만 기록합니다.
                _logger.LogWarning(ex,
                    "Failed to create audit log for {EntityType} {EntityId}. " +
                    "This is non-critical and business operation continued successfully.",
                    resourceType, resourceId);
            }
        }
        public async Task<ServiceResult<bool>> ExistsAsync(Guid id, CancellationToken cancellationToken = default)
        {
            if (id == Guid.Empty)
            {
                return ServiceResult<bool>.Failure("Permission ID cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 캐시 확인: ServiceResult 객체를 직접 받습니다.
                var cacheResult = await _cacheService.GetByIdAsync(id);

                // IsSuccess와 Data가 null이 아닌지로 캐시 존재 여부를 판단합니다.
                if (cacheResult.IsSuccess && cacheResult.Data != null)
                {
                    _logger.LogDebug("Existence check for permission ID '{Id}' resolved from cache.", id);
                    return ServiceResult<bool>.Success(true);
                }

                // 캐시에 없으면 데이터베이스에서 존재 여부 확인
                var exists = await _permissionRepository.AnyAsync(p => p.Id == id);
                return ServiceResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for permission existence by ID: {Id}", id);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking for permission existence.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> UpdateBulkAsync(
    IEnumerable<(Guid Id, UpdatePermissionRequest Request)> updates, CancellationToken cancellationToken = default)
        {
            // 인터페이스 멤버를 구현하는 기본 메서드입니다.
            // 내부적으로는 connectedId와 organizationId를 null로 하여 확장 메서드를 호출합니다.
            return await UpdateBulkAsync(updates, null, null);
        }

        /// <summary>
        /// 여러 권한을 한 번에 업데이트하는 핵심 로직입니다.
        /// </summary>
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> UpdateBulkAsync(
            IEnumerable<(Guid Id, UpdatePermissionRequest Request)> updates,
            Guid? connectedId = null,
            Guid? organizationId = null)
        {
            // 1. 입력 값 유효성 검사
            if (updates == null)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("Updates collection cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            var updateList = updates.ToList();
            if (!updateList.Any())
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Success(new List<PermissionDto>(), "No items to update.");
            }

            // 2. 한 번에 처리할 수 있는 최대 개수 제한 검사
            if (updateList.Count > PermissionConstants.Limits.MaxBulkOperationSize)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    $"Bulk operation size ({updateList.Count}) exceeds limit of {PermissionConstants.Limits.MaxBulkOperationSize}",
                    PermissionConstants.ErrorCodes.InvalidParameter);
            }

            try
            {
                // 3. 데이터 일관성을 위해 트랜잭션 시작
                await _unitOfWork.BeginTransactionAsync();
                var updatedPermissions = new List<PermissionEntity>();

                try
                {
                    foreach (var (id, request) in updateList)
                    {
                        var permission = await _permissionRepository.GetByIdAsync(id);
                        if (permission == null) continue; // 존재하지 않는 권한은 건너뜁니다.
                        if (permission.IsSystemPermission) continue; // 시스템 권한은 수정할 수 없으므로 건너뜁니다.

                        _mapper.Map(request, permission);
                        permission.UpdatedAt = _dateTimeProvider.UtcNow;

                        await _permissionRepository.UpdateAsync(permission);
                        updatedPermissions.Add(permission);
                    }

                    await _unitOfWork.SaveChangesAsync();

                    // 4. 각 수정 사항에 대해 도메인 이벤트 발행
                    foreach (var permission in updatedPermissions)
                    {
                        var domainEvent = new PermissionUpdatedEvent(
                            permission.Id,
                            permission.Scope,
                            connectedId,
                            organizationId);
                        await _eventBus.PublishAsync(domainEvent);
                    }

                    // 5. 감사 로그 기록
                    if (connectedId.HasValue && updatedPermissions.Any())
                    {
                        await LogAuditAsync(
                            connectedId.Value,
                            AuditActionType.BulkUpdate, // 이전에 수정한 Enum 사용
                            "Permission",
                            null,
                            $"Bulk updated {updatedPermissions.Count} permissions",
                            organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw; // 예외를 다시 던져 상위 catch 블록에서 처리
                }

                // 6. 캐시 무효화 (대량 작업이므로 전체 캐시를 비웁니다)
                if (updatedPermissions.Any())
                {
                    await _cacheService.RefreshAllAsync();
                }

                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(updatedPermissions);
                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk update permissions");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure(
                    "An error occurred while bulk updating permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult> DeleteBulkAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
        {
            // 인터페이스 멤버를 구현하는 기본 메서드입니다.
            return await DeleteBulkAsync(ids, null, null);
        }

        /// <summary>
        /// 여러 권한을 한 번에 삭제하는 핵심 로직입니다.
        /// </summary>
        public async Task<ServiceResult> DeleteBulkAsync(
            IEnumerable<Guid> ids,
            Guid? connectedId = null,
            Guid? organizationId = null)
        {
            // 1. 입력 값 유효성 검사
            if (ids == null)
            {
                return ServiceResult.Failure("IDs collection cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            var idList = ids.ToList();
            if (!idList.Any())
            {
                return ServiceResult.Success("No items to delete.");
            }

            // 2. 한 번에 처리할 수 있는 최대 개수 제한 검사
            if (idList.Count > PermissionConstants.Limits.MaxBulkOperationSize)
            {
                return ServiceResult.Failure(
                    $"Bulk operation size ({idList.Count}) exceeds limit of {PermissionConstants.Limits.MaxBulkOperationSize}",
                    PermissionConstants.ErrorCodes.InvalidParameter);
            }

            try
            {
                // 3. 데이터 일관성을 위해 트랜잭션 시작
                await _unitOfWork.BeginTransactionAsync();
                var deletedPermissions = new List<PermissionEntity>();

                try
                {
                    foreach (var id in idList)
                    {
                        var permission = await _permissionRepository.GetByIdAsync(id);
                        if (permission == null) continue; // 존재하지 않는 권한은 건너뜁니다.
                        if (permission.IsSystemPermission) continue; // 시스템 권한은 삭제할 수 없으므로 건너뜁니다.
                                                                     // TODO: 자식 권한이 있는지 등 의존성 체크 로직 추가 필요

                        await _permissionRepository.DeleteAsync(permission);
                        deletedPermissions.Add(permission);
                    }

                    await _unitOfWork.SaveChangesAsync();

                    // 4. 각 삭제된 항목에 대해 도메인 이벤트 발행
                    foreach (var permission in deletedPermissions)
                    {
                        // 최종 수정: 원본 코드의 버그 수정 (DelegatedEvent -> DeletedEvent)
                        var domainEvent = new PermissionDeletedEvent(
                            permission.Id,
                            permission.Scope,
                            permission.IsSystemPermission,
                            connectedId,
                            organizationId);
                        await _eventBus.PublishAsync(domainEvent);
                    }

                    // 5. 감사 로그 기록
                    if (connectedId.HasValue && deletedPermissions.Any())
                    {
                        await LogAuditAsync(
                            connectedId.Value,
                            AuditActionType.BulkDelete, // 수정한 Enum 사용
                            "Permission",
                            null,
                            $"Bulk deleted {deletedPermissions.Count} permissions",
                            organizationId);
                    }

                    await _unitOfWork.CommitTransactionAsync();
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw; // 예외를 다시 던져 상위 catch 블록에서 처리
                }

                // 6. 캐시 무효화 (대량 작업이므로 전체 캐시를 비웁니다)
                if (deletedPermissions.Any())
                {
                    await _cacheService.RefreshAllAsync();
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk delete permissions");
                return ServiceResult.Failure(
                    "An error occurred while bulk deleting permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<int>> CountAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 리포지토리를 통해 전체 항목의 개수를 조회합니다.
                var count = await _permissionRepository.CountAsync();
                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error counting permissions");
                return ServiceResult<int>.Failure(
                    "An error occurred while counting permissions.",
                    PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        public async Task<ServiceResult<bool>> ValidateUpdateAsync(Guid id, UpdatePermissionRequest request, CancellationToken cancellationToken =default)
        {
            // 인터페이스 멤버를 구현하는 기본 메서드입니다.
            return await ValidateUpdateAsync(id, request, null);
        }

        /// <summary>
        /// 권한 업데이트 요청 데이터의 유효성을 검사하는 핵심 로직입니다.
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateUpdateAsync(
            Guid id,
            UpdatePermissionRequest request,
            string? subscriptionPlanKey = null)
        {
            // 1. 입력 값 유효성 검사
            if (id == Guid.Empty)
            {
                return ServiceResult<bool>.Failure("Permission ID cannot be empty.", PermissionConstants.ErrorCodes.InvalidInput);
            }
            if (request == null)
            {
                return ServiceResult<bool>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 2. 수정할 권한이 DB에 존재하는지 확인
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<bool>.Failure(
                        "Permission not found",
                        PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                // 3. 시스템 권한은 수정할 수 없으므로 확인
                if (permission.IsSystemPermission)
                {
                    return ServiceResult<bool>.Failure(
                        "Cannot modify a system permission",
                        PermissionConstants.ErrorCodes.CannotModifySystemPermission);
                }

                // 모든 검증 통과
                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating permission update request for ID: {Id}", id);
                return ServiceResult<bool>.Failure(
                    "An error occurred during update validation.",
                    PermissionConstants.ErrorCodes.SystemError);
            }
        }
        /// <summary>
        /// 권한 생성 요청 데이터의 유효성을 검사하는 핵심 로직입니다.
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateCreateAsync(
            CreatePermissionRequest request,
            string? subscriptionPlanKey = null)
        {
            // 1. 입력 값 유효성 검사
            if (request == null)
            {
                return ServiceResult<bool>.Failure("Request cannot be null.", PermissionConstants.ErrorCodes.InvalidInput);
            }

            try
            {
                // 2. 스코프(Scope) 형식 검증 (정규식 사용)
                if (!System.Text.RegularExpressions.Regex.IsMatch(
                    request.Scope,
                    PermissionConstants.Limits.ScopePattern))
                {
                    return ServiceResult<bool>.Failure(
                        $"Invalid scope format. Expected pattern: {PermissionConstants.Limits.ScopePattern}",
                        PermissionConstants.ErrorCodes.InvalidScope);
                }

                // 3. 구독 플랜에 따른 스코프 깊이 제한 검증
                var depthResult = await ValidateScopeDepthByPlan(request.Scope, subscriptionPlanKey);
                if (!depthResult.IsSuccess)
                {
                    return depthResult; // 검증 실패 결과를 그대로 반환
                }

                // 4. 스코프 중복 검증 (DB 조회)
                var exists = await _permissionRepository.AnyAsync(p => p.Scope == request.Scope);
                if (exists)
                {
                    return ServiceResult<bool>.Failure(
                        $"Permission with scope '{request.Scope}' already exists",
                        PermissionConstants.ErrorCodes.DuplicateScope);
                }

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating permission create request");
                return ServiceResult<bool>.Failure(
                    "An error occurred during create validation.",
                    PermissionConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// 권한 트리 구성 헬퍼 메서드
        /// 재귀적으로 부모-자식 관계를 트리 구조로 변환합니다.
        /// </summary>
        /// <param name="permissions">모든 권한의 전체 목록</param>
        /// <param name="rootId">트리를 시작할 루트 노드의 ID (null이면 최상위 노드부터 시작)</param>
        /// <param name="maxDepth">탐색할 최대 깊이</param>
        /// <param name="currentDepth">현재 재귀 호출의 깊이</param>
        /// <returns>트리 구조로 구성된 PermissionNode 목록</returns>
        private List<PermissionNode> BuildPermissionTree(
            IEnumerable<PermissionEntity> permissions,
            Guid? rootId,
            int? maxDepth,
            int currentDepth = 0)
        {
            var nodes = new List<PermissionNode>();

            // 현재 깊이의 자식 노드들만 필터링
            // rootId가 null이면 ParentPermissionId가 null인 최상위 노드들을 찾습니다.
            var filteredPermissions = rootId.HasValue
                ? permissions.Where(p => p.ParentPermissionId == rootId)
                : permissions.Where(p => p.ParentPermissionId == null);

            foreach (var permission in filteredPermissions)
            {
                // 최대 깊이 제한을 초과하면 더 이상 자식 노드를 탐색하지 않습니다.
                if (maxDepth.HasValue && currentDepth >= maxDepth.Value)
                    break;

                // AutoMapper를 사용해 PermissionEntity를 PermissionNode DTO로 변환합니다.
                var node = _mapper.Map<PermissionNode>(permission);

                // 재귀 호출: 현재 노드를 부모로 삼아 자식 노드들을 구성합니다.
                node.Children = BuildPermissionTree(
                    permissions,
                    permission.Id, // 현재 노드의 ID가 다음 재귀 호출의 rootId가 됩니다.
                    maxDepth,
                    currentDepth + 1); // 깊이를 1 증가시킵니다.

                nodes.Add(node);
            }

            return nodes;
        }

        #endregion
    }
}