using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Core;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Auth.Role.Events;
using AuthHive.Core.Models.Auth.ConnectedId.Common;
using AuthHive.Core.Models.Audit.Common;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Common;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Models.External;

namespace AuthHive.Auth.Validator
{
    /// <summary>
    /// Role Validator Implementation - AuthHive v15
    /// Implements all role-related business rules and validation logic
    /// Following event usage guidelines:
    /// - Events needed: Security violations, plan limits, business thresholds, async processing
    /// - Events not needed: Simple validation, normal CRUD, internal checks
    /// </summary>
    public class RoleValidator : IRoleValidator
    {
        #region Dependencies

        private readonly IRoleRepository _roleRepository;
        private readonly IRolePermissionRepository _permissionRepository;
        private readonly IConnectedIdRoleRepository _connectedIdRoleRepository;
        private readonly IRoleMaintenanceRepository _maintenanceRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly IPlanSubscriptionRepository _planSubscriptionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEmailService _emailService;
        private readonly ILogger<RoleValidator> _logger;

        // Cache configuration
        private const string CACHE_KEY_PREFIX = "role:validator:";
        private const int CACHE_DURATION_MINUTES = 15;

        // System reserved role keys
        private readonly HashSet<string> _systemReservedRoleKeys = new()
        {
            "SYSTEM", "SUPER_ADMIN", "ADMIN", "OWNER", "GUEST", "DEFAULT",
            "ROOT", "GOD", "MASTER", "SERVICE", "API", "INTERNAL"
        };

        // Dangerous permission combinations
        private readonly List<(string Perm1, string Perm2, string Risk)> _dangerousPermissionCombos = new()
        {
            ("DELETE_ALL", "BYPASS_AUDIT", "Can delete without audit trail"),
            ("GRANT_PERMISSION", "REVOKE_PERMISSION", "Full permission control"),
            ("CREATE_USER", "DELETE_USER", "Complete user lifecycle control"),
            ("MANAGE_BILLING", "MANAGE_SUBSCRIPTION", "Full financial control"),
            ("EXPORT_DATA", "DELETE_DATA", "Data exfiltration risk")
        };

        #endregion

        #region Constructor

        public RoleValidator(
            IRoleRepository roleRepository,
            IRolePermissionRepository permissionRepository,
            IConnectedIdRoleRepository connectedIdRoleRepository,
            IRoleMaintenanceRepository maintenanceRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationMembershipRepository membershipRepository,
            IPlanSubscriptionRepository planSubscriptionRepository,
            IConnectedIdRepository connectedIdRepository,
            IAuditService auditService,
            IEventBus eventBus,
            IUnitOfWork unitOfWork,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IEmailService emailService,
            ILogger<RoleValidator> logger)
        {
            _roleRepository = roleRepository ?? throw new ArgumentNullException(nameof(roleRepository));
            _permissionRepository = permissionRepository ?? throw new ArgumentNullException(nameof(permissionRepository));
            _connectedIdRoleRepository = connectedIdRoleRepository ?? throw new ArgumentNullException(nameof(connectedIdRoleRepository));
            _maintenanceRepository = maintenanceRepository ?? throw new ArgumentNullException(nameof(maintenanceRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _membershipRepository = membershipRepository ?? throw new ArgumentNullException(nameof(membershipRepository));
            _planSubscriptionRepository = planSubscriptionRepository ?? throw new ArgumentNullException(nameof(planSubscriptionRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #endregion

        #region IValidator<Role> Implementation

        public Task<ServiceResult> ValidateAsync(Role entity)
        {
            if (entity == null)
                return Task.FromResult(ServiceResult.Failure("Role cannot be null", RoleConstants.ErrorCodes.InvalidRole));

            var errors = new List<string>();

            // Basic validation
            if (string.IsNullOrWhiteSpace(entity.Name))
                errors.Add("Role name is required");

            if (entity.Name?.Length > RoleConstants.Limits.MaxRoleNameLength)
                errors.Add($"Role name cannot exceed {RoleConstants.Limits.MaxRoleNameLength} characters");

            if (string.IsNullOrWhiteSpace(entity.RoleKey))
                errors.Add("Role key is required");

            if (entity.RoleKey?.Length > RoleConstants.Limits.MaxRoleKeyLength)
                errors.Add($"Role key cannot exceed {RoleConstants.Limits.MaxRoleKeyLength} characters");

            if (entity.OrganizationId == Guid.Empty)
                errors.Add("Organization ID is required");

            if (entity.Priority < 0 || entity.Priority > 1000)
                errors.Add("Role priority must be between 0 and 1000");

            if (errors.Any())
                return Task.FromResult(ServiceResult.Failure(string.Join("; ", errors), RoleConstants.ErrorCodes.ValidationFailed));

            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<bool> IsValidAsync(Role entity)
        {
            var result = await ValidateAsync(entity);
            return result.IsSuccess;
        }

        #endregion

        #region Role CRUD Validation

        public async Task<ServiceResult> ValidateCreateAsync(
            CreateRoleRequest request,
            Guid createdByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating role creation for {RoleName} by {CreatedBy}",
                    request.Name, createdByConnectedId);

                // 1. Validate basic request
                if (request == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Create role request cannot be null", RoleConstants.ErrorCodes.InvalidRequest);
                }

                var errors = new List<string>();

                // 2. Validate role name
                if (string.IsNullOrWhiteSpace(request.Name))
                    errors.Add("Role name is required");
                else if (request.Name.Length > RoleConstants.Limits.MaxRoleNameLength)
                    errors.Add($"Role name cannot exceed {RoleConstants.Limits.MaxRoleNameLength} characters");

                // 3. Validate role key
                if (string.IsNullOrWhiteSpace(request.RoleKey))
                    errors.Add("Role key is required");
                else if (request.RoleKey.Length > RoleConstants.Limits.MaxRoleKeyLength)
                    errors.Add($"Role key cannot exceed {RoleConstants.Limits.MaxRoleKeyLength} characters");
                else if (_systemReservedRoleKeys.Contains(request.RoleKey.ToUpper()))
                    errors.Add($"Role key '{request.RoleKey}' is reserved by the system");

                if (errors.Any())
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(string.Join("; ", errors), RoleConstants.ErrorCodes.ValidationFailed);
                }

                // 4. Check for duplicate role name in organization
                // IRoleRepository에 GetByNameAsync가 없으므로 GetByOrganizationAsync를 사용하여 필터링
                var existingRoles = await _roleRepository.GetByOrganizationAsync(request.OrganizationId, includeInactive: true);
                var existingRole = existingRoles.FirstOrDefault(r => r.Name.Equals(request.Name, StringComparison.OrdinalIgnoreCase));
                if (existingRole != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role with name '{request.Name}' already exists in this organization",
                        RoleConstants.ErrorCodes.DuplicateRole);
                }

                // 5. Check for duplicate role key - GetByRoleKeyAsync 사용
                var existingRoleByKey = await _roleRepository.GetByRoleKeyAsync(request.OrganizationId, request.RoleKey);
                if (existingRoleByKey != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role with key '{request.RoleKey}' already exists",
                        RoleConstants.ErrorCodes.DuplicateKey);
                }

                // 6. Get organization's plan and check role limit from PricingConstants
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(request.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                if (roleLimit > 0) // -1 means unlimited
                {
                    var currentRoleCount = await _roleRepository.CountByOrganizationAsync(request.OrganizationId);

                    if (currentRoleCount >= roleLimit)
                    {
                        // Fire plan limit reached event - this is a business opportunity
                        await _eventBus.PublishAsync(new RoleLimitReachedEvent
                        {
                            OrganizationId = request.OrganizationId,
                            PlanKey = planKey,
                            CurrentRoleCount = currentRoleCount,
                            MaxRoleLimit = roleLimit,
                            AttemptedBy = createdByConnectedId,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        _logger.LogWarning(
                            "Role limit reached for organization {OrgId}: {Current}/{Max} on {Plan} plan",
                            request.OrganizationId, currentRoleCount, roleLimit, planKey);

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Organization has reached the role limit ({roleLimit}) for {planKey} plan",
                            RoleConstants.ErrorCodes.RoleLimitExceeded);
                    }
                }

                // 7. Validate parent role if specified (check hierarchy depth against plan)
                if (request.ParentRoleId.HasValue)
                {
                    var parentRole = await _roleRepository.GetByIdAsync(request.ParentRoleId.Value);
                    if (parentRole == null)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure("Parent role not found", RoleConstants.ErrorCodes.ParentNotFound);
                    }

                    if (parentRole.OrganizationId != request.OrganizationId)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Parent role must belong to the same organization",
                            RoleConstants.ErrorCodes.InvalidParent);
                    }

                    // Check hierarchy depth against plan limits
                    var depth = await GetRoleHierarchyDepthAsync(request.ParentRoleId.Value);
                    var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                    if (maxDepth > 0 && depth >= maxDepth)
                    {
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent
                        {
                            OrganizationId = request.OrganizationId,
                            PlanKey = planKey,
                            LimitType = "RoleHierarchyDepth",
                            CurrentValue = depth + 1,
                            MaxValue = maxDepth,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Role hierarchy depth would exceed {planKey} plan limit ({maxDepth})",
                            RoleConstants.ErrorCodes.HierarchyDepthExceeded);
                    }
                }

                // 8. Validate initial permissions if provided
                if (request.InitialPermissionIds?.Any() == true)
                {
                    var permissionValidation = await ValidatePermissionsExistAsync(request.InitialPermissionIds);
                    if (!permissionValidation.IsSuccess)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return permissionValidation;
                    }

                    // Check for dangerous combinations
                    var riskAssessment = await AssessPermissionRiskAsync(request.InitialPermissionIds);
                    if (riskAssessment.IsSuccess && riskAssessment.Data?.Level == RiskLevel.Critical)
                    {
                        _logger.LogWarning(
                            "Critical risk permissions detected in new role: {Risks}",
                            string.Join(", ", riskAssessment.Data.Risks));

                        // Fire dangerous permission event - security issue
                        await _eventBus.PublishAsync(new DangerousPermissionCombinationEvent
                        {
                            OrganizationId = request.OrganizationId,
                            RoleId = Guid.Empty, // Will be assigned after creation
                            PermissionIds = request.InitialPermissionIds,
                            RiskLevel = RiskLevel.Critical,
                            RiskDetails = riskAssessment.Data.Risks,
                            AssignedBy = createdByConnectedId,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        // For critical risks, still allow but notify
                        if (request.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                        {
                            await SendCriticalSecurityAlertAsync(
                                request.OrganizationId,
                                createdByConnectedId,
                                "Critical permission combination in new role",
                                riskAssessment.Data.Risks);
                        }
                    }
                }

                // 9. Check creator permissions
                var hasCreatePermission = await CheckUserPermissionAsync(
                    createdByConnectedId,
                    "ROLE_CREATE",
                    request.OrganizationId);

                if (!hasCreatePermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to create roles",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // Audit log - success
                await _auditService.LogActionAsync(
                    createdByConnectedId,
                    "ValidateRoleCreate",
                    AuditActionType.Validation,
                    "Role",
                    request.Name,
                    true,
                    JsonSerializer.Serialize(new
                    {
                        RoleName = request.Name,
                        RoleKey = request.RoleKey,
                        OrganizationId = request.OrganizationId,
                        ParentRoleId = request.ParentRoleId,
                        PermissionCount = request.InitialPermissionIds?.Count ?? 0
                    }));

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Role creation validation successful for {RoleName}", request.Name);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex, "Error validating role creation");

                // Send alert for critical errors in system organization
                if (request.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                {
                    await SendCriticalErrorAlertAsync(ex, "RoleCreateValidation", createdByConnectedId);
                }

                return ServiceResult.Failure(
                    "An error occurred during role validation",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> ValidateUpdateAsync(
            Guid roleId,
            UpdateRoleRequest request,
            Guid updatedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating role update for {RoleId} by {UpdatedBy}",
                    roleId, updatedByConnectedId);

                // 1. Check if role exists
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 2. Prevent system role modification
                if (role.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                {
                    _logger.LogWarning(
                        "Attempt to modify system role {RoleId} by {UpdatedBy}",
                        roleId, updatedByConnectedId);

                    // Fire system role modification attempt event - security issue
                    await _eventBus.PublishAsync(new SystemRoleModificationAttemptedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        AttemptedBy = updatedByConnectedId,
                        RoleId = roleId,
                        RoleName = role.Name,
                        Action = "Update",
                        IsAuthorized = false,
                        IpAddress = string.Empty, // Would come from context
                        UserAgent = string.Empty, // Would come from context
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _auditService.LogActionAsync(
                        updatedByConnectedId,
                        "SystemRoleUpdateAttempt",
                        AuditActionType.Others,
                        "Role",
                        roleId.ToString(),
                        false,
                        JsonSerializer.Serialize(new { RoleId = roleId, RoleName = role.Name }));

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "System roles cannot be modified",
                        RoleConstants.ErrorCodes.SystemRoleProtected);
                }

                // 3. Check update permissions
                var hasUpdatePermission = await CheckUserPermissionAsync(
                    updatedByConnectedId,
                    "ROLE_UPDATE",
                    role.OrganizationId);

                if (!hasUpdatePermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to update roles",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // 4. Validate name change if provided
                if (!string.IsNullOrWhiteSpace(request.Name) && request.Name != role.Name)
                {
                    // GetByOrganizationAsync를 사용하여 이름 중복 검사
                    var allRoles = await _roleRepository.GetByOrganizationAsync(role.OrganizationId, includeInactive: true);
                    var duplicateRole = allRoles.FirstOrDefault(r =>
                        r.Name.Equals(request.Name, StringComparison.OrdinalIgnoreCase) &&
                        r.Id != roleId);

                    if (duplicateRole != null)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Role with name '{request.Name}' already exists",
                            RoleConstants.ErrorCodes.DuplicateRole);
                    }
                }

                // 5. Validate key change if provided - GetByRoleKeyAsync 사용
                if (!string.IsNullOrWhiteSpace(request.RoleKey) && request.RoleKey != role.RoleKey)
                {
                    if (_systemReservedRoleKeys.Contains(request.RoleKey.ToUpper()))
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Role key '{request.RoleKey}' is reserved",
                            RoleConstants.ErrorCodes.ReservedKey);
                    }

                    var duplicateRoleKey = await _roleRepository.GetByRoleKeyAsync(role.OrganizationId, request.RoleKey);
                    if (duplicateRoleKey != null && duplicateRoleKey.Id != roleId)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Role with key '{request.RoleKey}' already exists",
                            RoleConstants.ErrorCodes.DuplicateKey);
                    }
                }

                // 6. Validate hierarchy change if parent role is being changed
                if (request.ParentRoleId.HasValue && request.ParentRoleId != role.ParentRoleId)
                {
                    // Prevent circular reference
                    if (await IsCircularReferenceAsync(roleId, request.ParentRoleId.Value))
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "This change would create a circular reference in the role hierarchy",
                            RoleConstants.ErrorCodes.CircularReference);
                    }

                    // Check depth against plan limits
                    var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                    var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                    var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                    if (maxDepth > 0)
                    {
                        var newDepth = await GetRoleHierarchyDepthAsync(request.ParentRoleId.Value);
                        if (newDepth >= maxDepth)
                        {
                            await _eventBus.PublishAsync(new PlanLimitReachedEvent
                            {
                                OrganizationId = role.OrganizationId,
                                PlanKey = planKey,
                                LimitType = "RoleHierarchyDepth",
                                CurrentValue = newDepth + 1,
                                MaxValue = maxDepth,
                                Timestamp = _dateTimeProvider.UtcNow
                            });

                            await _unitOfWork.RollbackTransactionAsync();
                            return ServiceResult.Failure(
                                $"Role hierarchy depth would exceed {planKey} plan limit ({maxDepth})",
                                RoleConstants.ErrorCodes.HierarchyDepthExceeded);
                        }
                    }
                }

                // 7. Check impact of permission changes
                if (request.PermissionIds != null)
                {
                    // [수정 1] GetByRoleAsync와 Select를 사용해 현재 권한 ID 목록을 가져옵니다.
                    var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                    var currentPermissionIds = rolePermissions.Select(rp => rp.PermissionId).ToHashSet(); // HashSet으로 변경하여 성능 향상

                    // Set으로 변경하여 Except 성능을 최적화 할 수 있습니다.
                    //"Set으로 변경한다"는 것은, C#의 데이터 종류 중 하나인 'List' 대신 'HashSet'을 사용한다는 의미입니다.
                    var removedPermissions = currentPermissionIds.Except(request.PermissionIds).ToList();

                    if (removedPermissions.Any())
                    {

                        // [수정 2] 역할이 할당된 사용자-역할 '목록'을 가져옵니다.
                        var assignments = await _connectedIdRoleRepository.GetByRoleAsync(roleId);

                        // [수정 3] 목록의 '개수(숫자)'를 세어 변수에 저장합니다.
                        var affectedUserCount = assignments.Count();

                        // [수정 4] '개수'를 사용하여 비교하고, 로깅하고, 이벤트에 전달합니다.
                        if (affectedUserCount > 100) // Threshold for mass impact
                        {
                            _logger.LogWarning(
                                "Role update will remove permissions from {Count} users",
                                affectedUserCount);

                            // Fire mass cache invalidation event - performance impact
                            await _eventBus.PublishAsync(new MassRoleCacheInvalidationEvent
                            {
                                OrganizationId = role.OrganizationId,
                                TriggeringRoleId = roleId,
                                AffectedConnectedIds = affectedUserCount,
                                AffectedSessions = affectedUserCount, // Estimate
                                InvalidationReason = "Permission removal from role",
                                Timestamp = _dateTimeProvider.UtcNow
                            });
                        }
                    }
                }
                // Audit log - success
                await _auditService.LogActionAsync(
                    updatedByConnectedId,
                    "ValidateRoleUpdate",
                    AuditActionType.Validation,
                    "Role",
                    roleId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        RoleId = roleId,
                        Changes = new
                        {
                            Name = request.Name != role.Name ? $"{role.Name} -> {request.Name}" : null,
                            Key = request.RoleKey != role.RoleKey ? $"{role.RoleKey} -> {request.RoleKey}" : null,
                            ParentId = request.ParentRoleId != role.ParentRoleId
                        }
                    }));

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Role update validation successful for {RoleId}", roleId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex, "Error validating role update for {RoleId}", roleId);
                return ServiceResult.Failure(
                    "An error occurred during role update validation",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        public async Task<ServiceResult> ValidateDeleteAsync(
            Guid roleId,
            Guid? replacementRoleId,
            Guid deletedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating role deletion for {RoleId} by {DeletedBy}",
                    roleId, deletedByConnectedId);

                // 1. Check if role exists
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 2. Prevent system role deletion
                if (role.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                {
                    _logger.LogWarning(
                        "Attempt to delete system role {RoleId} by {DeletedBy}",
                        roleId, deletedByConnectedId);

                    await _eventBus.PublishAsync(new SystemRoleModificationAttemptedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        AttemptedBy = deletedByConnectedId,
                        RoleId = roleId,
                        RoleName = role.Name,
                        Action = "Delete",
                        IsAuthorized = false,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _auditService.LogActionAsync(
                        deletedByConnectedId,
                        "SystemRoleDeleteAttempt",
                        AuditActionType.Others,
                        "Role",
                        roleId.ToString(),
                        false,
                        null);

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "System roles cannot be deleted",
                        RoleConstants.ErrorCodes.SystemRoleProtected);
                }

                // 3. Check delete permissions
                var hasDeletePermission = await CheckUserPermissionAsync(
                    deletedByConnectedId,
                    "ROLE_DELETE",
                    role.OrganizationId);

                if (!hasDeletePermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to delete roles",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // 4. Check if role is in use
                // [수정] GetByRoleAsync를 호출하고 .Count()로 사용자 수를 계산합니다.
                var assignments = await _connectedIdRoleRepository.GetByRoleAsync(roleId);
                var usersWithRole = assignments.Count();
                if (usersWithRole > 0)
                {
                    if (!replacementRoleId.HasValue)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"Cannot delete role assigned to {usersWithRole} users without replacement",
                            RoleConstants.ErrorCodes.RoleInUse);
                    }

                    // Validate replacement role
                    var replacementRole = await _roleRepository.GetByIdAsync(replacementRoleId.Value);
                    if (replacementRole == null)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Replacement role not found",
                            RoleConstants.ErrorCodes.ReplacementNotFound);
                    }

                    if (replacementRole.OrganizationId != role.OrganizationId)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Replacement role must belong to the same organization",
                            RoleConstants.ErrorCodes.InvalidReplacement);
                    }
                }

                // 5. Check for child roles
                var childRoles = await _roleRepository.GetChildRolesAsync(roleId);
                if (childRoles.Any())
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Cannot delete role with {childRoles.Count()} child roles",
                        RoleConstants.ErrorCodes.HasChildRoles);
                }

                // 6. Check if this is the last admin role
                // [수정] _rolePermissionRepository를 사용하고 Permission.Scope 속성을 올바르게 참조합니다.
                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionScopes = rolePermissions.Select(rp => rp.Permission?.Scope ?? string.Empty).ToHashSet();

                if (permissionScopes.Contains("ADMIN") || permissionScopes.Contains("SUPER_ADMIN"))
                {
                    // [수정] GetByMinimumLevelAsync를 사용해 관리자 역할 수를 계산합니다.
                    const int AdminLevel = 3; // 관리자 최소 레벨을 3으로 가정
                    var adminRoles = await _roleRepository.GetByMinimumLevelAsync(role.OrganizationId, AdminLevel);
                    var adminRolesCount = adminRoles.Count();

                    if (adminRolesCount <= 1)
                    {
                        _logger.LogWarning(
                            "Attempt to delete last admin role for organization {OrgId}",
                            role.OrganizationId);

                        await _eventBus.PublishAsync(new LastAdminRoleWarningEvent
                        {
                            OrganizationId = role.OrganizationId,
                            RoleId = roleId,
                            ConnectedId = deletedByConnectedId,
                            Action = "Delete",
                            RemainingAdmins = 0,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Cannot delete the last administrative role",
                            RoleConstants.ErrorCodes.LastAdminRole);
                    }
                }

                // 7. Fire critical role deleted event if applicable
                // [수정] Role 엔티티에 IsCritical 속성이 추가되었다고 가정합니다.
                if (role.IsCritical || usersWithRole > 50)
                {
                    await _eventBus.PublishAsync(new CriticalRoleDeletedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        RoleId = roleId,
                        RoleName = role.Name,
                        AffectedUsers = usersWithRole,
                        DeletedBy = deletedByConnectedId,
                        ReplacementRoleId = replacementRoleId,
                        Timestamp = _dateTimeProvider.UtcNow
                    });
                }

                // Audit log - success
                await _auditService.LogActionAsync(
                    deletedByConnectedId,
                    "ValidateRoleDelete",
                    AuditActionType.Validation,
                    "Role",
                    roleId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        RoleId = roleId,
                        RoleName = role.Name,
                        AffectedUsers = usersWithRole,
                        ReplacementRoleId = replacementRoleId
                    }));

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Role deletion validation successful for {RoleId}", roleId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error validating role deletion for {RoleId}", roleId);
                return ServiceResult.Failure(
                    "An error occurred during role deletion validation",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        #endregion

        #region Role-Permission Validation

        public async Task<ServiceResult> ValidatePermissionAssignmentAsync(
            Guid roleId,
            List<Guid> permissionIds,
            Guid assignedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating permission assignment for role {RoleId}", roleId);

                // 1. Check if role exists
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 2. Check permission to modify role
                var hasPermission = await CheckUserPermissionAsync(
                    assignedByConnectedId,
                    "PERMISSION_ASSIGN",
                    role.OrganizationId);

                if (!hasPermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to assign permissions",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // 3. Validate all permissions exist
                var validationResult = await ValidatePermissionsExistAsync(permissionIds);
                if (!validationResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return validationResult;
                }

                // 4. Check permission count against plan limits
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                // Using scope depth as proxy for permission complexity
                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];
                if (maxComplexity > 0 && permissionIds.Count > maxComplexity * 10) // Arbitrary multiplier
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "PermissionComplexity",
                        CurrentValue = permissionIds.Count,
                        MaxValue = maxComplexity * 10,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Permission count exceeds {planKey} plan complexity limit",
                        RoleConstants.ErrorCodes.ComplexityExceeded);
                }

                // 5. Check for permission conflicts
                var conflicts = await CheckPermissionConflictsAsync(permissionIds);
                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RolePermissionConflictEvent
                    {
                        OrganizationId = role.OrganizationId,
                        ChildRoleId = roleId,
                        ParentRoleId = role.ParentRoleId ?? Guid.Empty,
                        ConflictingPermissions = conflicts,
                        Resolution = "Assignment blocked",
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Permission conflicts detected: {string.Join(", ", conflicts)}",
                        RoleConstants.ErrorCodes.PermissionConflict);
                }

                // 6. Assess risk level
                var riskAssessment = await AssessPermissionRiskAsync(permissionIds);
                if (riskAssessment.IsSuccess && riskAssessment.Data?.Level >= RiskLevel.High)
                {
                    _logger.LogWarning(
                        "High risk permission combination for role {RoleId}: {Risks}",
                        roleId, string.Join(", ", riskAssessment.Data.Risks));

                    if (riskAssessment.Data.Level == RiskLevel.Critical)
                    {
                        await _eventBus.PublishAsync(new DangerousPermissionCombinationEvent
                        {
                            OrganizationId = role.OrganizationId,
                            RoleId = roleId,
                            PermissionIds = permissionIds,
                            RiskLevel = RiskLevel.Critical,
                            RiskDetails = riskAssessment.Data.Risks,
                            AssignedBy = assignedByConnectedId,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        // Don't block, but notify
                        if (role.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                        {
                            await SendCriticalSecurityAlertAsync(
                                role.OrganizationId,
                                assignedByConnectedId,
                                "Critical permission combination detected",
                                riskAssessment.Data.Risks);
                        }
                    }
                }

                await _auditService.LogActionAsync(
                    assignedByConnectedId,
                    "ValidatePermissionAssignment",
                    AuditActionType.PermissionValidated,
                    "Role",
                    roleId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        RoleId = roleId,
                        PermissionCount = permissionIds.Count,
                        RiskLevel = riskAssessment.Data?.Level.ToString()
                    }));

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation(
                    "Permission assignment validation successful for role {RoleId}", roleId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex,
                    "Error validating permission assignment for role {RoleId}", roleId);
                return ServiceResult.Failure(
                    "An error occurred during permission validation",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult<RiskAssessment>> AssessPermissionRiskAsync(List<Guid> permissionIds)
        {
            try
            {
                var assessment = new RiskAssessment
                {
                    Level = RiskLevel.Low,
                    Risks = new List<string>(),
                    Recommendations = new List<string>(),
                    RiskScores = new Dictionary<string, int>()
                };

                // [수정 1] _permissionRepository를 사용하고, FindAsync로 여러 권한을 한 번에 조회합니다.
                var permissions = await _permissionRepository.FindAsync(p => permissionIds.Contains(p.Id));

                // [수정 2] Permission 엔티티의 'Scope' 속성을 사용합니다.
                var permissionScopes = permissions.Select(p => p.PermissionScope).ToHashSet();


                // Check for dangerous combinations
                foreach (var combo in _dangerousPermissionCombos)
                {
                    if (permissionScopes.Contains(combo.Perm1) && permissionScopes.Contains(combo.Perm2))
                    {
                        assessment.Risks.Add(combo.Risk);
                        assessment.RiskScores[$"{combo.Perm1}+{combo.Perm2}"] = 10; // High score
                        assessment.Level = RiskLevel.High;
                    }
                }

                // Check for broad access patterns
                if (permissionScopes.Any(p => p.EndsWith("_ALL")))
                {
                    assessment.Risks.Add("Broad access permissions detected");
                    assessment.RiskScores["BROAD_ACCESS"] = 7;
                    if (assessment.Level < RiskLevel.Medium)
                        assessment.Level = RiskLevel.Medium;
                }

                // Check for system-level permissions
                if (permissionScopes.Any(p => p.StartsWith("SYSTEM_")))
                {
                    assessment.Risks.Add("System-level permissions detected");
                    assessment.RiskScores["SYSTEM_ACCESS"] = 9;
                    assessment.Level = RiskLevel.Critical;
                }

                // Add recommendations based on risk level
                switch (assessment.Level)
                {
                    case RiskLevel.Critical:
                        assessment.Recommendations.Add("Requires approval from organization owner");
                        assessment.Recommendations.Add("Enable audit logging for all actions");
                        assessment.Recommendations.Add("Consider time-based access restrictions");
                        break;
                    case RiskLevel.High:
                        assessment.Recommendations.Add("Review permission necessity");
                        assessment.Recommendations.Add("Enable activity monitoring");
                        break;
                    case RiskLevel.Medium:
                        assessment.Recommendations.Add("Document permission usage");
                        assessment.Recommendations.Add("Regular permission audits recommended");
                        break;
                    default:
                        assessment.Recommendations.Add("Standard monitoring sufficient");
                        break;
                }

                return ServiceResult<RiskAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assessing permission risk");
                return ServiceResult<RiskAssessment>.Failure(
                    "Failed to assess permission risk",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region Role Hierarchy Validation
        public async Task<ServiceResult> ValidateHierarchyAsync(Guid roleId, Guid? parentRoleId)
        {
            try
            {
                if (!parentRoleId.HasValue)
                    return ServiceResult.Success();

                // Check if parent exists
                var parentRole = await _roleRepository.GetByIdAsync(parentRoleId.Value);
                if (parentRole == null)
                    return ServiceResult.Failure("Parent role not found", RoleConstants.ErrorCodes.ParentNotFound);

                // Check for circular reference
                if (await IsCircularReferenceAsync(roleId, parentRoleId.Value))
                    return ServiceResult.Failure(
                        "This would create a circular reference in the hierarchy",
                        RoleConstants.ErrorCodes.CircularReference);

                // Check hierarchy depth against plan limits
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(parentRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                if (maxDepth > 0)
                {
                    var depth = await GetRoleHierarchyDepthAsync(parentRoleId.Value);
                    if (depth >= maxDepth)
                    {
                        // ... (이하 로직은 ValidateCreateAsync의 계층 검증 부분과 유사)
                        return ServiceResult.Failure(
                            $"Role hierarchy cannot exceed {maxDepth} levels for {planKey} plan",
                            RoleConstants.ErrorCodes.HierarchyDepthExceeded);
                    }
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating role hierarchy");
                return ServiceResult.Failure(
                    "Failed to validate role hierarchy",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        public async Task<ServiceResult> ValidateInheritanceAsync(Guid childRoleId, Guid parentRoleId)
        {
            try
            {
                // Get both roles
                var childRole = await _roleRepository.GetByIdAsync(childRoleId);
                var parentRole = await _roleRepository.GetByIdAsync(parentRoleId);

                if (childRole == null)
                    return ServiceResult.Failure("Child role not found", RoleConstants.ErrorCodes.RoleNotFound);
                if (parentRole == null)
                    return ServiceResult.Failure("Parent role not found", RoleConstants.ErrorCodes.ParentNotFound);

                // Ensure same organization
                if (childRole.OrganizationId != parentRole.OrganizationId)
                    return ServiceResult.Failure(
                        "Roles must belong to the same organization",
                        RoleConstants.ErrorCodes.DifferentOrganization);

                // Check if parent is inheritable
                if (!parentRole.IsInheritable)
                    return ServiceResult.Failure(
                        "Parent role is not inheritable",
                        RoleConstants.ErrorCodes.NotInheritable);

                // Check for conflicts
                var childRolePermissions = await _permissionRepository.GetByRoleAsync(childRoleId);
                var parentRolePermissions = await _permissionRepository.GetByRoleAsync(parentRoleId);

                // [수정] 부모 권한을 Dictionary로 만들어 조회를 빠르게 합니다.
                var parentPermissionsMap = parentRolePermissions
                    .Where(prp => prp.Permission != null)
                    // '!' (null forgiving operator)를 사용해 컴파일러에게 Permission이 null이 아님을 명확히 알려줍니다.
                    // 이렇게 하면 CS8621 경고가 해결됩니다.
                    .ToDictionary(prp => prp.Permission!.ScopeResource, prp => prp.Permission);

                var conflicts = new List<string>();
                foreach (var childRolePerm in childRolePermissions)
                {
                    var childPerm = childRolePerm.Permission;
                    if (childPerm == null) continue;

                    // Dictionary를 사용해 부모에게 같은 리소스에 대한 권한이 있는지 빠르게 찾습니다.
                    if (parentPermissionsMap.TryGetValue(childPerm.ScopeResource, out var conflictingParentPerm))
                    {
                        // 리소스는 같지만, 액션이 다르고 부모 권한이 배타적일 경우 충돌로 간주합니다.
                        if (conflictingParentPerm.ScopeAction != childPerm.ScopeAction && conflictingParentPerm.IsExclusive)
                        {
                            conflicts.Add($"'{childPerm.Scope}' conflicts with exclusive parent permission '{conflictingParentPerm.Scope}'");
                        }
                    }
                }

                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RolePermissionConflictEvent
                    {
                        OrganizationId = childRole.OrganizationId,
                        ChildRoleId = childRoleId,
                        ParentRoleId = parentRoleId,
                        ConflictingPermissions = conflicts,
                        Resolution = "Inheritance blocked",
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    return ServiceResult.Failure(
                        $"Permission conflicts detected: {string.Join(", ", conflicts)}",
                        RoleConstants.ErrorCodes.PermissionConflict);
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating role inheritance");
                return ServiceResult.Failure(
                    "Failed to validate role inheritance",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        #endregion

        #region ConnectedId-Role Assignment Validation

        public async Task<ServiceResult> ValidateRoleAssignmentAsync(
            Guid connectedId,
            Guid roleId,
            Guid assignedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating role assignment: ConnectedId={ConnectedId}, Role={RoleId}",
                    connectedId, roleId);

                // 1. Check if role exists
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                // 2. Check if user has permission to assign this role
                var hasAssignPermission = await CheckUserPermissionAsync(
                    assignedByConnectedId,
                    "ROLE_ASSIGN",
                    role.OrganizationId);

                if (!hasAssignPermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to assign roles",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // 3. Check if target ConnectedId is active
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || !connectedIdEntity.IsActive)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "Cannot assign role to inactive user",
                        RoleConstants.ErrorCodes.InactiveUser);
                }

                // 4. Check concurrent role limit based on plan
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                // Use member limits as proxy for concurrent role limits
                var memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[planKey];
                var currentRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);

                // Allow multiple roles but with reasonable limit based on plan
                var maxConcurrentRoles = memberLimit > 0 ? Math.Min(memberLimit / 5, 10) : 10;

                if (currentRoles.Count() >= maxConcurrentRoles)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "ConcurrentRoles",
                        CurrentValue = currentRoles.Count(),
                        MaxValue = maxConcurrentRoles,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"User cannot have more than {maxConcurrentRoles} concurrent roles on {planKey} plan",
                        RoleConstants.ErrorCodes.RoleLimitExceeded);
                }

                // 5. Check for conflicting roles
                var conflicts = await CheckRoleConflictsAsync(connectedId, roleId, currentRoles);
                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RoleConflictDetectedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        ConnectedId = connectedId,
                        ExistingRoleId = currentRoles.First().RoleId,
                        NewRoleId = roleId,
                        ConflictType = "MutuallyExclusive",
                        ConflictDetails = conflicts,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role conflicts detected: {string.Join(", ", conflicts)}",
                        RoleConstants.ErrorCodes.RoleConflict);
                }

                // 6. Check if this is an admin role assignment
                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                if (rolePermissions?.Any(p => p.PermissionScope.Contains("ADMIN")) == true)
                {
                    _logger.LogInformation("Admin role assignment detected for {ConnectedId}", connectedId);

                    await _eventBus.PublishAsync(new AdminRoleAssignedEvent
                    {
                        OrganizationId = role.OrganizationId,
                        ConnectedId = connectedId,
                        RoleId = roleId,
                        RoleName = role.Name,
                        PermissionLevel = PermissionLevel.Admin,
                        AssignedBy = assignedByConnectedId,
                        ExpiresAt = _dateTimeProvider.UtcNow.AddDays(90),
                        Timestamp = _dateTimeProvider.UtcNow
                    });
                }

                // 7. Check membership type compatibility
                var membership = await _membershipRepository.GetMembershipAsync(role.OrganizationId, connectedId);
                if (membership?.MemberRole == OrganizationMemberRole.Guest && role.RequiresMembership)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "Guest users cannot be assigned membership-required roles",
                        RoleConstants.ErrorCodes.MembershipRequired);
                }

                await _auditService.LogActionAsync(
                    assignedByConnectedId,
                    "ValidateRoleAssignment",
                    AuditActionType.Others,
                    "Role",
                    roleId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        ConnectedId = connectedId,
                        RoleId = roleId,
                        RoleName = role.Name
                    }));

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex, "Error validating role assignment");
                return ServiceResult.Failure(
                    "Failed to validate role assignment",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> ValidateMultipleRolesAsync(
            Guid connectedId,
            List<Guid> roleIds)
        {
            try
            {
                if (roleIds == null || !roleIds.Any())
                    return ServiceResult.Failure("No roles specified", RoleConstants.ErrorCodes.InvalidRequest);

                // Get plan limits
                var firstRole = await _roleRepository.GetByIdAsync(roleIds.First());
                if (firstRole == null)
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[planKey];
                var maxConcurrentRoles = memberLimit > 0 ? Math.Min(memberLimit / 5, 10) : 10;

                if (roleIds.Count > maxConcurrentRoles)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = firstRole.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "BulkRoleAssignment",
                        CurrentValue = roleIds.Count,
                        MaxValue = maxConcurrentRoles,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    return ServiceResult.Failure(
                        $"Cannot assign more than {maxConcurrentRoles} roles at once on {planKey} plan",
                        RoleConstants.ErrorCodes.BulkLimitExceeded);
                }

                // Check each role exists
                var roles = new List<Role>();
                foreach (var roleId in roleIds)
                {
                    var role = await _roleRepository.GetByIdAsync(roleId);
                    if (role == null)
                        return ServiceResult.Failure($"Role {roleId} not found", RoleConstants.ErrorCodes.RoleNotFound);
                    roles.Add(role);
                }

                // Check for mutual exclusions
                var exclusiveRoles = roles.Where(r => r.IsMutuallyExclusive).ToList();
                if (exclusiveRoles.Count > 1)
                    return ServiceResult.Failure(
                        $"Cannot assign multiple mutually exclusive roles: {string.Join(", ", exclusiveRoles.Select(r => r.Name))}",
                        RoleConstants.ErrorCodes.MutualExclusion);

                // Check total permission complexity
                var totalPermissions = new HashSet<Guid>();

                // 2. ID 목록을 사용해 관련된 모든 RolePermission을 DB에서 한 번에 가져옵니다.
                var allRolePermissions = await _permissionRepository.FindAsync(rp => roleIds.Contains(rp.RoleId));

                // 3. 가져온 권한 ID들을 totalPermissions에 추가합니다.
                foreach (var permId in allRolePermissions.Select(rp => rp.PermissionId))
                {
                    totalPermissions.Add(permId);
                }
                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey] * 20;
                if (maxComplexity > 0 && totalPermissions.Count > maxComplexity)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = firstRole.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "CombinedPermissionComplexity",
                        CurrentValue = totalPermissions.Count,
                        MaxValue = maxComplexity,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    return ServiceResult.Failure(
                        $"Combined roles exceed permission complexity limit for {planKey} plan",
                        RoleConstants.ErrorCodes.ComplexityExceeded);
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating multiple role assignment");
                return ServiceResult.Failure(
                    "Failed to validate multiple roles",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> ValidateRoleRevocationAsync(
            Guid connectedId,
            Guid roleId,
            Guid revokedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // 1. Check if role assignment exists
                // [수정] GetAssignmentAsync 대신 GetActiveRolesAsync와 FirstOrDefault를 사용합니다.
                var userRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);
                var assignment = userRoles.FirstOrDefault(r => r.RoleId == roleId);
                if (assignment == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role assignment not found", RoleConstants.ErrorCodes.AssignmentNotFound);
                }

                // 2. Check revocation permission
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null) // 역할이 없는 경우에 대한 방어 코드 추가
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role to be revoked not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                var hasRevokePermission = await CheckUserPermissionAsync(
                    revokedByConnectedId,
                    "ROLE_REVOKE",
                    role.OrganizationId);

                if (!hasRevokePermission)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "User does not have permission to revoke roles",
                        RoleConstants.ErrorCodes.InsufficientPermission);
                }

                // 3. Check if this is a required role
                // (Role 엔티티에 IsRequired 속성이 추가되었다고 가정)
                if (role.IsRequired)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "Cannot revoke a required role",
                        RoleConstants.ErrorCodes.RequiredRole);
                }

                // 4. Check if this would leave the organization without admins
                // [수정] GetRolePermissionsAsync 대신 GetByRoleAsync와 Select를 사용합니다.
                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionScopes = rolePermissions.Select(rp => rp.Permission?.Scope ?? string.Empty).ToHashSet();

                if (permissionScopes.Any(scope => scope.Contains("ADMIN")))
                {
                    // [수정] CountOtherAdminsAsync 대신 내부 헬퍼 메서드를 호출합니다.
                    var otherAdmins = await CountOtherAdminsInOrgAsync(role.OrganizationId, connectedId);

                    if (otherAdmins == 0)
                    {
                        await _eventBus.PublishAsync(new LastAdminRoleWarningEvent
                        {
                            OrganizationId = role.OrganizationId,
                            RoleId = roleId,
                            ConnectedId = connectedId,
                            Action = "Revoke",
                            RemainingAdmins = 0,
                            Timestamp = _dateTimeProvider.UtcNow
                        });

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Cannot revoke the last administrative role",
                            RoleConstants.ErrorCodes.LastAdminRole);
                    }
                }

                await _auditService.LogActionAsync(
                    revokedByConnectedId,
                    "ValidateRoleRevocation",
                    AuditActionType.Others,
                    "Role",
                    roleId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        ConnectedId = connectedId,
                        RoleId = roleId
                    }));

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex, "Error validating role revocation");
                return ServiceResult.Failure(
                    "Failed to validate role revocation",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }
        #endregion

        #region Role Policy Validation

        public async Task<ServiceResult> ValidateOrganizationPolicyAsync(
            Guid organizationId,
            Guid roleId)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);

                // Get organization's plan
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(organizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                var errors = new List<string>();

                // Check role count against plan limit
                var roleCount = await _roleRepository.CountByOrganizationAsync(organizationId);
                var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                if (roleLimit > 0 && roleCount > roleLimit)
                {
                    errors.Add($"Organization exceeds role limit ({roleLimit}) for {planKey} plan");
                }

                // Check permission complexity
                // [수정] GetByRoleAsync를 호출하고 .Count()로 권한 수를 계산합니다.
                var permissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionCount = permissions.Count();
                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey] * 10;

                if (maxComplexity > 0 && permissionCount > maxComplexity)
                {
                    errors.Add($"Role permission complexity exceeds {planKey} plan limit");
                }

                if (errors.Any())
                {
                    // Fire consolidated plan violation event
                    await _eventBus.PublishAsync(new ComplianceRoleChangeEvent
                    {
                        OrganizationId = organizationId,
                        RoleId = roleId,
                        ComplianceStandard = $"{planKey}_PLAN_POLICY",
                        ChangeType = "PolicyViolation",
                        ChangeReason = string.Join("; ", errors),
                        ChangedBy = Guid.Empty, // System check
                        RequiresApproval = true,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    return ServiceResult.Failure(
                        string.Join("; ", errors),
                        RoleConstants.ErrorCodes.PolicyViolation);
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating organization policy");
                return ServiceResult.Failure(
                    "Failed to validate organization policy",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        public async Task<ServiceResult> ValidateActivationConditionsAsync(
            Guid roleId,
            Guid connectedId)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);

                var now = _dateTimeProvider.UtcNow;

                // Check time-based activation
                if (now < role.ActivationStartTime)
                    return ServiceResult.Failure("Role is not yet active", RoleConstants.ErrorCodes.NotYetActive);

                if (role.ExpiresAt.HasValue && now > role.ExpiresAt.Value)
                    return ServiceResult.Failure("Role has expired", RoleConstants.ErrorCodes.Expired);

                // Check condition-based activation
                if (role.RequiresApproval)
                {
                    // Check if there's an approval record
                    var cacheKey = $"{CACHE_KEY_PREFIX}approval:{connectedId}:{roleId}";
                    // [수정] bool? 대신 CacheBoolWrapper 클래스를 사용해 캐시를 조회합니다.
                    var approvalWrapper = await _cacheService.GetAsync<CacheBoolWrapper>(cacheKey);
                    var isApproved = approvalWrapper?.Value; // wrapper가 null이면 isApproved도 null이 됩니다.

                    if (!isApproved.HasValue || !isApproved.Value)
                        return ServiceResult.Failure(
                            "Role assignment requires approval",
                            RoleConstants.ErrorCodes.ApprovalRequired);
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating activation conditions");
                return ServiceResult.Failure(
                    "Failed to validate activation conditions",
                    RoleConstants.ErrorCodes.SystemError);
            }
        }

        #endregion

        #region Bulk Operations
        public async Task<ServiceResult<BulkValidationResult>> ValidateBulkCreateAsync(
            List<CreateRoleRequest> requests,
            Guid createdByConnectedId)
        {
            var result = new BulkValidationResult
            {
                TotalCount = requests.Count,
                ValidCount = 0,
                InvalidCount = 0,
                IsValid = true, // [추가] 기본값은 true로 시작하고, 에러 발생 시 false로 변경
                ItemResults = new List<ItemValidationResult>(),   // [변경] Errors -> ItemResults
                ErrorSummary = new Dictionary<string, int>()   // [추가] 에러 유형별 개요
            };

            if (requests == null || !requests.Any())
            {
                return ServiceResult<BulkValidationResult>.Success(result);
            }

            // Check bulk operation limit based on plan
            var firstOrgId = requests.First().OrganizationId;
            var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstOrgId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var bulkLimit = PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var limit) ? limit : 100;
            bulkLimit = bulkLimit > 0 ? Math.Min(bulkLimit, 100) : 100;

            if (requests.Count > bulkLimit)
            {
                await _eventBus.PublishAsync(new BulkOperationLimitReachedEvent
                {
                    OrganizationId = firstOrgId,
                    PlanKey = planKey,
                    OperationType = "RoleCreate",
                    RequestedCount = requests.Count,
                    AllowedCount = bulkLimit,
                    Timestamp = _dateTimeProvider.UtcNow
                });

                result.InvalidCount = requests.Count;
                result.IsValid = false; // [추가] 전체 작업이 유효하지 않음을 명시
                result.ItemResults.Add(new ItemValidationResult
                {
                    Index = -1, // -1은 특정 항목이 아닌, 전체 작업에 대한 에러를 의미
                    Identifier = "Bulk Operation Limit",
                    IsValid = false,
                    Errors = new List<string> { $"Bulk operation exceeds {planKey} plan limit of {bulkLimit}" }
                });

                return ServiceResult<BulkValidationResult>.FailureWithData(
                    "Bulk operation limit exceeded",
                    result,
                    RoleConstants.ErrorCodes.BulkLimitExceeded);
            }

            for (int i = 0; i < requests.Count; i++)
            {
                // ValidateCreateAsync는 내부적으로 트랜잭션을 시작하므로, 
                // 여기서는 개별 검증만 수행하고 트랜잭션은 한 번만 관리하는 것이 좋습니다.
                // 여기서는 각 요청을 개별적으로 검증한다고 가정합니다.
                var validation = await ValidateCreateAsync(requests[i], createdByConnectedId);
                if (validation.IsSuccess)
                {
                    result.ValidCount++;
                }
                else
                {
                    result.InvalidCount++;
                    result.ItemResults.Add(new ItemValidationResult
                    {
                        Index = i,
                        Identifier = requests[i].Name, // 혹은 다른 식별자
                        IsValid = false,
                        Errors = new List<string> { validation.ErrorMessage ?? "Validation failed" }
                    });
                }
            }

            return ServiceResult<BulkValidationResult>.Success(result);
        }

        public async Task<ServiceResult<BulkValidationResult>> ValidateBulkAssignmentAsync(
            List<(Guid ConnectedId, Guid RoleId)> assignments,
            Guid assignedByConnectedId)
        {
            // [수정] BulkValidationResult의 새로운 구조에 맞게 객체를 생성합니다.
            var result = new BulkValidationResult
            {
                TotalCount = assignments.Count,
                ValidCount = 0,
                InvalidCount = 0,
                IsValid = true,
                ItemResults = new List<ItemValidationResult>(),
                ErrorSummary = new Dictionary<string, int>()
            };

            if (assignments == null || !assignments.Any())
            {
                return ServiceResult<BulkValidationResult>.Success(result);
            }

            // Similar bulk limit check
            var firstRole = await _roleRepository.GetByIdAsync(assignments.First().RoleId);
            if (firstRole != null)
            {
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var bulkLimit = PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var limit) ? limit : 200;
                bulkLimit = bulkLimit > 0 ? Math.Min(bulkLimit * 2, 200) : 200;

                if (assignments.Count > bulkLimit)
                {
                    await _eventBus.PublishAsync(new BulkOperationLimitReachedEvent
                    {
                        OrganizationId = firstRole.OrganizationId,
                        PlanKey = planKey,
                        OperationType = "RoleAssignment",
                        RequestedCount = assignments.Count,
                        AllowedCount = bulkLimit,
                        Timestamp = _dateTimeProvider.UtcNow
                    });

                    result.InvalidCount = assignments.Count;
                    result.IsValid = false;
                    // [수정] ItemResults에 전체 에러를 추가합니다.
                    result.ItemResults.Add(new ItemValidationResult
                    {
                        Index = -1, // -1 for global error
                        Identifier = "Bulk Operation",
                        IsValid = false,
                        Errors = new List<string> { $"Bulk operation exceeds {planKey} plan limit of {bulkLimit}" }
                    });

                    return ServiceResult<BulkValidationResult>.FailureWithData("Bulk operation limit exceeded", result, RoleConstants.ErrorCodes.BulkLimitExceeded);
                }
            }

            for (int i = 0; i < assignments.Count; i++)
            {
                var validation = await ValidateRoleAssignmentAsync(
                    assignments[i].ConnectedId,
                    assignments[i].RoleId,
                    assignedByConnectedId);

                if (validation.IsSuccess)
                {
                    result.ValidCount++;
                }
                else
                {
                    result.InvalidCount++;
                    result.IsValid = false;

                    // [수정] Errors 속성 대신 ItemResults 리스트에 상세 결과를 추가합니다.
                    result.ItemResults.Add(new ItemValidationResult
                    {
                        Index = i,
                        Identifier = $"User: {assignments[i].ConnectedId}, Role: {assignments[i].RoleId}",
                        IsValid = false,
                        Errors = new List<string> { validation.ErrorMessage ?? "Validation failed" }
                    });
                }
            }

            return ServiceResult<BulkValidationResult>.Success(result);
        }


        #endregion

        #region Helper Methods
        private async Task<int> CountOtherAdminsInOrgAsync(Guid organizationId, Guid currentConnectedId)
        {
            const int AdminLevel = 3;
            var adminRoles = await _roleRepository.GetByMinimumLevelAsync(organizationId, AdminLevel);

            var adminUserIds = new HashSet<Guid>();
            foreach (var adminRole in adminRoles)
            {
                var assignments = await _connectedIdRoleRepository.GetByRoleAsync(adminRole.Id);
                foreach (var assignment in assignments)
                {
                    adminUserIds.Add(assignment.ConnectedId);
                }
            }

            // 자기 자신을 제외
            adminUserIds.Remove(currentConnectedId);

            return adminUserIds.Count;
        }

        private async Task<bool> CheckUserPermissionAsync(Guid connectedId, string permissionScope, Guid organizationId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}permission:{connectedId}:{permissionScope}:{organizationId}";

            // [수정] bool? 대신 CacheBoolWrapper를 사용해 캐시를 조회합니다.
            var cachedWrapper = await _cacheService.GetAsync<CacheBoolWrapper>(cacheKey);
            if (cachedWrapper != null)
            {
                return cachedWrapper.Value;
            }

            // [수정] GetUserRolesAsync -> GetActiveRolesAsync로 변경
            var userRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);
            if (!userRoles.Any())
            {
                // [수정] bool 값을 Wrapper에 담아 캐시에 저장합니다.
                await _cacheService.SetAsync(cacheKey, new CacheBoolWrapper { Value = false }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));
                return false;
            }

            // [개선] N+1 문제를 해결하기 위해 DB 조회를 루프 밖으로 이동 (성능 향상)
            // 1. 사용자가 가진 모든 역할의 ID 목록을 추출합니다.
            var roleIds = userRoles.Select(ur => ur.RoleId).ToList();

            // 2. 모든 역할에 대한 권한 정보를 DB에서 한 번에 가져옵니다.
            var allPermissions = await _permissionRepository.FindAsync(rp => roleIds.Contains(rp.RoleId));

            // 3. 가져온 권한 정보에 원하는 권한이 있는지 확인합니다.
            bool hasPermission = allPermissions.Any(rp => rp.PermissionScope == permissionScope);

            // [수정] 결과를 Wrapper에 담아 캐시에 저장합니다.
            await _cacheService.SetAsync(cacheKey, new CacheBoolWrapper { Value = hasPermission }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

            return hasPermission;
        }

        private async Task<ServiceResult> ValidatePermissionsExistAsync(List<Guid> permissionIds)
        {
            // [수정] _permissionRepository의 FindAsync를 사용해 여러 권한을 한 번에 조회합니다.
            var permissions = await _permissionRepository.FindAsync(p => permissionIds.Contains(p.Id));
            var foundIds = permissions.Select(p => p.Id).ToHashSet();

            var missingIds = permissionIds.Where(id => !foundIds.Contains(id)).ToList();

            if (missingIds.Any())
            {
                return ServiceResult.Failure(
                    $"Permissions not found: {string.Join(", ", missingIds)}",
                    RoleConstants.ErrorCodes.PermissionsNotFound);
            }

            return ServiceResult.Success();
        }

        private async Task<bool> IsCircularReferenceAsync(Guid roleId, Guid parentId)
        {
            var visited = new HashSet<Guid>();
            return await IsCircularReferenceRecursiveAsync(roleId, parentId, visited);
        }

        private async Task<bool> IsCircularReferenceRecursiveAsync(Guid roleId, Guid checkId, HashSet<Guid> visited)
        {
            if (roleId == checkId)
                return true;

            if (visited.Contains(checkId))
                return false;

            visited.Add(checkId);

            var role = await _roleRepository.GetByIdAsync(checkId);
            if (role?.ParentRoleId == null)
                return false;

            return await IsCircularReferenceRecursiveAsync(roleId, role.ParentRoleId.Value, visited);
        }

        private async Task<int> GetRoleHierarchyDepthAsync(Guid roleId)
        {
            var depth = 0;
            var currentId = roleId;
            var maxCheck = 20; // Prevent infinite loops

            while (currentId != Guid.Empty && depth < maxCheck)
            {
                var role = await _roleRepository.GetByIdAsync(currentId);
                if (role?.ParentRoleId == null)
                    break;

                currentId = role.ParentRoleId.Value;
                depth++;
            }

            return depth;
        }

        private async Task<Guid> GetRootRoleIdAsync(Guid roleId)
        {
            var currentId = roleId;
            var maxCheck = 20; // Prevent infinite loops
            var iterations = 0;

            while (currentId != Guid.Empty && iterations < maxCheck)
            {
                var role = await _roleRepository.GetByIdAsync(currentId);
                if (role?.ParentRoleId == null)
                    return currentId;

                currentId = role.ParentRoleId.Value;
                iterations++;
            }

            return roleId;
        }

        private async Task<List<string>> CheckPermissionConflictsAsync(List<Guid> permissionIds)
        {
            var conflicts = new List<string>();
            var permissions = await _permissionRepository.FindAsync(p => permissionIds.Contains(p.Id));

            // [수정] 그룹화(GroupBy)를 할 때 p.Permission을 거쳐서 ScopeResource에 접근합니다.
            // 또한, Permission 객체가 null인 경우를 대비해 먼저 필터링해주는 것이 안전합니다.
            var permissionsByResource = permissions
                .Where(p => p.Permission != null)
                .GroupBy(p => p.Permission!.ScopeResource);

            foreach (var group in permissionsByResource)
            {
                // 같은 리소스에 대한 권한이 2개 이상이고, 그 중 하나라도 'IsExclusive'가 true이면 충돌로 간주
                if (group.Count() > 1 && group.Any(p => p.Permission!.IsExclusive))
                {
                    var conflictingScopes = string.Join(", ", group.Select(p => $"'{p.Permission!.Scope}'"));
                    conflicts.Add($"Mutually exclusive permissions found for resource '{group.Key}': {conflictingScopes}");
                }
            }

            return conflicts;
        }

        private async Task<List<string>> CheckRoleConflictsAsync(Guid connectedId, Guid newRoleId, IEnumerable<ConnectedIdRole> currentRoles)
        {
            var conflicts = new List<string>();
            var newRole = await _roleRepository.GetByIdAsync(newRoleId);

            // [수정 1] newRole이 null일 경우를 처리하여 NullReferenceException을 방지합니다.
            if (newRole == null)
            {
                // 존재하지 않는 역할이므로 충돌 검사를 진행할 수 없습니다.
                // 에러를 던지거나, 호출한 쪽에서 처리하도록 빈 목록을 반환합니다.
                _logger.LogWarning("Could not check role conflicts for a non-existent new role with ID {RoleId}", newRoleId);
                return conflicts;
            }

            // [개선] 새로운 역할이 상호 배타적인 역할인지 확인합니다.
            if (newRole.IsMutuallyExclusive)
            {
                // 사용자가 이미 가지고 있는 역할들 중에서 상호 배타적인 역할들을 찾습니다.
                var existingExclusiveRoles = currentRoles
                    .Where(r => r.Role?.IsMutuallyExclusive == true)
                    .Select(r => r.Role!.Name) // [개선] 충돌 메시지에 표시할 역할 이름을 추출합니다.
                    .ToList();

                if (existingExclusiveRoles.Any())
                {
                    // [개선] 어떤 역할과 충돌하는지 명확한 메시지를 추가합니다.
                    var conflictDetails = string.Join(", ", existingExclusiveRoles);
                    conflicts.Add($"Cannot assign mutually exclusive role '{newRole.Name}' because user already has exclusive role(s): {conflictDetails}");
                }
            }

            // (추가 개선 제안) 사용자가 이미 배타적 역할을 가지고 있을 때, 
            // 새로운 역할(배타적이 아니더라도)을 추가하는 것을 막는 로직도 고려해볼 수 있습니다.
            // else if (currentRoles.Any(r => r.Role?.IsMutuallyExclusive == true)) { ... }

            return conflicts;
        }

        private async Task SendCriticalSecurityAlertAsync(
            Guid organizationId,
            Guid triggeredBy,
            string alertType,
            List<string> details)
        {
            try
            {
                var message = new EmailMessageDto
                {
                    To = "security@authhive.com",
                    Subject = $"[SECURITY ALERT] {alertType}",
                    Body = $@"
                        Alert Type: {alertType}
                        Organization: {organizationId}
                        Triggered By: {triggeredBy}
                        Details: {string.Join("\n", details)}
                        Time: {_dateTimeProvider.UtcNow:yyyy-MM-dd HH:mm:ss} UTC
                    "
                };

                await _emailService.SendEmailAsync(message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send security alert");
            }
        }

        private async Task SendCriticalErrorAlertAsync(
            Exception exception,
            string operation,
            Guid connectedId)
        {
            try
            {
                var message = new EmailMessageDto
                {
                    To = "admin@authhive.com",
                    Subject = $"[CRITICAL ERROR] {operation}",
                    Body = $@"
                        Operation: {operation}
                        ConnectedId: {connectedId}
                        Error: {exception.Message}
                        Stack: {exception.StackTrace}
                        Time: {_dateTimeProvider.UtcNow:yyyy-MM-dd HH:mm:ss} UTC
                    "
                };

                await _emailService.SendEmailAsync(message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send error alert");
            }
        }
        private class CacheBoolWrapper { public bool Value { get; set; } }
        #endregion
    }
}