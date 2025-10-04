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
using AuthHive.Core.Models.Business.Events;

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
                var existingRoles = await _roleRepository.GetByOrganizationAsync(request.OrganizationId, includeInactive: true);
                var existingRole = existingRoles.FirstOrDefault(r => r.Name.Equals(request.Name, StringComparison.OrdinalIgnoreCase));
                if (existingRole != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role with name '{request.Name}' already exists in this organization",
                        RoleConstants.ErrorCodes.DuplicateRole);
                }

                // 5. Check for duplicate role key
                var existingRoleByKey = await _roleRepository.GetByRoleKeyAsync(request.OrganizationId, request.RoleKey);
                if (existingRoleByKey != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role with key '{request.RoleKey}' already exists",
                        RoleConstants.ErrorCodes.DuplicateKey);
                }

                // 6. Get organization's plan and check role limit
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(request.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                if (roleLimit > 0) // -1 means unlimited
                {
                    var currentRoleCount = await _roleRepository.CountByOrganizationAsync(request.OrganizationId);

                    if (currentRoleCount >= roleLimit)
                    {
                        await _eventBus.PublishAsync(new RoleLimitReachedEvent(request.OrganizationId)
                        {
                            PlanKey = planKey,
                            CurrentRoleCount = currentRoleCount,
                            MaxRoleLimit = roleLimit,
                            AttemptedBy = createdByConnectedId,
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

                // 7. Validate parent role if specified
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

                    var depth = await GetRoleHierarchyDepthAsync(request.ParentRoleId.Value);
                    var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                    if (maxDepth > 0 && depth >= maxDepth)
                    {
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                            request.OrganizationId,
                            planKey,
                            PlanLimitType.OrganizationDepth,
                            depth + 1,
                            maxDepth,
                            createdByConnectedId
                        ));

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

                    var riskAssessment = await AssessPermissionRiskAsync(request.InitialPermissionIds);
                    if (riskAssessment.IsSuccess && riskAssessment.Data?.Level == RiskLevel.Critical)
                    {
                        _logger.LogWarning(
                            "Critical risk permissions detected in new role: {Risks}",
                            string.Join(", ", riskAssessment.Data.Risks));

                        await _eventBus.PublishAsync(new DangerousPermissionCombinationEvent(Guid.Empty) // RoleId is not known yet
                        {
                           // OrganizationId is inherited from BaseEvent's aggregateId
                            PermissionIds = request.InitialPermissionIds,
                            RiskLevel = RiskLevel.Critical,
                            RiskDetails = riskAssessment.Data.Risks,
                            AssignedBy = createdByConnectedId
                        });

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

                if (request?.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
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

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                if (role.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                {
                    _logger.LogWarning(
                        "Attempt to modify system role {RoleId} by {UpdatedBy}",
                        roleId, updatedByConnectedId);

                    await _eventBus.PublishAsync(new SystemRoleModificationAttemptedEvent(roleId)
                    {
                        // OrganizationId is inherited
                        AttemptedBy = updatedByConnectedId,
                        RoleName = role.Name,
                        Action = "Update",
                        IsAuthorized = false,
                        IpAddress = string.Empty,
                        UserAgent = string.Empty,
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

                if (!string.IsNullOrWhiteSpace(request.Name) && request.Name != role.Name)
                {
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

                if (request.ParentRoleId.HasValue && request.ParentRoleId != role.ParentRoleId)
                {
                    if (await IsCircularReferenceAsync(roleId, request.ParentRoleId.Value))
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "This change would create a circular reference in the role hierarchy",
                            RoleConstants.ErrorCodes.CircularReference);
                    }

                    var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                    var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                    var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                    if (maxDepth > 0)
                    {
                        var newDepth = await GetRoleHierarchyDepthAsync(request.ParentRoleId.Value);
                        if (newDepth >= maxDepth)
                        {
                            await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                                role.OrganizationId,
                                planKey,
                                PlanLimitType.OrganizationDepth,
                                newDepth + 1,
                                maxDepth,
                                updatedByConnectedId
                            ));

                            await _unitOfWork.RollbackTransactionAsync();
                            return ServiceResult.Failure(
                                $"Role hierarchy depth would exceed {planKey} plan limit ({maxDepth})",
                                RoleConstants.ErrorCodes.HierarchyDepthExceeded);
                        }
                    }
                }

                if (request.PermissionIds != null)
                {
                    var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                    var currentPermissionIds = rolePermissions.Select(rp => rp.PermissionId).ToHashSet();
                    var removedPermissions = currentPermissionIds.Except(request.PermissionIds).ToList();

                    if (removedPermissions.Any())
                    {
                        var assignments = await _connectedIdRoleRepository.GetByRoleAsync(roleId);
                        var affectedUserCount = assignments.Count();

                        if (affectedUserCount > 100)
                        {
                            _logger.LogWarning(
                                "Role update will remove permissions from {Count} users",
                                affectedUserCount);

                            await _eventBus.PublishAsync(new MassRoleCacheInvalidationEvent(roleId)
                            {
                                // OrganizationId is inherited
                                AffectedConnectedIds = affectedUserCount,
                                AffectedSessions = affectedUserCount,
                                InvalidationReason = "Permission removal from role"
                            });
                        }
                    }
                }

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

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

                if (role.OrganizationId == CommonConstants.SystemConstants.AUTHHIVE_ORGANIZATION_ID)
                {
                    _logger.LogWarning(
                        "Attempt to delete system role {RoleId} by {DeletedBy}",
                        roleId, deletedByConnectedId);

                    await _eventBus.PublishAsync(new SystemRoleModificationAttemptedEvent(roleId)
                    {
                        // OrganizationId is inherited
                        AttemptedBy = deletedByConnectedId,
                        RoleName = role.Name,
                        Action = "Delete",
                        IsAuthorized = false
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

                var childRoles = await _roleRepository.GetChildRolesAsync(roleId);
                if (childRoles.Any())
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Cannot delete role with {childRoles.Count()} child roles",
                        RoleConstants.ErrorCodes.HasChildRoles);
                }

                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionScopes = rolePermissions.Select(rp => rp.Permission?.Scope ?? string.Empty).ToHashSet();

                if (permissionScopes.Contains("ADMIN") || permissionScopes.Contains("SUPER_ADMIN"))
                {
                    const int AdminLevel = 3;
                    var adminRoles = await _roleRepository.GetByMinimumLevelAsync(role.OrganizationId, AdminLevel);
                    var adminRolesCount = adminRoles.Count();

                    if (adminRolesCount <= 1)
                    {
                        _logger.LogWarning(
                            "Attempt to delete last admin role for organization {OrgId}",
                            role.OrganizationId);

                        await _eventBus.PublishAsync(new LastAdminRoleWarningEvent(role.OrganizationId)
                        {
                            RoleId = roleId,
                            ConnectedId = deletedByConnectedId,
                            Action = "Delete",
                            RemainingAdmins = 0
                        });

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Cannot delete the last administrative role",
                            RoleConstants.ErrorCodes.LastAdminRole);
                    }
                }

                if (role.IsCritical || usersWithRole > 50)
                {
                    await _eventBus.PublishAsync(new CriticalRoleDeletedEvent(roleId)
                    {
                        // OrganizationId is inherited
                        RoleName = role.Name,
                        AffectedUsers = usersWithRole,
                        DeletedBy = deletedByConnectedId,
                        ReplacementRoleId = replacementRoleId
                    });
                }

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

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

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

                var validationResult = await ValidatePermissionsExistAsync(permissionIds);
                if (!validationResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return validationResult;
                }

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];
                if (maxComplexity > 0 && permissionIds.Count > maxComplexity * 10)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                        role.OrganizationId,
                        planKey,
                        PlanLimitType.PermissionScopeDepth,
                        permissionIds.Count,
                        maxComplexity * 10,
                        assignedByConnectedId
                    ));

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Permission count exceeds {planKey} plan complexity limit",
                        RoleConstants.ErrorCodes.ComplexityExceeded);
                }

                var conflicts = await CheckPermissionConflictsAsync(permissionIds);
                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RolePermissionConflictEvent(role.OrganizationId)
                    {
                        ChildRoleId = roleId,
                        ParentRoleId = role.ParentRoleId ?? Guid.Empty,
                        ConflictingPermissions = conflicts,
                        Resolution = "Assignment blocked"
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Permission conflicts detected: {string.Join(", ", conflicts)}",
                        RoleConstants.ErrorCodes.PermissionConflict);
                }

                var riskAssessment = await AssessPermissionRiskAsync(permissionIds);
                if (riskAssessment.IsSuccess && riskAssessment.Data?.Level >= RiskLevel.High)
                {
                    _logger.LogWarning(
                        "High risk permission combination for role {RoleId}: {Risks}",
                        roleId, string.Join(", ", riskAssessment.Data.Risks));

                    if (riskAssessment.Data.Level == RiskLevel.Critical)
                    {
                        await _eventBus.PublishAsync(new DangerousPermissionCombinationEvent(roleId)
                        {
                           // OrganizationId is inherited
                            PermissionIds = permissionIds,
                            RiskLevel = RiskLevel.Critical,
                            RiskDetails = riskAssessment.Data.Risks,
                            AssignedBy = assignedByConnectedId
                        });

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

                var permissions = await _permissionRepository.FindAsync(p => permissionIds.Contains(p.Id));
                var permissionScopes = permissions.Select(p => p.PermissionScope).ToHashSet();


                foreach (var combo in _dangerousPermissionCombos)
                {
                    if (permissionScopes.Contains(combo.Perm1) && permissionScopes.Contains(combo.Perm2))
                    {
                        assessment.Risks.Add(combo.Risk);
                        assessment.RiskScores[$"{combo.Perm1}+{combo.Perm2}"] = 10;
                        assessment.Level = RiskLevel.High;
                    }
                }

                if (permissionScopes.Any(p => p.EndsWith("_ALL")))
                {
                    assessment.Risks.Add("Broad access permissions detected");
                    assessment.RiskScores["BROAD_ACCESS"] = 7;
                    if (assessment.Level < RiskLevel.Medium)
                        assessment.Level = RiskLevel.Medium;
                }

                if (permissionScopes.Any(p => p.StartsWith("SYSTEM_")))
                {
                    assessment.Risks.Add("System-level permissions detected");
                    assessment.RiskScores["SYSTEM_ACCESS"] = 9;
                    assessment.Level = RiskLevel.Critical;
                }

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

                var parentRole = await _roleRepository.GetByIdAsync(parentRoleId.Value);
                if (parentRole == null)
                    return ServiceResult.Failure("Parent role not found", RoleConstants.ErrorCodes.ParentNotFound);

                if (await IsCircularReferenceAsync(roleId, parentRoleId.Value))
                    return ServiceResult.Failure(
                        "This would create a circular reference in the hierarchy",
                        RoleConstants.ErrorCodes.CircularReference);

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(parentRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

                if (maxDepth > 0)
                {
                    var depth = await GetRoleHierarchyDepthAsync(parentRoleId.Value);
                    if (depth >= maxDepth)
                    {
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
                var childRole = await _roleRepository.GetByIdAsync(childRoleId);
                var parentRole = await _roleRepository.GetByIdAsync(parentRoleId);

                if (childRole == null)
                    return ServiceResult.Failure("Child role not found", RoleConstants.ErrorCodes.RoleNotFound);
                if (parentRole == null)
                    return ServiceResult.Failure("Parent role not found", RoleConstants.ErrorCodes.ParentNotFound);

                if (childRole.OrganizationId != parentRole.OrganizationId)
                    return ServiceResult.Failure(
                        "Roles must belong to the same organization",
                        RoleConstants.ErrorCodes.DifferentOrganization);

                if (!parentRole.IsInheritable)
                    return ServiceResult.Failure(
                        "Parent role is not inheritable",
                        RoleConstants.ErrorCodes.NotInheritable);

                var childRolePermissions = await _permissionRepository.GetByRoleAsync(childRoleId);
                var parentRolePermissions = await _permissionRepository.GetByRoleAsync(parentRoleId);

                var parentPermissionsMap = parentRolePermissions
                    .Where(prp => prp.Permission != null)
                    .ToDictionary(prp => prp.Permission!.ScopeResource, prp => prp.Permission);

                var conflicts = new List<string>();
                foreach (var childRolePerm in childRolePermissions)
                {
                    var childPerm = childRolePerm.Permission;
                    if (childPerm == null) continue;

                    if (parentPermissionsMap.TryGetValue(childPerm.ScopeResource, out var conflictingParentPerm))
                    {
                        if (conflictingParentPerm.ScopeAction != childPerm.ScopeAction && conflictingParentPerm.IsExclusive)
                        {
                            conflicts.Add($"'{childPerm.Scope}' conflicts with exclusive parent permission '{conflictingParentPerm.Scope}'");
                        }
                    }
                }

                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RolePermissionConflictEvent(childRole.OrganizationId)
                    {
                        ChildRoleId = childRoleId,
                        ParentRoleId = parentRoleId,
                        ConflictingPermissions = conflicts,
                        Resolution = "Inheritance blocked"
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

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);
                }

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

                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || !connectedIdEntity.IsActive)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "Cannot assign role to inactive user",
                        RoleConstants.ErrorCodes.InactiveUser);
                }

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(role.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                var memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[planKey];
                var currentRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);

                var maxConcurrentRoles = memberLimit > 0 ? Math.Min(memberLimit / 5, 10) : 10;

                if (currentRoles.Count() >= maxConcurrentRoles)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                        role.OrganizationId,
                        planKey,
                        PlanLimitType.RoleCount,
                        currentRoles.Count(),
                        maxConcurrentRoles,
                        assignedByConnectedId
                    ));

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"User cannot have more than {maxConcurrentRoles} concurrent roles on {planKey} plan",
                        RoleConstants.ErrorCodes.RoleLimitExceeded);
                }

                var conflicts = await CheckRoleConflictsAsync(connectedId, roleId, currentRoles);
                if (conflicts.Any())
                {
                    await _eventBus.PublishAsync(new RoleConflictDetectedEvent(role.OrganizationId)
                    {
                        ConnectedId = connectedId,
                        ExistingRoleId = currentRoles.First().RoleId,
                        NewRoleId = roleId,
                        ConflictType = "MutuallyExclusive",
                        ConflictDetails = conflicts
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Role conflicts detected: {string.Join(", ", conflicts)}",
                        RoleConstants.ErrorCodes.RoleConflict);
                }

                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                if (rolePermissions?.Any(p => p.PermissionScope.Contains("ADMIN")) == true)
                {
                    _logger.LogInformation("Admin role assignment detected for {ConnectedId}", connectedId);

                    await _eventBus.PublishAsync(new AdminRoleAssignedEvent(role.OrganizationId)
                    {
                        ConnectedId = connectedId,
                        RoleId = roleId,
                        RoleName = role.Name,
                        PermissionLevel = PermissionLevel.Admin,
                        AssignedBy = assignedByConnectedId,
                        ExpiresAt = _dateTimeProvider.UtcNow.AddDays(90)
                    });
                }

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

                var firstRole = await _roleRepository.GetByIdAsync(roleIds.First());
                if (firstRole == null)
                    return ServiceResult.Failure("Role not found", RoleConstants.ErrorCodes.RoleNotFound);

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[planKey];
                var maxConcurrentRoles = memberLimit > 0 ? Math.Min(memberLimit / 5, 10) : 10;

                if (roleIds.Count > maxConcurrentRoles)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                        firstRole.OrganizationId,
                        planKey,
                        PlanLimitType.BulkRoleAssignment,
                        roleIds.Count,
                        maxConcurrentRoles,
                        connectedId
                    ));

                    return ServiceResult.Failure(
                        $"Cannot assign more than {maxConcurrentRoles} roles at once on {planKey} plan",
                        RoleConstants.ErrorCodes.BulkLimitExceeded);
                }

                var roles = new List<Role>();
                foreach (var roleId in roleIds)
                {
                    var role = await _roleRepository.GetByIdAsync(roleId);
                    if (role == null)
                        return ServiceResult.Failure($"Role {roleId} not found", RoleConstants.ErrorCodes.RoleNotFound);
                    roles.Add(role);
                }

                var exclusiveRoles = roles.Where(r => r.IsMutuallyExclusive).ToList();
                if (exclusiveRoles.Count > 1)
                    return ServiceResult.Failure(
                        $"Cannot assign multiple mutually exclusive roles: {string.Join(", ", exclusiveRoles.Select(r => r.Name))}",
                        RoleConstants.ErrorCodes.MutualExclusion);

                var totalPermissions = new HashSet<Guid>();
                var allRolePermissions = await _permissionRepository.FindAsync(rp => roleIds.Contains(rp.RoleId));

                foreach (var permId in allRolePermissions.Select(rp => rp.PermissionId))
                {
                    totalPermissions.Add(permId);
                }
                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey] * 20;
                if (maxComplexity > 0 && totalPermissions.Count > maxComplexity)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                        firstRole.OrganizationId,
                        planKey,
                        PlanLimitType.TotalPermissionComplexity,
                        totalPermissions.Count,
                        maxComplexity,
                        connectedId
                    ));

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
                var userRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);
                var assignment = userRoles.FirstOrDefault(r => r.RoleId == roleId);
                if (assignment == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure("Role assignment not found", RoleConstants.ErrorCodes.AssignmentNotFound);
                }

                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
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

                if (role.IsRequired)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        "Cannot revoke a required role",
                        RoleConstants.ErrorCodes.RequiredRole);
                }

                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionScopes = rolePermissions.Select(rp => rp.Permission?.Scope ?? string.Empty).ToHashSet();

                if (permissionScopes.Any(scope => scope.Contains("ADMIN")))
                {
                    var otherAdmins = await CountOtherAdminsInOrgAsync(role.OrganizationId, connectedId);

                    if (otherAdmins == 0)
                    {
                        await _eventBus.PublishAsync(new LastAdminRoleWarningEvent(role.OrganizationId)
                        {
                            RoleId = roleId,
                            ConnectedId = connectedId,
                            Action = "Revoke",
                            RemainingAdmins = 0
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

                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(organizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                var errors = new List<string>();

                var roleCount = await _roleRepository.CountByOrganizationAsync(organizationId);
                var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                if (roleLimit > 0 && roleCount > roleLimit)
                {
                    errors.Add($"Organization exceeds role limit ({roleLimit}) for {planKey} plan");
                }

                var permissions = await _permissionRepository.GetByRoleAsync(roleId);
                var permissionCount = permissions.Count();
                var maxComplexity = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey] * 10;

                if (maxComplexity > 0 && permissionCount > maxComplexity)
                {
                    errors.Add($"Role permission complexity exceeds {planKey} plan limit");
                }

                if (errors.Any())
                {
                    await _eventBus.PublishAsync(new ComplianceRoleChangeEvent(roleId)
                    {
                       // OrganizationId is inherited
                        ComplianceStandard = $"{planKey}_PLAN_POLICY",
                        ChangeType = "PolicyViolation",
                        ChangeReason = string.Join("; ", errors),
                        ChangedBy = Guid.Empty,
                        RequiresApproval = true
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

                if (now < role.ActivationStartTime)
                    return ServiceResult.Failure("Role is not yet active", RoleConstants.ErrorCodes.NotYetActive);

                if (role.ExpiresAt.HasValue && now > role.ExpiresAt.Value)
                    return ServiceResult.Failure("Role has expired", RoleConstants.ErrorCodes.Expired);

                if (role.RequiresApproval)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}approval:{connectedId}:{roleId}";
                    var approvalWrapper = await _cacheService.GetAsync<CacheBoolWrapper>(cacheKey);
                    var isApproved = approvalWrapper?.Value;

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
                IsValid = true,
                ItemResults = new List<ItemValidationResult>(),
                ErrorSummary = new Dictionary<string, int>()
            };

            if (requests == null || !requests.Any())
            {
                return ServiceResult<BulkValidationResult>.Success(result);
            }

            var firstOrgId = requests.First().OrganizationId;
            var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstOrgId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var bulkLimit = PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var limit) ? limit : 100;
            bulkLimit = bulkLimit > 0 ? Math.Min(bulkLimit, 100) : 100;

            if (requests.Count > bulkLimit)
            {
                await _eventBus.PublishAsync(new BulkOperationLimitReachedEvent(firstOrgId)
                {
                    PlanKey = planKey,
                    OperationType = "RoleCreate",
                    RequestedCount = requests.Count,
                    AllowedCount = bulkLimit
                });

                result.InvalidCount = requests.Count;
                result.IsValid = false;
                result.ItemResults.Add(new ItemValidationResult
                {
                    Index = -1,
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
                        Identifier = requests[i].Name,
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

            var firstRole = await _roleRepository.GetByIdAsync(assignments.First().RoleId);
            if (firstRole != null)
            {
                var subscription = await _planSubscriptionRepository.GetActiveByOrganizationIdAsync(firstRole.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var bulkLimit = PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var limit) ? limit : 200;
                bulkLimit = bulkLimit > 0 ? Math.Min(bulkLimit * 2, 200) : 200;

                if (assignments.Count > bulkLimit)
                {
                    await _eventBus.PublishAsync(new BulkOperationLimitReachedEvent(firstRole.OrganizationId)
                    {
                        PlanKey = planKey,
                        OperationType = "RoleAssignment",
                        RequestedCount = assignments.Count,
                        AllowedCount = bulkLimit
                    });

                    result.InvalidCount = assignments.Count;
                    result.IsValid = false;
                    result.ItemResults.Add(new ItemValidationResult
                    {
                        Index = -1,
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

            adminUserIds.Remove(currentConnectedId);

            return adminUserIds.Count;
        }

        private async Task<bool> CheckUserPermissionAsync(Guid connectedId, string permissionScope, Guid organizationId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}permission:{connectedId}:{permissionScope}:{organizationId}";

            var cachedWrapper = await _cacheService.GetAsync<CacheBoolWrapper>(cacheKey);
            if (cachedWrapper != null)
            {
                return cachedWrapper.Value;
            }

            var userRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);
            if (!userRoles.Any())
            {
                await _cacheService.SetAsync(cacheKey, new CacheBoolWrapper { Value = false }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));
                return false;
            }

            var roleIds = userRoles.Select(ur => ur.RoleId).ToList();
            var allPermissions = await _permissionRepository.FindAsync(rp => roleIds.Contains(rp.RoleId));
            bool hasPermission = allPermissions.Any(rp => rp.PermissionScope == permissionScope);

            await _cacheService.SetAsync(cacheKey, new CacheBoolWrapper { Value = hasPermission }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

            return hasPermission;
        }

        private async Task<ServiceResult> ValidatePermissionsExistAsync(List<Guid> permissionIds)
        {
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
            var maxCheck = 20;

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
            var maxCheck = 20;
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

            var permissionsByResource = permissions
                .Where(p => p.Permission != null)
                .GroupBy(p => p.Permission!.ScopeResource);

            foreach (var group in permissionsByResource)
            {
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

            if (newRole == null)
            {
                _logger.LogWarning("Could not check role conflicts for a non-existent new role with ID {RoleId}", newRoleId);
                return conflicts;
            }

            if (newRole.IsMutuallyExclusive)
            {
                var existingExclusiveRoles = currentRoles
                    .Where(r => r.Role?.IsMutuallyExclusive == true)
                    .Select(r => r.Role!.Name)
                    .ToList();

                if (existingExclusiveRoles.Any())
                {
                    var conflictDetails = string.Join(", ", existingExclusiveRoles);
                    conflicts.Add($"Cannot assign mutually exclusive role '{newRole.Name}' because user already has exclusive role(s): {conflictDetails}");
                }
            }
            
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

