using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Core.Validators;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Auth.Permissions.Events;
using AuthHive.Core.Models.PlatformApplication.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

namespace AuthHive.Auth.Validator
{
    public class UserApplicationAccessValidator : IUserApplicationAccessValidator
    {
        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IPlatformApplicationAccessTemplateRepository _templateRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPlanService _planService;
        private readonly IEventBus _eventBus;
        private readonly ILogger<UserApplicationAccessValidator> _logger;
        private static readonly Regex PermissionScopeRegex = new Regex(@"^([\w\-]+|\*):([\w\-]+|\*)?$");

        public UserApplicationAccessValidator(
            IUserPlatformApplicationAccessRepository accessRepository,
            IPlatformApplicationRepository applicationRepository,
            IPlatformApplicationAccessTemplateRepository templateRepository,
            IConnectedIdRepository connectedIdRepository,
            IRoleRepository roleRepository,
            IPlanService planService,
            IEventBus eventBus,
            ILogger<UserApplicationAccessValidator> logger)
        {
            _accessRepository = accessRepository;
            _applicationRepository = applicationRepository;
            _templateRepository = templateRepository;
            _connectedIdRepository = connectedIdRepository;
            _roleRepository = roleRepository;
            _planService = planService;
            _eventBus = eventBus;
            _logger = logger;
        }

        #region Basic Validation

        public async Task<AccessValidationResult> ValidateCreateAsync(UserPlatformApplicationAccess access)
        {
            var result = AccessValidationResult.Success();

            var application = await _applicationRepository.GetByIdAsync(access.ApplicationId);
            if (application == null)
                return AccessValidationResult.Failure("Application", "Target application not found.", "APPLICATION_NOT_FOUND");

            var targetUser = await _connectedIdRepository.GetByIdAsync(access.ConnectedId);
            if (targetUser == null)
                return AccessValidationResult.Failure("ConnectedId", "Target user not found.", "TARGET_USER_NOT_FOUND");

            result.Merge(await ValidateUserLimitsAsync(access.ApplicationId, access.OrganizationId));
            if (!result.IsValid) return result;

            result.Merge(await ValidateDuplicateAccessAsync(access.ConnectedId, access.ApplicationId));
            if (!result.IsValid) return result;

            if (access.GrantedByConnectedId.HasValue)
            {
                result.Merge(await ValidateGranterAuthorityAsync(access.GrantedByConnectedId.Value, access.ConnectedId, access.ApplicationId, access.AccessLevel));
            }

            return result;
        }

        public async Task<AccessValidationResult> ValidateUpdateAsync(UserPlatformApplicationAccess existingAccess, UserPlatformApplicationAccess updatedAccess)
        {
            var result = AccessValidationResult.Success();

            if (existingAccess.AccessLevel != updatedAccess.AccessLevel)
            {
                result.Merge(await ValidateAccessLevelChangeAsync(
                    existingAccess.ConnectedId, existingAccess.ApplicationId,
                    existingAccess.AccessLevel, updatedAccess.AccessLevel,
                    updatedAccess.UpdatedByConnectedId ?? Guid.Empty));
            }

            return result;
        }

        public async Task<AccessValidationResult> ValidateDeleteAsync(UserPlatformApplicationAccess access, Guid deletedByConnectedId)
        {
            if (access.AccessLevel == ApplicationAccessLevel.Owner)
            {
                var ownerCount = await _accessRepository.GetCountByAccessLevelAsync(access.ApplicationId, ApplicationAccessLevel.Owner);
                if (ownerCount <= 1)
                    return AccessValidationResult.Failure("Owner", "Cannot remove the last owner of the application.", "LAST_OWNER_CANNOT_BE_REMOVED");
            }
            return AccessValidationResult.Success();
        }

        #endregion

        #region Granter Validation

        public async Task<AccessValidationResult> ValidateGranterAuthorityAsync(Guid grantedByConnectedId, Guid targetConnectedId, Guid applicationId, ApplicationAccessLevel requestedLevel)
        {
            if (grantedByConnectedId == targetConnectedId) return AccessValidationResult.Success();

            var granterAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(grantedByConnectedId, applicationId);
            if (granterAccess == null)
            {
                return AccessValidationResult.Failure("Granter", "The user granting permission does not have access to this application.", "GRANTER_NO_ACCESS");
            }

            if (granterAccess.AccessLevel < requestedLevel || (granterAccess.AccessLevel == requestedLevel && granterAccess.AccessLevel != ApplicationAccessLevel.Owner))
            {
                await _eventBus.PublishAsync(new UnauthorizedPermissionGrantAttemptedEvent
                {
                    GranterConnectedId = grantedByConnectedId,
                    TargetConnectedId = targetConnectedId,
                    ApplicationId = applicationId,
                    GranterLevel = granterAccess.AccessLevel,
                    RequestedLevel = requestedLevel
                });
                return AccessValidationResult.Failure("AccessLevel", $"Users with '{granterAccess.AccessLevel}' access cannot grant '{requestedLevel}' access.", "INSUFFICIENT_GRANT_AUTHORITY");
            }

            return AccessValidationResult.Success();
        }

        #endregion

        #region Business Rule Validation

        public async Task<AccessValidationResult> ValidateUserLimitsAsync(Guid applicationId, Guid organizationId)
        {
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

            if (PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var memberLimit) && memberLimit != -1)
            {
                var currentUserCount = await _accessRepository.GetActiveCountByApplicationAsync(applicationId);
                if (currentUserCount >= memberLimit)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = organizationId,
                        PlanKey = planKey,
                        LimitType = "ApplicationUsers",
                        CurrentValue = currentUserCount,
                        MaxValue = memberLimit
                    });

                    return AccessValidationResult.Failure("UserLimit", $"The user limit ({memberLimit}) for the current '{planKey}' plan has been reached.", "APPLICATION_USER_LIMIT_REACHED");
                }
            }
            return AccessValidationResult.Success();
        }

        #endregion

        #region Duplication & Conflict Validation

        public async Task<AccessValidationResult> ValidateDuplicateAccessAsync(Guid connectedId, Guid applicationId, Guid? excludeAccessId = null)
        {
            if (excludeAccessId == null)
            {
                var exists = await _accessRepository.ExistsAsync(connectedId, applicationId);
                if (exists)
                {
                    return AccessValidationResult.Failure("Access", "This user already has access to this application.", "DUPLICATE_ACCESS_GRANT");
                }
            }
            return AccessValidationResult.Success();
        }

        #endregion

        // --- Start of newly filled methods ---

        public async Task<AccessValidationResult> ValidateAccessLevelChangeAsync(Guid connectedId, Guid applicationId, ApplicationAccessLevel currentLevel, ApplicationAccessLevel newLevel, Guid changedByConnectedId)
        {
            return await ValidateGranterAuthorityAsync(changedByConnectedId, connectedId, applicationId, newLevel);
        }

        public async Task<AccessValidationResult> ValidateLevelRoleConsistencyAsync(ApplicationAccessLevel level, Guid? roleId)
        {
            if (!roleId.HasValue) return AccessValidationResult.Success();

            var role = await _roleRepository.GetByIdAsync(roleId.Value);
            if (role != null)
            {
                // Example rule: 'Owner' level access should not be tied to a specific, restrictive role.
                if (level == ApplicationAccessLevel.Owner && role.Level < PermissionLevel.Admin)
                {
                    return AccessValidationResult.Failure("RoleConsistency", "Owner access level cannot be assigned with a non-administrative role.", "OWNER_ROLE_MISMATCH");
                }
            }
            return AccessValidationResult.Success();
        }

        public AccessValidationResult ValidateScopeFormat(IEnumerable<string> scopes)
        {
            var result = AccessValidationResult.Success();
            foreach (var scope in scopes ?? Enumerable.Empty<string>())
            {
                if (!PermissionScopeRegex.IsMatch(scope))
                {
                    result.AddError("ScopeFormat", $"Invalid scope format: '{scope}'. Expected 'resource:action'.", "INVALID_SCOPE_FORMAT");
                }
            }
            return result;
        }

        public async Task<AccessValidationResult> ValidateTemplateApplicationAsync(Guid? templateId, Guid connectedId, Guid applicationId)
        {
            if (!templateId.HasValue) return AccessValidationResult.Success();

            var template = await _templateRepository.GetByIdAsync(templateId.Value);
            if (template == null)
                return AccessValidationResult.Failure("Template", "The specified access template does not exist.", "TEMPLATE_NOT_FOUND");

            var application = await _applicationRepository.GetByIdAsync(applicationId);
            if (template.OrganizationId != application?.OrganizationId)
                return AccessValidationResult.Failure("Template", "The specified template does not belong to the same organization as the application.", "TEMPLATE_ORG_MISMATCH");

            return AccessValidationResult.Success();
        }

        // --- Other methods are filled below with placeholder logic as requested ---

        #region Other Method Implementations (with placeholder logic)

        public Task<AccessValidationResult> ValidateDelegationAsync(Guid delegatorConnectedId, Guid delegateeConnectedId, Guid applicationId, IEnumerable<string> permissions)
        {
            _logger.LogWarning("ValidateDelegationAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateAdditionalPermissionsAsync(string? additionalPermissions, Guid applicationId, ApplicationAccessLevel level)
        {
            if (string.IsNullOrWhiteSpace(additionalPermissions)) return Task.FromResult(AccessValidationResult.Success());
            try
            {
                var scopes = JsonSerializer.Deserialize<List<string>>(additionalPermissions);
                return Task.FromResult(ValidateScopeFormat(scopes ?? new List<string>()));
            }
            catch (JsonException)
            {
                return Task.FromResult(AccessValidationResult.Failure("AdditionalPermissions", "Invalid JSON format.", "INVALID_JSON"));
            }
        }

        public Task<AccessValidationResult> ValidateExcludedPermissionsAsync(string? excludedPermissions, Guid applicationId, ApplicationAccessLevel level, Guid? roleId)
        {
            if (string.IsNullOrWhiteSpace(excludedPermissions)) return Task.FromResult(AccessValidationResult.Success());
            try
            {
                var scopes = JsonSerializer.Deserialize<List<string>>(excludedPermissions);
                return Task.FromResult(ValidateScopeFormat(scopes ?? new List<string>()));
            }
            catch (JsonException)
            {
                return Task.FromResult(AccessValidationResult.Failure("ExcludedPermissions", "Invalid JSON format.", "INVALID_JSON"));
            }
        }

        public AccessValidationResult ValidatePermissionConflicts(IEnumerable<string> additionalPermissions, IEnumerable<string> excludedPermissions)
        {
            var added = new HashSet<string>(additionalPermissions ?? Enumerable.Empty<string>());
            var excluded = new HashSet<string>(excludedPermissions ?? Enumerable.Empty<string>());

            var conflicts = added.Intersect(excluded).ToList();
            if (conflicts.Any())
            {
                return AccessValidationResult.Failure("PermissionConflict", $"A permission cannot be both included and excluded: {string.Join(", ", conflicts)}", "PERMISSION_CONFLICT");
            }
            return AccessValidationResult.Success();
        }

        public async Task<AccessValidationResult> ValidateRoleAssignmentAsync(Guid? roleId, Guid connectedId, Guid applicationId, Guid assignedByConnectedId)
        {
            if (!roleId.HasValue) return AccessValidationResult.Success();

            var role = await _roleRepository.GetByIdAsync(roleId.Value);
            if (role == null) return AccessValidationResult.Failure("Role", "Role not found.", "ROLE_NOT_FOUND");

            // Further validation can be added here
            return AccessValidationResult.Success();
        }

        public Task<AccessValidationResult> ValidateTemplatePermissionCompatibilityAsync(Guid? templateId, string? additionalPermissions, string? excludedPermissions)
        {
            _logger.LogWarning("ValidateTemplatePermissionCompatibilityAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public AccessValidationResult ValidateExpirationDate(DateTime? expiresAt, DateTime grantedAt)
        {
            if (expiresAt.HasValue && expiresAt.Value <= grantedAt)
            {
                return AccessValidationResult.Failure("ExpiresAt", "Expiration date must be after the grant date.", "EXPIRATION_IN_PAST");
            }
            return AccessValidationResult.Success();
        }

        public Task<AccessValidationResult> ValidateInheritanceAsync(bool isInherited, Guid? inheritedFromId, Guid connectedId, Guid applicationId)
        {
            _logger.LogWarning("ValidateInheritanceAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateInheritanceChainAsync(Guid inheritedFromId, Guid targetAccessId)
        {
            _logger.LogWarning("ValidateInheritanceChainAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateRoleConflictsAsync(Guid connectedId, Guid applicationId, Guid? newRoleId, Guid? currentRoleId = null)
        {
            _logger.LogWarning("ValidateRoleConflictsAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateOrganizationPolicyAsync(Guid organizationId, Guid applicationId, ApplicationAccessLevel level)
        {
            _logger.LogWarning("ValidateOrganizationPolicyAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateApprovalRequirementsAsync(Guid connectedId, Guid applicationId, ApplicationAccessLevel level)
        {
            _logger.LogWarning("ValidateApprovalRequirementsAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateIpRestrictionsAsync(Guid connectedId, Guid applicationId, string? clientIp)
        {
            _logger.LogWarning("ValidateIpRestrictionsAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateMfaRequirementsAsync(Guid connectedId, Guid applicationId, ApplicationAccessLevel level)
        {
            _logger.LogWarning("ValidateMfaRequirementsAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessValidationResult> ValidateSessionRequirementsAsync(Guid connectedId, Guid applicationId)
        {
            _logger.LogWarning("ValidateSessionRequirementsAsync is not fully implemented.");
            return Task.FromResult(AccessValidationResult.Success());
        }

        public Task<AccessChangeImpact> AnalyzeAccessChangeImpactAsync(UserPlatformApplicationAccess existingAccess, UserPlatformApplicationAccess newAccess)
        {
            _logger.LogWarning("AnalyzeAccessChangeImpactAsync is not fully implemented.");
            return Task.FromResult(new AccessChangeImpact());
        }

        public Task<AccessRemovalImpact> AnalyzeAccessRemovalImpactAsync(UserPlatformApplicationAccess access)
        {
            _logger.LogWarning("AnalyzeAccessRemovalImpactAsync is not fully implemented.");
            return Task.FromResult(new AccessRemovalImpact());
        }

        #endregion
    }
    public class UnauthorizedPermissionGrantAttemptedEvent : IDomainEvent
    {
        // Required by the IDomainEvent interface
        public Guid EventId { get; } = Guid.NewGuid();
        public DateTime OccurredAt { get; } = DateTime.UtcNow;

        // Your existing properties
        public Guid GranterConnectedId { get; set; }
        public Guid TargetConnectedId { get; set; }
        public Guid ApplicationId { get; set; }
        public ApplicationAccessLevel GranterLevel { get; set; }
        public ApplicationAccessLevel RequestedLevel { get; set; }
    }
}