using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Constants.Business;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Common.Validation;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Models.Auth.Permissions.Events;
using AuthHive.Core.Models.Auth.Role.Requests;
using AuthHive.Core.Models.Business.Events;

namespace AuthHive.Auth.Validators
{
    /// <summary>
    /// ConnectedId Validator Implementation - AuthHive v15 SaaS Edition
    /// </summary>
    public class ConnectedIdValidator : IConnectedIdValidator
    {
        private readonly ILogger<ConnectedIdValidator> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IPlanService _planService;
        private readonly ISessionRepository _sessionRepository;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus; // 추가
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IInvitationRepository _invitationRepository;
        private readonly IConnectedIdRoleRepository _connectedIdRoleRepository;
        private readonly IRoleService _roleService;

        // Cache constants
        private const string CACHE_KEY_ORG_MEMBER_COUNT = "org:members:count:{0}";
        private const int CACHE_DURATION_SECONDS = 300;

        public ConnectedIdValidator(
            ILogger<ConnectedIdValidator> logger,
            IHttpContextAccessor httpContextAccessor,
            IConnectedIdRepository connectedIdRepository,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            IPlanService planService,
            ISessionRepository sessionRepository,
            ICacheService cacheService,
            IAuditService auditService,
            IEventBus eventBus,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IInvitationRepository invitationRepository,
            IConnectedIdRoleRepository connectedIdRoleRepository,
            IRoleService roleService)
        {
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _connectedIdRepository = connectedIdRepository;
            _userRepository = userRepository;
            _organizationRepository = organizationRepository;
            _planService = planService;
            _sessionRepository = sessionRepository;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _invitationRepository = invitationRepository;
            _connectedIdRoleRepository = connectedIdRoleRepository;
            _roleService = roleService;
        }

        #region IValidator<ConnectedId> Implementation

        public async Task<ValidationResult> ValidateCreateAsync(ConnectedId entity)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // Required field validation
                if (entity.UserId == Guid.Empty)
                {
                    result.AddError("UserId", "UserId is required", "REQUIRED_USER_ID");
                }

                if (entity.OrganizationId == Guid.Empty)
                {
                    result.AddError("OrganizationId", "OrganizationId is required", "REQUIRED_ORGANIZATION_ID");
                }

                // User existence check
                User? user = null;

                // FIX: UserId가 null이 아닌 경우에만 사용자 정보를 조회합니다.
                if (entity.UserId.HasValue)
                {
                    user = await SafeGetUserAsync(entity.UserId.Value);
                }


                if (user == null || user.IsDeleted)
                {
                    result.AddError("UserId", "Invalid user", "INVALID_USER");
                }

                // Organization existence check
                var organization = await SafeGetOrganizationAsync(entity.OrganizationId);
                if (organization is null)
                {
                    result.AddError("OrganizationId", "Invalid organization", "INVALID_ORGANIZATION");
                }

                // Duplicate membership validation
                // First, check if a UserId exists before trying to find a duplicate.
                if (entity.UserId.HasValue)
                {
                    // If it exists, pass the definite value using .Value
                    var existing = await SafeGetByUserAndOrganizationAsync(entity.UserId.Value, entity.OrganizationId);

                    if (existing != null && !existing.IsDeleted)
                    {
                        // This block now only runs for human users
                        result.AddError("UserId", "User is already an active member of this organization.", "ALREADY_MEMBER");
                    }
                }

                // Plan-based member limit validation
                if (organization is not null)
                {
                    var memberCount = await GetOrganizationMemberCountAsync(entity.OrganizationId);
                    var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(entity.OrganizationId);
                    var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                    var memberLimit = GetMemberLimitFromPlan(planKey);

                    if (memberLimit > 0 && memberCount >= memberLimit)
                    {
                        // 이벤트 발생 추가
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent(
      entity.OrganizationId,
      planKey,
      PlanLimitType.MemberCount,
      memberCount,
      memberLimit
  ));

                        result.AddError("OrganizationId",
                            $"Organization member limit ({memberLimit}) exceeded",
                            "MEMBER_LIMIT_EXCEEDED");
                    }
                }
                await _unitOfWork.CommitTransactionAsync();
                await LogValidationAsync("CREATE", entity, result);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error during ConnectedId entity creation validation");
                result.AddError("Validation error occurred");
            }

            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(ConnectedId entity, ConnectedId? existingEntity = null)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                existingEntity ??= await _connectedIdRepository.GetByIdAsync(entity.Id);
                if (existingEntity == null)
                {
                    result.AddError("Id", "ConnectedId not found for update", "NOT_FOUND");
                    return result;
                }

                // Immutable field validation
                if (entity.UserId != existingEntity.UserId)
                {
                    result.AddError("UserId", "UserId cannot be changed", "IMMUTABLE_USER_ID");
                }

                if (entity.OrganizationId != existingEntity.OrganizationId)
                {
                    result.AddError("OrganizationId", "OrganizationId cannot be changed", "IMMUTABLE_ORGANIZATION_ID");
                }

                await LogValidationAsync("UPDATE", entity, result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ConnectedId entity update validation");
                result.AddError("Validation error occurred");
            }

            return result;
        }

        public async Task<ValidationResult> ValidateDeleteAsync(ConnectedId entity)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                if (entity.IsDeleted)
                {
                    result.AddWarning("ConnectedId is already deleted");
                    return result;
                }

                // Last Owner protection
                if (entity.MembershipType == MembershipType.Owner)
                {
                    var owners = await SafeGetByOrganizationAsync(entity.OrganizationId);
                    var activeOwnerCount = owners.Count(o => !o.IsDeleted && o.MembershipType == MembershipType.Owner);

                    if (activeOwnerCount <= 1)
                    {
                        result.AddError("MembershipType", "Cannot delete last owner", "LAST_OWNER_PROTECTION");
                    }
                }

                await LogValidationAsync("DELETE", entity, result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ConnectedId entity deletion validation");
                result.AddError("Validation error occurred");
            }

            return result;
        }

        public async Task<ValidationResult> ValidateBusinessRulesAsync(ConnectedId entity)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Organization member count validation
                var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(entity.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                // Check member count against plan limits
                var memberCount = await GetOrganizationMemberCountAsync(entity.OrganizationId);
                var memberLimit = GetMemberLimitFromPlan(planKey);

                if (memberLimit > 0 && memberCount >= memberLimit)
                {
                    // Fire event for plan limit reached
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                    entity.OrganizationId,
                    planKey,
                    PlanLimitType.MemberCount,
                    memberCount,
                    memberLimit
                ));

                    result.AddError("OrganizationId",
                        $"Organization member limit ({memberLimit}) exceeded",
                        "MEMBER_LIMIT_EXCEEDED");
                }

                // Fix - Add null check
                if (entity.UserId.HasValue)
                {
                    var userOrgs = await SafeGetByUserAsync(entity.UserId.Value);
                    var userOrgCount = userOrgs.Count(o => !o.IsDeleted);
                    var maxOrganizations = GetMaxOrganizationsFromPlan(planKey);

                    if (maxOrganizations > 0 && userOrgCount >= maxOrganizations)
                    {
                        // Fire event for user organization limit
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                            entity.OrganizationId,
                            planKey,
                            PlanLimitType.MemberCount,
                            memberCount,
                            memberLimit
                        ));

                        result.AddWarning($"User organization limit ({maxOrganizations}) reached");
                    }


                    // Check role limits based on membership type
                    if (entity.MembershipType >= MembershipType.Admin)
                    {
                        var adminCount = userOrgs.Count(o =>
                            !o.IsDeleted &&
                            o.MembershipType >= MembershipType.Admin);

                        // Basic plan has limited admin roles
                        if (planKey == PricingConstants.SubscriptionPlans.BASIC_KEY && adminCount > 2)
                        {
                            result.AddWarning("Basic plan supports limited admin roles");
                        }
                    }

                    // Check role count limits for the organization using existing service method
                    var rolesSearchRequest = new SearchRolesRequest
                    {
                        OrganizationId = entity.OrganizationId,
                        PageSize = 1000  // Get count without loading all data
                    };

                    var rolesResult = await _roleService.GetRolesAsync(rolesSearchRequest);
                    if (rolesResult.IsSuccess && rolesResult.Data != null)
                    {
                        var roleCount = rolesResult.Data.TotalCount;
                        var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                        if (roleLimit > 0 && roleCount >= roleLimit * 0.9) // 90% warning threshold
                        {
                            result.AddWarning($"Organization approaching role limit ({roleCount}/{roleLimit})");

                            if (roleCount >= roleLimit)
                            {
                                await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                                    entity.OrganizationId,
                                    planKey,
                                    PlanLimitType.MemberCount,
                                    memberCount,
                                    memberLimit
                                ));
                                result.AddError("RoleLimit",
                                    $"Organization role limit ({roleLimit}) exceeded",
                                    "ROLE_LIMIT_EXCEEDED");
                            }
                        }
                    }

                    // Check API rate limits for the organization
                    var currentApiRate = await GetCurrentApiRateForOrganization(entity.OrganizationId);
                    var apiRateLimit = PricingConstants.SubscriptionPlans.ApiRateLimits[planKey];

                    if (apiRateLimit > 0)
                    {
                        if (currentApiRate >= apiRateLimit * 0.8) // 80% threshold warning
                        {
                            result.AddWarning($"Organization approaching API rate limit ({currentApiRate}/{apiRateLimit} requests per minute)");
                        }

                        if (currentApiRate >= apiRateLimit)
                        {
                            await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                             entity.OrganizationId,
                             planKey,
                             PlanLimitType.MemberCount,
                             memberCount,
                             memberLimit
                         ));

                            result.AddError("ApiRateLimit",
                                $"API rate limit ({apiRateLimit} requests/minute) exceeded",
                                "API_RATE_LIMIT_EXCEEDED");
                        }
                    }

                    // Validate storage limits if applicable
                    if (entity.OrganizationId != Guid.Empty)
                    {
                        var storageUsedGB = await GetOrganizationStorageUsageGB(entity.OrganizationId);
                        var storageLimitGB = PricingConstants.SubscriptionPlans.StorageLimits[planKey];

                        if (storageLimitGB > 0)
                        {
                            var usagePercentage = (storageUsedGB * 100m / storageLimitGB);

                            if (usagePercentage >= 90) // 90% threshold warning
                            {
                                result.AddWarning($"Organization storage usage at {usagePercentage:F1}% of limit");
                            }

                            if (storageUsedGB >= storageLimitGB)
                            {
                                await _eventBus.PublishAsync(new PlanLimitReachedEvent(
                          entity.OrganizationId,
                          planKey,
                          PlanLimitType.MemberCount,
                          memberCount,
                          memberLimit
                      ));
                                result.AddError("StorageLimit",
                                    $"Storage limit ({storageLimitGB}GB) exceeded",
                                    "STORAGE_LIMIT_EXCEEDED");
                            }
                        }
                    }

                    // Log validation for audit
                    await LogValidationAsync("BUSINESS_RULES", entity, result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during business rules validation for ConnectedId: {ConnectedId}", entity.Id);
                result.AddError("Business rules validation error", "VALIDATION_ERROR", "");
            }

            return result;
        }

        // Helper method - renamed for clarity
        private Task<decimal> GetOrganizationStorageUsageGB(Guid organizationId)
        {
            // This would typically query a storage service or database
            // For now, returning placeholder
            return Task.FromResult(0m);
        }

        // Existing helper method
        private async Task<int> GetCurrentApiRateForOrganization(Guid organizationId)
        {
            var cacheKey = $"api:rate:{organizationId}";
            var cachedValue = await _cacheService.GetAsync<string>(cacheKey);

            if (!string.IsNullOrEmpty(cachedValue) && int.TryParse(cachedValue, out var rate))
                return rate;

            return 0;
        }

        #endregion

        #region IConnectedIdValidator Implementation

        public async Task<ServiceResult> ValidateCreateRequestAsync(CreateConnectedIdRequest request)
        {
            try
            {
                var entity = MapRequestToEntity(request);
                var validationResult = await ValidateCreateAsync(entity);
                return ConvertToServiceResult(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ConnectedId creation request validation");
                return ServiceResult.Failure("Validation error occurred", "VALIDATION_ERROR");
            }
        }

        public async Task<ServiceResult> ValidateUpdateRequestAsync(
            Guid connectedId,
            UpdateConnectedIdRequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                if (!await HasUpdatePermissionAsync(connectedId, updatedByConnectedId))
                {
                    return ServiceResult.Failure("Update permission denied", "PERMISSION_DENIED");
                }

                var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (entity == null)
                {
                    return ServiceResult.NotFound("ConnectedId not found");
                }

                ApplyUpdateToEntity(entity, request);
                var validationResult = await ValidateUpdateAsync(entity);
                return ConvertToServiceResult(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ConnectedId update request validation");
                return ServiceResult.Failure("Validation error occurred", "VALIDATION_ERROR");
            }
        }

        public async Task<ServiceResult> ValidateDeleteRequestAsync(
            Guid connectedId,
            Guid deletedByConnectedId)
        {
            try
            {
                if (!await HasDeletePermissionAsync(connectedId, deletedByConnectedId))
                {
                    return ServiceResult.Failure("Delete permission denied", "PERMISSION_DENIED");
                }

                var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (entity == null)
                {
                    return ServiceResult.NotFound("ConnectedId not found");
                }

                var validationResult = await ValidateDeleteAsync(entity);
                return ConvertToServiceResult(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ConnectedId deletion request validation");
                return ServiceResult.Failure("Validation error occurred", "VALIDATION_ERROR");
            }
        }

        public async Task<ServiceResult> ValidateMappingAsync(Guid userId, Guid organizationId)
        {
            var result = new ValidationResult { IsValid = true };

            var user = await SafeGetUserAsync(userId);
            if (user == null || user.IsDeleted)
            {
                result.AddError("UserId", "Invalid user", "INVALID_USER");
            }

            var org = await SafeGetOrganizationAsync(organizationId);
            if (org is null)
            {
                result.AddError("OrganizationId", "Invalid organization", "INVALID_ORGANIZATION");
            }

            var existing = await SafeGetByUserAndOrganizationAsync(userId, organizationId);
            if (existing != null && !existing.IsDeleted)
            {
                result.AddError("Mapping already exists");
            }

            return ConvertToServiceResult(result);
        }

        public async Task<ServiceResult> ValidateDuplicationAsync(Guid userId, Guid organizationId)
        {
            var existing = await SafeGetByUserAndOrganizationAsync(userId, organizationId);
            if (existing != null && !existing.IsDeleted)
            {
                var result = ServiceResult.Failure("User already member of organization", "DUPLICATE_MEMBERSHIP");
                result.Metadata = new Dictionary<string, object>
                {
                    ["existingConnectedId"] = existing.Id,
                    ["status"] = existing.Status.ToString()
                };
                return result;
            }

            return ServiceResult.Success("No duplicate membership found");
        }

        public async Task<ServiceResult> ValidateMembershipChangeAsync(
            Guid connectedId,
            MembershipType currentType,
            MembershipType newType,
            Guid changedByConnectedId)
        {
            var changer = await _connectedIdRepository.GetByIdAsync(changedByConnectedId);
            if (changer == null)
            {
                return ServiceResult.Failure("Unauthorized change attempt", "UNAUTHORIZED");
            }

            bool canChange = currentType switch
            {
                MembershipType.Guest when newType == MembershipType.Member =>
                    changer.MembershipType >= MembershipType.Admin,
                MembershipType.Member when newType == MembershipType.Admin =>
                    changer.MembershipType == MembershipType.Owner,
                MembershipType.Admin when newType == MembershipType.Member =>
                    changer.MembershipType == MembershipType.Owner,
                _ when newType == MembershipType.Owner =>
                    changer.MembershipType == MembershipType.Owner,
                _ => false
            };

            if (!canChange)
            {
                return ServiceResult.Failure(
                    $"Cannot change from '{currentType}' to '{newType}'",
                    "INSUFFICIENT_PERMISSION");
            }

            if (currentType == MembershipType.Owner && newType != MembershipType.Owner)
            {
                var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (entity != null)
                {
                    var owners = await SafeGetByOrganizationAsync(entity.OrganizationId);
                    if (owners.Count(o => !o.IsDeleted && o.MembershipType == MembershipType.Owner) <= 1)
                    {
                        return ServiceResult.Failure("Cannot change last owner", "LAST_OWNER");
                    }
                }
            }

            return ServiceResult.Success("Membership type change allowed");
        }

        public async Task<ServiceResult> ValidateOwnerTransferAsync(
            Guid currentOwnerId,
            Guid newOwnerId)
        {
            var currentOwner = await _connectedIdRepository.GetByIdAsync(currentOwnerId);
            if (currentOwner?.MembershipType != MembershipType.Owner)
            {
                return ServiceResult.Failure("Current user is not owner", "NOT_OWNER");
            }

            var newOwner = await _connectedIdRepository.GetByIdAsync(newOwnerId);
            if (newOwner == null)
            {
                return ServiceResult.NotFound("Target user not found");
            }

            if (currentOwner.OrganizationId != newOwner.OrganizationId)
            {
                return ServiceResult.Failure("Different organization member", "DIFFERENT_ORGANIZATION");
            }

            if (newOwner.MembershipType != MembershipType.Admin)
            {
                return ServiceResult.Failure("Owner can only be transferred to Admin", "REQUIRES_ADMIN");
            }

            if (newOwner.Status != ConnectedIdStatus.Active)
            {
                return ServiceResult.Failure("Cannot transfer to inactive user", "INACTIVE_USER");
            }

            return ServiceResult.Success("Owner transfer allowed");
        }

        public async Task<ServiceResult> ValidateInvitationCreateAsync(
            CreateInvitationRequest request,
            Guid invitedByConnectedId)
        {
            var inviter = await _connectedIdRepository.GetByIdAsync(invitedByConnectedId);
            if (inviter == null || inviter.MembershipType == MembershipType.Guest)
            {
                return ServiceResult.Failure("No invitation permission", "NO_INVITATION_PERMISSION");
            }

            if (!IsValidEmail(request.InviteeEmail))
            {
                return ServiceResult.Failure("Invalid email address", "INVALID_EMAIL");
            }

            var existingUser = await SafeGetUserByEmailAsync(request.InviteeEmail!);
            if (existingUser != null)
            {
                var existing = await SafeGetByUserAndOrganizationAsync(
                    existingUser.Id, request.OrganizationId);
                if (existing != null && !existing.IsDeleted)
                {
                    return ServiceResult.Failure("Already organization member", "ALREADY_MEMBER");
                }
            }

            var memberCount = await GetOrganizationMemberCountAsync(request.OrganizationId);
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(request.OrganizationId);

            if (subscription != null)
            {
                var memberLimit = GetMemberLimitFromPlan(subscription.PlanKey);
                if (memberLimit > 0 && memberCount >= memberLimit)
                {
                    return ServiceResult.Failure(
                        $"Organization member limit ({memberLimit}) exceeded",
                        "MEMBER_LIMIT_EXCEEDED");
                }
            }

            return ServiceResult.Success("Invitation creation allowed");
        }

        public async Task<ServiceResult> ValidateInvitationAcceptAsync(
            string invitationCode,
            Guid userId)
        {
            var invitation = await SafeGetInvitationByCodeAsync(invitationCode);
            if (invitation == null)
            {
                return ServiceResult.Failure("Invalid invitation code", "INVALID_CODE");
            }

            if (invitation.IsExpired(_dateTimeProvider.UtcNow))
            {
                return ServiceResult.Failure("Invitation expired", "INVITATION_EXPIRED");
            }

            var user = await SafeGetUserAsync(userId);
            if (user == null || user.IsDeleted)
            {
                return ServiceResult.Failure("Invalid user", "INVALID_USER");
            }

            return ServiceResult.Success("Invitation accept allowed");
        }

        public async Task<ServiceResult> ValidateActivationAsync(Guid connectedId)
        {
            var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (entity == null)
            {
                return ServiceResult.NotFound("ConnectedId not found");
            }

            if (entity.Status == ConnectedIdStatus.Suspended)
            {
                return ServiceResult.Failure("Cannot activate suspended status", "SUSPENDED");
            }

            // FIX: UserId가 null이 아닌 경우에만 사용자 정보를 조회
            if (!entity.UserId.HasValue)
            {
                return ServiceResult.Failure("User ID is missing", "INVALID_USER_ID");
            }

            var user = await SafeGetUserAsync(entity.UserId.Value);
            if (user == null || user.IsDeleted || user.Status != UserStatus.Active)
            {
                return ServiceResult.Failure("User is inactive", "USER_INACTIVE");
            }

            var org = await SafeGetOrganizationAsync(entity.OrganizationId);
            if (org is null)
            {
                return ServiceResult.Failure("Organization is inactive", "ORGANIZATION_INACTIVE");
            }

            return ServiceResult.Success("Activation allowed");
        }

        public async Task<ServiceResult> ValidateSuspensionAsync(
            Guid connectedId,
            string reason,
            Guid suspendedByConnectedId)
        {
            if (string.IsNullOrWhiteSpace(reason))
            {
                return ServiceResult.Failure("Suspension reason required", "REASON_REQUIRED");
            }

            if (connectedId == suspendedByConnectedId)
            {
                return ServiceResult.Failure("Cannot suspend self", "CANNOT_SUSPEND_SELF");
            }

            var suspender = await _connectedIdRepository.GetByIdAsync(suspendedByConnectedId);
            if (suspender == null || suspender.MembershipType < MembershipType.Admin)
            {
                return ServiceResult.Failure("Suspension permission denied", "INSUFFICIENT_PERMISSION");
            }

            var target = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (target == null)
            {
                return ServiceResult.NotFound("Target ConnectedId not found");
            }

            if (target.MembershipType == MembershipType.Owner)
            {
                return ServiceResult.Failure("Cannot suspend owner", "CANNOT_SUSPEND_OWNER");
            }

            return ServiceResult.Success("Suspension allowed");
        }

        public async Task<ServiceResult> ValidateSessionCreationAsync(
            Guid connectedId,
            string ipAddress,
            string? userAgent = null)
        {
            var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (entity == null)
            {
                return ServiceResult.NotFound("ConnectedId not found");
            }

            if (entity.Status != ConnectedIdStatus.Active)
            {
                return ServiceResult.Failure("Inactive ConnectedId", "INACTIVE");
            }

            var activeSessions = await SafeGetActiveSessionsAsync(connectedId);
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(entity.OrganizationId);

            if (subscription != null)
            {
                var sessionLimit = GetSessionLimitFromPlan(subscription.PlanKey);
                if (sessionLimit > 0 && activeSessions.Count() >= sessionLimit)
                {
                    return ServiceResult.Failure(
                        $"Session limit ({sessionLimit}) exceeded",
                        "SESSION_LIMIT_EXCEEDED");
                }
            }

            return ServiceResult.Success("Session creation allowed");
        }

        public async Task<ServiceResult> ValidateActivityRateAsync(
            Guid connectedId,
            string activityType,
            DateTime? lastActivityTime = null)
        {
            var rateLimitKey = $"ratelimit:{connectedId}:{activityType}";

            var cachedValue = await _cacheService.GetAsync<string>(rateLimitKey);
            var currentCount = 0;
            if (!string.IsNullOrEmpty(cachedValue) && int.TryParse(cachedValue, out var parsed))
            {
                currentCount = parsed;
            }

            var entity = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (entity == null)
            {
                return ServiceResult.NotFound("ConnectedId not found");
            }

            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(entity.OrganizationId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var limit = GetRateLimitFromPlan(activityType, planKey);

            if (currentCount >= limit)
            {
                return ServiceResult.Failure(
                    $"Activity rate limit ({currentCount}/{limit}) exceeded",
                    "RATE_LIMIT_EXCEEDED");
            }

            if (lastActivityTime.HasValue)
            {
                var timeSinceLastActivity = _dateTimeProvider.UtcNow - lastActivityTime.Value;
                if (timeSinceLastActivity.TotalSeconds < 1)
                {
                    return ServiceResult.Success("Activity allowed with abnormal pattern detected");
                }
            }

            await _cacheService.IncrementAsync(rateLimitKey, 60);
            return ServiceResult.Success("Activity allowed");
        }

        public async Task<ServiceResult> ValidatePermissionAsync(
            Guid connectedId,
            string requiredPermission)
        {
            // Get active roles for the ConnectedId
            var activeRoles = await _connectedIdRoleRepository.GetActiveRolesAsync(connectedId);

            if (activeRoles.Any())
            {
                // Check permissions for each role
                foreach (var roleAssignment in activeRoles)
                {
                    var permissionsResult = await _roleService.GetPermissionsAsync(
                        roleAssignment.RoleId,
                        includeInherited: true
                    );

                    if (permissionsResult.IsSuccess && permissionsResult.Data != null)
                    {
                        var hasPermission = permissionsResult.Data
                            .Any(p => p.Scope == requiredPermission ||
                                     p.Name == requiredPermission);

                        if (hasPermission)
                        {
                            return ServiceResult.Success("Permission verified");
                        }
                    }
                }
            }

            // Fallback to MembershipType-based permission check
            var connected = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (connected != null)
            {
                bool hasPermission = connected.MembershipType switch
                {
                    MembershipType.Owner => true,
                    MembershipType.Admin => !requiredPermission.StartsWith("OWNER_"),
                    MembershipType.Member => !requiredPermission.StartsWith("ADMIN_"),
                    MembershipType.Guest => requiredPermission.StartsWith("GUEST_"),
                    _ => false
                };

                if (hasPermission)
                {
                    return ServiceResult.Success("Permission verified");
                }
            }

            return ServiceResult.Failure(
                $"Required permission missing: {requiredPermission}",
                "PERMISSION_DENIED");
        }

        public async Task<ServiceResult> ValidateActionOnTargetAsync(
            Guid actorConnectedId,
            Guid targetConnectedId,
            string action)
        {
            var actor = await _connectedIdRepository.GetByIdAsync(actorConnectedId);
            var target = await _connectedIdRepository.GetByIdAsync(targetConnectedId);

            if (actor == null || target == null)
            {
                return ServiceResult.NotFound("ConnectedId not found");
            }

            if (actor.OrganizationId != target.OrganizationId)
            {
                return ServiceResult.Failure("Different organization member", "DIFFERENT_ORGANIZATION");
            }

            bool canPerform = action switch
            {
                "UPDATE" => actor.MembershipType >= target.MembershipType,
                "DELETE" => actor.MembershipType > target.MembershipType,
                "SUSPEND" => actor.MembershipType > target.MembershipType && actor.MembershipType >= MembershipType.Admin,
                _ => false
            };

            if (!canPerform)
            {
                return ServiceResult.Failure(
                    $"Cannot perform '{action}' action",
                    "INSUFFICIENT_PERMISSION");
            }

            return ServiceResult.Success("Action allowed");
        }

        public async Task<ServiceResult<BulkValidationResult>> ValidateBulkCreateAsync(
            List<CreateConnectedIdRequest> requests,
            Guid createdByConnectedId)
        {
            var bulkResult = new BulkValidationResult
            {
                TotalCount = requests.Count
            };

            var creator = await _connectedIdRepository.GetByIdAsync(createdByConnectedId);
            if (creator == null || creator.MembershipType < MembershipType.Admin)
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = false,
                    ErrorMessage = "Bulk creation permission denied",
                    ErrorCode = "INSUFFICIENT_PERMISSION",
                    Data = null
                };
            }

            for (int i = 0; i < requests.Count; i++)
            {
                var validation = await ValidateCreateRequestAsync(requests[i]);
                var itemResult = new ItemValidationResult
                {
                    Index = i,
                    Identifier = requests[i].UserId.ToString(),
                    IsValid = validation.IsSuccess
                };

                if (!validation.IsSuccess)
                {
                    itemResult.Errors = new List<string> { validation.ErrorMessage ?? "Validation failed" };
                    bulkResult.InvalidCount++;
                }
                else
                {
                    bulkResult.ValidCount++;
                }

                bulkResult.ItemResults.Add(itemResult);
            }

            bulkResult.IsValid = bulkResult.InvalidCount == 0;

            if (bulkResult.IsValid)
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = true,
                    Data = bulkResult,
                    Message = "Bulk validation successful"
                };
            }
            else
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = false,
                    Data = bulkResult,
                    ErrorMessage = $"Bulk validation failed: {bulkResult.InvalidCount}/{bulkResult.TotalCount} items invalid",
                    ErrorCode = "BULK_VALIDATION_FAILED"
                };
            }
        }

        public async Task<ServiceResult<BulkValidationResult>> ValidateBulkStatusChangeAsync(
            List<Guid> connectedIds,
            ConnectedIdStatus newStatus,
            Guid changedByConnectedId)
        {
            var bulkResult = new BulkValidationResult
            {
                TotalCount = connectedIds.Count
            };

            var changer = await _connectedIdRepository.GetByIdAsync(changedByConnectedId);
            if (changer == null || changer.MembershipType < MembershipType.Admin)
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = false,
                    ErrorMessage = "Bulk status change permission denied",
                    ErrorCode = "INSUFFICIENT_PERMISSION",
                    Data = null
                };
            }

            for (int i = 0; i < connectedIds.Count; i++)
            {
                var entity = await _connectedIdRepository.GetByIdAsync(connectedIds[i]);
                var itemResult = new ItemValidationResult
                {
                    Index = i,
                    Identifier = connectedIds[i].ToString()
                };

                if (entity == null)
                {
                    itemResult.IsValid = false;
                    itemResult.Errors = new List<string> { "ConnectedId not found" };
                    bulkResult.InvalidCount++;
                }
                else
                {
                    var validation = await ValidateStatusTransitionAsync(
                        connectedIds[i], entity.Status, newStatus, changedByConnectedId);

                    itemResult.IsValid = validation.IsSuccess;
                    if (!validation.IsSuccess)
                    {
                        itemResult.Errors = new List<string> { validation.ErrorMessage ?? "Validation failed" };
                        bulkResult.InvalidCount++;
                    }
                    else
                    {
                        bulkResult.ValidCount++;
                    }
                }

                bulkResult.ItemResults.Add(itemResult);
            }

            bulkResult.IsValid = bulkResult.InvalidCount == 0;

            if (bulkResult.IsValid)
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = true,
                    Data = bulkResult,
                    Message = "Bulk status change validation successful"
                };
            }
            else
            {
                return new ServiceResult<BulkValidationResult>
                {
                    IsSuccess = false,
                    Data = bulkResult,
                    ErrorMessage = $"Bulk validation failed: {bulkResult.InvalidCount}/{bulkResult.TotalCount} items invalid",
                    ErrorCode = "BULK_VALIDATION_FAILED"
                };
            }
        }


        #endregion

        #region Helper Methods

        private async Task<User?> SafeGetUserAsync(Guid userId)
        {
            try
            {
                return await _userRepository.GetByIdAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get user by ID: {UserId}", userId);
                return null;
            }
        }

        private async Task<User?> SafeGetUserByEmailAsync(string email)
        {
            try
            {
                return await _userRepository.GetByEmailAsync(email);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get user by email: {Email}", email);
                return null;
            }
        }

        private async Task<Core.Entities.Organization.Organization?> SafeGetOrganizationAsync(Guid organizationId)
        {
            try
            {
                return await _organizationRepository.GetByIdAsync(organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get organization by ID: {OrganizationId}", organizationId);
                return null;
            }
        }

        private async Task<ConnectedId?> SafeGetByUserAndOrganizationAsync(Guid userId, Guid organizationId)
        {
            try
            {
                return await _connectedIdRepository.GetByUserAndOrganizationAsync(userId, organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get ConnectedId by user and organization");
                return null;
            }
        }

        private async Task<IEnumerable<ConnectedId>> SafeGetByOrganizationAsync(Guid organizationId)
        {
            try
            {
                // IRepository의 Query() 메서드 사용
                var query = _connectedIdRepository.Query()
                    .Where(c => c.OrganizationId == organizationId);

                return await query.ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get ConnectedIds by organization");
                return Enumerable.Empty<ConnectedId>();
            }
        }
        private async Task<IEnumerable<ConnectedId>> SafeGetByUserAsync(Guid userId)
        {
            try
            {
                // IRepository의 Query() 메서드 사용
                var query = _connectedIdRepository.Query()
                    .Where(c => c.UserId == userId);

                return await query.ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get ConnectedIds by user");
                return Enumerable.Empty<ConnectedId>();
            }
        }

        private async Task<IEnumerable<SessionEntity>> SafeGetActiveSessionsAsync(Guid connectedId)
        {
            try
            {
                return await _sessionRepository.GetActiveSessionsAsync(connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get active sessions");
                return Enumerable.Empty<SessionEntity>();
            }
        }

        private async Task<Core.Entities.Auth.Invitation?> SafeGetInvitationByCodeAsync(string code)
        {
            try
            {
                return await _invitationRepository.GetByCodeAsync(code);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get invitation by code");
                return null;
            }
        }

        private async Task<int> GetOrganizationMemberCountAsync(Guid organizationId)
        {
            var cacheKey = string.Format(CACHE_KEY_ORG_MEMBER_COUNT, organizationId);
            var cachedValue = await _cacheService.GetAsync<string>(cacheKey);

            if (!string.IsNullOrEmpty(cachedValue) && int.TryParse(cachedValue, out var cached))
                return cached;

            var members = await SafeGetByOrganizationAsync(organizationId);
            var count = members.Count(m => !m.IsDeleted && m.Status == ConnectedIdStatus.Active);

            await _cacheService.SetAsync(cacheKey, count.ToString(), TimeSpan.FromSeconds(CACHE_DURATION_SECONDS));
            return count;
        }

        private int GetMemberLimitFromPlan(string planKey)
        {
            if (!PricingConstants.SubscriptionPlans.MAULimits.TryGetValue(planKey, out var limit))
            {
                return PricingConstants.SubscriptionPlans.MAULimits[PricingConstants.SubscriptionPlans.BASIC_KEY];
            }
            return limit;
        }

        private int GetMaxOrganizationsFromPlan(string planKey)
        {
            if (!PricingConstants.SubscriptionPlans.OrganizationLimits.TryGetValue(planKey, out var limit))
            {
                return PricingConstants.SubscriptionPlans.OrganizationLimits[PricingConstants.SubscriptionPlans.BASIC_KEY];
            }
            return limit;
        }

        private int GetSessionLimitFromPlan(string planKey)
        {
            return planKey switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => 1,
                PricingConstants.SubscriptionPlans.PRO_KEY => 3,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => 10,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => -1,
                _ => 1
            };
        }

        private int GetRateLimitFromPlan(string activityType, string planKey)
        {
            if (!PricingConstants.SubscriptionPlans.ApiRateLimits.TryGetValue(planKey, out var baseLimit))
            {
                baseLimit = PricingConstants.SubscriptionPlans.ApiRateLimits[PricingConstants.SubscriptionPlans.BASIC_KEY];
            }

            return activityType switch
            {
                "API_CALL" => baseLimit,
                "LOGIN_ATTEMPT" => 5,
                "PASSWORD_RESET" => 3,
                _ => baseLimit
            };
        }

        private bool IsValidEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            return Regex.IsMatch(email,
                @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
        }

        private ServiceResult ConvertToServiceResult(ValidationResult validationResult)
        {
            if (validationResult.IsValid)
            {
                return ServiceResult.Success("Validation successful");
            }

            var primaryError = validationResult.Errors.FirstOrDefault();
            return ServiceResult.Failure(
                primaryError?.Message ?? "Validation failed",
                primaryError?.ErrorCode ?? "VALIDATION_FAILED"
            );
        }

        private ConnectedId MapRequestToEntity(CreateConnectedIdRequest request)
        {
            return new ConnectedId
            {
                UserId = request.UserId,
                OrganizationId = request.OrganizationId,
                Provider = request.Provider,
                ProviderUserId = request.ProviderUserId,
                AccessToken = request.AccessToken,
                RefreshToken = request.RefreshToken,
                TokenExpiresAt = request.TokenExpiresAt,
                MembershipType = request.MembershipType,
                DisplayName = request.DisplayName,
                InvitedByConnectedId = request.InvitedByConnectedId,
                Status = request.InitialStatus,
                JoinedAt = _dateTimeProvider.UtcNow
            };
        }

        private void ApplyUpdateToEntity(ConnectedId entity, UpdateConnectedIdRequest request)
        {
            if (request.MembershipType.HasValue)
                entity.MembershipType = request.MembershipType.Value;

            if (request.Status.HasValue)
                entity.Status = request.Status.Value;

            if (request.UpdateDisplayName)
                entity.DisplayName = request.DisplayName;

            if (request.LastActiveAt.HasValue)
                entity.LastActiveAt = request.LastActiveAt.Value;
        }

        private async Task<bool> HasUpdatePermissionAsync(Guid connectedId, Guid updaterConnectedId)
        {
            if (connectedId == updaterConnectedId)
                return true;

            var updater = await _connectedIdRepository.GetByIdAsync(updaterConnectedId);
            return updater?.MembershipType >= MembershipType.Admin;
        }

        private async Task<bool> HasDeletePermissionAsync(Guid connectedId, Guid deleterConnectedId)
        {
            var deleter = await _connectedIdRepository.GetByIdAsync(deleterConnectedId);
            var target = await _connectedIdRepository.GetByIdAsync(connectedId);

            if (deleter == null || target == null)
                return false;

            if (deleter.OrganizationId != target.OrganizationId)
                return false;

            return deleter.MembershipType > target.MembershipType;
        }

        private async Task LogValidationAsync(string action, ConnectedId entity, ValidationResult result)
        {
            await _auditService.LogActionAsync(
                performedByConnectedId: entity.Id,
                action: $"ConnectedId.Validate.{action}",
                actionType: AuditActionType.Validation,
                resourceType: "ConnectedId",
                resourceId: entity.Id.ToString(),
                success: result.IsValid,
                metadata: System.Text.Json.JsonSerializer.Serialize(new
                {
                    UserId = entity.UserId,
                    OrganizationId = entity.OrganizationId,
                    Success = result.IsValid,
                    Errors = result.Errors,
                    Warnings = result.Warnings
                })
            );
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateCreateRequestAsync(CreateConnectedIdRequest request)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateUpdateRequestAsync(Guid connectedId, UpdateConnectedIdRequest request, Guid updatedByConnectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateDeleteRequestAsync(Guid connectedId, Guid deletedByConnectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateMappingAsync(Guid userId, Guid organizationId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateDuplicationAsync(Guid userId, Guid organizationId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateMembershipChangeAsync(Guid connectedId, MembershipType currentType, MembershipType newType, Guid changedByConnectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateOwnerTransferAsync(Guid currentOwnerId, Guid newOwnerId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateInvitationCreateAsync(CreateInvitationRequest request, Guid invitedByConnectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateInvitationAcceptAsync(string invitationCode, Guid userId)
        {
            throw new NotImplementedException();
        }

        public async Task<ServiceResult> ValidateInvitationCancelAsync(
            Guid invitationId,
            Guid cancelledByConnectedId)
        {
            var canceller = await _connectedIdRepository.GetByIdAsync(cancelledByConnectedId);
            if (canceller == null || canceller.MembershipType < MembershipType.Admin)
            {
                return ServiceResult.Failure("No cancel permission", "NO_CANCEL_PERMISSION");
            }

            return ServiceResult.Success("Invitation cancel allowed");
        }


        public async Task<ServiceResult> ValidateStatusTransitionAsync(
            Guid connectedId,
            ConnectedIdStatus currentStatus,
            ConnectedIdStatus newStatus,
            Guid changedByConnectedId)
        {
            var validTransitions = new Dictionary<ConnectedIdStatus, List<ConnectedIdStatus>>
            {
                [ConnectedIdStatus.Pending] = new() { ConnectedIdStatus.Active, ConnectedIdStatus.Rejected },
                [ConnectedIdStatus.Active] = new() { ConnectedIdStatus.Inactive, ConnectedIdStatus.Suspended, ConnectedIdStatus.Deleted },
                [ConnectedIdStatus.Inactive] = new() { ConnectedIdStatus.Active, ConnectedIdStatus.Deleted },
                [ConnectedIdStatus.Suspended] = new() { ConnectedIdStatus.Active, ConnectedIdStatus.Deleted },
                [ConnectedIdStatus.Rejected] = new() { ConnectedIdStatus.Deleted },
                [ConnectedIdStatus.Deleted] = new()
            };

            if (!validTransitions.ContainsKey(currentStatus) ||
                !validTransitions[currentStatus].Contains(newStatus))
            {
                return ServiceResult.Failure(
                    $"Cannot transition from '{currentStatus}' to '{newStatus}'",
                    "INVALID_TRANSITION");
            }

            var changer = await _connectedIdRepository.GetByIdAsync(changedByConnectedId);
            if (changer == null || changer.MembershipType < MembershipType.Admin)
            {
                return ServiceResult.Failure("Status change permission denied", "INSUFFICIENT_PERMISSION");
            }

            return ServiceResult.Success("Status transition allowed");
        }


        Task<ServiceResult> IConnectedIdValidator.ValidateActivationAsync(Guid connectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateSuspensionAsync(Guid connectedId, string reason, Guid suspendedByConnectedId)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateSessionCreationAsync(Guid connectedId, string ipAddress, string? userAgent)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateActivityRateAsync(Guid connectedId, string activityType, DateTime? lastActivityTime)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidatePermissionAsync(Guid connectedId, string requiredPermission)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult> IConnectedIdValidator.ValidateActionOnTargetAsync(Guid actorConnectedId, Guid targetConnectedId, string action)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult<BulkValidationResult>> IConnectedIdValidator.ValidateBulkCreateAsync(List<CreateConnectedIdRequest> requests, Guid createdByConnectedId)
        {
            throw new NotImplementedException();
        }


        #endregion
    }

    #region Support Classes


    public class Session
    {
        public Guid Id { get; set; }
        public Guid ConnectedId { get; set; }
        public bool IsActive { get; set; }
    }

    #endregion
}