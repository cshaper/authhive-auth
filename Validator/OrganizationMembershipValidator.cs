using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Constants.Common;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Business.Platform;
using AuthHive.Core.Models.Common.Validation;
using Microsoft.Extensions.Logging;

using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using ValidationError = AuthHive.Core.Models.Common.Validation.ValidationError;
using AuthHive.Core.Interfaces.Organization.Validators;
using AuthHive.Core.Models.Business.Events;

namespace AuthHive.Auth.Services.Validators
{
    public class OrganizationMembershipValidator : IOrganizationMembershipValidator
    {
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IPlanService _planService;
        private readonly IEventBus _eventBus;
        private readonly ILogger<OrganizationMembershipValidator> _logger;
        
        public OrganizationMembershipValidator(
            IOrganizationRepository organizationRepository,
            IOrganizationMembershipRepository membershipRepository,
            IConnectedIdRepository connectedIdRepository,
            IPlanService planService,
            IEventBus eventBus,
            ILogger<OrganizationMembershipValidator> logger)
        {
            _organizationRepository = organizationRepository;
            _membershipRepository = membershipRepository;
            _connectedIdRepository = connectedIdRepository;
            _planService = planService;
            _eventBus = eventBus;
            _logger = logger;
        }

        public async Task<ValidationResult> ValidateCreateAsync(OrganizationMembership membership, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            var organization = await _organizationRepository.GetByIdAsync(membership.OrganizationId);
            if (organization == null)
                return ValidationResult.Failure(new ValidationError { Field = "OrganizationId", Message = "Organization not found.", ErrorCode = "ORGANIZATION_NOT_FOUND" });

            if (organization.Status != OrganizationStatus.Active)
                errors.Add(new ValidationError { Field = "Organization", Message = $"Cannot add members to an inactive organization (Status: {organization.Status}).", ErrorCode = "ORGANIZATION_INACTIVE" });

            if (!await _connectedIdRepository.ExistsAsync(membership.ConnectedId))
                errors.Add(new ValidationError { Field = "ConnectedId", Message = "User (ConnectedId) not found.", ErrorCode = "USER_NOT_FOUND" });

            var duplicateCheckResult = await ValidateDuplicateMembershipAsync(membership.OrganizationId, membership.ConnectedId);
            if (!duplicateCheckResult.IsValid)
                errors.AddRange(duplicateCheckResult.Errors);

            var memberLimitResult = await ValidateMemberLimitAsync(membership.OrganizationId);
            if (!memberLimitResult.IsValid)
                errors.AddRange(memberLimitResult.Errors);

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        public async Task<ValidationResult> ValidateUpdateAsync(OrganizationMembership membership, OrganizationMembership existingMembership, Guid connectedId)
        {
            var errors = new List<ValidationError>();
            
            if (membership.MemberRole != existingMembership.MemberRole)
            {
                var roleChangeResult = await ValidateRoleChangeAsync(existingMembership, membership.MemberRole.ToString(), connectedId);
                if (!roleChangeResult.IsValid) errors.AddRange(roleChangeResult.Errors);
            }

            if (membership.Status != existingMembership.Status)
            {
                var statusChangeResult = await ValidateStatusChangeAsync(existingMembership, membership.Status, connectedId);
                if (!statusChangeResult.IsValid) errors.AddRange(statusChangeResult.Errors);
            }
            
            if (membership.AccessLevel != existingMembership.AccessLevel)
            {
                var accessLevelResult = await ValidateAccessLevelChangeAsync(existingMembership, membership.AccessLevel, connectedId);
                if (!accessLevelResult.IsValid) errors.AddRange(accessLevelResult.Errors);
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }
        
        public async Task<ValidationResult> ValidateDeleteAsync(OrganizationMembership membership, Guid connectedId)
        {
            var errors = new List<ValidationError>();
            
            if (membership.MemberRole == OrganizationMemberRole.Owner)
            {
                var owners = await _membershipRepository.GetMembersByRoleAsync(membership.OrganizationId, OrganizationMemberRole.Owner);
                if (owners.Count() <= 1)
                {
                    errors.Add(new ValidationError { Field = "MemberRole", Message = "The last owner of an organization cannot be deleted.", ErrorCode = "LAST_OWNER_CANNOT_BE_DELETED" });
                }
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }
        
        public async Task<ValidationResult> ValidateDuplicateMembershipAsync(Guid organizationId, Guid userId, Guid? excludeMembershipId = null)
        {
            var existingMembership = await _membershipRepository.GetMembershipAsync(organizationId, userId);

            if (existingMembership != null && (excludeMembershipId == null || existingMembership.Id != excludeMembershipId))
            {
                var error = new ValidationError { Field = "UserId", Message = "This user is already a member of the organization.", ErrorCode = "USER_ALREADY_MEMBER" };
                return ValidationResult.Failure(error);
            }

            return ValidationResult.Success();
        }

        /// <summary>
        /// 역할 변경 검증
        /// </summary>
        public async Task<ValidationResult> ValidateRoleChangeAsync(OrganizationMembership membership, string newRole, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            // Parse the string role to enum
            if (!Enum.TryParse<OrganizationMemberRole>(newRole, out var newRoleEnum))
            {
                errors.Add(new ValidationError { Field = "MemberRole", Message = "Invalid role specified.", ErrorCode = "INVALID_ROLE" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            if (membership.MemberRole == OrganizationMemberRole.Owner && newRoleEnum != OrganizationMemberRole.Owner)
            {
                var owners = await _membershipRepository.GetMembersByRoleAsync(membership.OrganizationId, OrganizationMemberRole.Owner);
                if (owners.Count() <= 1)
                {
                    errors.Add(new ValidationError { Field = "MemberRole", Message = "The role of the last owner cannot be changed.", ErrorCode = "LAST_OWNER_ROLE_CHANGE_NOT_ALLOWED" });
                }
            }

            if (newRoleEnum == OrganizationMemberRole.Owner)
            {
                var modifier = await _membershipRepository.GetMembershipAsync(membership.OrganizationId, connectedId);
                if (modifier?.MemberRole != OrganizationMemberRole.Owner)
                {
                    errors.Add(new ValidationError { Field = "Permission", Message = "Only an existing owner can assign the owner role.", ErrorCode = "INSUFFICIENT_PERMISSION_FOR_OWNER_ROLE" });
                }
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 상태 변경 검증
        /// </summary>
        public async Task<ValidationResult> ValidateStatusChangeAsync(OrganizationMembership membership, OrganizationMembershipStatus newStatus, Guid connectedId)
        {
            var validTransitions = new Dictionary<OrganizationMembershipStatus, HashSet<OrganizationMembershipStatus>>
            {
                [OrganizationMembershipStatus.Invited] = new() { OrganizationMembershipStatus.Active, OrganizationMembershipStatus.Rejected, OrganizationMembershipStatus.Expired },
                [OrganizationMembershipStatus.Active] = new() { OrganizationMembershipStatus.Suspended, OrganizationMembershipStatus.Left },
                [OrganizationMembershipStatus.Suspended] = new() { OrganizationMembershipStatus.Active },
            };

            if (validTransitions.TryGetValue(membership.Status, out var allowedStatuses) && allowedStatuses.Contains(newStatus))
            {
                return await Task.FromResult(ValidationResult.Success());
            }

            var error = new ValidationError { Field = "Status", Message = $"Cannot transition membership from '{membership.Status}' to '{newStatus}'.", ErrorCode = "INVALID_STATUS_TRANSITION" };
            return await Task.FromResult(ValidationResult.Failure(error));
        }

        /// <summary>
        /// [WHEN] 관리자가 조직 멤버의 세부 권한 레벨(0-100)을 조정하려고 할 때 호출됩니다.
        /// [WHY]  유효하지 않은 레벨(예: 101)이 설정되는 것을 막고, 낮은 등급의 관리자가 자신보다 높은 등급의 권한을 다른 멤버에게 부여하는 것을 방지하기 위함입니다.
        /// [HOW]  액세스 레벨이 유효한 범위(0-100) 내에 있는지 확인하고, 높은 수준의 레벨을 부여하려는 경우 변경을 시도하는 사용자가 'Owner'인지 검사합니다.
        /// [SCENARIO] 조직의 'Admin'이 다른 멤버의 액세스 레벨을 최상위 등급인 95로 설정하려고 시도하면, 이 검증이 실패하여 'Owner만 높은 레벨을 부여할 수 있다'는 오류를 반환합니다.
        /// </summary>
        public async Task<ValidationResult> ValidateAccessLevelChangeAsync(OrganizationMembership membership, int newAccessLevel, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            if (newAccessLevel < 0 || newAccessLevel > 100)
            {
                errors.Add(new ValidationError { Field = "AccessLevel", Message = "Access level must be between 0 and 100.", ErrorCode = "ACCESS_LEVEL_OUT_OF_RANGE" });
            }

            // 예시 규칙: 90 이상의 높은 액세스 레벨은 Owner만 부여 가능
            if (newAccessLevel >= 90)
            {
                var modifier = await _membershipRepository.GetMembershipAsync(membership.OrganizationId, connectedId);
                if (modifier?.MemberRole != OrganizationMemberRole.Owner)
                {
                    errors.Add(new ValidationError { Field = "Permission", Message = "Only an Owner can grant an access level of 90 or higher.", ErrorCode = "INSUFFICIENT_PERMISSION_FOR_ACCESS_LEVEL" });
                }
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 타입 변경 검증
        /// </summary>
        public async Task<ValidationResult> ValidateMembershipTypeChangeAsync(OrganizationMembership membership, OrganizationMembershipType newType, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            // 타입 변경 권한 확인
            var modifier = await _membershipRepository.GetMembershipAsync(membership.OrganizationId, connectedId);
            if (modifier == null || (modifier.MemberRole != OrganizationMemberRole.Owner && modifier.MemberRole != OrganizationMemberRole.Admin))
            {
                errors.Add(new ValidationError { Field = "Permission", Message = "Only Owners and Admins can change membership types.", ErrorCode = "INSUFFICIENT_PERMISSION_FOR_TYPE_CHANGE" });
            }

            // Direct에서 External로의 변경은 특별한 검증이 필요할 수 있음
            if (membership.MembershipType == OrganizationMembershipType.Direct && newType == OrganizationMembershipType.External)
            {
                errors.Add(new ValidationError { Field = "MembershipType", Message = "Cannot change direct member to external.", ErrorCode = "INVALID_TYPE_CHANGE" });
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 초대 검증
        /// </summary>
        public async Task<ValidationResult> ValidateInvitationAsync(Guid organizationId, string email, string role, Guid invitedByConnectedId)
        {
            var errors = new List<ValidationError>();

            // 조직 존재 여부 확인
            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                errors.Add(new ValidationError { Field = "OrganizationId", Message = "Organization not found.", ErrorCode = "ORGANIZATION_NOT_FOUND" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 초대자 권한 확인
            var inviter = await _membershipRepository.GetMembershipAsync(organizationId, invitedByConnectedId);
            if (inviter == null || (inviter.MemberRole != OrganizationMemberRole.Owner && inviter.MemberRole != OrganizationMemberRole.Admin))
            {
                errors.Add(new ValidationError { Field = "Permission", Message = "Only Owners and Admins can invite new members.", ErrorCode = "INSUFFICIENT_PERMISSION_TO_INVITE" });
            }

            // 이메일 유효성 검증
            if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            {
                errors.Add(new ValidationError { Field = "Email", Message = "Invalid email address.", ErrorCode = "INVALID_EMAIL" });
            }

            // 역할 유효성 검증
            if (!Enum.TryParse<OrganizationMemberRole>(role, out var roleEnum))
            {
                errors.Add(new ValidationError { Field = "Role", Message = "Invalid role specified.", ErrorCode = "INVALID_ROLE" });
            }

            // 멤버 수 제한 확인
            var memberLimitResult = await ValidateMemberLimitAsync(organizationId);
            if (!memberLimitResult.IsValid)
                errors.AddRange(memberLimitResult.Errors);

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 수락 검증
        /// </summary>
        public Task<ValidationResult> ValidateAcceptInvitationAsync(Guid invitationId, Guid userId)
        {
            var errors = new List<ValidationError>();

            // 초대 존재 여부 확인 (실제 구현 시 InvitationRepository가 필요)
            // TODO: Implement invitation validation logic
            _logger.LogInformation($"Validating invitation acceptance for invitation {invitationId} by user {userId}");

            return Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }

        /// <summary>
        /// 벌크 멤버십 생성 검증
        /// </summary>
        public async Task<ValidationResult> ValidateBulkCreateAsync(Guid organizationId, List<OrganizationMembership> memberships, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            // 조직 존재 여부 확인
            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                errors.Add(new ValidationError { Field = "OrganizationId", Message = "Organization not found.", ErrorCode = "ORGANIZATION_NOT_FOUND" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 권한 확인
            var creator = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
            if (creator == null || (creator.MemberRole != OrganizationMemberRole.Owner && creator.MemberRole != OrganizationMemberRole.Admin))
            {
                errors.Add(new ValidationError { Field = "Permission", Message = "Only Owners and Admins can bulk create memberships.", ErrorCode = "INSUFFICIENT_PERMISSION_FOR_BULK_CREATE" });
            }

            // 중복 체크
            var existingMembers = await _membershipRepository.GetMembersAsync(organizationId);
            var existingConnectedIds = existingMembers.Select(m => m.ConnectedId).ToHashSet();
            var duplicates = memberships.Where(m => existingConnectedIds.Contains(m.ConnectedId)).ToList();
            
            if (duplicates.Any())
            {
                errors.Add(new ValidationError { Field = "Memberships", Message = $"{duplicates.Count} duplicate members found.", ErrorCode = "DUPLICATE_MEMBERS_IN_BULK" });
            }

            // 멤버 수 제한 확인
            var memberLimitResult = await ValidateMemberLimitAsync(organizationId, memberships.Count);
            if (!memberLimitResult.IsValid)
                errors.AddRange(memberLimitResult.Errors);

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 권한 검증
        /// </summary>
        public Task<ValidationResult> ValidatePermissionsAsync(OrganizationMembership membership, string requiredPermission)
        {
            var errors = new List<ValidationError>();

            // 멤버십 상태 확인
            if (membership.Status != OrganizationMembershipStatus.Active)
            {
                errors.Add(new ValidationError { Field = "Status", Message = "Membership is not active.", ErrorCode = "MEMBERSHIP_NOT_ACTIVE" });
                return Task.FromResult(new ValidationResult { IsValid = false, Errors = errors });
            }

            // 권한 매핑 (실제 구현 시 더 복잡한 권한 시스템이 필요할 수 있음)
            var rolePermissions = new Dictionary<OrganizationMemberRole, HashSet<string>>
            {
                [OrganizationMemberRole.Owner] = new() { "all", "manage_members", "manage_settings", "view_data", "edit_data" },
                [OrganizationMemberRole.Admin] = new() { "manage_members", "view_data", "edit_data" },
                [OrganizationMemberRole.Member] = new() { "view_data", "edit_own_data" },
                [OrganizationMemberRole.Guest] = new() { "view_data" }
            };

            if (rolePermissions.TryGetValue(membership.MemberRole, out var permissions))
            {
                if (!permissions.Contains(requiredPermission) && !permissions.Contains("all"))
                {
                    errors.Add(new ValidationError { Field = "Permission", Message = $"Member does not have '{requiredPermission}' permission.", ErrorCode = "PERMISSION_DENIED" });
                }
            }

            return Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }

        /// <summary>
        /// 계층 구조 멤버십 검증 (상위/하위 조직)
        /// </summary>
        public async Task<ValidationResult> ValidateHierarchicalMembershipAsync(Guid organizationId, Guid userId, bool includeParent, bool includeChildren)
        {
            var errors = new List<ValidationError>();

            // 기본 멤버십 확인
            var membership = await _membershipRepository.GetMembershipAsync(organizationId, userId);
            if (membership == null)
            {
                errors.Add(new ValidationError { Field = "Membership", Message = "User is not a member of the organization.", ErrorCode = "NOT_A_MEMBER" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 상위 조직 검증
            if (includeParent)
            {
                // TODO: Implement parent organization validation
                _logger.LogInformation($"Checking parent organization membership for user {userId}");
            }

            // 하위 조직 검증
            if (includeChildren)
            {
                // TODO: Implement child organizations validation
                _logger.LogInformation($"Checking child organizations membership for user {userId}");
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 만료 검증
        /// </summary>
        public async Task<ValidationResult> ValidateExpirationAsync(OrganizationMembership membership, DateTime? newExpirationDate = null)
        {
            var errors = new List<ValidationError>();

            // 현재 만료 상태 확인
            if (membership.ExpiresAt.HasValue && membership.ExpiresAt.Value < DateTime.UtcNow)
            {
                errors.Add(new ValidationError { Field = "ExpiresAt", Message = "Membership has already expired.", ErrorCode = "MEMBERSHIP_EXPIRED" });
            }

            // 새 만료일 검증
            if (newExpirationDate.HasValue)
            {
                if (newExpirationDate.Value < DateTime.UtcNow)
                {
                    errors.Add(new ValidationError { Field = "ExpiresAt", Message = "Cannot set expiration date in the past.", ErrorCode = "INVALID_EXPIRATION_DATE" });
                }

                // 최대 만료 기간 검증 (예: 1년)
                if (newExpirationDate.Value > DateTime.UtcNow.AddYears(1))
                {
                    errors.Add(new ValidationError { Field = "ExpiresAt", Message = "Expiration date cannot be more than 1 year in the future.", ErrorCode = "EXPIRATION_TOO_FAR" });
                }
            }

            return await Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }

        /// <summary>
        /// 최대 멤버 수 제한 검증
        /// </summary>
        public async Task<ValidationResult> ValidateMemberLimitAsync(Guid organizationId, int additionalMembers = 1)
        {
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

            if (PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var limit) && limit != -1)
            {
                var currentCount = await _membershipRepository.GetMemberCountAsync(organizationId);
                if ((currentCount + additionalMembers) > limit)
                {
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    { 
                        OrganizationId = organizationId, 
                        PlanKey = planKey, 
                        LimitType = PlanLimitType.MemberCount,
                        CurrentValue = currentCount, 
                        MaxValue = limit 
                    });
                    return ValidationResult.Failure(new ValidationError { Field = "MemberCount", Message = $"Member limit ({limit}) for the current plan has been exceeded.", ErrorCode = "MEMBER_LIMIT_EXCEEDED" });
                }
            }
            return ValidationResult.Success();
        }

        /// <summary>
        /// 외부 사용자 멤버십 검증
        /// </summary>
        public async Task<ValidationResult> ValidateExternalUserMembershipAsync(Guid organizationId, string externalUserId, string externalProvider)
        {
            var errors = new List<ValidationError>();

            // 외부 사용자 ID 유효성 검증
            if (string.IsNullOrWhiteSpace(externalUserId))
            {
                errors.Add(new ValidationError { Field = "ExternalUserId", Message = "External user ID is required.", ErrorCode = "EXTERNAL_USER_ID_REQUIRED" });
            }

            // 외부 제공자 유효성 검증
            var validProviders = new[] { "Google", "Microsoft", "GitHub", "SAML" };
            if (!validProviders.Contains(externalProvider))
            {
                errors.Add(new ValidationError { Field = "ExternalProvider", Message = "Invalid external provider.", ErrorCode = "INVALID_EXTERNAL_PROVIDER" });
            }

            // 조직 존재 여부 및 상태 확인
            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                errors.Add(new ValidationError { Field = "OrganizationId", Message = "Organization not found.", ErrorCode = "ORGANIZATION_NOT_FOUND" });
            }
            else if (organization.Status != OrganizationStatus.Active)
            {
                errors.Add(new ValidationError { Field = "Organization", Message = "Organization is not active.", ErrorCode = "ORGANIZATION_INACTIVE" });
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 멤버십 이전 검증 (다른 조직으로)
        /// </summary>
        public async Task<ValidationResult> ValidateTransferMembershipAsync(OrganizationMembership membership, Guid targetOrganizationId, Guid connectedId)
        {
            var errors = new List<ValidationError>();

            // 대상 조직 존재 여부 확인
            var targetOrganization = await _organizationRepository.GetByIdAsync(targetOrganizationId);
            if (targetOrganization == null)
            {
                errors.Add(new ValidationError { Field = "TargetOrganizationId", Message = "Target organization not found.", ErrorCode = "TARGET_ORGANIZATION_NOT_FOUND" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 권한 확인 (양쪽 조직 모두에서)
            var sourcePermission = await _membershipRepository.GetMembershipAsync(membership.OrganizationId, connectedId);
            var targetPermission = await _membershipRepository.GetMembershipAsync(targetOrganizationId, connectedId);

            if (sourcePermission?.MemberRole != OrganizationMemberRole.Owner)
            {
                errors.Add(new ValidationError { Field = "Permission", Message = "Only source organization owner can transfer memberships.", ErrorCode = "INSUFFICIENT_SOURCE_PERMISSION" });
            }

            if (targetPermission?.MemberRole != OrganizationMemberRole.Owner && targetPermission?.MemberRole != OrganizationMemberRole.Admin)
            {
                errors.Add(new ValidationError { Field = "Permission", Message = "Requires owner or admin permission in target organization.", ErrorCode = "INSUFFICIENT_TARGET_PERMISSION" });
            }

            // 중복 멤버십 확인
            var duplicateCheck = await ValidateDuplicateMembershipAsync(targetOrganizationId, membership.ConnectedId);
            if (!duplicateCheck.IsValid)
            {
                errors.AddRange(duplicateCheck.Errors);
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 비즈니스 규칙 검증
        /// </summary>
        public async Task<ValidationResult> ValidateBusinessRulesAsync(OrganizationMembership membership)
        {
            var errors = new List<ValidationError>();

            // 규칙 1: Guest는 AccessLevel이 50을 넘을 수 없음
            if (membership.MemberRole == OrganizationMemberRole.Guest && membership.AccessLevel > 50)
            {
                errors.Add(new ValidationError { Field = "AccessLevel", Message = "Guest members cannot have access level greater than 50.", ErrorCode = "GUEST_ACCESS_LEVEL_EXCEEDED" });
            }

            // 규칙 2: Suspended 멤버는 Owner 역할을 가질 수 없음
            if (membership.Status == OrganizationMembershipStatus.Suspended && membership.MemberRole == OrganizationMemberRole.Owner)
            {
                errors.Add(new ValidationError { Field = "Status", Message = "Suspended members cannot be owners.", ErrorCode = "SUSPENDED_OWNER_NOT_ALLOWED" });
            }

            // 규칙 3: External 멤버는 Admin 이상의 역할을 가질 수 없음
            if (membership.MembershipType == OrganizationMembershipType.External && 
                (membership.MemberRole == OrganizationMemberRole.Owner || membership.MemberRole == OrganizationMemberRole.Admin))
            {
                errors.Add(new ValidationError { Field = "MemberRole", Message = "External members cannot be owners or admins.", ErrorCode = "EXTERNAL_HIGH_ROLE_NOT_ALLOWED" });
            }

            // 규칙 4: 만료된 멤버십은 Active 상태가 될 수 없음
            if (membership.ExpiresAt.HasValue && membership.ExpiresAt.Value < DateTime.UtcNow && 
                membership.Status == OrganizationMembershipStatus.Active)
            {
                errors.Add(new ValidationError { Field = "Status", Message = "Expired membership cannot be active.", ErrorCode = "EXPIRED_ACTIVE_NOT_ALLOWED" });
            }

            return await Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }
    }
}