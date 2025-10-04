using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Models.Organization.Requests;
using Microsoft.Extensions.Logging;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;

namespace AuthHive.Auth.Services.Validators
{
    /// <summary>
    /// 조직 검증 구현체 - AuthHive v16
    /// 조직 생성/수정/삭제 시 비즈니스 규칙 검증
    /// AI 중요: 조직 계층 구조 및 플랜별 제한사항 엄격 적용
    /// </summary>
    public class OrganizationValidator : IOrganizationValidator
    {
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IPlanService _planService;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cache;
        private readonly ILogger<OrganizationValidator> _logger;

        // 캐시 키 상수
        private const string ORG_KEY_CACHE = "org_key_exists_{0}";
        private const string ORG_HIERARCHY_CACHE = "org_hierarchy_{0}";
        private const int CACHE_DURATION_MINUTES = 10;

        public OrganizationValidator(
            IOrganizationRepository organizationRepository,
            IOrganizationHierarchyRepository hierarchyRepository,
            IPlanService planService,
            IEventBus eventBus,
            IAuditService auditService,
            ICacheService cache,
            ILogger<OrganizationValidator> logger)
        {
            _organizationRepository = organizationRepository;
            _hierarchyRepository = hierarchyRepository;
            _planService = planService;
            _eventBus = eventBus;
            _auditService = auditService;
            _cache = cache;
            _logger = logger;
        }

        /// <summary>
        /// 조직 생성 요청 검증
        /// </summary>
        public async Task<ValidationResult> ValidateCreateAsync(CreateOrganizationRequest request)
        {
            var errors = new List<ValidationError>();

            // 1. 기본 필드 검증
            if (string.IsNullOrWhiteSpace(request.Name))
                errors.Add(new ValidationError { Field = "Name", Message = "조직명은 필수입니다.", ErrorCode = "NAME_REQUIRED" });

            if (request.Name?.Length > 100)
                errors.Add(new ValidationError { Field = "Name", Message = "조직명은 100자 이하여야 합니다.", ErrorCode = "NAME_TOO_LONG" });

            // 2. 조직 키 중복 및 유효성 검증
            if (!string.IsNullOrWhiteSpace(request.OrganizationKey))
            {
                var keyValidation = await ValidateOrganizationKeyAsync(request.OrganizationKey);
                if (!keyValidation.IsValid) errors.AddRange(keyValidation.Errors);
            }
            else
            {
                errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 필수입니다.", ErrorCode = ValidationErrorCodes.Required });
            }

            // 3. 상위 조직 검증 (하위 조직 생성인 경우)
            if (request.ParentId.HasValue)
            {
                var parentValidation = await ValidateChildOrganizationCreationAsync(request.ParentId.Value);
                if (!parentValidation.IsValid) errors.AddRange(parentValidation.Errors);
            }

            // 4. 플랜별 조직 생성 제한 검증 (부모가 있을 경우 부모 조직 기준)
            var checkOrganizationId = request.ParentId;
            if (checkOrganizationId.HasValue)
            {
                var planLimitValidation = await ValidatePlanOrganizationLimitAsync(checkOrganizationId.Value);
                if (!planLimitValidation.IsValid) errors.AddRange(planLimitValidation.Errors);
            }

            // 5. 조직 타입별 검증
            if (request.Type == OrganizationType.Enterprise)
            {
                errors.Add(new ValidationError { Field = "Type", Message = "Enterprise 조직 생성은 관리자 승인이 필요합니다.", ErrorCode = "ENTERPRISE_APPROVAL_REQUIRED" });
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 수정 요청 검증
        /// </summary>
        public async Task<ValidationResult> ValidateUpdateAsync(Guid organizationId, UpdateOrganizationRequest request)
        {
            var errors = new List<ValidationError>();

            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                errors.Add(new ValidationError { Field = "OrganizationId", Message = "조직을 찾을 수 없습니다.", ErrorCode = ValidationErrorCodes.NotFound });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 이름 변경 검증
            if (!string.IsNullOrWhiteSpace(request.Name) && request.Name != organization.Name)
            {
                if (request.Name.Length > 200)
                    errors.Add(new ValidationError { Field = "Name", Message = "조직명은 200자 이하여야 합니다.", ErrorCode = ValidationErrorCodes.TooLong });
            }

            // 타입 변경 검증
            if (request.Type != organization.Type)
            {
                var typeValidation = await ValidateTypeChangeAsync(organizationId, organization.Type, request.Type);
                if (!typeValidation.IsValid) errors.AddRange(typeValidation.Errors);
            }

            // Region 유효성 검증
            if (!string.IsNullOrWhiteSpace(request.Region) && !System.Text.RegularExpressions.Regex.IsMatch(request.Region, @"^[A-Z]{2}$"))
            {
                errors.Add(new ValidationError { Field = "Region", Message = "지역 코드는 ISO 3166-1 alpha-2 형식이어야 합니다.", ErrorCode = ValidationErrorCodes.InvalidFormat });
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 삭제 가능 여부 검증
        /// </summary>
        public async Task<ValidationResult> ValidateDeleteAsync(Guid organizationId)
        {
            var errors = new List<ValidationError>();

            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                errors.Add(new ValidationError { Field = "OrganizationId", Message = "조직을 찾을 수 없습니다.", ErrorCode = "ORG_NOT_FOUND" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            // 하위 조직 확인
            var children = await _hierarchyRepository.GetChildrenAsync(organizationId);
            if (children.Any())
                errors.Add(new ValidationError { Field = "Hierarchy", Message = $"하위 조직({children.Count()})이 존재하여 삭제할 수 없습니다.", ErrorCode = "HAS_CHILD_ORGANIZATIONS" });

            // TODO: 활성 멤버십 확인 로직 추가

            // 활성 구독 확인
            var activeSubscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (activeSubscription != null)
                errors.Add(new ValidationError { Field = "Subscription", Message = "활성 구독이 존재하여 삭제할 수 없습니다.", ErrorCode = "HAS_ACTIVE_SUBSCRIPTION" });

            // 시스템 조직 삭제 방지
            if (organization.OrganizationKey?.StartsWith("system-") == true || organization.OrganizationKey == "authhive")
                errors.Add(new ValidationError { Field = "Type", Message = "시스템 조직은 삭제할 수 없습니다.", ErrorCode = "SYSTEM_ORG_UNDELETABLE" });

            await _auditService.LogActionAsync(null, "Organization.Delete.Attempt", AuditActionType.Delete, "Organization", organizationId.ToString(), !errors.Any(), System.Text.Json.JsonSerializer.Serialize(new { Status = organization.Status, Type = organization.Type }));

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 비즈니스 규칙 검증 (엔티티 대상)
        /// </summary>
        public async Task<ValidationResult> ValidateBusinessRulesAsync(OrganizationEntity entity)
        {
            var errors = new List<ValidationError>();

            // [통합] 기존 ValidateAsync의 기본 엔티티 검증 로직을 여기에 통합
            if (entity == null)
            {
                errors.Add(new ValidationError { Field = "Entity", Message = "조직 엔티티가 null입니다.", ErrorCode = "NULL_ENTITY" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }
            if (string.IsNullOrWhiteSpace(entity.Name))
                errors.Add(new ValidationError { Field = "Name", Message = "조직명은 필수입니다.", ErrorCode = ValidationErrorCodes.Required });
            if (string.IsNullOrWhiteSpace(entity.OrganizationKey))
                errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 필수입니다.", ErrorCode = ValidationErrorCodes.Required });
            if (!string.IsNullOrWhiteSpace(entity.OrganizationKey) && !System.Text.RegularExpressions.Regex.IsMatch(entity.OrganizationKey, @"^[a-z0-9-]+$"))
                errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 영문 소문자, 숫자, 하이픈만 사용 가능합니다.", ErrorCode = ValidationErrorCodes.InvalidFormat });

            if (errors.Any()) return new ValidationResult { IsValid = false, Errors = errors };


            // 플랜별 제한사항 검증
            var planResult = await ValidatePlanOrganizationLimitAsync(entity.Id);
            if (!planResult.IsValid) errors.AddRange(planResult.Errors);

            // 계층 깊이 검증
            if (entity.ParentId.HasValue)
            {
                var depthResult = await ValidateHierarchyDepthAsync(entity.Id);
                if (!depthResult.IsValid) errors.AddRange(depthResult.Errors);
            }

            // 상태별 제한사항 검증
            switch (entity.Status)
            {
                case OrganizationStatus.Suspended:
                case OrganizationStatus.Terminated:
                    // 이 부분의 로직은 상태 '변경' 시에 더 적합하므로 ValidateStatusChangeAsync에서 처리하는 것이 좋습니다.
                    // 여기서는 현재 상태가 유효한지에 대한 검증이 필요합니다. 
                    break;
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 키 유효성 및 중복 검증
        /// </summary>
        public async Task<ValidationResult> ValidateOrganizationKeyAsync(string organizationKey, Guid? excludeOrganizationId = null)
        {
            var errors = new List<ValidationError>();

            if (string.IsNullOrWhiteSpace(organizationKey))
            {
                errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 필수입니다.", ErrorCode = "KEY_REQUIRED" });
            }
            else
            {
                if (!System.Text.RegularExpressions.Regex.IsMatch(organizationKey, @"^[a-z0-9-]+$"))
                    errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 영문 소문자, 숫자, 하이픈만 사용 가능합니다.", ErrorCode = "KEY_INVALID_FORMAT" });

                if (organizationKey.Length < 3 || organizationKey.Length > 50)
                    errors.Add(new ValidationError { Field = "OrganizationKey", Message = "조직 키는 3자 이상 50자 이하여야 합니다.", ErrorCode = "KEY_INVALID_LENGTH" });

                var reservedKeys = new[] { "admin", "api", "www", "app", "auth", "system", "root", "super" };
                if (reservedKeys.Contains(organizationKey.ToLower()))
                    errors.Add(new ValidationError { Field = "OrganizationKey", Message = "예약된 조직 키는 사용할 수 없습니다.", ErrorCode = "KEY_RESERVED" });
            }

            if (!errors.Any())
            {
                var existingOrg = await _organizationRepository.GetByOrganizationKeyAsync(organizationKey);
                if (existingOrg != null && (!excludeOrganizationId.HasValue || existingOrg.Id != excludeOrganizationId))
                    errors.Add(new ValidationError { Field = "OrganizationKey", Message = "이미 사용 중인 조직 키입니다.", ErrorCode = "KEY_DUPLICATE" });
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 계층 구조 검증 (순환 참조 방지)
        /// </summary>
        public async Task<ValidationResult> ValidateHierarchyAsync(Guid organizationId, Guid? newParentId)
        {
            var errors = new List<ValidationError>();

            if (!newParentId.HasValue) return new ValidationResult { IsValid = true };

            if (organizationId == newParentId.Value)
                errors.Add(new ValidationError { Field = "ParentOrganizationId", Message = "조직은 자기 자신을 상위 조직으로 설정할 수 없습니다.", ErrorCode = "SELF_PARENT" });

            var parent = await _organizationRepository.GetByIdAsync(newParentId.Value);
            if (parent == null)
                errors.Add(new ValidationError { Field = "ParentOrganizationId", Message = "상위 조직을 찾을 수 없습니다.", ErrorCode = "PARENT_NOT_FOUND" });

            if (!errors.Any())
            {
                if (await _hierarchyRepository.WouldCreateCycleAsync(organizationId, newParentId.Value))
                    errors.Add(new ValidationError { Field = "Hierarchy", Message = "순환 참조가 발생합니다. 하위 조직을 상위로 설정할 수 없습니다.", ErrorCode = "CIRCULAR_REFERENCE" });

                var depthValidation = await ValidateHierarchyDepthAsync(organizationId);
                if (!depthValidation.IsValid) errors.AddRange(depthValidation.Errors);
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 상태 변경 검증
        /// </summary>
        public async Task<ValidationResult> ValidateStatusChangeAsync(Guid organizationId, OrganizationStatus currentStatus, OrganizationStatus newStatus)
        {
            var errors = new List<ValidationError>();

            var validTransitions = new Dictionary<OrganizationStatus, HashSet<OrganizationStatus>>
            {
                [OrganizationStatus.Pending] = new() { OrganizationStatus.Active, OrganizationStatus.Inactive },
                [OrganizationStatus.Active] = new() { OrganizationStatus.Suspended, OrganizationStatus.Inactive },
                [OrganizationStatus.Suspended] = new() { OrganizationStatus.Active, OrganizationStatus.Inactive, OrganizationStatus.Terminated },
                [OrganizationStatus.Inactive] = new() { OrganizationStatus.Active, OrganizationStatus.Terminated },
                [OrganizationStatus.Terminated] = new() { }
            };

            if (!validTransitions.ContainsKey(currentStatus) || !validTransitions[currentStatus].Contains(newStatus))
                errors.Add(new ValidationError { Field = "Status", Message = $"Transitioning from '{currentStatus}' to '{newStatus}' is not allowed.", ErrorCode = "INVALID_STATUS_TRANSITION" });

            if (newStatus == OrganizationStatus.Suspended)
            {
                // ✅ FIXED: Switched from object initializer to the correct constructor call.
                var suspendedEvent = new OrganizationSuspendedEvent(
                    organizationId: organizationId,
                    previousStatus: currentStatus,
                    reason: "Organization status was changed to Suspended.",
                    triggeredBy: null // Or pass the user's ConnectedId if available in this context
                );
                await _eventBus.PublishAsync(suspendedEvent);
            }

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }
        /// <summary>
        /// 조직 타입 변경 검증
        /// </summary>
        public Task<ValidationResult> ValidateTypeChangeAsync(Guid organizationId, OrganizationType currentType, OrganizationType newType)
        {
            var errors = new List<ValidationError>();

            if (newType == OrganizationType.Enterprise && currentType != OrganizationType.Enterprise)
                errors.Add(new ValidationError { Field = "Type", Message = "Enterprise 타입으로의 변경은 관리자 승인이 필요합니다.", ErrorCode = "ENTERPRISE_APPROVAL_REQUIRED" });

            if (currentType == OrganizationType.Enterprise && newType != OrganizationType.Enterprise)
                errors.Add(new ValidationError { Field = "Type", Message = "Enterprise 타입에서 다른 타입으로 변경할 수 없습니다.", ErrorCode = "ENTERPRISE_DOWNGRADE_FORBIDDEN" });

            if ((currentType == OrganizationType.Government || currentType == OrganizationType.Educational) && (newType != currentType))
                errors.Add(new ValidationError { Field = "Type", Message = $"{currentType} 타입은 변경할 수 없습니다.", ErrorCode = "TYPE_CHANGE_RESTRICTED" });

            return Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }

        /// <summary>
        /// 하위 조직 생성 가능 여부 검증
        /// </summary>
        public async Task<ValidationResult> ValidateChildOrganizationCreationAsync(Guid parentOrganizationId)
        {
            var errors = new List<ValidationError>();

            var parentOrg = await _organizationRepository.GetByIdAsync(parentOrganizationId);
            if (parentOrg == null)
            {
                errors.Add(new ValidationError { Field = "ParentOrganizationId", Message = "상위 조직을 찾을 수 없습니다.", ErrorCode = "PARENT_NOT_FOUND" });
                return new ValidationResult { IsValid = false, Errors = errors };
            }

            if (parentOrg.Status != OrganizationStatus.Active)
                errors.Add(new ValidationError { Field = "ParentOrganization", Message = $"비활성 상태({parentOrg.Status})의 조직에는 하위 조직을 생성할 수 없습니다.", ErrorCode = "PARENT_INACTIVE" });

            var planSubscription = await _planService.GetCurrentSubscriptionForOrgAsync(parentOrganizationId);
            if (planSubscription != null)
            {
                var planKey = planSubscription.PlanKey;
                var orgLimit = GetOrganizationLimitByPlan(planKey);

                if (orgLimit != -1)
                {
                    var children = await _hierarchyRepository.GetChildrenAsync(parentOrganizationId);
                    if (children.Count() >= orgLimit)
                        errors.Add(new ValidationError { Field = "ChildOrganizations", Message = $"플랜({planKey})의 하위 조직 제한({orgLimit}개)에 도달했습니다.", ErrorCode = "CHILD_ORG_LIMIT_REACHED" });
                }
            }

            var depthValidation = await ValidateHierarchyDepthAsync(parentOrganizationId);
            if (!depthValidation.IsValid) errors.AddRange(depthValidation.Errors);

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        /// <summary>
        /// 조직 계층 깊이 검증
        /// </summary>
        public async Task<ValidationResult> ValidateHierarchyDepthAsync(Guid organizationId, int maxDepth = 5)
        {
            var errors = new List<ValidationError>();

            var depth = await _hierarchyRepository.GetDepthLevelAsync(organizationId);

            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization != null)
            {
                var planSubscription = await _planService.GetCurrentSubscriptionForOrgAsync(organization.ParentId ?? organizationId);
                if (planSubscription != null)
                {
                    var planKey = planSubscription.PlanKey;
                    var depthLimit = GetOrganizationDepthLimitByPlan(planKey);

                    if (depthLimit != -1 && depth >= depthLimit)
                        errors.Add(new ValidationError { Field = "HierarchyDepth", Message = $"플랜({planKey})의 계층 깊이 제한({depthLimit})에 도달했습니다.", ErrorCode = "HIERARCHY_DEPTH_LIMIT" });
                }
            }

            if (depth >= maxDepth)
                errors.Add(new ValidationError { Field = "HierarchyDepth", Message = $"최대 계층 깊이({maxDepth})를 초과할 수 없습니다.", ErrorCode = "MAX_DEPTH_EXCEEDED" });

            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        #region Private Helper Methods

        private async Task<ValidationResult> ValidatePlanOrganizationLimitAsync(Guid organizationId)
        {
            var errors = new List<ValidationError>();
            var planSubscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (planSubscription != null)
            {
                var planKey = planSubscription.PlanKey;
                var orgLimit = GetOrganizationLimitByPlan(planKey);

                if (orgLimit != -1)
                {
                    var descendants = await _organizationRepository.GetDescendantsAsync(organizationId);
                    if (descendants.Count() >= orgLimit)
                        errors.Add(new ValidationError { Field = "OrganizationCount", Message = $"플랜({planKey})의 조직 수 제한({orgLimit}개)에 도달했습니다.", ErrorCode = "ORG_LIMIT_REACHED" });
                }
            }
            return new ValidationResult { IsValid = !errors.Any(), Errors = errors };
        }

        private int GetOrganizationLimitByPlan(string planKey)
        {
            return PricingConstants.SubscriptionPlans.OrganizationLimits.TryGetValue(planKey, out var limit) ? limit : 1;
        }

        private int GetOrganizationDepthLimitByPlan(string planKey)
        {
            return PricingConstants.SubscriptionPlans.OrganizationDepthLimits.TryGetValue(planKey, out var depth) ? depth : 1;
        }

        #endregion

        #region Cache Wrapper Classes (if needed, otherwise can be removed)
        // 캐시 로직이 복잡하지 않다면 이 클래스는 필요 없을 수 있습니다.
        // 현재 ValidateOrganizationKeyAsync 에서는 사용하지 않도록 수정했습니다.
        private class CachedBoolValue { public bool Value { get; set; } }
        #endregion
    }
}