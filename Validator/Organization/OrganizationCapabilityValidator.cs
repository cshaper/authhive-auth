using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using Microsoft.Extensions.Logging;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using ValidationError = AuthHive.Core.Models.Common.Validation.ValidationError;
using static AuthHive.Core.Constants.Common.OrganizationConstants;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Organization.Events;

namespace AuthHive.Auth.Services.Validators
{
    /// <summary>
    /// [WHAT] 조직(Organization)이 특정 기능(Capability)을 사용할 수 있는지 모든 비즈니스 규칙을 검증합니다.
    /// [WHY]  조직의 구독 플랜, 현재 활성화된 다른 기능과의 관계 등 복잡한 조건을 확인하여 시스템의 무결성과 정책을 강제하기 위해 필요합니다.
    /// [HOW]  서비스 레이어에서 Capability를 할당/변경하는 로직이 실행되기 직전에 호출되어, 각종 규칙을 검사하고 결과를 반환합니다.
    /// </summary>
    public class OrganizationCapabilityValidator : IOrganizationCapabilityValidator
    {
        private readonly IOrganizationCapabilityAssignmentRepository _assignmentRepository;
        private readonly IPlanService _planService;
        private readonly ICacheService _cache;
        private readonly IDomainEvent _eventBus;
        private readonly IAuditService _auditService;
        private readonly ILogger<OrganizationCapabilityValidator> _logger;

        private const string ORG_HAS_CAPABILITY_CACHE = "org_has_capability_{0}_{1}";
        private const int CACHE_DURATION_MINUTES = 10;

        // [WHAT] 서로 함께 활성화될 수 없는 기능들의 목록입니다. (예: 기본 인증 vs SSO)
        // [WHY]  기술적으로 또는 정책적으로 동시에 존재할 수 없는 기능들의 조합을 막기 위함입니다.
        private static readonly Dictionary<string, HashSet<string>> ConflictingCapabilities = new()
        {
            [FeatureCapabilityCodes.SingleSignOn] = new() { FeatureCapabilityCodes.BasicAuthentication },
            [FeatureCapabilityCodes.AdvancedSecurity] = new() { FeatureCapabilityCodes.BasicSecurity },
            [FeatureCapabilityCodes.CustomBranding] = new() { FeatureCapabilityCodes.WhiteLabel }
        };

        // [WHAT] 특정 기능을 활성화하기 위해 먼저 활성화되어 있어야 하는 기능들의 목록입니다. (예: SCIM을 켜려면 SSO가 먼저 필요)
        // [WHY]  기능 간의 기술적 종속성을 강제하여 시스템 오류를 방지하기 위함입니다.
        private static readonly Dictionary<string, HashSet<string>> DependentCapabilities = new()
        {
            [FeatureCapabilityCodes.SCIM] = new() { FeatureCapabilityCodes.SingleSignOn },
            [FeatureCapabilityCodes.AdvancedAnalytics] = new() { FeatureCapabilityCodes.BasicAnalytics },
            [FeatureCapabilityCodes.EnterpriseSupport] = new() { FeatureCapabilityCodes.PremiumSupport }
        };

        public OrganizationCapabilityValidator(
            IOrganizationCapabilityAssignmentRepository assignmentRepository,
            IPlanService planService,
            ICacheService cache,
            IDomainEvent eventBus,
            IAuditService auditService,
            ILogger<OrganizationCapabilityValidator> logger)
        {
            _assignmentRepository = assignmentRepository;
            _planService = planService;
            _cache = cache;
            _eventBus = eventBus;
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// [WHEN] 관리자가 조직에 새로운 기능을 할당하려고 할 때 호출됩니다.
        /// [WHY]  새 기능이 기존에 활성화된 다른 기능들과 충돌하거나, 필요한 선행 기능이 없는 상태로 추가되는 것을 막기 위함입니다.
        /// [HOW]  새 기능의 코드를 `ConflictingCapabilities`와 `DependentCapabilities` 딕셔너리와 비교하여 규칙 위반 여부를 확인합니다.
        /// [SCENARIO] 'SSO' 기능이 이미 활성화된 조직에 관리자가 '기본 인증' 기능을 추가하려고 시도하면, 이 검증이 실패하여 "CAPABILITY_CONFLICT" 오류를 반환합니다.
        /// </summary>
        public async Task<ValidationResult> ValidateConflictsAsync(
            Guid organizationId,
            OrganizationCapability newCapability,
            IEnumerable<OrganizationCapability> existingCapabilities)
        {
            var errors = new List<ValidationError>();
            var newCapabilityCode = newCapability.Code;

            foreach (var existingCap in existingCapabilities)
            {
                var existingCapCode = existingCap.Code;
                if (ConflictingCapabilities.TryGetValue(newCapabilityCode, out var conflicts) && conflicts.Contains(existingCapCode))
                    errors.Add(new ValidationError { Field = "Capability", Message = $"Capability '{newCapability.Name}' conflicts with '{existingCap.Name}'.", ErrorCode = "CAPABILITY_CONFLICT" });

                if (ConflictingCapabilities.TryGetValue(existingCapCode, out var reverseConflicts) && reverseConflicts.Contains(newCapabilityCode))
                    errors.Add(new ValidationError { Field = "Capability", Message = $"Cannot add '{newCapability.Name}' because it conflicts with the already active '{existingCap.Name}'.", ErrorCode = "CAPABILITY_CONFLICT" });
            }

            if (DependentCapabilities.TryGetValue(newCapabilityCode, out var dependencies))
            {
                var existingCapabilityCodes = existingCapabilities.Select(c => c.Code).ToHashSet();
                foreach (var requiredCapCode in dependencies)
                {
                    if (!existingCapabilityCodes.Contains(requiredCapCode))
                        errors.Add(new ValidationError { Field = "Dependency", Message = $"To use '{newCapability.Name}', the '{requiredCapCode}' capability must be enabled first.", ErrorCode = "MISSING_DEPENDENCY" });
                }
            }

            return await Task.FromResult(new ValidationResult { IsValid = !errors.Any(), Errors = errors });
        }

        /// <summary>
        /// [WHEN] 특정 기능에 대한 설정을 저장하거나 업데이트할 때 호출됩니다.
        /// [WHY]  기능이 동작하는 데 필수적인 설정값이 누락되거나, 설정값의 형식이 잘못되는 것을 방지하기 위함입니다.
        /// [HOW]  기능의 `RequiresConfiguration` 속성을 확인하고, 전달된 설정 문자열이 유효한 JSON 형식인지 파싱하여 검증합니다.
        /// [SCENARIO] 'SSO' 기능은 IdP URL 같은 설정이 필수입니다. 관리자가 설정을 비워둔 채 저장을 시도하면, 이 검증이 실패하여 "SETTINGS_REQUIRED" 오류를 반환합니다.
        /// </summary>
        public async Task<ValidationResult> ValidateSettingsAsync(
            OrganizationCapability capability,
            string settings)
        {
            if (string.IsNullOrWhiteSpace(settings))
            {
                if (capability.RequiresConfiguration)
                    return ValidationResult.Failure("Settings", $"Settings are required for the '{capability.Name}' capability.", "SETTINGS_REQUIRED");

                return ValidationResult.Success();
            }

            try
            {
                System.Text.Json.JsonDocument.Parse(settings).Dispose();
            }
            catch (System.Text.Json.JsonException ex)
            {
                _logger.LogWarning(ex, "Invalid JSON settings provided for capability {CapabilityCode}", capability.Code);
                return ValidationResult.Failure("Settings", $"Invalid JSON format in settings: {ex.Message}", "INVALID_JSON_FORMAT");
            }

            return await Task.FromResult(ValidationResult.Success());
        }

        /// <summary>
        /// [WHEN] 조직에 새로운 기능을 활성화하려고 할 때 호출됩니다.
        /// [WHY]  'Pro' 플랜 이상에서만 사용할 수 있는 프리미엄 기능을 'Basic' 플랜 사용자가 활성화하는 것을 막기 위함입니다.
        /// [HOW]  조직의 현재 구독 플랜 정보를 조회하고, 해당 플랜에서 이 기능을 사용할 수 있는지 정책과 비교하여 확인합니다.
        /// [SCENARIO] 'Basic' 플랜을 구독 중인 조직의 관리자가 'SCIM 프로비저닝' 기능을 활성화하려고 하면, 이 검증이 실패하며 "PLAN_INSUFFICIENT" 오류를 반환하고, 동시에 플랜 업그레이드를 유도하는 이벤트(CapabilityPlanLimitEvent)를 발생시킵니다.
        /// </summary>
        public async Task<ValidationResult> ValidatePlanLimitsAsync(
            Guid organizationId,
            OrganizationCapability capability)
        {
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (subscription == null)
                return ValidationResult.Failure("Plan", "Active subscription not found.", "ACTIVE_SUBSCRIPTION_NOT_FOUND");

            var planKey = subscription.PlanKey;
            if (planKey == PricingConstants.SubscriptionPlans.ENTERPRISE_KEY)
                return ValidationResult.Success();

            if (!IsCapabilityAllowedForPlan(capability.Code, planKey))
            {
                var requiredPlan = GetMinimumPlanForCapability(capability.Code);
                await _eventBus.PublishAsync(new CapabilityPlanLimitEvent(
                  organizationId: organizationId,
                  capabilityCode: capability.Code,
                  currentPlan: planKey,
                  requiredPlan: requiredPlan,
                  triggeredBy: null  // 또는 적절한 사용자 ID
              ));

                return ValidationResult.Failure("PlanLimit", $"The '{capability.Name}' capability requires the '{requiredPlan}' plan or higher.", "PLAN_INSUFFICIENT");
            }

            return ValidationResult.Success();
        }

        /// <summary>
        /// [WHEN] 하위 조직이 상위 조직으로부터 기능을 상속받는 시점에 호출됩니다.
        /// [WHY]  상속이 불가능한 기능이 전파되거나, 상위 조직에 없는 기능이 하위로 상속되는 잘못된 상황을 막기 위함입니다.
        /// [HOW]  기능의 `IsInheritable` 속성을 확인하고, 캐시를 통해 상위 조직이 실제로 해당 기능을 보유했는지 빠르게 확인합니다.
        /// [SCENARIO] 상위 조직인 '현대자동차'가 'SSO' 기능을 사용 중일 때, 하위 조직인 '현대모비스'가 생성됩니다. 시스템은 이 검증을 통해 'SSO' 기능이 상속 가능한지, 그리고 현대자동차가 실제로 SSO를 사용하는지 확인한 후 모비스에 기능을 자동으로 상속시켜줍니다.
        /// </summary>
        public async Task<ValidationResult> ValidateInheritanceAsync(
            Guid parentOrganizationId,
            Guid childOrganizationId,
            OrganizationCapability capability)
        {
            if (!capability.IsInheritable)
            {
                await _auditService.LogActionAsync(null, "Capability.Inheritance.Failed", AuditActionType.Validation, "OrganizationCapability", capability.Id.ToString(), false, $"Attempted to inherit non-inheritable capability '{capability.Code}' to org '{childOrganizationId}'.");
                return ValidationResult.Failure("Inheritance", $"The capability '{capability.Name}' is not inheritable.", "CAPABILITY_NOT_INHERITABLE");
            }

            var cacheKey = string.Format(ORG_HAS_CAPABILITY_CACHE, parentOrganizationId, capability.Id);
            var cachedResult = await _cache.GetAsync<CachedBoolValue>(cacheKey);
            bool parentHasCapability;

            if (cachedResult == null)
            {
                _logger.LogTrace("Cache miss for key: {CacheKey}", cacheKey);
                parentHasCapability = await _assignmentRepository.HasCapabilityAsync(parentOrganizationId, capability.Code);
                await _cache.SetAsync(cacheKey, new CachedBoolValue { Value = parentHasCapability }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));
            }
            else
            {
                _logger.LogTrace("Cache hit for key: {CacheKey}", cacheKey);
                parentHasCapability = cachedResult.Value;
            }

            if (!parentHasCapability)
                return ValidationResult.Failure("ParentCapability", "Cannot inherit capability because the parent organization does not have it enabled.", "PARENT_MISSING_CAPABILITY");

            return await ValidatePlanLimitsAsync(childOrganizationId, capability);
        }

        #region Private Helper Methods

        private bool IsCapabilityAllowedForPlan(string capabilityCode, string planKey)
        {
            return planKey switch
            {
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => true,
                PricingConstants.SubscriptionPlans.PRO_KEY => capabilityCode != FeatureCapabilityCodes.SCIM,
                PricingConstants.SubscriptionPlans.BASIC_KEY => capabilityCode == FeatureCapabilityCodes.BasicAuthentication,
                _ => false
            };
        }

        private string GetMinimumPlanForCapability(string capabilityCode)
        {
            if (capabilityCode == FeatureCapabilityCodes.SCIM)
                return PricingConstants.SubscriptionPlans.BUSINESS_KEY;
            if (capabilityCode == FeatureCapabilityCodes.SingleSignOn)
                return PricingConstants.SubscriptionPlans.PRO_KEY;

            return PricingConstants.SubscriptionPlans.BASIC_KEY;
        }

        #endregion

        #region Helper Classes & Events

        private class CachedBoolValue { public bool Value { get; set; } }

        #endregion
    }
}