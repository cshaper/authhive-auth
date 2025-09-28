using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using Microsoft.Extensions.Logging;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;

namespace AuthHive.Auth.Services.Validators
{
    /// <summary>
    /// [WHAT] 조직 설정(OrganizationSettings)의 유효성을 검증하는 구현체입니다.
    /// [WHY]  조직별로 커스터마이징된 설정 값이 시스템의 규칙(데이터 타입, 플랜 제한, 권한 등)을 준수하도록 보장하여 안정성과 데이터 무결성을 유지하기 위해 필요합니다.
    /// [HOW]  설정의 데이터 타입, 값의 범위, 정규식 패턴, 플랜 구독 상태 등 다양한 조건을 복합적으로 검사하여 유효성을 판단합니다.
    /// </summary>
    public class OrganizationSettingsValidator : IOrganizationSettingsValidator
    {
        private readonly IPlanService _planService;
        private readonly IAuditService _auditService;
        private readonly ILogger<OrganizationSettingsValidator> _logger;

        public OrganizationSettingsValidator(
            IPlanService planService,
            IAuditService auditService,
            ILogger<OrganizationSettingsValidator> logger)
        {
            _planService = planService;
            _auditService = auditService;
            _logger = logger;
        }

        #region IValidator<TEntity> Implementation

        public async Task<ValidationResult> ValidateCreateAsync(OrganizationSettings entity)
        {
            var result = ValidationResult.Success();

            result.Merge(await ValidateSettingValueAsync(Enum.Parse<OrganizationSettingCategory>(entity.Category), entity.SettingKey, entity.SettingValue, entity.DataType));
            result.Merge(await ValidatePlanRestrictionsAsync(entity.OrganizationId, Enum.Parse<OrganizationSettingCategory>(entity.Category), entity.SettingKey, entity.RequiredPlan));
            result.Merge(await ValidateSettingRangeAsync(entity.SettingValue, entity.MinValue, entity.MaxValue, entity.DataType));
            result.Merge(await ValidateAllowedValuesAsync(entity.SettingValue, entity.AllowedValues));
            result.Merge(await ValidatePatternAsync(entity.SettingValue, entity.ValidationRule));

            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(OrganizationSettings entity, OrganizationSettings? existingEntity = null)
        {
            // 수정 시에는 생성과 동일한 검증 로직을 따르지만, 'IsUserConfigurable'과 같은 추가적인 제약을 확인할 수 있습니다.
            if (existingEntity != null && !existingEntity.IsUserConfigurable)
            {
                return ValidationResult.Failure("Setting", "This setting is not user-configurable and cannot be modified.", "SETTING_NOT_CONFIGURABLE");
            }

            return await ValidateCreateAsync(entity); // Re-use the same comprehensive validation logic.
        }

        public Task<ValidationResult> ValidateDeleteAsync(OrganizationSettings entity)
        {
            // 필수 설정(IsRequired)은 삭제할 수 없도록 방지합니다.
            if (entity.IsRequired)
            {
                return Task.FromResult(ValidationResult.Failure("Setting", "This is a required setting and cannot be deleted.", "REQUIRED_SETTING_DELETION_FORBIDDEN"));
            }

            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region IOrganizationSettingsValidator Implementation

        public Task<ValidationResult> ValidateSettingValueAsync(OrganizationSettingCategory category, string settingKey, string? settingValue, string dataType)
        {
            if (string.IsNullOrWhiteSpace(settingValue))
            {
                // 값은 비어있을 수 있으므로 성공 처리. 필수 여부는 ValidateDeleteAsync에서 처리.
                return Task.FromResult(ValidationResult.Success());
            }

            switch (dataType.ToLower())
            {
                case "number":
                    if (!decimal.TryParse(settingValue, out _))
                        return Task.FromResult(ValidationResult.Failure(settingKey, $"Setting value '{settingValue}' is not a valid number.", "INVALID_DATA_TYPE"));
                    break;
                case "boolean":
                    if (!bool.TryParse(settingValue, out _))
                        return Task.FromResult(ValidationResult.Failure(settingKey, $"Setting value '{settingValue}' is not a valid boolean.", "INVALID_DATA_TYPE"));
                    break;
                case "json":
                    return ValidateJsonFormatAsync(settingValue);
                // "string", "array" etc. don't need specific format validation here.
            }

            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateSettingPermissionAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid modifiedByConnectedId)
        {
            // TODO: 실제 권한 검증 로직 구현 필요
            // 예: 사용자가 'Security' 카테고리 설정을 변경할 'OrganizationAdmin' 역할을 가지고 있는지 확인
            if (category == OrganizationSettingCategory.Security)
            {
                _logger.LogWarning("Security setting '{settingKey}' modification attempted by {modifierId} for organization {orgId}. Permission check is not yet implemented.", settingKey, modifiedByConnectedId, organizationId);
                // return ValidationResult.Failure(settingKey, "You do not have permission to modify security settings.", "PERMISSION_DENIED");
            }

            return Task.FromResult(ValidationResult.Success());
        }

        public async Task<ValidationResult> ValidatePlanRestrictionsAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, string? requiredPlan)
        {
            if (string.IsNullOrWhiteSpace(requiredPlan))
            {
                return ValidationResult.Success();
            }

            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (subscription == null)
            {
                return ValidationResult.Failure(settingKey, "Could not verify plan restrictions due to missing subscription.", "SUBSCRIPTION_NOT_FOUND");
            }
            
            // This logic assumes higher-tier plans include lower-tier ones.
            // For example, if requiredPlan is "Business", "Enterprise" plan should also pass.
            var planHierarchy = new List<string> { "Basic", "Pro", "Business", "Enterprise" }; // Define your plan hierarchy
            var requiredPlanIndex = planHierarchy.IndexOf(requiredPlan);
            var currentPlanIndex = planHierarchy.IndexOf(subscription.PlanKey);

            if (requiredPlanIndex == -1 || currentPlanIndex < requiredPlanIndex)
            {
                 return ValidationResult.Failure(settingKey, $"The setting '{settingKey}' requires a '{requiredPlan}' plan or higher.", "PLAN_INSUFFICIENT");
            }

            return ValidationResult.Success();
        }

        public Task<ValidationResult> ValidateSettingRangeAsync(string? settingValue, string? minValue, string? maxValue, string dataType)
        {
            if (dataType.ToLower() != "number" || string.IsNullOrWhiteSpace(settingValue))
            {
                return Task.FromResult(ValidationResult.Success());
            }

            if (!decimal.TryParse(settingValue, out var value))
            {
                return Task.FromResult(ValidationResult.Failure(nameof(settingValue), "The setting value is not a valid number for a range check.", "INVALID_DATA_TYPE"));
            }

            if (decimal.TryParse(minValue, out var min) && value < min)
            {
                return Task.FromResult(ValidationResult.Failure(nameof(settingValue), $"Value must be greater than or equal to {min}.", "VALUE_BELOW_MINIMUM"));
            }

            if (decimal.TryParse(maxValue, out var max) && value > max)
            {
                return Task.FromResult(ValidationResult.Failure(nameof(settingValue), $"Value must be less than or equal to {max}.", "VALUE_ABOVE_MAXIMUM"));
            }
            
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateAllowedValuesAsync(string? settingValue, string? allowedValues)
        {
            if (string.IsNullOrWhiteSpace(allowedValues) || string.IsNullOrWhiteSpace(settingValue))
            {
                return Task.FromResult(ValidationResult.Success());
            }

            try
            {
                var values = JsonSerializer.Deserialize<List<string>>(allowedValues, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (values != null && !values.Contains(settingValue, StringComparer.OrdinalIgnoreCase))
                {
                    return Task.FromResult(ValidationResult.Failure(nameof(settingValue), $"The value '{settingValue}' is not one of the allowed values.", "VALUE_NOT_ALLOWED"));
                }
            }
            catch (JsonException ex)
            {
                 _logger.LogWarning(ex, "Could not parse AllowedValues JSON: {allowedValues}", allowedValues);
                 return Task.FromResult(ValidationResult.Failure(nameof(allowedValues), "Invalid format for allowed values.", "INVALID_ALLOWED_VALUES_FORMAT"));
            }

            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidatePatternAsync(string? settingValue, string? validationRule)
        {
             if (string.IsNullOrWhiteSpace(validationRule) || string.IsNullOrWhiteSpace(settingValue))
            {
                return Task.FromResult(ValidationResult.Success());
            }

            try
            {
                if (!Regex.IsMatch(settingValue, validationRule))
                {
                    return Task.FromResult(ValidationResult.Failure(nameof(settingValue), "The provided value does not match the required format.", "PATTERN_MISMATCH"));
                }
            }
            catch(ArgumentException ex)
            {
                _logger.LogError(ex, "Invalid Regex pattern provided in ValidationRule: {pattern}", validationRule);
                return Task.FromResult(ValidationResult.Failure(nameof(validationRule), "The validation rule contains an invalid regular expression.", "INVALID_REGEX_PATTERN"));
            }
            
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateInheritanceOverrideAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, bool isInherited, bool canOverrideInherited)
        {
            if (isInherited && !canOverrideInherited)
            {
                return Task.FromResult(ValidationResult.Failure(settingKey, "This setting is inherited and cannot be overridden.", "INHERITANCE_OVERRIDE_FORBIDDEN"));
            }

            return Task.FromResult(ValidationResult.Success());
        }
        
          public Task<ValidationResult> ValidateJsonFormatAsync(string? settingValue, string? jsonSchema = null)
        {
            if (string.IsNullOrWhiteSpace(settingValue))
            {
                return Task.FromResult(ValidationResult.Success());
            }

            try
            {
                JsonDocument.Parse(settingValue).Dispose();
            }
            catch (JsonException ex)
            {
                return Task.FromResult(ValidationResult.Failure(nameof(settingValue), $"Invalid JSON format: {ex.Message}", "INVALID_JSON_FORMAT"));
            }
            return Task.FromResult(ValidationResult.Success());
        }
        
        public async Task<ValidationResult> ValidateBatchSettingsAsync(Guid organizationId, IEnumerable<OrganizationSettings> settings)
        {
            var batchResult = ValidationResult.Success();
            foreach(var setting in settings)
            {
                // Ensure each setting in the batch belongs to the same organization
                if (setting.OrganizationId != organizationId)
                {
                    batchResult.AddError(setting.SettingKey, $"Setting '{setting.SettingKey}' does not belong to the target organization.", "BATCH_ORG_ID_MISMATCH");
                    continue;
                }
                
                var singleResult = await ValidateUpdateAsync(setting);
                if (!singleResult.IsValid)
                {
                    batchResult.Merge(singleResult);
                }
            }
            return batchResult;
        }

        public Task<ValidationResult> ValidateEncryptionRequirementAsync(OrganizationSettingCategory category, string settingKey, bool requiresEncryption)
        {
            if (requiresEncryption)
            {
                // This validation would typically happen in a service layer before saving,
                // ensuring the value is actually encrypted. This validator can only flag the requirement.
                _logger.LogInformation("Encryption check for {category}.{settingKey}: Requires encryption. Ensure value is encrypted before saving.", category, settingKey);
            }
            return Task.FromResult(ValidationResult.Success());
        }
        #endregion
    }
}