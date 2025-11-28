using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using Microsoft.Extensions.Logging;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult; 

namespace AuthHive.Auth.Validator
{
    /// <summary>
    /// [WHAT] 조직 정책(OrganizationPolicy)의 유효성을 검증하는 구현체입니다.
    /// [WHY]  새로운 정책이 시스템의 무결성을 해치거나 기존 정책과 충돌하는 것을 방지하고, 비즈니스 규칙을 강제하기 위해 필요합니다.
    /// [HOW]  정책 저장소(Repository)에서 관련 데이터를 조회하고, 미리 정의된 규칙(예: 우선순위, 기간, 형식)에 따라 유효성을 검사합니다.
    /// </summary>
    public class OrganizationPolicyValidator : IOrganizationPolicyValidator
    {
        private readonly IOrganizationPolicyRepository _policyRepository;
        private readonly IAuditService _auditService;
        private readonly ILogger<OrganizationPolicyValidator> _logger;

        public OrganizationPolicyValidator(
            IOrganizationPolicyRepository policyRepository,
            IAuditService auditService,
            ILogger<OrganizationPolicyValidator> logger)
        {
            _policyRepository = policyRepository;
            _auditService = auditService;
            _logger = logger;
        }

        #region IValidator<TEntity> Implementation

        public async Task<ValidationResult> ValidateCreateAsync(OrganizationPolicy entity)
        {
            var result = ValidationResult.Success();

            result.Merge(await ValidatePolicyRulesAsync(entity.PolicyType, entity.PolicyRules));
            // 'Create' 시점에서는 중복 검사 시 제외할 ID가 없으므로 인터페이스에 정의된 public 메서드를 직접 호출합니다.
            result.Merge(await ValidatePriorityAsync(entity.OrganizationId, entity.PolicyType, entity.Priority));
            result.Merge(await ValidateEffectivePeriodAsync(entity.EffectiveFrom, entity.EffectiveUntil));
            result.Merge(await ValidateComplianceStandardsAsync(entity.ComplianceStandards));

            if (!result.IsValid)
            {
                await _auditService.LogActionAsync(
                    entity.CreatedByConnectedId, "Policy.Create.Validation.Failed", AuditActionType.Validation,
                    nameof(OrganizationPolicy), entity.Id.ToString(), false,
                    $"Policy creation validation failed for '{entity.PolicyName}'. Reason: {result.GetCombinedErrorMessage()}");
            }

            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(OrganizationPolicy entity, OrganizationPolicy? existingEntity = default)
        {
            var currentEntity = existingEntity ?? await _policyRepository.GetByIdAsync(entity.Id);
            if (currentEntity == null)
                return ValidationResult.Failure("Policy", "The policy to be updated was not found.", "POLICY_NOT_FOUND");

            if (currentEntity.IsSystemPolicy)
                return ValidationResult.Failure("Policy", "System policies cannot be modified.", "SYSTEM_POLICY_MODIFICATION_NOT_ALLOWED");
            
            var result = ValidationResult.Success();

            result.Merge(await ValidatePolicyRulesAsync(entity.PolicyType, entity.PolicyRules));
            result.Merge(await ValidateEffectivePeriodAsync(entity.EffectiveFrom, entity.EffectiveUntil));
            result.Merge(await ValidateComplianceStandardsAsync(entity.ComplianceStandards));

            // 'Update' 시점에서는 자기 자신을 제외하고 우선순위 중복 검사를 해야 합니다.
            // 인터페이스 메서드는 ID 제외 기능을 지원하지 않으므로, Repository 메서드를 직접 호출합니다.
            if (entity.Priority <= 0)
            {
                 result.AddError("Priority", "Priority must be a positive integer.", "INVALID_PRIORITY_VALUE");
            }
            else
            {
                var isTaken = await _policyRepository.IsPriorityTakenAsync(entity.OrganizationId, entity.PolicyType, entity.Priority, entity.Id);
                if (isTaken)
                {
                    result.AddError("Priority", $"A policy with the same type and priority ({entity.Priority}) already exists.", "PRIORITY_CONFLICT");
                }
            }

            if (!result.IsValid)
            {
                await _auditService.LogActionAsync(
                    entity.UpdatedByConnectedId, "Policy.Update.Validation.Failed", AuditActionType.Validation,
                    nameof(OrganizationPolicy), entity.Id.ToString(), false,
                    $"Policy update validation failed for '{entity.PolicyName}'. Reason: {result.GetCombinedErrorMessage()}");
            }

            return result;
        }

        public Task<ValidationResult> ValidateDeleteAsync(OrganizationPolicy entity)
        {
            if (entity.IsSystemPolicy)
                return Task.FromResult(ValidationResult.Failure("Policy", "System policies cannot be deleted.", "SYSTEM_POLICY_DELETION_NOT_ALLOWED"));

            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region IOrganizationPolicyValidator Implementation

        public Task<ValidationResult> ValidatePolicyRulesAsync(OrganizationPolicyType policyType, string policyRules)
        {
            if (string.IsNullOrWhiteSpace(policyRules))
                return Task.FromResult(ValidationResult.Failure("PolicyRules", "Policy rules cannot be empty.", "POLICY_RULES_EMPTY"));

            try
            {
                JsonDocument.Parse(policyRules).Dispose();
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Invalid JSON format for policy rules. Type: {PolicyType}", policyType);
                return Task.FromResult(ValidationResult.Failure("PolicyRules", $"Invalid JSON format: {ex.Message}", "INVALID_JSON_FORMAT"));
            }

            return Task.FromResult(ValidationResult.Success());
        }

        public async Task<ValidationResult> ValidatePolicyConflictsAsync(Guid organizationId, OrganizationPolicyType policyType, string policyRules, int priority)
        {
            // 정책 충돌의 핵심은 우선순위이므로, 우선순위 검증 메서드를 호출합니다.
            return await ValidatePriorityAsync(organizationId, policyType, priority);
        }

        public async Task<ValidationResult> ValidatePriorityAsync(Guid organizationId, OrganizationPolicyType policyType, int priority)
        {
            if (priority <= 0)
                return ValidationResult.Failure("Priority", "Priority must be a positive integer.", "INVALID_PRIORITY_VALUE");

            var isTaken = await _policyRepository.IsPriorityTakenAsync(organizationId, policyType, priority, null);
            if (isTaken)
                return ValidationResult.Failure("Priority", $"A policy with the same type and priority ({priority}) already exists.", "PRIORITY_CONFLICT");

            return ValidationResult.Success();
        }

        public Task<ValidationResult> ValidateEffectivePeriodAsync(DateTime effectiveFrom, DateTime? effectiveTo)
        {
            if (effectiveTo.HasValue && effectiveTo.Value < effectiveFrom)
                return Task.FromResult(ValidationResult.Failure("EffectivePeriod", "The policy's effective end date cannot be earlier than the start date.", "INVALID_EFFECTIVE_PERIOD"));

            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateComplianceStandardsAsync(string? complianceStandards)
        {
            if (string.IsNullOrWhiteSpace(complianceStandards))
                return Task.FromResult(ValidationResult.Success());

            var standards = complianceStandards.Split(',').Select(s => s.Trim());
            foreach (var standard in standards)
            {
                if (string.IsNullOrEmpty(standard)) continue;
                if (!Enum.TryParse<CompliancePolicyName>(standard, true, out _))
                    return Task.FromResult(ValidationResult.Failure("ComplianceStandards", $"The compliance standard '{standard}' is not recognized.", "INVALID_COMPLIANCE_STANDARD"));
            }

            return Task.FromResult(ValidationResult.Success());
        }

        #endregion
    }
}