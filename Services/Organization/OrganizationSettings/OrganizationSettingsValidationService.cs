// Services/Organization/OrganizationSettings/OrganizationSettingsValidationService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Auth.Repositories;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Auth.Repositories.Organization;

namespace AuthHive.Auth.Services.Organization.OrganizationSettings
{
    /// <summary>
    /// 조직 설정 검증 서비스
    /// 설정 값의 유효성, 권한, 플랜 제한 등을 검증합니다.
    /// </summary>
    public class OrganizationSettingsValidationService : IOrganizationSettingsValidator
    {
        private readonly OrganizationSettingsRepository _repository;
        private readonly OrganizationRepository _organizationRepository;
        private readonly IPermissionService _permissionService;
        private readonly IPlanService _planService;
        private readonly ILogger<OrganizationSettingsValidationService> _logger;

        public OrganizationSettingsValidationService(
            OrganizationSettingsRepository repository,
            OrganizationRepository organizationRepository,
            IPermissionService permissionService,
            IPlanService planService,
            ILogger<OrganizationSettingsValidationService> logger)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _permissionService = permissionService ?? throw new ArgumentNullException(nameof(permissionService));
            _planService = planService ?? throw new ArgumentNullException(nameof(planService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IValidator<OrganizationSettings> 구현

        /// <summary>
        /// 설정 생성 시 검증
        /// </summary>
        public async Task<ValidationResult> ValidateCreateAsync(OrganizationSettings entity)
        {
            var result = ValidationResult.Success();

            // 필수 필드 검증
            if (entity.OrganizationId == Guid.Empty)
            {
                result.AddError("OrganizationId", "조직 ID는 필수입니다.", ValidationErrorCodes.Required);
            }

            if (string.IsNullOrWhiteSpace(entity.Category))
            {
                result.AddError("Category", "카테고리는 필수입니다.", ValidationErrorCodes.Required);
            }

            if (string.IsNullOrWhiteSpace(entity.SettingKey))
            {
                result.AddError("SettingKey", "설정 키는 필수입니다.", ValidationErrorCodes.Required);
            }

            // 중복 검사
            if (!result.HasErrorForField("OrganizationId") && !result.HasErrorForField("SettingKey"))
            {
                var exists = await _repository.SettingExistsAsync(
                    entity.OrganizationId,
                    entity.Category,
                    entity.SettingKey);

                if (exists)
                {
                    result.AddError("SettingKey", 
                        $"설정 키 '{entity.SettingKey}'가 이미 존재합니다.", 
                        ValidationErrorCodes.Duplicate);
                }
            }

            // 비즈니스 규칙 검증
            var businessRulesResult = await ValidateBusinessRulesAsync(entity);
            result.Merge(businessRulesResult);

            return result;
        }

        /// <summary>
        /// 설정 수정 시 검증
        /// </summary>
        public async Task<ValidationResult> ValidateUpdateAsync(
            OrganizationSettings entity, 
            OrganizationSettings? existingEntity = null)
        {
            var result = ValidationResult.Success();

            if (existingEntity == null)
            {
                result.AddError("설정을 찾을 수 없습니다.", ValidationErrorCodes.NotFound);
                return result;
            }

            // 읽기 전용 필드 변경 검증
            if (entity.OrganizationId != existingEntity.OrganizationId)
            {
                result.AddError("OrganizationId", "조직 ID는 변경할 수 없습니다.");
            }

            if (entity.Category != existingEntity.Category)
            {
                result.AddError("Category", "카테고리는 변경할 수 없습니다.");
            }

            if (entity.SettingKey != existingEntity.SettingKey)
            {
                result.AddError("SettingKey", "설정 키는 변경할 수 없습니다.");
            }

            // 비즈니스 규칙 검증
            var businessRulesResult = await ValidateBusinessRulesAsync(entity);
            result.Merge(businessRulesResult);

            return result;
        }

        /// <summary>
        /// 설정 삭제 시 검증
        /// </summary>
        public async Task<ValidationResult> ValidateDeleteAsync(OrganizationSettings entity)
        {
            var result = ValidationResult.Success();

            // 필수 설정 삭제 방지
            if (entity.IsRequired)
            {
                result.AddError("이 설정은 필수 설정으로 삭제할 수 없습니다.");
            }

            // 시스템 설정 삭제 방지
            if (!entity.IsUserConfigurable)
            {
                result.AddError("시스템 설정은 삭제할 수 없습니다.");
            }

            await Task.CompletedTask;
            return result;
        }

        /// <summary>
        /// 비즈니스 규칙 검증
        /// </summary>
        public async Task<ValidationResult> ValidateBusinessRulesAsync(OrganizationSettings entity)
        {
            var result = ValidationResult.Success();

            // 설정 값 검증
            if (!string.IsNullOrEmpty(entity.SettingValue))
            {
                var valueResult = await ValidateSettingValueAsync(
                    Enum.TryParse<OrganizationSettingCategory>(entity.Category, out var cat) 
                        ? cat 
                        : OrganizationSettingCategory.Custom,
                    entity.SettingKey,
                    entity.SettingValue,
                    entity.DataType);
                
                result.Merge(valueResult);

                // 범위 검증
                if (!string.IsNullOrEmpty(entity.MinValue) || !string.IsNullOrEmpty(entity.MaxValue))
                {
                    var rangeResult = await ValidateSettingRangeAsync(
                        entity.SettingValue,
                        entity.MinValue,
                        entity.MaxValue,
                        entity.DataType);
                    
                    result.Merge(rangeResult);
                }

                // 허용된 값 검증
                if (!string.IsNullOrEmpty(entity.AllowedValues))
                {
                    var allowedResult = await ValidateAllowedValuesAsync(
                        entity.SettingValue,
                        entity.AllowedValues);
                    
                    result.Merge(allowedResult);
                }

                // 정규식 검증
                if (!string.IsNullOrEmpty(entity.ValidationRule))
                {
                    var patternResult = await ValidatePatternAsync(
                        entity.SettingValue,
                        entity.ValidationRule);
                    
                    result.Merge(patternResult);
                }
            }
            else if (entity.IsRequired)
            {
                result.AddError("SettingValue", "필수 설정의 값은 비어있을 수 없습니다.", ValidationErrorCodes.Required);
            }

            // 플랜 제한 검증
            if (!string.IsNullOrEmpty(entity.RequiredPlan))
            {
                var planResult = await ValidatePlanRestrictionsAsync(
                    entity.OrganizationId,
                    Enum.TryParse<OrganizationSettingCategory>(entity.Category, out var cat2) 
                        ? cat2 
                        : OrganizationSettingCategory.Custom,
                    entity.SettingKey,
                    entity.RequiredPlan);
                
                result.Merge(planResult);
            }

            return result;
        }

        #endregion

        #region IOrganizationSettingsValidator 구현

        /// <summary>
        /// 설정 값 유효성 검증
        /// </summary>
        public async Task<ValidationResult> ValidateSettingValueAsync(
            OrganizationSettingCategory category,
            string settingKey,
            string? settingValue,
            string dataType)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            if (string.IsNullOrEmpty(settingValue))
                return result;

            switch (dataType.ToLower())
            {
                case "int":
                case "integer":
                    if (!int.TryParse(settingValue, out _))
                    {
                        result.AddError("SettingValue", "정수 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidFormat);
                    }
                    break;

                case "decimal":
                case "double":
                case "float":
                    if (!decimal.TryParse(settingValue, out _))
                    {
                        result.AddError("SettingValue", "숫자 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidFormat);
                    }
                    break;

                case "bool":
                case "boolean":
                    if (!bool.TryParse(settingValue, out _))
                    {
                        result.AddError("SettingValue", "불린 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidFormat);
                    }
                    break;

                case "datetime":
                case "date":
                    if (!DateTime.TryParse(settingValue, out _))
                    {
                        result.AddError("SettingValue", "날짜 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidDate);
                    }
                    break;

                case "json":
                    var jsonResult = await ValidateJsonFormatAsync(settingValue);
                    result.Merge(jsonResult);
                    break;

                case "email":
                    if (!IsValidEmail(settingValue))
                    {
                        result.AddError("SettingValue", "이메일 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidFormat);
                    }
                    break;

                case "url":
                    if (!Uri.TryCreate(settingValue, UriKind.Absolute, out _))
                    {
                        result.AddError("SettingValue", "URL 형식이 올바르지 않습니다.", ValidationErrorCodes.InvalidFormat);
                    }
                    break;
            }

            return result;
        }

        /// <summary>
        /// 설정 변경 권한 검증
        /// </summary>
        public async Task<ValidationResult> ValidateSettingPermissionAsync(
            Guid organizationId,
            OrganizationSettingCategory category,
            string settingKey,
            Guid modifiedByConnectedId)
        {
            var result = ValidationResult.Success();

            // 권한 확인
            var hasPermission = await _permissionService.HasPermissionAsync(
                modifiedByConnectedId,
                $"organization:settings:{category.ToString().ToLower()}:write");

            if (!hasPermission)
            {
                result.AddError($"{category} 카테고리의 설정을 수정할 권한이 없습니다.", ValidationErrorCodes.Forbidden);
            }

            return result;
        }

        /// <summary>
        /// 플랜별 설정 제한 검증
        /// </summary>
        public async Task<ValidationResult> ValidatePlanRestrictionsAsync(
            Guid organizationId,
            OrganizationSettingCategory category,
            string settingKey,
            string? requiredPlan)
        {
            var result = ValidationResult.Success();

            if (string.IsNullOrEmpty(requiredPlan))
                return result;

            var organization = await _organizationRepository.GetByIdAsync(organizationId);
            if (organization == null)
            {
                result.AddError("조직을 찾을 수 없습니다.", ValidationErrorCodes.NotFound);
                return result;
            }

            // 플랜 확인 (실제 구현에서는 PlanService를 통해 확인)
            var currentPlan = await _planService.GetCurrentPlanAsync(organizationId);
            if (currentPlan == null || !IsPlanSufficient(currentPlan.PlanType, requiredPlan))
            {
                result.AddError($"이 설정은 {requiredPlan} 플랜 이상에서만 사용 가능합니다.", ValidationErrorCodes.Forbidden);
            }

            return result;
        }

        /// <summary>
        /// 설정 범위 검증
        /// </summary>
        public async Task<ValidationResult> ValidateSettingRangeAsync(
            string settingValue,
            string? minValue,
            string? maxValue,
            string dataType)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            switch (dataType.ToLower())
            {
                case "int":
                case "integer":
                    if (int.TryParse(settingValue, out var intVal))
                    {
                        if (minValue != null && int.TryParse(minValue, out var minInt) && intVal < minInt)
                        {
                            result.AddError("SettingValue", $"값은 {minInt} 이상이어야 합니다.", ValidationErrorCodes.OutOfRange);
                        }
                        if (maxValue != null && int.TryParse(maxValue, out var maxInt) && intVal > maxInt)
                        {
                            result.AddError("SettingValue", $"값은 {maxInt} 이하여야 합니다.", ValidationErrorCodes.OutOfRange);
                        }
                    }
                    break;

                case "decimal":
                case "double":
                case "float":
                    if (decimal.TryParse(settingValue, out var decVal))
                    {
                        if (minValue != null && decimal.TryParse(minValue, out var minDec) && decVal < minDec)
                        {
                            result.AddError("SettingValue", $"값은 {minDec} 이상이어야 합니다.", ValidationErrorCodes.OutOfRange);
                        }
                        if (maxValue != null && decimal.TryParse(maxValue, out var maxDec) && decVal > maxDec)
                        {
                            result.AddError("SettingValue", $"값은 {maxDec} 이하여야 합니다.", ValidationErrorCodes.OutOfRange);
                        }
                    }
                    break;

                case "string":
                    var length = settingValue.Length;
                    if (minValue != null && int.TryParse(minValue, out var minLen) && length < minLen)
                    {
                        result.AddError("SettingValue", $"길이는 {minLen}자 이상이어야 합니다.", ValidationErrorCodes.TooShort);
                    }
                    if (maxValue != null && int.TryParse(maxValue, out var maxLen) && length > maxLen)
                    {
                        result.AddError("SettingValue", $"길이는 {maxLen}자 이하여야 합니다.", ValidationErrorCodes.TooLong);
                    }
                    break;
            }

            return result;
        }

        /// <summary>
        /// 허용된 값 목록 검증
        /// </summary>
        public async Task<ValidationResult> ValidateAllowedValuesAsync(
            string settingValue,
            string? allowedValues)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            if (string.IsNullOrEmpty(allowedValues))
                return result;

            try
            {
                var allowedList = JsonSerializer.Deserialize<string[]>(allowedValues);
                if (allowedList != null && !allowedList.Contains(settingValue))
                {
                    result.AddError("SettingValue", 
                        $"허용된 값이 아닙니다. 가능한 값: {string.Join(", ", allowedList)}", 
                        ValidationErrorCodes.InvalidFormat);
                }
            }
            catch (JsonException)
            {
                result.AddWarning("허용된 값 목록 형식이 올바르지 않습니다.");
            }

            return result;
        }

        /// <summary>
        /// 정규식 패턴 검증
        /// </summary>
        public async Task<ValidationResult> ValidatePatternAsync(
            string settingValue,
            string? validationRule)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            if (string.IsNullOrEmpty(validationRule))
                return result;

            try
            {
                if (!Regex.IsMatch(settingValue, validationRule))
                {
                    result.AddError("SettingValue", "값이 검증 규칙과 일치하지 않습니다.", ValidationErrorCodes.InvalidFormat);
                }
            }
            catch (ArgumentException)
            {
                result.AddWarning("검증 규칙(정규식) 형식이 올바르지 않습니다.");
            }

            return result;
        }

        /// <summary>
        /// 상속 설정 덮어쓰기 가능 여부 검증
        /// </summary>
        public async Task<ValidationResult> ValidateInheritanceOverrideAsync(
            Guid organizationId,
            OrganizationSettingCategory category,
            string settingKey,
            bool isInherited,
            bool canOverrideInherited)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            if (isInherited && !canOverrideInherited)
            {
                result.AddError("상속된 설정을 덮어쓸 수 없습니다.", ValidationErrorCodes.Forbidden);
            }

            return result;
        }

        /// <summary>
        /// JSON 형식 검증
        /// </summary>
        public async Task<ValidationResult> ValidateJsonFormatAsync(
            string settingValue,
            string? jsonSchema = null)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            try
            {
                var doc = JsonDocument.Parse(settingValue);
                doc.Dispose();

                // TODO: jsonSchema가 제공된 경우 스키마 검증
                if (!string.IsNullOrEmpty(jsonSchema))
                {
                    result.AddWarning("JSON 스키마 검증은 아직 구현되지 않았습니다.");
                }
            }
            catch (JsonException ex)
            {
                result.AddError("SettingValue", $"유효한 JSON 형식이 아닙니다: {ex.Message}", ValidationErrorCodes.InvalidFormat);
            }

            return result;
        }

        /// <summary>
        /// 일괄 설정 변경 검증
        /// </summary>
        public async Task<ValidationResult> ValidateBatchSettingsAsync(
            Guid organizationId,
            IEnumerable<OrganizationSettings> settings)
        {
            var result = ValidationResult.Success();

            // 중복 키 검사
            var duplicates = settings
                .GroupBy(s => $"{s.Category}:{s.SettingKey}")
                .Where(g => g.Count() > 1)
                .Select(g => g.Key);

            foreach (var duplicate in duplicates)
            {
                result.AddError($"중복된 설정 키: {duplicate}", ValidationErrorCodes.Duplicate);
            }

            // 각 설정 개별 검증
            foreach (var setting in settings)
            {
                var validationResult = await ValidateBusinessRulesAsync(setting);
                if (!validationResult.IsValid)
                {
                    result.AddError($"[{setting.Category}:{setting.SettingKey}] {validationResult.GetFirstErrorMessage()}");
                }
            }

            return result;
        }

        /// <summary>
        /// 암호화 필요 설정 검증
        /// </summary>
        public async Task<ValidationResult> ValidateEncryptionRequirementAsync(
            OrganizationSettingCategory category,
            string settingKey,
            bool requiresEncryption)
        {
            await Task.CompletedTask;
            var result = ValidationResult.Success();

            // 보안 카테고리의 특정 설정들은 반드시 암호화되어야 함
            if (category == OrganizationSettingCategory.Security)
            {
                var mustEncryptKeys = new[] { "api_key", "secret_key", "password", "token", "certificate" };
                if (mustEncryptKeys.Any(k => settingKey.ToLower().Contains(k)) && !requiresEncryption)
                {
                    result.AddError("이 설정은 반드시 암호화되어야 합니다.", ValidationErrorCodes.BusinessRule);
                }
            }

            return result;
        }

        #endregion

        #region 헬퍼 메서드

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private bool IsPlanSufficient(string currentPlan, string requiredPlan)
        {
            var planHierarchy = new[] { "basic", "pro", "business", "enterprise" };
            var currentIndex = Array.IndexOf(planHierarchy, currentPlan.ToLower());
            var requiredIndex = Array.IndexOf(planHierarchy, requiredPlan.ToLower());

            return currentIndex >= requiredIndex;
        }

        #endregion
    }
}