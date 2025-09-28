using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Core.Validators;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common.Validation; // Use the correct ValidationResult namespace
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Validator
{
    public class ApplicationAccessTemplateValidator : IApplicationAccessTemplateValidator
    {
        private readonly IPlatformApplicationAccessTemplateRepository _templateRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly ILogger<ApplicationAccessTemplateValidator> _logger;
        private static readonly Regex PermissionPatternRegex = new Regex(@"^([\w\-]+|\*):([\w\-]+|\*):?([\w\-]+|\*)?$");

        public ApplicationAccessTemplateValidator(
            IPlatformApplicationAccessTemplateRepository templateRepository,
            IRoleRepository roleRepository,
            ILogger<ApplicationAccessTemplateValidator> logger)
        {
            _templateRepository = templateRepository;
            _roleRepository = roleRepository;
            _logger = logger;
        }

        #region Basic Validation

        public async Task<ValidationResult> ValidateCreateAsync(PlatformApplicationAccessTemplate template)
        {
            var result = ValidationResult.Success();
            
            result.Merge(await ValidateTemplateNameAsync(template.Name, template.OrganizationId));
            result.Merge(ValidatePermissionPatterns(GetPatternsFromJson(template.PermissionPatterns)));
            result.Merge(ValidateAccessLevelConsistency(template.Level, GetPatternsFromJson(template.PermissionPatterns)));
            result.Merge(ValidatePriority(template.Priority, template.Level));
            result.Merge(await ValidateDefaultRoleAsync(template.DefaultRoleId, template.OrganizationId));

            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(PlatformApplicationAccessTemplate existingTemplate, PlatformApplicationAccessTemplate updatedTemplate)
        {
            var result = ValidationResult.Success();

            // [FIXED] Corrected property name from LastModifiedByConnectedId to UpdatedByConnectedId
            result.Merge(ValidateSystemTemplateModification(existingTemplate, updatedTemplate.UpdatedByConnectedId ?? Guid.Empty));
            if (!result.IsValid) return result;

            if (existingTemplate.Name != updatedTemplate.Name)
            {
                result.Merge(await ValidateTemplateNameAsync(updatedTemplate.Name, updatedTemplate.OrganizationId, existingTemplate.Id));
            }

            result.Merge(ValidatePermissionPatterns(GetPatternsFromJson(updatedTemplate.PermissionPatterns)));
            result.Merge(ValidateAccessLevelConsistency(updatedTemplate.Level, GetPatternsFromJson(updatedTemplate.PermissionPatterns)));
            result.Merge(ValidatePriority(updatedTemplate.Priority, updatedTemplate.Level));

            if (existingTemplate.DefaultRoleId != updatedTemplate.DefaultRoleId)
            {
                result.Merge(await ValidateDefaultRoleAsync(updatedTemplate.DefaultRoleId, updatedTemplate.OrganizationId));
            }
            
            return result;
        }

        public async Task<ValidationResult> ValidateDeleteAsync(PlatformApplicationAccessTemplate template)
        {
            var result = ValidationResult.Success();
            result.Merge(ValidateSystemTemplateModification(template, Guid.Empty));
            if (!result.IsValid) return result;

            if (await IsTemplateInUseAsync(template.Id))
            {
                result.AddError("TemplateInUse", "This template is currently assigned to one or more users and cannot be deleted.", "TEMPLATE_IN_USE");
            }
            
            return result;
        }

        #endregion

        #region Permission Pattern Validation
        
        public ValidationResult ValidatePermissionPattern(string pattern)
        {
            if (!PermissionPatternRegex.IsMatch(pattern))
            {
                // [FIXED] Use ValidationResult.Failure factory method
                return ValidationResult.Failure("PermissionPattern", $"Invalid permission pattern format: '{pattern}'.", "INVALID_PATTERN_FORMAT");
            }
            return ValidationResult.Success();
        }

        public ValidationResult ValidatePermissionPatterns(IEnumerable<string> patterns)
        {
            var result = ValidationResult.Success();
            foreach (var pattern in patterns ?? Enumerable.Empty<string>())
            {
                result.Merge(ValidatePermissionPattern(pattern));
            }
            return result;
        }
        
        public ValidationResult ValidateWildcardUsage(string pattern)
        {
            if (pattern.StartsWith("*:"))
            {
                return ValidationResult.Failure("WildcardUsage", "Wildcard '*' is not allowed for the resource part of the pattern.", "WILDCARD_NOT_ALLOWED_FOR_RESOURCE");
            }
            return ValidationResult.Success();
        }

        #endregion

        #region Template Property Validation

        public async Task<ValidationResult> ValidateTemplateNameAsync(string name, Guid organizationId, Guid? excludeTemplateId = null)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
            {
                return ValidationResult.Failure("TemplateName", "Template name must be between 1 and 100 characters.", "INVALID_NAME_LENGTH");
            }

            var exists = await _templateRepository.NameExistsAsync(organizationId, name, excludeTemplateId);
            if (exists)
            {
                return ValidationResult.Failure("TemplateName", $"A template with the name '{name}' already exists.", "DUPLICATE_TEMPLATE_NAME");
            }
            return ValidationResult.Success();
        }

        public ValidationResult ValidateAccessLevelConsistency(ApplicationAccessLevel level, IEnumerable<string> permissionPatterns)
        {
            if (level == ApplicationAccessLevel.Viewer)
            {
                var forbiddenActions = new[] { "delete", "update", "create", "write", "*" };
                foreach (var pattern in permissionPatterns)
                {
                    var parts = pattern.Split(':');
                    if (parts.Length > 1 && forbiddenActions.Contains(parts[1]))
                    {
                        return ValidationResult.Failure("AccessLevel", $"Viewer level templates cannot contain '{parts[1]}' actions.", "INCONSISTENT_ACCESS_LEVEL");
                    }
                }
            }
            return ValidationResult.Success();
        }

        public ValidationResult ValidatePriority(int priority, ApplicationAccessLevel level)
        {
            if ((level == ApplicationAccessLevel.Owner || level == ApplicationAccessLevel.Admin) && priority < 50)
            {
                 return ValidationResult.Failure("Priority", "Owner and Admin templates must have a priority of 50 or higher.", "PRIORITY_TOO_LOW_FOR_LEVEL");
            }
            return ValidationResult.Success();
        }

        public ValidationResult ValidateSystemTemplateModification(PlatformApplicationAccessTemplate template, Guid modifierConnectedId)
        {
            if (template.IsSystemTemplate)
            {
                return ValidationResult.Failure("SystemTemplate", "System templates cannot be modified or deleted.", "SYSTEM_TEMPLATE_MODIFICATION_FORBIDDEN");
            }
            return ValidationResult.Success();
        }

        #endregion
        
        #region Role Integration Validation
        
        public async Task<ValidationResult> ValidateDefaultRoleAsync(Guid? roleId, Guid organizationId)
        {
            if (roleId.HasValue)
            {
                var role = await _roleRepository.GetByIdAsync(roleId.Value);
                if (role == null || role.OrganizationId != organizationId)
                {
                    return ValidationResult.Failure("DefaultRole", "The specified default role was not found in this organization.", "DEFAULT_ROLE_NOT_FOUND");
                }
            }
            return ValidationResult.Success();
        }

        #endregion

        #region Usage Status Validation

        public async Task<bool> IsTemplateInUseAsync(Guid templateId)
        {
            var usageCount = await _templateRepository.GetUsageCountAsync(templateId);
            return usageCount > 0;
        }

        public async Task<TemplateChangeImpact> AnalyzeTemplateChangeImpactAsync(PlatformApplicationAccessTemplate existingTemplate, PlatformApplicationAccessTemplate updatedTemplate)
        {
            var existingPatterns = GetPatternsFromJson(existingTemplate.PermissionPatterns);
            var updatedPatterns = GetPatternsFromJson(updatedTemplate.PermissionPatterns);

            var impact = new TemplateChangeImpact
            {
                AffectedUsers = await _templateRepository.GetUsageCountAsync(existingTemplate.Id),
                AddedPermissions = updatedPatterns.Except(existingPatterns).ToList(),
                RemovedPermissions = existingPatterns.Except(updatedPatterns).ToList(),
            };

            if (impact.RemovedPermissions.Any(p => p.Contains("delete") || p.Contains("*")))
            {
                impact.RequiresReauthentication = true;
                impact.ImpactSummary = "Critical permissions have been removed, re-authentication for affected users is recommended.";
            }

            return impact;
        }

        #endregion
        
        // --- Other method implementations (placeholders) ---

        public Task<ValidationResult> ValidatePatternConflictsAsync(IEnumerable<string> patterns, Guid? excludeTemplateId = null)
        {
            _logger.LogWarning("ValidatePatternConflictsAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateRoleCompatibilityAsync(Guid? roleId, IEnumerable<string> permissionPatterns)
        {
            _logger.LogWarning("ValidateRoleCompatibilityAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }
        
        public ValidationResult ValidateBillingAccessConsistency(bool includesBillingAccess, IEnumerable<string> permissionPatterns)
        {
            bool hasBillingPattern = permissionPatterns.Any(p => p.StartsWith("billing:"));
            if (includesBillingAccess != hasBillingPattern)
            {
                return ValidationResult.Failure("BillingAccess", "The 'IncludesBillingAccess' flag does not match the permission patterns.", "BILLING_FLAG_INCONSISTENT");
            }
            return ValidationResult.Success();
        }

        public Task<ValidationResult> ValidateBillingAccessEligibilityAsync(Guid organizationId, ApplicationAccessLevel level)
        {
             _logger.LogWarning("ValidateBillingAccessEligibilityAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }

        public ValidationResult ValidateMetadata(string? metadata)
        {
            if (string.IsNullOrWhiteSpace(metadata)) return ValidationResult.Success();
            try { JsonDocument.Parse(metadata).Dispose(); }
            catch (JsonException ex) { return ValidationResult.Failure("Metadata", $"Invalid metadata JSON format: {ex.Message}", "INVALID_METADATA_JSON"); }
            return ValidationResult.Success();
        }

        public ValidationResult ValidateRequiredMetadataFields(string? metadata, IEnumerable<string> requiredFields)
        {
             _logger.LogWarning("ValidateRequiredMetadataFields is not fully implemented.");
            return ValidationResult.Success();
        }
        
        public Task<ValidationResult> ValidateTemplateHierarchyAsync(ApplicationAccessLevel level, int priority, Guid organizationId)
        {
             _logger.LogWarning("ValidateTemplateHierarchyAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidatePermissionInclusionAsync(ApplicationAccessLevel level, IEnumerable<string> permissionPatterns, Guid organizationId)
        {
            _logger.LogWarning("ValidatePermissionInclusionAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }
        
        #region Private Helper
        private List<string> GetPatternsFromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return new List<string>();
            try
            {
                return JsonSerializer.Deserialize<List<string>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }
        #endregion
    }
}