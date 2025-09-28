using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Validator;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.PlatformApplication.Requests;
using Microsoft.Extensions.Logging;

// [FIX] Create an alias for the PlatformApplication entity to resolve naming conflicts.
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;

namespace AuthHive.Auth.Validator
{
    public class PlatformApplicationValidator : IPlatformApplicationValidator
    {
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IPlanService _planService;
        private readonly ILogger<PlatformApplicationValidator> _logger;

        public PlatformApplicationValidator(
            IPlatformApplicationRepository applicationRepository,
            IPlanService planService,
            ILogger<PlatformApplicationValidator> logger)
        {
            _applicationRepository = applicationRepository;
            _planService = planService;
            _logger = logger;
        }

        #region IValidator<PlatformApplicationEntity> Implementation

        // [FIX] Added missing IValidator<T> interface implementations.
        public Task<ValidationResult> ValidateCreateAsync(PlatformApplicationEntity entity)
        {
            var result = ValidationResult.Success();
            if (string.IsNullOrWhiteSpace(entity.Name))
                result.AddError(nameof(entity.Name), "Application name is required.", "NAME_REQUIRED");
            if (string.IsNullOrWhiteSpace(entity.ApplicationKey))
                result.AddError(nameof(entity.ApplicationKey), "ApplicationKey is required.", "KEY_REQUIRED");
            
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateUpdateAsync(PlatformApplicationEntity entity, PlatformApplicationEntity? existingEntity = null)
        {
            var result = ValidationResult.Success();
            if (existingEntity != null && entity.ApplicationKey != existingEntity.ApplicationKey)
            {
                result.AddError(nameof(entity.ApplicationKey), "ApplicationKey cannot be changed.", "KEY_IMMUTABLE");
            }
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateDeleteAsync(PlatformApplicationEntity entity)
        {
            if (entity.Status == ApplicationStatus.Active)
            {
                return Task.FromResult(ValidationResult.Failure("Application", "Active applications cannot be deleted. Please deactivate it first.", "DELETE_ACTIVE_APP_FORBIDDEN"));
            }
            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region IPlatformApplicationValidator Implementation

        public async Task<ValidationResult> ValidateCreateAsync(CreateApplicationRequest request, Guid organizationId)
        {
            var result = ValidationResult.Success();
            result.Merge(await ValidateOrganizationLimitsAsync(organizationId));
            if (!result.IsValid) return result;
            result.Merge(await ValidateNameAsync(request.Name, organizationId));
            if (!result.IsValid) return result;
            result.Merge(await ValidateOAuthSettingsAsync(request.CallbackUrls, request.AllowedOrigins, null));
            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(Guid applicationId, UpdateApplicationRequest request)
        {
            var application = await _applicationRepository.GetByIdAsync(applicationId);
            if (application == null)
                return ValidationResult.Failure("Application not found.", "APPLICATION_NOT_FOUND");

            var result = ValidationResult.Success();
            if (!string.IsNullOrWhiteSpace(request.Name) && application.Name != request.Name)
            {
                result.Merge(await ValidateNameAsync(request.Name, application.OrganizationId, applicationId));
            }
            result.Merge(await ValidateOAuthSettingsAsync(request.CallbackUrls, request.AllowedOrigins, null));
            return result;
        }

        public async Task<ValidationResult> ValidateDeleteAsync(Guid applicationId)
        {
            var application = await _applicationRepository.GetByIdAsync(applicationId);
            if (application == null)
                return ValidationResult.Failure("Application not found.", "APPLICATION_NOT_FOUND");
            
            return await ValidateDeleteAsync(application); // Reuse IValidator implementation
        }

        public async Task<ValidationResult> ValidateApplicationKeyAsync(string applicationKey, Guid organizationId, Guid? excludeApplicationId = null)
        {
             if (string.IsNullOrWhiteSpace(applicationKey) || applicationKey.Length > 100)
                return ValidationResult.Failure("Application key must be between 1 and 100 characters.", "INVALID_KEY_LENGTH");
            
            var keyExists = await _applicationRepository.ExistsByApplicationKeyAsync(applicationKey, excludeApplicationId);
            if (keyExists)
                return ValidationResult.Failure($"An application with the key '{applicationKey}' already exists.", "DUPLICATE_APPLICATION_KEY");
            
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateNameAsync(string name, Guid organizationId, Guid? excludeApplicationId = null)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 200)
                return ValidationResult.Failure("Application name must be between 1 and 200 characters.", "INVALID_NAME_LENGTH");
            
            var isDuplicate = await _applicationRepository.IsDuplicateNameAsync(organizationId, name, excludeApplicationId);
            if (isDuplicate)
                return ValidationResult.Failure($"An application with the name '{name}' already exists in this organization.", "DUPLICATE_APPLICATION_NAME");

            return ValidationResult.Success();
        }

        public Task<ValidationResult> ValidateOAuthSettingsAsync(string? callbackUrls, string? allowedOrigins, string? allowedScopes)
        {
            var result = ValidationResult.Success();
            if (!string.IsNullOrWhiteSpace(callbackUrls))
                result.Merge(ValidateJsonUrlArray(callbackUrls, nameof(callbackUrls)));
            
            if (!string.IsNullOrWhiteSpace(allowedOrigins))
                 result.Merge(ValidateJsonUrlArray(allowedOrigins, nameof(allowedOrigins)));

            return Task.FromResult(result);
        }

        public async Task<ValidationResult> ValidateStatusChangeAsync(Guid applicationId, ApplicationStatus currentStatus, ApplicationStatus newStatus)
        {
            _logger.LogWarning("ValidateStatusChangeAsync is not fully implemented.");
            return await Task.FromResult(ValidationResult.Success());
        }

        public async Task<ValidationResult> ValidateOrganizationLimitsAsync(Guid organizationId)
        {
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            var planKey = subscription?.PlanKey ?? "Free";

            var limit = planKey switch
            {
                "Enterprise" => 50, "Business" => 10, "Pro" => 3, _ => 1
            };

            var currentCount = await _applicationRepository.GetCountByOrganizationAsync(organizationId);
            if (currentCount >= limit)
                return ValidationResult.Failure($"Application creation limit ({limit}) for your current plan has been reached.", "APPLICATION_LIMIT_REACHED");

            return ValidationResult.Success();
        }

        #endregion

        #region Private Helper Methods

        private ValidationResult ValidateJsonUrlArray(string json, string fieldName)
        {
            try
            {
                var urls = JsonSerializer.Deserialize<List<string>>(json);
                if (urls == null) 
                    return ValidationResult.Failure($"{fieldName} must be a valid JSON array of strings.", "INVALID_JSON_ARRAY");

                foreach (var url in urls)
                {
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                        return ValidationResult.Failure($"The URL '{url}' in {fieldName} is not a valid absolute HTTP/HTTPS URL.", "INVALID_URL_FORMAT");
                }
            }
            catch (JsonException)
            {
                return ValidationResult.Failure($"{fieldName} must be a valid JSON array of strings.", "INVALID_JSON_FORMAT");
            }
            return ValidationResult.Success();
        }

        #endregion
    }
}