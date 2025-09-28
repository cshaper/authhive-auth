using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Validator;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.PlatformApplication.Requests;
using Microsoft.Extensions.Logging;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;

namespace AuthHive.Auth.Validator
{
    public class ApplicationApiKeyValidator : IApplicationApiKeyValidator
    {
        private readonly IPlatformApplicationApiKeyRepository _apiKeyRepository;
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IPlanService _planService;
        private readonly ILogger<ApplicationApiKeyValidator> _logger;

        public ApplicationApiKeyValidator(
            IPlatformApplicationApiKeyRepository apiKeyRepository,
            IPlatformApplicationRepository applicationRepository,
            IPlanService planService,
            ILogger<ApplicationApiKeyValidator> logger)
        {
            _apiKeyRepository = apiKeyRepository;
            _applicationRepository = applicationRepository;
            _planService = planService;
            _logger = logger;
        }

        public async Task<ValidationResult> ValidateCreateAsync(CreateApplicationApiKeyRequest request, Guid applicationId)
        {
            var result = ValidationResult.Success();

            result.Merge(await ValidateApplicationLimitsAsync(applicationId));
            if (!result.IsValid) return result;

            result.Merge(await ValidateNameAsync(request.Name, applicationId));
            result.Merge(await ValidatePermissionsAsync(request.PermissionLevel, request.AllowedScopes));
            result.Merge(await ValidateIpRestrictionsAsync(request.IpRestrictionPolicy, request.AllowedIpAddresses));
            result.Merge(await ValidateRateLimitAsync(request.RateLimitPolicy, request.CustomRateLimitPerMinute));
            result.Merge(await ValidateExpirationAsync(request.ExpiresAt));

            return result;
        }

        public async Task<ValidationResult> ValidateUpdateAsync(Guid apiKeyId, UpdateApplicationApiKeyRequest request)
        {
            var apiKey = await _apiKeyRepository.GetByIdAsync(apiKeyId);
            if (apiKey == null)
            {
                return ValidationResult.Failure("ApiKey", "API Key not found.", "API_KEY_NOT_FOUND");
            }

            var result = ValidationResult.Success();

            if (!string.IsNullOrWhiteSpace(request.Name) && request.Name != apiKey.KeyName)
            {
                result.Merge(await ValidateNameAsync(request.Name, apiKey.ApplicationId, apiKeyId));
            }
            
            // [FIXED] 'Status' 속성이 없어 발생한 오류 수정
            // DTO의 ApiKeyStatus?를 엔티티의 bool IsActive와 비교하도록 로직 변경
            if (request.Status.HasValue)
            {
                bool newIsActive = (request.Status.Value == ApiKeyStatus.Active);
                if (newIsActive != apiKey.IsActive)
                {
                    // ApiKeyStatus enum을 직접 사용하기 위해 'using' 추가 필요
                    result.Merge(await ValidateStatusChangeAsync(apiKeyId, apiKey.IsActive ? ApiKeyStatus.Active : ApiKeyStatus.Inactive, request.Status.Value));
                }
            }
            
            return result;
        }

        public async Task<ValidationResult> ValidateDeleteAsync(Guid apiKeyId)
        {
            var apiKey = await _apiKeyRepository.GetByIdAsync(apiKeyId);
            if (apiKey == null)
            {
                return ValidationResult.Failure("ApiKey", "API Key not found.", "API_KEY_NOT_FOUND");
            }
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateNameAsync(string name, Guid applicationId, Guid? excludeApiKeyId = null)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
            {
                return ValidationResult.Failure("Name", "API Key name must be between 1 and 100 characters.", "INVALID_NAME_LENGTH");
            }
            
            var exists = await _apiKeyRepository.IsDuplicateNameAsync(applicationId, name, excludeApiKeyId);
            if (exists)
            {
                return ValidationResult.Failure("Name", $"An API Key with the name '{name}' already exists for this application.", "DUPLICATE_API_KEY_NAME");
            }

            return ValidationResult.Success();
        }
        
        public async Task<ValidationResult> ValidateApplicationLimitsAsync(Guid applicationId)
        {
            var application = await _applicationRepository.GetByIdAsync(applicationId);
            if (application == null)
            {
                 return ValidationResult.Failure("Application", "Parent application not found.", "APPLICATION_NOT_FOUND");
            }
            
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(application.OrganizationId);
            var planKey = subscription?.PlanKey ?? "Free";

            var limit = planKey switch
            {
                "Enterprise" => 100,
                "Business" => 20,
                "Pro" => 5,
                _ => 2
            };

            var currentCount = await _apiKeyRepository.GetActiveCountByApplicationAsync(applicationId);
            if (currentCount >= limit)
            {
                return ValidationResult.Failure("ApiKeyLimit", $"API Key creation limit ({limit}) for your current plan has been reached.", "API_KEY_LIMIT_REACHED");
            }

            return ValidationResult.Success();
        }

        #region Other Methods (Unchanged)

        public Task<ValidationResult> ValidateKeyValueAsync(string keyValue)
        {
             _logger.LogWarning("ValidateKeyValueAsync is not fully implemented.");
             return Task.FromResult(ValidationResult.Success());
        }
        
        public Task<ValidationResult> ValidatePermissionsAsync(ApiKeyPermissionLevel permissionLevel, List<ApiKeyScope> scopes)
        {
            _logger.LogWarning("ValidatePermissionsAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateIpRestrictionsAsync(IpRestrictionPolicy policy, List<string> ipAddresses)
        {
            if (policy == IpRestrictionPolicy.Whitelist || policy == IpRestrictionPolicy.Blacklist)
            {
                if (ipAddresses == null || !ipAddresses.Any())
                {
                    return Task.FromResult(ValidationResult.Failure("IpRestrictions", "IP address list cannot be empty for Whitelist or Blacklist policies.", "IP_LIST_REQUIRED"));
                }
                foreach (var ip in ipAddresses)
                {
                    if (!IPAddress.TryParse(ip, out _))
                    {
                         return Task.FromResult(ValidationResult.Failure("IpRestrictions", $"The IP address '{ip}' is not in a valid format.", "INVALID_IP_FORMAT"));
                    }
                }
            }
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateRateLimitAsync(ApiKeyRateLimitPolicy policy, int? customRateLimitPerMinute)
        {
            if (policy == ApiKeyRateLimitPolicy.Custom && (!customRateLimitPerMinute.HasValue || customRateLimitPerMinute.Value <= 0))
            {
                return Task.FromResult(ValidationResult.Failure("RateLimit", "A positive custom rate limit is required when the policy is set to Custom.", "CUSTOM_RATE_LIMIT_REQUIRED"));
            }
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateExpirationAsync(DateTime? expiresAt)
        {
            if (expiresAt.HasValue && expiresAt.Value <= DateTime.UtcNow)
            {
                return Task.FromResult(ValidationResult.Failure("ExpiresAt", "Expiration date must be in the future.", "EXPIRATION_IN_PAST"));
            }
            return Task.FromResult(ValidationResult.Success());
        }
        
        public Task<ValidationResult> ValidateStatusChangeAsync(Guid apiKeyId, ApiKeyStatus currentStatus, ApiKeyStatus newStatus)
        {
             _logger.LogWarning("ValidateStatusChangeAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }

        public Task<ValidationResult> ValidateRegenerationAsync(Guid apiKeyId)
        {
             _logger.LogWarning("ValidateRegenerationAsync is not fully implemented.");
            return Task.FromResult(ValidationResult.Success());
        }
        #endregion
    }
}