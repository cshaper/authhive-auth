// Path: AuthHive.Auth/Services/Authentication/ApiKeyAuthenticationService.cs
using System;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Common;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// IApiKeyAuthenticationService의 최종 구현체입니다. (v16.4 Final)
    /// </summary>
    public class ApiKeyAuthenticationService : IApiKeyAuthenticationService
    {
        private readonly IApiKeyProvider _apiKeyProvider;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IAuthenticationCacheService _authCacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly ILogger<ApiKeyAuthenticationService> _logger;

        public ApiKeyAuthenticationService(
            IApiKeyProvider apiKeyProvider,
            IConnectedIdService connectedIdService,
            IAuthenticationCacheService authCacheService,
            IAuditService auditService,
            IEventBus eventBus,
            ILogger<ApiKeyAuthenticationService> logger)
        {
            _apiKeyProvider = apiKeyProvider;
            _connectedIdService = connectedIdService;
            _authCacheService = authCacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _logger = logger;
        }
        #region IService Implementation with CancellationToken

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        #endregion


        public async Task<ServiceResult<AuthenticationResult>> AuthenticateWithApiKeyAsync(string apiKey, string? apiSecret = null)
        {
            try
            {
                var validationResult = await _authCacheService.GetApiKeyValidationResultAsync(
                    apiKey,
                    () => _apiKeyProvider.ValidateApiKeyAsync(apiKey)
                );

                if (!validationResult.IsSuccess || validationResult.Data?.IsValid != true)
                {
                    var errorMessage = validationResult.ErrorMessage ?? "Invalid API Key or validation failed.";
                    await _auditService.LogActionAsync(AuditActionType.Authentication, "ApiKeyValidationFailed", Guid.Empty, false, errorMessage, "ApiKey", apiKey);
                    return ServiceResult<AuthenticationResult>.Failure(errorMessage);
                }

                var validationData = validationResult.Data;

                // A valid API key must have an ApplicationId. If not, it's a data integrity issue.
                if (!validationData.ApplicationId.HasValue)
                {
                    const string error = "API Key validation succeeded but is missing an ApplicationId.";
                    _logger.LogError(error);
                    return ServiceResult<AuthenticationResult>.Failure(error);
                }

                // FIX 1: Use .Value to pass the non-nullable Guid.
                var serviceAccountResult = await _connectedIdService.GetOrCreateServiceAccountForApplicationAsync(validationData.ApplicationId.Value);

                if (!serviceAccountResult.IsSuccess)
                {
                    var errorMessage = $"Failed to resolve service account for Application ID: {validationData.ApplicationId.Value}";
                    _logger.LogWarning(errorMessage);
                    return ServiceResult<AuthenticationResult>.Failure(errorMessage);
                }

                var serviceAccountConnectedId = serviceAccountResult.Data;

                if (validationData.OrganizationId.HasValue && validationData.Scopes.Contains("core.admin"))
                {
                    // FIX 2: Use .Value for ApplicationId as well.
                    var highPrivilegeEvent = new HighPrivilegeApiKeyUsedEvent(
                        validationData.OrganizationId.Value,
                        validationData.ApplicationId.Value,
                        serviceAccountConnectedId
                    );
                    await _eventBus.PublishAsync(highPrivilegeEvent);
                    _logger.LogWarning("High-privilege API key used for ApplicationId: {ApplicationId}", validationData.ApplicationId.Value);
                }

                var response = new AuthenticationResult
                {
                    Success = true,
                    UserId = null,
                    ConnectedId = serviceAccountConnectedId,
                    OrganizationId = validationData.OrganizationId,
                    ApplicationId = validationData.ApplicationId,
                    Permissions = validationData.Scopes,
                    AuthenticationMethod = AuthenticationMethod.ApiKey.ToString()
                };

                return ServiceResult<AuthenticationResult>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during API key authentication.");
                return ServiceResult<AuthenticationResult>.Failure("An internal server error occurred during authentication.");
            }
        }
    }

    // --- Event Model Example ---
    // This should be in its own file under AuthHive.Core/Models/Auth/Events/
    public class HighPrivilegeApiKeyUsedEvent : BaseEvent
    {

        public HighPrivilegeApiKeyUsedEvent(Guid organizationId, Guid applicationId, Guid connectedId)
            : base(organizationId)
        {
            ApplicationId = applicationId;
            TriggeredBy = connectedId;
            AddTag("Security");
            AddTag("HighPrivilege");
            AddTag("ApiKey");
        }
    }
}