// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/InvalidateApiKeyCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // API Key events
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// Invalidates Application API Key caches when lifecycle events occur.
    /// (Created, Updated, Deleted, Deactivated, Reactivated, ScopeChanged)
    /// </summary>
    public class InvalidateApiKeyCacheHandler :
        IDomainEventHandler<ApplicationApiKeyCreatedEvent>, // Renamed
        IDomainEventHandler<ApplicationApiKeyUpdatedEvent>, // Renamed (Assumption)
        IDomainEventHandler<ApplicationApiKeyDeletedEvent>, // Renamed (Assumption)
        IDomainEventHandler<ApplicationApiKeyDeactivatedEvent>, // Renamed (Assumption)
        IDomainEventHandler<ApplicationApiKeyReactivatedEvent>, // Renamed (Assumption)
        IDomainEventHandler<ApplicationApiKeyScopeChangedEvent>, // Renamed (Assumption)
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateApiKeyCacheHandler> _logger;
        // Example cache key format: "apikeys:appId:keyId" or "apikey:keyId"
        private const string APIKEY_CACHE_KEY_FORMAT = "apikey:{0}"; // Key ID based seems safer
        private const string APP_APIKEYS_LIST_CACHE_KEY_FORMAT = "appkeys:{0}"; // List of keys for an app

        public int Priority => 5; // High priority
        public bool IsEnabled => true;

        public InvalidateApiKeyCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateApiKeyCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // --- Event Handlers ---
        public Task HandleAsync(ApplicationApiKeyCreatedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "Created", c);

        public Task HandleAsync(ApplicationApiKeyUpdatedEvent @event, CancellationToken c) =>
             InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "Updated", c);
        
        public Task HandleAsync(ApplicationApiKeyDeletedEvent @event, CancellationToken c) =>
             InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "Deleted", c);

        public Task HandleAsync(ApplicationApiKeyDeactivatedEvent @event, CancellationToken c) =>
             InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "Deactivated", c);

        public Task HandleAsync(ApplicationApiKeyReactivatedEvent @event, CancellationToken c) =>
             InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "Reactivated", c);
        
        public Task HandleAsync(ApplicationApiKeyScopeChangedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.ApplicationId, @event.AggregateId, "ScopeChanged", c);


        private async Task InvalidateCacheInternalAsync(Guid? applicationId, Guid apiKeyId, string reason, CancellationToken cancellationToken)
        {
            if (apiKeyId == Guid.Empty) return;

            try
            {
                var apiKeyCacheKey = string.Format(APIKEY_CACHE_KEY_FORMAT, apiKeyId);
                var appKeysListKey = applicationId.HasValue ? string.Format(APP_APIKEYS_LIST_CACHE_KEY_FORMAT, applicationId.Value) : null;

                var keysToRemove = new List<string> { apiKeyCacheKey };
                if (appKeysListKey != null) keysToRemove.Add(appKeysListKey);

                _logger.LogInformation(
                    "Invalidating API Key cache due to {Reason}. ApiKeyId: {ApiKeyId}, AppId: {AppId}",
                     reason, apiKeyId, applicationId?.ToString() ?? "N/A");

                await _cacheService.RemoveMultipleAsync(keysToRemove, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate API Key cache for ApiKeyId: {ApiKeyId}", apiKeyId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}