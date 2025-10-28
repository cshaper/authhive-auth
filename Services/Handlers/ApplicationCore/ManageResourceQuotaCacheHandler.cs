// File: AuthHive.Auth/Services/Handlers/ApplicationCore/ManageResourceQuotaCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // ResourceQuotaChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Updates the resource quota cache when it changes.
    /// (Separated from ApplicationEventHandler)
    /// </summary>
    public class ManageResourceQuotaCacheHandler :
        IDomainEventHandler<ResourceQuotaChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageResourceQuotaCacheHandler> _logger;

        // Cache Key (from ApplicationEventHandler)
        private const string QUOTA_CACHE_KEY_FORMAT = "app:{0}:quota:{1}";
        private static readonly TimeSpan QuotaCacheTTL = TimeSpan.FromHours(24); // Example: 24 hours

        public int Priority => 20; // After logging (10)
        public bool IsEnabled => true;

        public ManageResourceQuotaCacheHandler(
            ICacheService cacheService,
            ILogger<ManageResourceQuotaCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(ResourceQuotaChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var cacheKey = string.Format(QUOTA_CACHE_KEY_FORMAT, applicationId, @event.ResourceType);

            try
            {
                _logger.LogInformation(
                    "Updating resource quota cache for AppId: {AppId}, Resource: {Resource}, NewQuota: {NewQuota}",
                    applicationId, @event.ResourceType, @event.NewQuota);

                // ❗️ [FIX] CS0452 Error Fix: Store decimal as string
                string quotaAsString = @event.NewQuota.ToString(System.Globalization.CultureInfo.InvariantCulture); // Use invariant culture
                await _cacheService.SetAsync(cacheKey, quotaAsString, QuotaCacheTTL, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Updating resource quota cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update resource quota cache for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}