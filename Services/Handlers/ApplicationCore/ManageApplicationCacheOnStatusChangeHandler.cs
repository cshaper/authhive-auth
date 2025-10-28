// File: AuthHive.Auth/Services/Handlers/ApplicationCore/ManageApplicationCacheOnStatusChangeHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationStatusChangedEvent
using AuthHive.Core.Enums.Core; // ApplicationStatus
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Updates the application's status in the cache when it changes.
    /// (Logic from ApplicationEventHandler's UpdateApplicationStatusInCacheAsync)
    /// </summary>
    public class ManageApplicationCacheOnStatusChangeHandler :
        IDomainEventHandler<ApplicationStatusChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageApplicationCacheOnStatusChangeHandler> _logger;

        // Cache Key (from ApplicationEventHandler)
        private const string APP_CACHE_KEY_FORMAT = "tenant:{0}:app:{1}";
        private static readonly TimeSpan ApplicationCacheTTL = TimeSpan.FromHours(6);

        public int Priority => 20; // After logging
        public bool IsEnabled => true;

        public ManageApplicationCacheOnStatusChangeHandler(
            ICacheService cacheService,
            ILogger<ManageApplicationCacheOnStatusChangeHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;

            if (organizationId == Guid.Empty)
            {
                 _logger.LogError("Cannot update cache for AppId {AppId}: OrganizationId is missing.", applicationId);
                 return;
            }

            var cacheKey = string.Format(APP_CACHE_KEY_FORMAT, organizationId, applicationId);

            try
            {
                var cachedData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken);

                if (cachedData != null)
                {
                    // Update status and timestamp
                    cachedData["Status"] = @event.NewStatus.ToString();
                    cachedData["StatusChangedAt"] = @event.ChangedAt; // Use the specific time of change

                    await _cacheService.SetAsync(cacheKey, cachedData, ApplicationCacheTTL, cancellationToken);
                    _logger.LogDebug("Updated application status in cache for AppId={ApplicationId} to {Status}", applicationId, @event.NewStatus);
                }
                else
                {
                    _logger.LogWarning("Application cache data not found for AppId={ApplicationId} during status update.", applicationId);
                }
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Updating application status cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "Failed to update application status cache for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}