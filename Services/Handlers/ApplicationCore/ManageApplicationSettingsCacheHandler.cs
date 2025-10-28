// File: AuthHive.Auth/Services/Handlers/ApplicationCore/ManageApplicationSettingsCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationSettingsChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Updates the application's settings cache when a setting changes.
    /// (Logic from ApplicationEventHandler's HandleApplicationSettingsChangedAsync)
    /// </summary>
    public class ManageApplicationSettingsCacheHandler :
        IDomainEventHandler<ApplicationSettingsChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<ManageApplicationSettingsCacheHandler> _logger;

        // Cache Key (from ApplicationEventHandler)
        private const string SETTINGS_CACHE_KEY_FORMAT = "app:{0}:settings";
        private static readonly TimeSpan SettingsCacheTTL = TimeSpan.FromHours(1);

        public int Priority => 20; // After logging (if any)
        public bool IsEnabled => true;

        public ManageApplicationSettingsCacheHandler(
            ICacheService cacheService,
            ILogger<ManageApplicationSettingsCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var cacheKey = string.Format(SETTINGS_CACHE_KEY_FORMAT, applicationId);

            try
            {
                // Note: Potential race condition if multiple updates happen concurrently.
                // Consider using distributed locking (e.g., RedLock.net) if high concurrency is expected.

                // 1. Get current settings from cache
                var settings = await _cacheService.GetAsync<Dictionary<string, object?>>(cacheKey, cancellationToken)
                               ?? new Dictionary<string, object?>();

                // 2. Update or remove the specific setting
                if (@event.NewValue != null)
                {
                    settings[@event.SettingKey] = @event.NewValue;
                }
                else
                {
                    settings.Remove(@event.SettingKey); // Remove if the new value is null
                }

                // 3. Set the updated dictionary back into the cache
                await _cacheService.SetAsync(cacheKey, settings, SettingsCacheTTL, cancellationToken);

                _logger.LogDebug("Updated application settings cache for AppId: {AppId}, Key: {SettingKey}", applicationId, @event.SettingKey);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Updating application settings cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "Failed to update application settings cache for AppId: {AppId}, Key: {SettingKey}", applicationId, @event.SettingKey);
                 // Cache failures usually shouldn't break the main flow.
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}