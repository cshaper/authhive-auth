// File: AuthHive.Auth/Services/Handlers/ApplicationCore/InvalidateOAuthCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // OAuthSettingsChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ Correct namespace
{
    /// <summary>
    /// Invalidates OAuth-related caches when settings change.
    /// (Logic from ApplicationEventHandler's InvalidateOAuthCacheAsync)
    /// </summary>
    public class InvalidateOAuthCacheHandler :
        IDomainEventHandler<OAuthSettingsChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateOAuthCacheHandler> _logger;

        // Cache Pattern (from ApplicationEventHandler)
        private const string OAUTH_CACHE_PATTERN_FORMAT = "app:{0}:oauth:*";

        public int Priority => 20; // After logging
        public bool IsEnabled => true;

        public InvalidateOAuthCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateOAuthCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(OAuthSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var pattern = string.Format(OAUTH_CACHE_PATTERN_FORMAT, applicationId);

            try
            {
                // Invalidate all caches matching the pattern
                // Assumes ICacheService supports pattern-based removal (like Redis KEYS/SCAN + DEL)
                await _cacheService.RemoveByPatternAsync(pattern, cancellationToken);
                _logger.LogInformation("Invalidated OAuth cache pattern '{Pattern}' for AppId={ApplicationId}", pattern, applicationId);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating OAuth cache for AppId {AppId} was canceled.", applicationId);
                 throw;
            }
            catch (NotSupportedException nse) // Handle if RemoveByPatternAsync isn't supported
            {
                 _logger.LogWarning(nse, "Cache service does not support pattern removal. OAuth cache for AppId {AppId} might be stale.", applicationId);
                 // Consider invalidating specific known keys if pattern removal fails
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "Failed to invalidate OAuth cache for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}