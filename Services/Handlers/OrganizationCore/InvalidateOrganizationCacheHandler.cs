// File: AuthHive.Auth/Services/Handlers/OrganizationCore/InvalidateOrganizationCacheHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Organization.Events; // All Organization events
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// **[Final Version]** Invalidates the organization detail cache ("org:id:{orgId}")
    /// when the organization's information or status changes (Update, Status Change, Delete, Parent Change).
    /// </summary>
    public class InvalidateOrganizationCacheHandler :
        // Subscribes to all relevant events
        IDomainEventHandler<OrganizationUpdatedEvent>,
        IDomainEventHandler<OrganizationSuspendedEvent>,
        IDomainEventHandler<OrganizationDeletedEvent>,
        IDomainEventHandler<OrganizationParentChangedEvent>,
        IDomainEventHandler<OrganizationActivatedEvent>,
        IDomainEventHandler<OrganizationDeactivatedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateOrganizationCacheHandler> _logger;

        // Cache key format must match OrganizationRepository
        private const string CacheKeyFormat = "org:id:{0}";

        public int Priority => 50; // Runs after audit logging
        public bool IsEnabled => true;

        public InvalidateOrganizationCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateOrganizationCacheHandler> logger)
        {
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // --- Event Handlers ---

        public Task HandleAsync(OrganizationUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        public Task HandleAsync(OrganizationSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        public Task HandleAsync(OrganizationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        public Task HandleAsync(OrganizationParentChangedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        public Task HandleAsync(OrganizationActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        public Task HandleAsync(OrganizationDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidateCacheAsync(@event.AggregateId, @event.EventType, cancellationToken);
        }

        /// <summary>
        /// Common logic to invalidate the cache.
        /// </summary>
        private async Task InvalidateCacheAsync(Guid organizationId, string eventType, CancellationToken cancellationToken)
        {
            if (organizationId == Guid.Empty)
            {
                _logger.LogWarning("Invalid OrganizationId (Guid.Empty) received from {EventType}. Skipping cache invalidation.", eventType);
                return;
            }

            var cacheKey = string.Format(CacheKeyFormat, organizationId);

            try
            {
                _logger.LogInformation(
                    "Invalidating organization cache triggered by {EventType}. Key: {CacheKey}",
                    eventType, cacheKey);

                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate organization cache for key: {CacheKey}", cacheKey);
                // Cache removal failure should not stop main business logic
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}