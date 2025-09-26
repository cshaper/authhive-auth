// Namespaces
using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Application.Handlers;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
// Assuming IEmailService and related DTOs are in this namespace

using AuthHive.Core.Models.PlatformApplication.Events;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience;


namespace AuthHive.Application.Handlers
{
    /// <summary>
    /// </summary>
    public class ApplicationApiKeyEventHandler : IApplicationApiKeyEventHandler
    {
        private readonly ILogger<ApplicationApiKeyEventHandler> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        // IEmailService for critical notifications
        private readonly IEmailService _emailService; 

        public ApplicationApiKeyEventHandler(
            ILogger<ApplicationApiKeyEventHandler> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IEventBus eventBus,
            IEmailService emailService)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _emailService = emailService;
        }

        #region Lifecycle Events

        public async Task HandleApiKeyCreatedAsync(ApiKeyCreatedEvent eventData)
        {
            await HandleEventAsync("ApiKeyCreated", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                // Cache the new API key details immediately for fast access.
                var cacheKey = GetApiKeyCacheKey(eventData.ApplicationId, eventData.ApiKeyId);
                // Cache only essential, non-sensitive data.
                var cachedData = new { eventData.ApiKeyId, eventData.ApplicationId, eventData.KeyName, Status = "Active" };
                await _cacheService.SetAsync(cacheKey, cachedData, TimeSpan.FromHours(24));

                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.CreatedByConnectedId,
                    action: "API_KEY_CREATED",
                    actionType: AuditActionType.Create,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString(),
                    metadata: JsonSerializer.Serialize(new { eventData.KeyName, eventData.KeyPrefix, eventData.KeySource })
                );
            });
        }

        public async Task HandleApiKeyUpdatedAsync(ApiKeyUpdatedEvent eventData)
        {
            await HandleEventAsync("ApiKeyUpdated", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.UpdatedByConnectedId,
                    action: "API_KEY_UPDATED",
                    actionType: AuditActionType.Update,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString(),
                    metadata: JsonSerializer.Serialize(new { eventData.ChangedProperties })
                );
            });
        }

        public async Task HandleApiKeyDeletedAsync(ApiKeyDeletedEvent eventData)
        {
            await HandleEventAsync("ApiKeyDeleted", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.DeletedByConnectedId,
                    action: "API_KEY_DELETED",
                    actionType: AuditActionType.Delete,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString(),
                    metadata: JsonSerializer.Serialize(new { eventData.Reason })
                );
            });
        }

        public async Task HandleApiKeyExpiredAsync(ApiKeyExpiredEvent eventData)
        {
            await HandleEventAsync("ApiKeyExpired", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                // System-triggered event
                await _auditService.LogSecurityEventAsync(
                    eventType: "ApiKeyExpired",
                    severity: AuditEventSeverity.Info,
                    description: $"API Key '{eventData.ApiKeyId}' for Application '{eventData.ApplicationId}' has expired.",
                    connectedId: null, // System event
                    details: new Dictionary<string, object> { ["ExpiredAt"] = eventData.ExpiredAt }
                );
            });
        }

        #endregion

        #region Usage Events (Performance & Cost Optimized)

        public Task HandleApiKeyUsedAsync(ApiKeyUsedEvent eventData)
        {
            // RECOMMENDATION: This is a high-frequency event.
            // Logging every single use to the main audit database is extremely costly.
            // This handler should focus on lightweight, in-memory operations like updating rate-limit counters.
            // For analytics, stream these events to a separate, high-throughput logging pipeline (e.g., Kafka -> Data Lake).
            
            // Example: Increment a counter in cache
            var usageCounterKey = GetApiKeyUsageCounterKey(eventData.ApiKeyId);
            _cacheService.IncrementAsync(usageCounterKey, 1);

            return Task.CompletedTask;
        }

        public async Task HandleApiKeyRateLimitReachedAsync(ApiKeyRateLimitEvent eventData)
        {
            _logger.LogWarning("Rate limit reached for API Key {ApiKeyId} on App {AppId}", eventData.ApiKeyId, eventData.ApplicationId);

            // This is a security-relevant event, log it as such.
            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyRateLimitReached",
                severity: AuditEventSeverity.Warning,
                description: $"API Key is being throttled.",
                connectedId: null, // System event, but tied to the key
                details: new Dictionary<string, object>
                {
                    ["ApiKeyId"] = eventData.ApiKeyId,
                    ["ApplicationId"] = eventData.ApplicationId,
                    ["RateLimitPerMinute"] = eventData.RateLimitPerMinute,
                    ["CurrentRequests"] = eventData.CurrentRequests
                }
            );
        }

        public async Task HandleApiKeyAuthenticationFailedAsync(ApiKeyAuthFailedEvent eventData)
        {
            _logger.LogWarning("API Key authentication failed. Reason: {Reason}, IP: {IP}", eventData.FailureReason, eventData.ClientIp);

            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyAuthenticationFailed",
                severity: AuditEventSeverity.Critical,
                description: $"Failed login attempt with API key prefix '{eventData.AttemptedKey}'. Reason: {eventData.FailureReason}",
                connectedId: null,
                details: new Dictionary<string, object>
                {
                    ["ApplicationId"] = eventData.ApplicationId ?? Guid.Empty,
                    ["ClientIp"] = eventData.ClientIp ?? "Unknown"
                }
            );
        }

        #endregion

        #region Management Events

        public async Task HandleApiKeyDeactivatedAsync(ApiKeyDeactivatedEvent eventData)
        {
            await HandleEventAsync("ApiKeyDeactivated", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.DeactivatedByConnectedId,
                    action: "API_KEY_DEACTIVATED",
                    actionType: AuditActionType.StatusChange,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString(),
                    metadata: JsonSerializer.Serialize(new { eventData.Reason })
                );
            });
        }

        public async Task HandleApiKeyReactivatedAsync(ApiKeyReactivatedEvent eventData)
        {
            await HandleEventAsync("ApiKeyReactivated", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.ReactivatedByConnectedId,
                    action: "API_KEY_REACTIVATED",
                    actionType: AuditActionType.StatusChange,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString()
                );
            });
        }

        public async Task HandleApiKeyScopeChangedAsync(ApiKeyScopeChangedEvent eventData)
        {
            await HandleEventAsync("ApiKeyScopeChanged", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                // Scope changes are critical security events.
                await _auditService.LogActionAsync(
                    performedByConnectedId: eventData.ChangedByConnectedId,
                    action: "API_KEY_SCOPE_CHANGED",
                    actionType: AuditActionType.PermissionUpdated,
                    resourceType: "ApiKey",
                    resourceId: eventData.ApiKeyId.ToString(),
                    metadata: JsonSerializer.Serialize(new { OldScopes = eventData.OldScopes, NewScopes = eventData.NewScopes })
                );
            });
        }

        #endregion

        #region Security Events

        public async Task HandleSuspiciousApiKeyActivityAsync(SuspiciousApiKeyActivityEvent eventData)
        {
            _logger.LogCritical("Suspicious activity detected for API Key {ApiKeyId}! Type: {Activity}", eventData.ApiKeyId, eventData.ActivityType);

            // Log a high-severity security event.
            await _auditService.LogSecurityEventAsync(
                eventType: "SuspiciousApiKeyActivity",
                severity: AuditEventSeverity.Critical,
                description: $"Suspicious activity detected: {eventData.ActivityType}",
                connectedId: null,
                details: eventData.Details.Concat(new Dictionary<string, object>
                {
                    ["ApiKeyId"] = eventData.ApiKeyId,
                    ["ApplicationId"] = eventData.ApplicationId
                }).ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
            );

            // RECOMMENDATION: Publish an internal event to trigger automated responses,
            // such as sending a critical alert email or temporarily locking the key.
            // await _eventBus.PublishAsync(new ApiKeyLockoutRequiredEvent { ... });
        }

        public async Task HandleApiKeyExposureDetectedAsync(ApiKeyExposureEvent eventData)
        {
            _logger.LogCritical("API Key {ApiKeyId} exposure detected at {Location}!", eventData.ApiKeyId, eventData.ExposureLocation);

            // 1. Log a critical security event.
            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyExposureDetected",
                severity: AuditEventSeverity.Critical,
                description: $"API Key has been detected in a public location: {eventData.ExposureLocation}",
                connectedId: null,
                details: new Dictionary<string, object>
                {
                    ["ApiKeyId"] = eventData.ApiKeyId,
                    ["ApplicationId"] = eventData.ApplicationId,
                    ["ExposureUrl"] = eventData.ExposureUrl ?? "N/A"
                }
            );

            // 2. Publish an event to automatically deactivate the key.
            // This is a crucial automated security response.
            await _eventBus.PublishAsync(new ApiKeyDeactivatedEvent
            {
                ApiKeyId = eventData.ApiKeyId,
                ApplicationId = eventData.ApplicationId,
                Reason = $"Automatically deactivated due to public exposure detected at {eventData.ExposureLocation}.",
                // System-level action, no specific user initiated it.
                DeactivatedByConnectedId = Guid.Empty, 
                DeactivatedAt = DateTime.UtcNow
            });

            // 3. Send an urgent email to the account owner.
            // await _emailService.SendApiKeyExposedAlertAsync(eventData);
        }

        #endregion

        #region Private Helper Methods

        private async Task HandleEventAsync(string eventName, Guid applicationId, Guid apiKeyId, Func<Task> handlerAction)
        {
            _logger.LogInformation("Handling {EventName}: App={AppId}, Key={KeyId}", eventName, applicationId, apiKeyId);
            try
            {
                await handlerAction();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling {EventName}: App={AppId}, Key={KeyId}", eventName, applicationId, apiKeyId);
                throw;
            }
        }

        private async Task InvalidateApiKeyCacheAsync(Guid applicationId, Guid apiKeyId)
        {
            var cacheKey = GetApiKeyCacheKey(applicationId, apiKeyId);
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated API Key cache for App={AppId}, Key={KeyId}", applicationId, apiKeyId);
        }

        // Cache keys must be designed for multi-tenancy.
        private static string GetApiKeyCacheKey(Guid applicationId, Guid apiKeyId) => $"apikeys:{applicationId}:{apiKeyId}";
        private static string GetApiKeyUsageCounterKey(Guid apiKeyId) => $"apikeys:usage:{apiKeyId}";

        #endregion
    }
}