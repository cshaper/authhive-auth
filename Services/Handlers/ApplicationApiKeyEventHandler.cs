// Namespaces
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // 이 네임스페이스는 이제 LogActionAsync에서 직접 사용되지 않습니다.
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Handlers;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.PlatformApplication.Events;
using Microsoft.Extensions.Logging;


namespace AuthHive.Application.Handlers
{
    /// <summary>
    /// API 키 관련 이벤트를 처리하며, 캐싱, 감사 로깅, 보안 응답 트리거 등의 작업을 수행합니다.
    /// </summary>
    public class ApplicationApiKeyEventHandler : IApplicationApiKeyEventHandler
    {
        private readonly ILogger<ApplicationApiKeyEventHandler> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        // 중요 알림을 위한 IEmailService (주석 처리됨)
        // private readonly IEmailService _emailService;

        public ApplicationApiKeyEventHandler(
            ILogger<ApplicationApiKeyEventHandler> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IEventBus eventBus
            /* IEmailService emailService */)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            // _emailService = emailService;
        }

        #region Lifecycle Events

        public async Task HandleApiKeyCreatedAsync(ApiKeyCreatedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyCreatedEvent: ApplicationId is missing or empty for ApiKeyId (AggregateId) {AggregateId}.", eventData.AggregateId);
                return; // 데이터가 유효하지 않으면 조기 종료합니다.
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyCreated", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                var cacheKey = GetApiKeyCacheKey(eventData.ApplicationId.Value, eventData.AggregateId);
                var cachedData = new { ApiKeyId = eventData.AggregateId, eventData.ApplicationId, eventData.KeyName, Status = "Active" };
                await _cacheService.SetAsync(cacheKey, cachedData, TimeSpan.FromHours(24), ct);

                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.CreatedByConnectedId,
                    action: "API_KEY_CREATED",
                    actionType: AuditActionType.Create,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    // [FIX] CS1503: string -> Dictionary<string, object>
                    metadata: new Dictionary<string, object>
                    {
                        ["KeyName"] = eventData.KeyName,
                        ["KeyPrefix"] = eventData.KeyPrefix,
                        ["KeySource"] = eventData.KeySource 
                    },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        public async Task HandleApiKeyUpdatedAsync(ApiKeyUpdatedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyUpdatedEvent: ApplicationId is missing or empty for ApiKeyId (AggregateId) {AggregateId}.", eventData.AggregateId);
                return; 
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyUpdated", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                
                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.UpdatedByConnectedId,
                    action: "API_KEY_UPDATED",
                    actionType: AuditActionType.Update,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    // [FIX] CS1503: string -> Dictionary<string, object>
                    metadata: new Dictionary<string, object>
                    {
                        ["ChangedProperties"] = eventData.ChangedProperties
                    },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        public async Task HandleApiKeyDeletedAsync(ApiKeyDeletedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyDeletedEvent: ApplicationId is missing or empty for ApiKeyId (AggregateId) {AggregateId}.", eventData.AggregateId);
                return; 
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyDeleted", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.DeletedByConnectedId,
                    action: "API_KEY_DELETED",
                    actionType: AuditActionType.Delete,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    // [FIX] CS1503: string -> Dictionary<string, object>
                    metadata: new Dictionary<string, object>
                    {
                        ["Reason"] = eventData.Reason ?? "Not specified"
                    },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        public async Task HandleApiKeyExpiredAsync(ApiKeyExpiredEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyExpiredEvent: ApplicationId is missing or empty for ApiKeyId (AggregateId) {AggregateId}.", eventData.AggregateId);
                return; 
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyExpired", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                await _auditService.LogSecurityEventAsync(
                    eventType: "ApiKeyExpired",
                    severity: AuditEventSeverity.Info,
                    description: $"API Key '{eventData.AggregateId}' for Application '{eventData.ApplicationId}' has expired.",
                    connectedId: null, 
                    details: new Dictionary<string, object> { ["ExpiredAt"] = eventData.OccurredAt },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        #endregion

        #region Usage Events (Performance & Cost Optimized)

        public async Task HandleApiKeyUsedAsync(ApiKeyUsedEvent eventData, CancellationToken cancellationToken)
        {
            // ... (주석 동일)

            // [FIX] ApiKeyId -> AggregateId
            var usageCounterKey = GetApiKeyUsageCounterKey(eventData.AggregateId);
            await _cacheService.IncrementAsync(usageCounterKey, 1, cancellationToken);
        }

        public async Task HandleApiKeyRateLimitReachedAsync(ApiKeyRateLimitEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApiKeyId -> AggregateId
            _logger.LogWarning("Rate limit reached for API Key {ApiKeyId} on App {AppId}", eventData.AggregateId, eventData.ApplicationId);

            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyRateLimitReached",
                severity: AuditEventSeverity.Warning,
                description: $"API Key is being throttled.",
                connectedId: null, 
                details: new Dictionary<string, object>
                {
                    // [FIX] ApiKeyId -> AggregateId
                    ["ApiKeyId"] = eventData.AggregateId,
                    ["ApplicationId"] = eventData.ApplicationId ?? Guid.Empty,
                    ["RateLimitPerMinute"] = eventData.RateLimitPerMinute,
                    ["CurrentRequests"] = eventData.CurrentRequests
                },
                cancellationToken: cancellationToken
            );
        }

        public async Task HandleApiKeyAuthenticationFailedAsync(ApiKeyAuthFailedEvent eventData, CancellationToken cancellationToken)
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
                },
                cancellationToken: cancellationToken
            );
        }

        #endregion

        #region Management Events

        public async Task HandleApiKeyDeactivatedAsync(ApiKeyDeactivatedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                // [FIX] ApiKeyId -> AggregateId
                _logger.LogError("Cannot handle ApiKeyDeactivatedEvent: ApplicationId is missing for ApiKeyId {AggregateId}.", eventData.AggregateId);
                return; 
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyDeactivated", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.DeactivatedByConnectedId,
                    action: "API_KEY_DEACTIVATED",
                    actionType: AuditActionType.StatusChange,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    // [FIX] CS1503: string -> Dictionary<string, object>
                    metadata: new Dictionary<string, object>
                    {
                        ["Reason"] = eventData.Reason ?? "Not specified"
                    },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        public async Task HandleApiKeyReactivatedAsync(ApiKeyReactivatedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                // [FIX] ApiKeyId -> AggregateId
                _logger.LogError("Cannot handle ApiKeyReactivatedEvent: ApplicationId is missing or empty for ApiKeyId {AggregateId}.", eventData.AggregateId);
                return;
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyReactivated", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.ReactivatedByConnectedId,
                    action: "API_KEY_REACTIVATED",
                    actionType: AuditActionType.StatusChange,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        public async Task HandleApiKeyScopeChangedAsync(ApiKeyScopeChangedEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                // [FIX] ApiKeyId -> AggregateId
                _logger.LogError("Cannot handle ApiKeyScopeChangedEvent: ApplicationId is missing or empty for ApiKeyId {AggregateId}.", eventData.AggregateId);
                return;
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await HandleEventAsync("ApiKeyScopeChanged", eventData.ApplicationId.Value, eventData.AggregateId, async (ct) =>
            {
                // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.AggregateId, ct);
                await _auditService.LogActionAsync(
                    // [FIX] CS1739: 'performedByConnectedId:' -> 'connectedId:'
                    connectedId: eventData.ChangedByConnectedId,
                    action: "API_KEY_SCOPE_CHANGED",
                    actionType: AuditActionType.PermissionUpdated,
                    resourceType: "ApiKey",
                    // [FIX] ApiKeyId -> AggregateId
                    resourceId: eventData.AggregateId.ToString(),
                    // [FIX] CS1503 & CS8601: null일 경우 빈 리스트로 대체
                    metadata: new Dictionary<string, object>
                    {
                        ["OldScopes"] = eventData.OldScopes ?? (object)new List<string>(),
                        ["NewScopes"] = eventData.NewScopes ?? (object)new List<string>()
                    },
                    cancellationToken: ct
                );
            }, cancellationToken);
        }

        #endregion

        #region Security Events

        public async Task HandleSuspiciousApiKeyActivityAsync(SuspiciousApiKeyActivityEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApiKeyId -> AggregateId
            _logger.LogCritical("Suspicious activity detected for API Key {ApiKeyId}! Type: {Activity}", eventData.AggregateId, eventData.ActivityType);

            await _auditService.LogSecurityEventAsync(
                eventType: "SuspiciousApiKeyActivity",
                severity: AuditEventSeverity.Critical,
                description: $"Suspicious activity detected: {eventData.ActivityType}",
                connectedId: null,
                details: eventData.Details.Concat(new Dictionary<string, object>
                {
                    // [FIX] ApiKeyId -> AggregateId
                    ["ApiKeyId"] = eventData.AggregateId,
                    ["ApplicationId"] = eventData.ApplicationId ?? Guid.Empty
                }).ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                cancellationToken: cancellationToken
            );

            // await _eventBus.PublishAsync(new ApiKeyLockoutRequiredEvent { ... }, cancellationToken);
        }

        public async Task HandleApiKeyExposureDetectedAsync(ApiKeyExposureEvent eventData, CancellationToken cancellationToken)
        {
            // [FIX] ApiKeyId -> AggregateId
            _logger.LogCritical("API Key {ApiKeyId} exposure detected at {Location}!", eventData.AggregateId, eventData.ExposureLocation);

            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyExposureDetected",
                severity: AuditEventSeverity.Critical,
                description: $"API Key has been detected in a public location: {eventData.ExposureLocation}",
                connectedId: null,
                details: new Dictionary<string, object>
                {
                    // [FIX] ApiKeyId -> AggregateId
                    ["ApiKeyId"] = eventData.AggregateId,
                    ["ApplicationId"] = eventData.ApplicationId ?? Guid.Empty, // Nullable 처리
                    ["ExposureUrl"] = eventData.ExposureUrl ?? "N/A"
                },
                cancellationToken: cancellationToken
            );

            // [FIX] ApplicationId는 Guid? 이므로 .Value를 사용하기 전 null 체크
            if (!eventData.ApplicationId.HasValue || eventData.ApplicationId.Value == Guid.Empty)
            {
                // [FIX] ApiKeyId -> AggregateId
                _logger.LogCritical("Cannot process ApiKeyExposureEvent for ApiKeyId {AggregateId}: ApplicationId is missing or empty.", eventData.AggregateId);
                return;
            }

            // [FIX] ApiKeyId -> AggregateId / ApplicationId.Value 사용
            await _eventBus.PublishAsync(new ApiKeyDeactivatedEvent(eventData.ApplicationId.Value, eventData.AggregateId)
            {
                Reason = $"Automatically deactivated due to public exposure detected at {eventData.ExposureLocation}.",
                DeactivatedByConnectedId = Guid.Empty,
                DeactivatedAt = DateTime.UtcNow
            }, cancellationToken);

            // await _emailService.SendApiKeyExposedAlertAsync(eventData, cancellationToken);
        }

        #endregion

        #region Private Helper Methods

        // [FIX] apiKeyId 매개변수 이름을 aggregateId로 변경하여 명확성 확보
        private async Task HandleEventAsync(string eventName, Guid applicationId, Guid aggregateId, Func<CancellationToken, Task> handlerAction, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling {EventName}: App={AppId}, Key={KeyId}", eventName, applicationId, aggregateId);
            try
            {
                await handlerAction(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling {EventName} was canceled: App={AppId}, Key={KeyId}", eventName, applicationId, aggregateId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling {EventName}: App={AppId}, Key={KeyId}", eventName, applicationId, aggregateId);
                throw; 
            }
        }

        // [FIX] apiKeyId 매개변수 이름을 aggregateId로 변경하여 명확성 확보
        private async Task InvalidateApiKeyCacheAsync(Guid applicationId, Guid aggregateId, CancellationToken cancellationToken)
        {
            var cacheKey = GetApiKeyCacheKey(applicationId, aggregateId);
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            _logger.LogDebug("Invalidated API Key cache for App={AppId}, Key={KeyId}", applicationId, aggregateId);
        }

        // [FIX] apiKeyId 매개변수 이름을 aggregateId로 변경하여 명확성 확보
        private static string GetApiKeyCacheKey(Guid applicationId, Guid aggregateId) => $"apikeys:{applicationId}:{aggregateId}";
        
        // [FIX] apiKeyId 매개변수 이름을 aggregateId로 변경하여 명확성 확보
        private static string GetApiKeyUsageCounterKey(Guid aggregateId) => $"apikeys:usage:{aggregateId}";

        #endregion
    }
}