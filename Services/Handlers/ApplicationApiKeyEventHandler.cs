// Namespaces
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
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

        public async Task HandleApiKeyCreatedAsync(ApiKeyCreatedEvent eventData)
        {
            await HandleEventAsync("ApiKeyCreated", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                // 새로운 API 키 정보를 즉시 캐시하여 빠른 접근을 보장합니다.
                var cacheKey = GetApiKeyCacheKey(eventData.ApplicationId, eventData.ApiKeyId);
                // 민감하지 않은 필수 데이터만 캐시합니다.
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
                // 시스템에 의해 트리거된 이벤트입니다.
                await _auditService.LogSecurityEventAsync(
                    eventType: "ApiKeyExpired",
                    severity: AuditEventSeverity.Info,
                    description: $"API Key '{eventData.ApiKeyId}' for Application '{eventData.ApplicationId}' has expired.",
                    connectedId: null, // 시스템 이벤트
                    details: new Dictionary<string, object> { ["ExpiredAt"] = eventData.ExpiredAt }
                );
            });
        }

        #endregion

        #region Usage Events (Performance & Cost Optimized)

        public Task HandleApiKeyUsedAsync(ApiKeyUsedEvent eventData)
        {
            // 권장 사항: 이 이벤트는 매우 빈번하게 발생합니다.
            // 모든 사용 기록을 메인 감사 데이터베이스에 로깅하는 것은 비용이 매우 큽니다.
            // 이 핸들러는 사용량 제한 카운터 업데이트와 같은 가벼운 인메모리 작업에 집중해야 합니다.
            // 분석을 위해서는 이 이벤트들을 별도의 고성능 로깅 파이프라인(예: Kafka -> Data Lake)으로 스트리밍하는 것이 좋습니다.

            // 예시: 캐시의 카운터 증가
            var usageCounterKey = GetApiKeyUsageCounterKey(eventData.ApiKeyId);
            _cacheService.IncrementAsync(usageCounterKey, 1);

            return Task.CompletedTask;
        }

        public async Task HandleApiKeyRateLimitReachedAsync(ApiKeyRateLimitEvent eventData)
        {
            _logger.LogWarning("Rate limit reached for API Key {ApiKeyId} on App {AppId}", eventData.ApiKeyId, eventData.ApplicationId);

            // 보안 관련 중요 이벤트이므로, 보안 로그로 기록합니다.
            await _auditService.LogSecurityEventAsync(
                eventType: "ApiKeyRateLimitReached",
                severity: AuditEventSeverity.Warning,
                description: $"API Key is being throttled.",
                connectedId: null, // 시스템 이벤트이지만, 특정 키와 관련이 있습니다.
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
            // 비활성화 이벤트는 반드시 연관된 애플리케이션 ID를 가져야 합니다.
            if (!eventData.ApplicationId.HasValue)
            {
                _logger.LogError("Cannot handle ApiKeyDeactivatedEvent: ApplicationId is missing for ApiKeyId {ApiKeyId}.", eventData.ApiKeyId);
                return; // 데이터가 유효하지 않으면 조기 종료합니다.
            }

            await HandleEventAsync("ApiKeyDeactivated", eventData.ApplicationId.Value, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId.Value, eventData.ApiKeyId);
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
            if (eventData.ApplicationId == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyReactivatedEvent: ApplicationId is an empty Guid for ApiKeyId {ApiKeyId}.", eventData.ApiKeyId);
                return;
            }

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
            if (eventData.ApplicationId == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApiKeyScopeChangedEvent: ApplicationId is an empty Guid for ApiKeyId {ApiKeyId}.", eventData.ApiKeyId);
                return;
            }

            await HandleEventAsync("ApiKeyScopeChanged", eventData.ApplicationId, eventData.ApiKeyId, async () =>
            {
                await InvalidateApiKeyCacheAsync(eventData.ApplicationId, eventData.ApiKeyId);
                // 스코프 변경은 중요한 보안 이벤트입니다.
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

            // 높은 심각도의 보안 이벤트를 기록합니다.
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

            // 권장 사항: 내부 이벤트를 발행하여 자동화된 응답(예: 관리자에게 긴급 알림 이메일 전송 또는 키 임시 잠금)을 트리거합니다.
            // await _eventBus.PublishAsync(new ApiKeyLockoutRequiredEvent { ... });
        }

        public async Task HandleApiKeyExposureDetectedAsync(ApiKeyExposureEvent eventData)
        {
            _logger.LogCritical("API Key {ApiKeyId} exposure detected at {Location}!", eventData.ApiKeyId, eventData.ExposureLocation);

            // 1. 심각한 보안 이벤트를 기록합니다.
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

            // 노출된 키는 반드시 애플리케이션 ID를 가져야 합니다.
            if (eventData.ApplicationId == Guid.Empty)
            {
                _logger.LogCritical("Cannot process ApiKeyExposureEvent for ApiKeyId {ApiKeyId}: ApplicationId is missing or empty.", eventData.ApiKeyId);
                return;
            }

            // 2. 키를 자동으로 비활성화하는 이벤트를 발행합니다.
            // 이것은 매우 중요한 자동화된 보안 조치입니다.
            await _eventBus.PublishAsync(new ApiKeyDeactivatedEvent(eventData.ApplicationId, eventData.ApiKeyId)
            {
                Reason = $"Automatically deactivated due to public exposure detected at {eventData.ExposureLocation}.",
                // 특정 사용자가 아닌 시스템에 의한 조치입니다.
                DeactivatedByConnectedId = Guid.Empty,
                DeactivatedAt = DateTime.UtcNow
            });

            // 3. 계정 소유자에게 긴급 이메일을 보냅니다.
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
                throw; // 에러를 다시 던져서 상위 호출자에게 알립니다.
            }
        }

        private async Task InvalidateApiKeyCacheAsync(Guid applicationId, Guid apiKeyId)
        {
            var cacheKey = GetApiKeyCacheKey(applicationId, apiKeyId);
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated API Key cache for App={AppId}, Key={KeyId}", applicationId, apiKeyId);
        }

        // 캐시 키는 멀티테넌시를 고려하여 설계해야 합니다.
        private static string GetApiKeyCacheKey(Guid applicationId, Guid apiKeyId) => $"apikeys:{applicationId}:{apiKeyId}";
        private static string GetApiKeyUsageCounterKey(Guid apiKeyId) => $"apikeys:usage:{apiKeyId}";

        #endregion
    }
}

