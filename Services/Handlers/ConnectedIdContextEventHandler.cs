using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Monitoring;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.ConnectedId.Events;
using System.Text.Json;
using System.Diagnostics;

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// ConnectedIdContext 이벤트 핸들러 구현 - AuthHive v15
    /// ConnectedIdContext 관련 모든 이벤트를 처리하고 감사, 메트릭, 캐시 관리를 수행합니다.
    /// </summary>
    public class ConnectedIdContextEventHandler : IConnectedIdContextEventHandler
    {
        private readonly ILogger<ConnectedIdContextEventHandler> _logger;
        private readonly IAuditLogRepository _auditRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ICacheService _cacheService;
        private readonly IMetricsService _metricsService;

        private const string CACHE_KEY_PREFIX = "context";
        private const string METRICS_PREFIX = "connectedid.context";
        private const int HOT_PATH_THRESHOLD = 100; // 100회 이상 접근 시 Hot Path로 승격
        private const int MEMORY_PRESSURE_THRESHOLD_MB = 1024; // 1GB

        public ConnectedIdContextEventHandler(
            ILogger<ConnectedIdContextEventHandler> logger,
            IAuditLogRepository auditRepository,
            IDateTimeProvider dateTimeProvider,
            ICacheService cacheService,
            IMetricsService metricsService)
        {
            _logger = logger;
            _auditRepository = auditRepository;
            _dateTimeProvider = dateTimeProvider;
            _cacheService = cacheService;
            _metricsService = metricsService;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 의존 서비스들의 상태 확인
                await _cacheService.GetAsync<string>("health_check");
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdContextEventHandler initialized");
            await Task.CompletedTask;
        }

        #endregion

        #region 컨텍스트 생명주기 이벤트

        public async Task<EventResult> OnContextCreatedAsync(
            ConnectedIdContext context,
            Guid createdBy)
        {
            try
            {
                _logger.LogInformation(
                    "Context created: {ContextKey} for ConnectedId {ConnectedId}, Type: {ContextType}",
                    context.ContextKey, context.ConnectedId, context.ContextType);

                // 1. 감사 로그
                await LogAuditAsync(
                    createdBy,
                    "CONTEXT_CREATED",
                    $"Created context {context.ContextKey}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["ContextType"] = context.ContextType.ToString(),
                        ["ConnectedId"] = context.ConnectedId,
                        ["ApplicationId"] = context.ApplicationId?.ToString() ?? "N/A",
                        ["ExpiresAt"] = context.ExpiresAt
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.created.{context.ContextType.ToString().ToLower()}");

                // 3. 캐시에 저장
                await _cacheService.SetAsync(
                    context.ContextKey,
                    JsonSerializer.Serialize(context),
                    context.ExpiresAt - _dateTimeProvider.UtcNow);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context created event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnContextUpdatedAsync(
            ConnectedIdContext context,
            Guid updatedBy,
            Dictionary<string, (object? OldValue, object? NewValue)> changes)
        {
            try
            {
                _logger.LogInformation(
                    "Context updated: {ContextKey} with {ChangeCount} changes",
                    context.ContextKey, changes.Count);

                // 1. 감사 로그 (변경 사항 포함)
                await LogAuditAsync(
                    updatedBy,
                    "CONTEXT_UPDATED",
                    $"Updated context {context.ContextKey}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["Changes"] = changes.Select(c => new
                        {
                            Field = c.Key,
                            OldValue = c.Value.OldValue?.ToString() ?? "null",
                            NewValue = c.Value.NewValue?.ToString() ?? "null"
                        }).ToList()
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.updated");

                // 3. 캐시 업데이트
                await _cacheService.SetAsync(
                    context.ContextKey,
                    JsonSerializer.Serialize(context),
                    context.ExpiresAt - _dateTimeProvider.UtcNow);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context updated event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnContextDeletedAsync(
            Guid contextId,
            Guid organizationId,
            Guid deletedBy,
            string? reason = null)
        {
            try
            {
                _logger.LogInformation(
                    "Context deleted: {ContextId}, Reason: {Reason}",
                    contextId, reason ?? "Not specified");

                // 1. 감사 로그
                await LogAuditAsync(
                    deletedBy,
                    "CONTEXT_DELETED",
                    $"Deleted context {contextId}: {reason}",
                    contextId,
                    organizationId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["Reason"] = reason ?? "Not specified"
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.deleted");

                // 3. 캐시에서 제거 (키 패턴으로 검색하여 제거)
                await _cacheService.RemoveByPatternAsync($"{CACHE_KEY_PREFIX}:*{contextId}*");

                return EventResult.CreateSuccess(contextId.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context deleted event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnContextExpiredAsync(
            ConnectedIdContext context,
            bool autoDeleted = false)
        {
            try
            {
                _logger.LogInformation(
                    "Context expired: {ContextKey}, AutoDeleted: {AutoDeleted}",
                    context.ContextKey, autoDeleted);

                // 1. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "CONTEXT_EXPIRED",
                    $"Context {context.ContextKey} expired",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["AutoDeleted"] = autoDeleted,
                        ["ExpiredAt"] = context.ExpiresAt
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.expired");

                // 3. 캐시에서 제거
                await _cacheService.RemoveAsync(context.ContextKey);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context expired event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnContextRefreshedAsync(
            ConnectedIdContext oldContext,
            ConnectedIdContext newContext,
            Guid? refreshedBy = null)
        {
            try
            {
                _logger.LogInformation(
                    "Context refreshed: {ContextKey}, New expiry: {ExpiresAt}",
                    newContext.ContextKey, newContext.ExpiresAt);

                // 1. 감사 로그
                await LogAuditAsync(
                    refreshedBy ?? Guid.Empty,
                    "CONTEXT_REFRESHED",
                    $"Refreshed context {newContext.ContextKey}",
                    newContext.Id,
                    newContext.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["OldExpiresAt"] = oldContext.ExpiresAt,
                        ["NewExpiresAt"] = newContext.ExpiresAt,
                        ["ExtendedBy"] = (newContext.ExpiresAt - oldContext.ExpiresAt).TotalMinutes
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.refreshed");

                // 3. 캐시 업데이트
                await _cacheService.SetAsync(
                    newContext.ContextKey,
                    JsonSerializer.Serialize(newContext),
                    newContext.ExpiresAt - _dateTimeProvider.UtcNow);

                return EventResult.CreateSuccess(newContext.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context refreshed event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        #endregion

        #region 접근 및 사용 이벤트

        public async Task<EventResult> OnContextAccessedAsync(
            ConnectedIdContext context,
            Guid accessedBy,
            string ipAddress,
            string? userAgent = null)
        {
            try
            {
                // 접근 카운트 증가 (실제 구현에서는 DB 업데이트 필요)
                context.AccessCount++;
                context.LastAccessedAt = _dateTimeProvider.UtcNow;

                // Hot Path 승격 체크
                if (context.AccessCount >= HOT_PATH_THRESHOLD && !context.IsHotPath)
                {
                    await OnPromotedToHotPathAsync(context, context.AccessCount, HOT_PATH_THRESHOLD);
                }

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.accessed");

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context accessed event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnCacheHitAsync(
            string contextKey,
            string cacheType,
            long latencyMs)
        {
            try
            {
                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.hit.{cacheType.ToLower()}");
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.cache.latency.{cacheType.ToLower()}", latencyMs);

                _logger.LogDebug(
                    "Cache hit for {ContextKey} in {CacheType}, Latency: {Latency}ms",
                    contextKey, cacheType, latencyMs);

                return EventResult.CreateSuccess();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle cache hit event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnCacheMissAsync(
            string contextKey,
            string cacheType,
            bool fallbackUsed = false)
        {
            try
            {
                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.miss.{cacheType.ToLower()}");
                
                if (fallbackUsed)
                {
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.fallback");
                }

                _logger.LogDebug(
                    "Cache miss for {ContextKey} in {CacheType}, Fallback used: {FallbackUsed}",
                    contextKey, cacheType, fallbackUsed);

                return EventResult.CreateSuccess();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle cache miss event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnPromotedToHotPathAsync(
            ConnectedIdContext context,
            int accessCount,
            int threshold)
        {
            try
            {
                _logger.LogInformation(
                    "Context promoted to Hot Path: {ContextKey}, Access count: {AccessCount}",
                    context.ContextKey, accessCount);

                context.IsHotPath = true;
                context.GrpcCacheEnabled = true; // Hot Path는 gRPC 캐시도 활성화

                // 1. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "HOT_PATH_PROMOTED",
                    $"Context {context.ContextKey} promoted to Hot Path",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["AccessCount"] = accessCount,
                        ["Threshold"] = threshold
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.hotpath.promoted");

                // 3. 캐시 우선순위 상승
                context.Priority = 10; // 최고 우선순위

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle hot path promotion event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnDemotedFromHotPathAsync(
            ConnectedIdContext context,
            string reason)
        {
            try
            {
                _logger.LogInformation(
                    "Context demoted from Hot Path: {ContextKey}, Reason: {Reason}",
                    context.ContextKey, reason);

                context.IsHotPath = false;
                context.Priority = 5; // 기본 우선순위로 복귀

                // 1. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "HOT_PATH_DEMOTED",
                    $"Context {context.ContextKey} demoted from Hot Path: {reason}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Info,
                    new Dictionary<string, object>
                    {
                        ["Reason"] = reason
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.hotpath.demoted");

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle hot path demotion event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 권한 및 역할 변경 이벤트

        public async Task<EventResult> OnPermissionContextChangedAsync(
            ConnectedIdContext context,
            List<string> addedPermissions,
            List<string> removedPermissions,
            Guid changedBy)
        {
            try
            {
                _logger.LogInformation(
                    "Permission context changed for {ContextKey}: +{Added}, -{Removed}",
                    context.ContextKey, addedPermissions.Count, removedPermissions.Count);

                // 1. 감사 로그
                await LogAuditAsync(
                    changedBy,
                    "PERMISSIONS_CHANGED",
                    $"Permissions changed for context {context.ContextKey}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["AddedPermissions"] = addedPermissions,
                        ["RemovedPermissions"] = removedPermissions
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.permissions.changed");

                // 3. 캐시 무효화 (권한 변경은 즉시 반영)
                await _cacheService.RemoveAsync(context.ContextKey);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle permission context changed event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnRoleContextChangedAsync(
            ConnectedIdContext context,
            List<Guid> addedRoles,
            List<Guid> removedRoles,
            Guid changedBy)
        {
            try
            {
                _logger.LogInformation(
                    "Role context changed for {ContextKey}: +{Added}, -{Removed}",
                    context.ContextKey, addedRoles.Count, removedRoles.Count);

                // 1. 감사 로그
                await LogAuditAsync(
                    changedBy,
                    "ROLES_CHANGED",
                    $"Roles changed for context {context.ContextKey}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["AddedRoles"] = addedRoles.Select(r => r.ToString()).ToList(),
                        ["RemovedRoles"] = removedRoles.Select(r => r.ToString()).ToList()
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.roles.changed");

                // 3. 캐시 무효화
                await _cacheService.RemoveAsync(context.ContextKey);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle role context changed event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnPermissionValidationFailedAsync(
            Guid connectedId,
            Guid applicationId,
            string requestedPermission,
            string failureReason)
        {
            try
            {
                _logger.LogWarning(
                    "Permission validation failed for ConnectedId {ConnectedId}, App {ApplicationId}, Permission: {Permission}, Reason: {Reason}",
                    connectedId, applicationId, requestedPermission, failureReason);

                // 1. 감사 로그 (보안 이벤트)
                await LogAuditAsync(
                    connectedId,
                    "PERMISSION_DENIED",
                    $"Permission denied: {requestedPermission}",
                    null,
                    null,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["ApplicationId"] = applicationId,
                        ["RequestedPermission"] = requestedPermission,
                        ["FailureReason"] = failureReason
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.permissions.denied");

                return EventResult.CreateSuccess();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle permission validation failed event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 세션 관련 이벤트

        public async Task<EventResult> OnSessionContextsCreatedAsync(
            Guid sessionId,
            Guid connectedId,
            int contextCount)
        {
            try
            {
                _logger.LogInformation(
                    "Session contexts created for Session {SessionId}, ConnectedId {ConnectedId}, Count: {Count}",
                    sessionId, connectedId, contextCount);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.session.created", contextCount);

                return EventResult.CreateSuccess(sessionId.ToString(), contextCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle session contexts created event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnSessionContextsClearedAsync(
            Guid sessionId,
            int clearedCount,
            string reason)
        {
            try
            {
                _logger.LogInformation(
                    "Session contexts cleared for Session {SessionId}, Cleared: {Count}, Reason: {Reason}",
                    sessionId, clearedCount, reason);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.session.cleared", clearedCount);

                // 캐시 정리
                await _cacheService.RemoveByPatternAsync($"{CACHE_KEY_PREFIX}:*session:{sessionId}*");

                return EventResult.CreateSuccess(sessionId.ToString(), clearedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle session contexts cleared event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 애플리케이션 관련 이벤트

        public async Task<EventResult> OnApplicationContextsInitializedAsync(
            Guid applicationId,
            Guid connectedId,
            List<ConnectedIdContextType> initialContexts)
        {
            try
            {
                _logger.LogInformation(
                    "Application contexts initialized for App {ApplicationId}, ConnectedId {ConnectedId}, Types: {Types}",
                    applicationId, connectedId, string.Join(", ", initialContexts));

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.application.initialized", initialContexts.Count);

                return EventResult.CreateSuccess(applicationId.ToString(), initialContexts.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle application contexts initialized event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnApplicationAccessChangedAsync(
            Guid connectedId,
            Guid applicationId,
            string? oldAccessLevel,
            string newAccessLevel)
        {
            try
            {
                _logger.LogInformation(
                    "Application access changed for ConnectedId {ConnectedId}, App {ApplicationId}: {Old} -> {New}",
                    connectedId, applicationId, oldAccessLevel ?? "None", newAccessLevel);

                // 관련 컨텍스트 캐시 무효화
                await _cacheService.RemoveByPatternAsync($"{CACHE_KEY_PREFIX}:*{connectedId}*{applicationId}*");

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.application.access.changed");

                return EventResult.CreateSuccess();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle application access changed event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        #endregion

        #region 무결성 및 동기화 이벤트

        public async Task<EventResult> OnIntegrityValidationFailedAsync(
            ConnectedIdContext context,
            List<string> validationErrors,
            bool autoFixed = false)
        {
            try
            {
                _logger.LogError(
                    "Integrity validation failed for context {ContextKey}: {Errors}",
                    context.ContextKey, string.Join(", ", validationErrors));

                // 1. 감사 로그 (Critical)
                await LogAuditAsync(
                    Guid.Empty,
                    "INTEGRITY_FAILED",
                    $"Integrity validation failed for {context.ContextKey}",
                    context.Id,
                    context.OrganizationId,
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["ValidationErrors"] = validationErrors,
                        ["AutoFixed"] = autoFixed
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.integrity.failed");

                if (autoFixed)
                {
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.integrity.autofixed");
                }

                return EventResult.CreateSuccess(context.Id.ToString(), autoFixed ? 1 : 0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle integrity validation failed event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnChecksumMismatchAsync(
            Guid contextId,
            string expectedChecksum,
            string actualChecksum,
            string action)
        {
            try
            {
                _logger.LogError(
                    "Checksum mismatch for context {ContextId}: Expected {Expected}, Actual {Actual}, Action: {Action}",
                    contextId, expectedChecksum, actualChecksum, action);

                // 1. 감사 로그 (Critical - 데이터 무결성 문제)
                await LogAuditAsync(
                    Guid.Empty,
                    "CHECKSUM_MISMATCH",
                    $"Checksum mismatch detected for context {contextId}",
                    contextId,
                    null,
                    AuditEventSeverity.Critical,
                    new Dictionary<string, object>
                    {
                        ["ExpectedChecksum"] = expectedChecksum,
                        ["ActualChecksum"] = actualChecksum,
                        ["Action"] = action
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.checksum.mismatch");

                return EventResult.CreateSuccess(contextId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle checksum mismatch event");
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnSyncCompletedAsync(
            Guid organizationId,
            string syncId,
            int successCount,
            int failureCount,
            TimeSpan duration)
        {
            try
            {
                _logger.LogInformation(
                    "Sync completed for Org {OrganizationId}, SyncId {SyncId}: Success {Success}, Failed {Failed}, Duration {Duration}ms",
                    organizationId, syncId, successCount, failureCount, duration.TotalMilliseconds);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.sync.completed");
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.sync.success", successCount);
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.sync.failed", failureCount);
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.sync.duration", (long)duration.TotalMilliseconds);

                return EventResult.CreateSuccess(syncId, successCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle sync completed event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 정리 및 유지보수 이벤트

        public async Task<EventResult> OnExpiredContextsCleanedAsync(
            Guid organizationId,
            int cleanedCount,
            int retentionDays)
        {
            try
            {
                _logger.LogInformation(
                    "Expired contexts cleaned for Org {OrganizationId}: {Count} contexts older than {Days} days",
                    organizationId, cleanedCount, retentionDays);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cleanup.expired", cleanedCount);

                return EventResult.CreateSuccess(organizationId.ToString(), cleanedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle expired contexts cleaned event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnAutoRefreshedAsync(
            ConnectedIdContext context,
            DateTime oldExpiryTime,
            DateTime newExpiryTime)
        {
            try
            {
                var extension = newExpiryTime - oldExpiryTime;
                _logger.LogInformation(
                    "Context auto-refreshed: {ContextKey}, Extended by {Minutes} minutes",
                    context.ContextKey, extension.TotalMinutes);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.autorefresh");

                // 캐시 TTL 업데이트
                await _cacheService.SetAsync(
                    context.ContextKey,
                    JsonSerializer.Serialize(context),
                    newExpiryTime - _dateTimeProvider.UtcNow);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle auto refresh event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 알림 및 경고 이벤트

        public async Task<EventResult> OnContextExpiringAsync(
            ConnectedIdContext context,
            int minutesRemaining,
            bool notificationSent = false)
        {
            try
            {
                _logger.LogWarning(
                    "Context expiring soon: {ContextKey}, Minutes remaining: {Minutes}",
                    context.ContextKey, minutesRemaining);

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.expiring");

                if (notificationSent)
                {
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.expiring.notified");
                }

                return EventResult.CreateSuccess(context.Id.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle context expiring event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnMemoryPressureAsync(
            Guid organizationId,
            int contextCount,
            long memoryUsageMB,
            long threshold)
        {
            try
            {
                _logger.LogWarning(
                    "Memory pressure detected for Org {OrganizationId}: {Count} contexts using {Memory}MB (threshold: {Threshold}MB)",
                    organizationId, contextCount, memoryUsageMB, threshold);

                // 1. 감사 로그
                await LogAuditAsync(
                    Guid.Empty,
                    "MEMORY_PRESSURE",
                    $"Memory pressure detected: {memoryUsageMB}MB / {threshold}MB",
                    null,
                    organizationId,
                    AuditEventSeverity.Warning,
                    new Dictionary<string, object>
                    {
                        ["ContextCount"] = contextCount,
                        ["MemoryUsageMB"] = memoryUsageMB,
                        ["ThresholdMB"] = threshold
                    });

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.memory.pressure");
                await _metricsService.SetGaugeAsync($"{METRICS_PREFIX}.memory.usage", memoryUsageMB);

                // 3. 자동 정리 트리거 (Low priority contexts)
                if (memoryUsageMB > threshold * 0.9) // 90% 초과 시
                {
                    // 낮은 우선순위 컨텍스트 정리 로직 호출
                    _logger.LogWarning("Triggering automatic cleanup of low-priority contexts");
                }

                return EventResult.CreateSuccess(organizationId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle memory pressure event");
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 일괄 처리

        public async Task<BatchEventResult> ProcessBatchEventsAsync(IEnumerable<ContextEvent> events)
        {
            var result = new BatchEventResult();
            var stopwatch = Stopwatch.StartNew();

            try
            {
                var eventList = events.ToList();
                result.ProcessedCount = eventList.Count;

                // 병렬 처리 (최대 10개씩)
                var tasks = new List<Task<EventResult>>();
                var semaphore = new SemaphoreSlim(10);

                foreach (var evt in eventList)
                {
                    await semaphore.WaitAsync();
                    
                    var task = ProcessSingleEventAsync(evt).ContinueWith(t =>
                    {
                        semaphore.Release();
                        return t.Result;
                    });
                    
                    tasks.Add(task);
                }

                var results = await Task.WhenAll(tasks);

                // 결과 집계
                foreach (var eventResult in results)
                {
                    result.Results.Add(eventResult);
                    if (eventResult.Success)
                        result.SuccessCount++;
                    else
                        result.FailureCount++;
                }

                result.AllSucceeded = result.FailureCount == 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process batch events");
                result.AllSucceeded = false;
            }
            finally
            {
                stopwatch.Stop();
                result.ProcessingTimeMs = stopwatch.ElapsedMilliseconds;
                
                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.batch.processed", result.ProcessedCount);
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.batch.duration", result.ProcessingTimeMs);
            }

            return result;
        }

        private async Task<EventResult> ProcessSingleEventAsync(ContextEvent evt)
        {
            // 이벤트 타입에 따라 적절한 핸들러 메서드 호출
            // 실제 구현에서는 이벤트 타입별 처리 로직 구현 필요
            await Task.Delay(10); // 시뮬레이션
            return EventResult.CreateSuccess();
        }

        #endregion

        #region Private Helper Methods

        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? resourceId,
            Guid? organizationId,
            AuditEventSeverity severity,
            Dictionary<string, object>? metadata = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = performedByConnectedId,
                    TargetOrganizationId = organizationId,
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = DetermineActionType(action),
                    Action = action,
                    ResourceType = "ConnectedIdContext",
                    ResourceId = resourceId?.ToString(),
                    Success = true,
                    Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null,
                    Severity = severity,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = performedByConnectedId
                };

                await _auditRepository.AddAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for action {Action}", action);
            }
        }

        private AuditActionType DetermineActionType(string action)
        {
            return action switch
            {
                "CONTEXT_CREATED" => AuditActionType.Create,
                "CONTEXT_UPDATED" => AuditActionType.Update,
                "CONTEXT_DELETED" => AuditActionType.Delete,
                "CONTEXT_EXPIRED" => AuditActionType.Delete,
                "CONTEXT_REFRESHED" => AuditActionType.Update,
                "PERMISSIONS_CHANGED" => AuditActionType.Update,
                "ROLES_CHANGED" => AuditActionType.Update,
                _ => AuditActionType.Others
            };
        }

        #endregion
    }
}