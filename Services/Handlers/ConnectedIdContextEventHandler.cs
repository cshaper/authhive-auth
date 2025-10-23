using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading; // CancellationToken 사용
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit; // AuditLog 엔티티 사용
using AuthHive.Core.Entities.Auth; // ConnectedIdContext 엔티티 사용
using AuthHive.Core.Enums.Audit; // AuditEventSeverity 사용
using AuthHive.Core.Enums.Auth; // ConnectedIdContextType 사용
using AuthHive.Core.Enums.Core; // EventPriority 사용 (암시적)
using AuthHive.Core.Interfaces.Audit; // IAuditService 사용 (LogActionAsync 호출 위함)
using AuthHive.Core.Interfaces.Auth.Handler; // IConnectedIdContextEventHandler 구현
using AuthHive.Core.Interfaces.Base; // IService, EventResult 등 사용
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider 사용
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService 사용
using AuthHive.Core.Interfaces.Infra.Monitoring; // IMetricsService 사용
using AuthHive.Core.Models.Auth.ConnectedId.Events; // ContextEvent (배치 처리용, 실제 정의 필요)
using AuthHive.Core.Models.Common; // EventResult, BatchEventResult 사용
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// ConnectedIdContext 이벤트 핸들러 구현 - AuthHive v16
    /// ConnectedIdContext 관련 모든 이벤트를 처리하고 감사, 메트릭, 캐시 관리를 수행합니다.
    /// </summary>
    public class ConnectedIdContextEventHandler : IConnectedIdContextEventHandler, IService
    {
        private readonly ILogger<ConnectedIdContextEventHandler> _logger;
        // IAuditLogRepository 대신 IAuditService 사용 (LogActionAsync 메서드 활용)
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ICacheService _cacheService;
        private readonly IMetricsService _metricsService; // 메트릭 기록 서비스

        // 상수 정의
        private const string CACHE_KEY_PREFIX = "context"; // 캐시 키 접두사
        private const string METRICS_PREFIX = "connectedid.context"; // 메트릭 접두사
        private const int HOT_PATH_THRESHOLD = 100; // Hot Path 승격 기준 접근 횟수

        public ConnectedIdContextEventHandler(
            ILogger<ConnectedIdContextEventHandler> logger,
            IAuditService auditService, // IAuditLogRepository -> IAuditService
            IDateTimeProvider dateTimeProvider,
            ICacheService cacheService,
            IMetricsService metricsService)
        {
            _logger = logger;
            _auditService = auditService; // 의존성 주입 변경
            _dateTimeProvider = dateTimeProvider;
            _cacheService = cacheService;
            _metricsService = metricsService;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 의존 서비스들의 상태 확인 (CacheService 예시)
                await _cacheService.ExistsAsync("health_check", cancellationToken);
                // 필요시 IAuditService, IMetricsService 등의 Health Check 추가
                // var auditHealthy = await _auditService.IsHealthyAsync(cancellationToken);
                // var metricsHealthy = await _metricsService.IsHealthyAsync(cancellationToken);
                return true; // && auditHealthy && metricsHealthy;
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("ConnectedIdContextEventHandler health check canceled.");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ConnectedIdContextEventHandler health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdContextEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }
        #endregion

        #region 컨텍스트 생명주기 이벤트 (IConnectedIdContextEventHandler 구현)

        public async Task<EventResult> OnContextCreatedAsync(
            ConnectedIdContext context,
            Guid createdBy,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Handling OnContextCreatedAsync: ContextKey={ContextKey}, ConnectedId={ConnectedId}, Type={ContextType}",
                    context.ContextKey, context.ConnectedId, context.ContextType);

                var stopwatch = Stopwatch.StartNew();

                // 1. 감사 로그
                await LogContextActionAsync(
                    AuditActionType.Create,
                    "CONTEXT_CREATED",
                    createdBy,
                    $"Created context {context.ContextKey}",
                    context,
                    new Dictionary<string, object>
                    {
                        ["ContextType"] = context.ContextType.ToString(),
                        ["ExpiresAt"] = context.ExpiresAt
                    },
                    cancellationToken);

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.created.{context.ContextType.ToString().ToLower()}", cancellationToken: cancellationToken);

                // 3. 캐시에 저장 (만료 시간 설정)
                var expiration = context.ExpiresAt > _dateTimeProvider.UtcNow ? context.ExpiresAt - _dateTimeProvider.UtcNow : TimeSpan.FromMinutes(1); // 만료 시간이 과거면 짧은 시간 설정
                // ConnectedIdContext가 클래스(참조 타입)라고 가정
                await _cacheService.SetAsync(context.ContextKey, context, expiration, cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.created.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OnContextCreatedAsync for ContextKey={ContextKey} was canceled.", context.ContextKey);
                // 롤백할 DB 작업이 없으므로 throw만 함
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnContextCreatedAsync for ContextKey={ContextKey}", context.ContextKey);
                return EventResult.CreateFailure(ex.Message, true); // 실패 시 재시도 가능하도록 설정 (선택 사항)
            }
        }

        public async Task<EventResult> OnContextUpdatedAsync(
            ConnectedIdContext context,
            Guid updatedBy,
            Dictionary<string, (object? OldValue, object? NewValue)> changes,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Handling OnContextUpdatedAsync: ContextKey={ContextKey} with {ChangeCount} changes",
                    context.ContextKey, changes.Count);
                var stopwatch = Stopwatch.StartNew();

                // 1. 감사 로그 (변경 사항 포함)
                await LogContextActionAsync(
                    AuditActionType.Update,
                    "CONTEXT_UPDATED",
                    updatedBy,
                    $"Updated context {context.ContextKey}",
                    context,
                     new Dictionary<string, object>
                     {
                         // 변경 사항을 직렬화 가능한 형태로 변환
                         ["Changes"] = changes.ToDictionary(
                             kvp => kvp.Key,
                             kvp => new { Old = kvp.Value.OldValue?.ToString(), New = kvp.Value.NewValue?.ToString() }
                         )
                     },
                    cancellationToken);

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.updated", cancellationToken: cancellationToken);

                // 3. 캐시 업데이트 (만료 시간 재설정)
                var expiration = context.ExpiresAt > _dateTimeProvider.UtcNow ? context.ExpiresAt - _dateTimeProvider.UtcNow : TimeSpan.FromMinutes(1);
                await _cacheService.SetAsync(context.ContextKey, context, expiration, cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.updated.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OnContextUpdatedAsync for ContextKey={ContextKey} was canceled.", context.ContextKey);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnContextUpdatedAsync for ContextKey={ContextKey}", context.ContextKey);
                return EventResult.CreateFailure(ex.Message, true);
            }
        }

        public async Task<EventResult> OnContextDeletedAsync(
           Guid contextId,
           Guid organizationId, // 조직 ID를 받아야 캐시 키 생성 및 감사 로그에 사용 가능
           Guid deletedBy,
           string? reason = null,
           CancellationToken cancellationToken = default)
        {
            // 컨텍스트 키를 생성하거나, 이벤트 발행 시 키를 전달받아야 함
            // 여기서는 contextId와 organizationId로 키를 재구성한다고 가정
            var contextKey = $"{CACHE_KEY_PREFIX}:{organizationId}:{contextId}"; // 예시 키 구조

            try
            {
                _logger.LogInformation(
                    "Handling OnContextDeletedAsync: ContextId={ContextId}, OrgId={OrganizationId}, Reason={Reason}",
                    contextId, organizationId, reason ?? "N/A");
                var stopwatch = Stopwatch.StartNew();

                // 1. 감사 로그
                await _auditService.LogActionAsync(
                                actionType: AuditActionType.Delete,
                                action: "CONTEXT_DELETED",
                                connectedId: deletedBy,
                                resourceType: "ConnectedIdContext",
                                resourceId: contextId.ToString(),
                                // success parameter (optional, defaults to true, might need adjustment based on context)
                                // errorMessage parameter (optional)
                                metadata: new Dictionary<string, object>
                                {
                                    ["Reason"] = reason ?? (object)"N/A", // null 처리
                                    ["OrganizationId"] = organizationId // organizationId를 metadata에 포함
                                                                        // severity가 필요하다면 여기에 추가: ["Severity"] = AuditEventSeverity.Warning.ToString()
                                },
                                cancellationToken: cancellationToken);


                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.deleted", cancellationToken: cancellationToken);

                // 3. 캐시에서 제거
                await _cacheService.RemoveAsync(contextKey, cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.deleted.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);


                return EventResult.CreateSuccess(contextId.ToString(), 1);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OnContextDeletedAsync for ContextId={ContextId} was canceled.", contextId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnContextDeletedAsync for ContextId={ContextId}", contextId);
                return EventResult.CreateFailure(ex.Message, false); // 삭제 실패는 재시도 불필요할 수 있음
            }
        }

        #endregion

        #region 접근 및 사용 이벤트 (IConnectedIdContextEventHandler 구현)

        public async Task<EventResult> OnContextAccessedAsync(
            ConnectedIdContext context, // 실제 컨텍스트 객체를 받아야 LastAccessedAt 업데이트 가능
            Guid accessedBy,
            string ipAddress,
            string? userAgent = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var now = _dateTimeProvider.UtcNow;
                // 마지막 접근 시간 업데이트는 캐시에만 반영 (DB 업데이트는 성능 부하)
                context.LastAccessedAt = now; // 이벤트 핸들러가 상태를 직접 변경하는 것은 좋지 않음 -> 캐시 업데이트로 대체

                // 캐시 업데이트 (LastAccessedAt만 갱신된 객체로 덮어쓰기)
                var expiration = context.ExpiresAt > now ? context.ExpiresAt - now : TimeSpan.FromMinutes(1);
                await _cacheService.SetAsync(context.ContextKey, context, expiration, cancellationToken);


                // 접근 카운트 증가 (캐시의 원자적 연산 사용)
                var accessCountKey = $"{context.ContextKey}:access_count";
                long currentAccessCount = await _cacheService.IncrementAsync(accessCountKey, 1, cancellationToken);

                // Hot Path 승격 체크 및 이벤트 발행 (별도 메서드 호출)
                if (currentAccessCount == HOT_PATH_THRESHOLD && !context.IsHotPath)
                {
                    // OnPromotedToHotPathAsync 호출 또는 관련 이벤트 발행
                    _logger.LogInformation("Context {ContextKey} reached hot path threshold.", context.ContextKey);
                    // context.IsHotPath = true; // 상태 변경 대신 이벤트 발행
                    // await _eventBus.PublishAsync(new ContextPromotedToHotPathEvent(context.Id, ...));
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.hotpath.promoted_check", cancellationToken: cancellationToken); // 메트릭만 기록
                }

                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.accessed", cancellationToken: cancellationToken);

                // 상세 접근 로그 (필요시, 성능 고려) - 감사 로그와 중복될 수 있음
                // LogAccessDetailsAsync(context, accessedBy, ipAddress, userAgent, cancellationToken);

                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OnContextAccessedAsync for ContextKey={ContextKey} was canceled.", context.ContextKey);
                // throw; // 접근 이벤트 취소는 무시 가능
                return EventResult.CreateFailure("Operation canceled", false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnContextAccessedAsync for ContextKey={ContextKey}", context.ContextKey);
                return EventResult.CreateFailure(ex.Message, false); // 접근 이벤트 실패는 무시 가능
            }
        }

        public async Task<EventResult> OnCacheHitAsync(
           string contextKey,
           string cacheType, // e.g., "Memory", "Redis"
           long latencyMs,
           CancellationToken cancellationToken = default)
        {
            try
            {
                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.hit.{cacheType.ToLower()}", cancellationToken: cancellationToken);
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.cache.latency.{cacheType.ToLower()}", latencyMs, cancellationToken: cancellationToken);

                _logger.LogTrace("Cache hit for {ContextKey} in {CacheType} ({Latency}ms)", contextKey, cacheType, latencyMs); // Trace 레벨 사용

                return EventResult.CreateSuccess(contextKey);
            }
            catch (OperationCanceledException) { return EventResult.CreateFailure("Operation canceled", false); } // 메트릭 기록 취소는 무시
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnCacheHitAsync for {ContextKey}", contextKey);
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        public async Task<EventResult> OnCacheMissAsync(
            string contextKey,
            string cacheType,
            bool fallbackUsed = false, // 캐시 미스 시 DB 등 다른 소스에서 로드했는지 여부
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.miss.{cacheType.ToLower()}", cancellationToken: cancellationToken);
                if (fallbackUsed)
                {
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.cache.miss.fallback_used.{cacheType.ToLower()}", cancellationToken: cancellationToken);
                }

                _logger.LogDebug("Cache miss for {ContextKey} in {CacheType}. Fallback used: {FallbackUsed}", contextKey, cacheType, fallbackUsed); // Debug 레벨 사용

                return EventResult.CreateSuccess(contextKey);
            }
            catch (OperationCanceledException) { return EventResult.CreateFailure("Operation canceled", false); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnCacheMissAsync for {ContextKey}", contextKey);
                return EventResult.CreateFailure(ex.Message, false);
            }
        }

        #endregion

        #region 권한 및 역할 변경 이벤트 (IConnectedIdContextEventHandler 구현)

        public async Task<EventResult> OnPermissionContextChangedAsync(
            ConnectedIdContext context, // 전체 컨텍스트 객체 필요
            List<string> addedPermissions,
            List<string> removedPermissions,
            Guid changedBy,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Handling OnPermissionContextChangedAsync for {ContextKey}: +{AddedCount}, -{RemovedCount}",
                    context.ContextKey, addedPermissions?.Count ?? 0, removedPermissions?.Count ?? 0);
                var stopwatch = Stopwatch.StartNew();

                // 1. 감사 로그
                await LogContextActionAsync(
                   AuditActionType.PermissionUpdated, // 구체적인 타입 사용
                   "PERMISSIONS_CHANGED",
                   changedBy,
                   $"Permissions changed for context {context.ContextKey}",
                   context,
                   new Dictionary<string, object>
                   {
                       ["AddedPermissions"] = addedPermissions ?? new List<string>(), // null 처리
                       ["RemovedPermissions"] = removedPermissions ?? new List<string>() // null 처리
                   },
                   cancellationToken);

                // 2. 메트릭 기록
                await _metricsService.IncrementAsync($"{METRICS_PREFIX}.permissions.changed", cancellationToken: cancellationToken);
                if (addedPermissions?.Any() ?? false)
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.permissions.added", addedPermissions.Count, cancellationToken: cancellationToken);
                if (removedPermissions?.Any() ?? false)
                    await _metricsService.IncrementAsync($"{METRICS_PREFIX}.permissions.removed", removedPermissions.Count, cancellationToken: cancellationToken);

                // 3. 캐시 무효화 (권한 변경은 즉시 반영 필요)
                await _cacheService.RemoveAsync(context.ContextKey, cancellationToken);

                stopwatch.Stop();
                await _metricsService.RecordTimingAsync($"{METRICS_PREFIX}.permissions.changed.duration", stopwatch.ElapsedMilliseconds, cancellationToken: cancellationToken);


                return EventResult.CreateSuccess(context.Id.ToString(), 1);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OnPermissionContextChangedAsync for ContextKey={ContextKey} was canceled.", context.ContextKey);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to handle OnPermissionContextChangedAsync for ContextKey={ContextKey}", context.ContextKey);
                return EventResult.CreateFailure(ex.Message, true); // 권한 변경 실패는 중요할 수 있음
            }
        }

        // OnRoleContextChangedAsync 구현 (IConnectedIdContextEventHandler에는 없지만 필요할 수 있음)
        // ...

        #endregion

        // --- 배치 처리 및 기타 필요한 메서드는 생략 ---

        #region Private Helper Methods

        // 감사 로그 기록 헬퍼 (IAuditService 사용하도록 수정)
        // 감사 로그 기록 헬퍼 (IAuditService.LogActionAsync 시그니처에 맞게 수정)
        private async Task LogContextActionAsync(
            AuditActionType actionType,
            string action,
            Guid performedByConnectedId,
            string description, // 설명은 metadata에 포함
            ConnectedIdContext context,
            Dictionary<string, object>? metadata = null, // 추가 메타데이터
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 기본 메타데이터 구성
                var fullMetadata = new Dictionary<string, object>
                {
                    ["Description"] = description, // 설명을 메타데이터에 추가
                    ["ContextId"] = context.Id,
                    ["ContextKey"] = context.ContextKey,
                    ["ContextType"] = context.ContextType.ToString(),
                    ["ConnectedId"] = context.ConnectedId,
                    ["OrganizationId"] = context.OrganizationId, // OrganizationId를 메타데이터에 추가
                    ["ApplicationId"] = context.ApplicationId ?? Guid.Empty // Nullable 처리
                    // 필요시 severity 추가: ["Severity"] = DetermineSeverity(actionType).ToString()
                };

                // 전달받은 추가 메타데이터 병합
                if (metadata != null)
                {
                    foreach (var kvp in metadata)
                    {
                        // 기본 메타데이터와 키가 겹치지 않도록 하거나, 덮어쓰기 정책 결정
                        if (!fullMetadata.ContainsKey(kvp.Key))
                        {
                            fullMetadata[kvp.Key] = kvp.Value;
                        }
                        // else { /* 키 충돌 시 로깅 또는 처리 */ }
                    }
                }

                // 수정된 LogActionAsync 호출 (organizationId, description, severity 제거)
                await _auditService.LogActionAsync(
                   actionType: actionType,
                   action: action,
                   connectedId: performedByConnectedId,
                   resourceType: "ConnectedIdContext",
                   resourceId: context.Id.ToString(),
                   // success: 기본값 true 사용 (필요시 조정)
                   // errorMessage: 기본값 null 사용 (필요시 조정)
                   metadata: fullMetadata, // 병합된 메타데이터 전달
                   cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for action {Action} on context {ContextKey}", action, context.ContextKey);
                // 감사 로깅 실패 시 예외를 다시 던지지 않음
            }
        }

        // DetermineSeverity 메서드는 LogActionAsync 시그니처에 severity가 없으므로 제거
        // private AuditEventSeverity DetermineSeverity(AuditActionType action
        // 액션 타입에 따른 심각도 결정 (예시)
        private AuditEventSeverity DetermineSeverity(AuditActionType actionType)
        {
            return actionType switch
            {
                AuditActionType.Delete => AuditEventSeverity.Warning,
                AuditActionType.Blocked => AuditEventSeverity.Critical,
                AuditActionType.PermissionUpdated => AuditEventSeverity.Warning,
                AuditActionType.Create => AuditEventSeverity.Info,
                AuditActionType.Update => AuditEventSeverity.Info,
                _ => AuditEventSeverity.Info,
            };
        }


        // 배치 처리 관련 메서드는 제거됨 (인터페이스에 없으므로)

        #endregion
    }
}

// 참고: ContextEvent 클래스 정의가 필요합니다.
// namespace AuthHive.Core.Models.Auth.ConnectedId.Events
// {
//     public class ContextEvent { /* 이벤트 관련 속성 정의 */ }
// }

// 참고: BatchEventResult 클래스 정의가 필요합니다.
// namespace AuthHive.Core.Models.Common
// {
//     public class BatchEventResult
//     {
//         public bool AllSucceeded { get; set; }
//         public int ProcessedCount { get; set; }
//         public int SuccessCount { get; set; }
//         public int FailureCount { get; set; }
//         public long ProcessingTimeMs { get; set; }
//         public List<EventResult> Results { get; set; } = new List<EventResult>();
//     }
// }