using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // 일부 LogActionAsync 호출에서 여전히 사용될 수 있음
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Audit; // AuditActionType 사용
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Service; // IService 인터페이스 사용
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.PlatformApplication.Handler;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Business.Commerce.Points.Events; // InsufficientPointsAlert 사용
using AuthHive.Core.Models.PlatformApplication.Common;     // ApiBlockInfo 사용
using AuthHive.Core.Models.PlatformApplication.Events;
// 분리된 Warning 클래스 사용
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Handlers
{
    /// <summary>
    /// 애플리케이션 이벤트 핸들러 - SaaS 최적화 버전
    /// 핵심: 동적 데이터 처리, 테넌트 격리, 캐싱, 비용 최적화
    /// </summary>
    public class ApplicationEventHandler : IApplicationEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IPlatformApplicationRepository _applicationRepository;
        // private readonly IPlatformApplicationService _applicationService; // 현재 사용되지 않음
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<ApplicationEventHandler> _logger;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;

        // 캐시 TTL 설정 (비용 최적화)
        private static readonly TimeSpan ApplicationCacheTTL = TimeSpan.FromHours(6);
        private static readonly TimeSpan SettingsCacheTTL = TimeSpan.FromHours(1);
        private static readonly TimeSpan UsageStatsCacheTTL = TimeSpan.FromMinutes(5);

        // 사용량 임계값 상수 (나중에 동적으로 변경 가능)
        private const decimal DefaultApiUsageThreshold = 0.80m; // 80%
        private const decimal DefaultStorageThreshold = 0.90m; // 90%

        public ApplicationEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IPlatformApplicationRepository applicationRepository,
            IPlatformApplicationService applicationService, // 생성자에 유지 (DI)
            IDateTimeProvider dateTimeProvider,
            ILogger<ApplicationEventHandler> logger,
            IEventBus eventBus,
            IUnitOfWork unitOfWork)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _applicationRepository = applicationRepository;
            // _applicationService = applicationService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
            _unitOfWork = unitOfWork;
        }


        #region IService Implementation

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ApplicationEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 의존성 서비스들의 상태 확인
                var cacheHealthy = await _cacheService.IsHealthyAsync(cancellationToken);
                var auditHealthy = await _auditService.IsHealthyAsync(cancellationToken);
                // 필요하다면 리포지토리(DB 연결) 상태 확인 로직 추가
                // var repoHealthy = await _applicationRepository.IsHealthyAsync(cancellationToken);

                return cacheHealthy && auditHealthy; // && repoHealthy;
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("ApplicationEventHandler health check canceled.");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ApplicationEventHandler health check failed");
                return false;
            }
        }

        #endregion


        #region Core Application Events (IApplicationEventHandler 구현)

        public async Task HandleApplicationCreatedAsync(ApplicationCreatedEvent eventData, CancellationToken cancellationToken = default)
        {
            // 애플리케이션 이벤트는 AggregateId가 ApplicationId임
            var applicationId = eventData.AggregateId;

            // OrganizationId는 BaseEvent에서 nullable이므로 확인 필요
            if (!eventData.OrganizationId.HasValue || eventData.OrganizationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApplicationCreatedEvent: OrganizationId is missing for ApplicationId {ApplicationId}.", applicationId);
                return; // 테넌트 격리를 위해 OrganizationId 없이 진행 불가
            }
            var organizationId = eventData.OrganizationId.Value;

            try
            {
                _logger.LogInformation("Handling ApplicationCreatedEvent: AppId={ApplicationId}, OrgId={OrganizationId}, Type={Type}",
                    applicationId, organizationId, eventData.ApplicationType);

                // 1. 감사 로그 (Dictionary 사용)
                var auditMetadata = new Dictionary<string, object>
                {
                    ["ApplicationKey"] = eventData.ApplicationKey,
                    ["ApplicationType"] = eventData.ApplicationType.ToString(),
                    ["OrganizationId"] = organizationId
                    // 필요시 eventData의 다른 관련 속성 추가
                };

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: "APPLICATION_CREATED",
                    connectedId: eventData.CreatedByConnectedId, // connectedId 파라미터 이름 사용
                    resourceType: "Application",
                    resourceId: applicationId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                // 2. 캐시 설정 (테넌트 격리)
                await CacheApplicationWithTenantIsolationAsync(applicationId, organizationId, eventData, cancellationToken);

                // 3. 기본 설정 초기화
                await InitializeApplicationDefaultsAsync(applicationId, eventData.ApplicationType, cancellationToken);

                // 4. 조직의 애플리케이션 목록 캐시 무효화
                await InvalidateOrganizationApplicationListCacheAsync(organizationId, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                _logger.LogDebug("Application created successfully handled for AppId={ApplicationId}, OrgId={OrganizationId}", applicationId, organizationId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApplicationCreatedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken); // 롤백 시도
                throw; // 취소 예외는 다시 던짐
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApplicationCreatedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // 일반 예외도 다시 던짐
            }
        }

        public async Task HandleApplicationUpdatedAsync(ApplicationUpdatedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            if (!eventData.OrganizationId.HasValue || eventData.OrganizationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApplicationUpdatedEvent: OrganizationId is missing for ApplicationId {ApplicationId}.", applicationId);
                return;
            }
            var organizationId = eventData.OrganizationId.Value;

            try
            {
                if (eventData.ChangedProperties != null && eventData.ChangedProperties.Any())
                {
                    _logger.LogInformation("Handling ApplicationUpdatedEvent: AppId={ApplicationId}, ChangedFields={Fields}",
                        applicationId, string.Join(",", eventData.ChangedProperties.Keys));

                    if (ShouldAuditUpdate(eventData.ChangedProperties))
                    {
                        var auditMetadata = eventData.ChangedProperties
                                                .Where(kvp => kvp.Value != null)
                                                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value!);

                        await _auditService.LogActionAsync(
                             actionType: AuditActionType.Update,
                             action: "APPLICATION_UPDATED",
                             connectedId: eventData.UpdatedByConnectedId,
                             resourceType: "Application",
                             resourceId: applicationId.ToString(),
                             metadata: auditMetadata,
                             cancellationToken: cancellationToken);
                    }

                    await UpdateApplicationCacheAsync(applicationId, organizationId, eventData.ChangedProperties, cancellationToken);
                }
                else
                {
                    _logger.LogInformation("Handling ApplicationUpdatedEvent for AppId={ApplicationId}: No properties changed.", applicationId);
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApplicationUpdatedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApplicationUpdatedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }

        public async Task HandleApplicationDeletedAsync(ApplicationDeletedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            if (!eventData.OrganizationId.HasValue || eventData.OrganizationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApplicationDeletedEvent: OrganizationId is missing for ApplicationId {ApplicationId}.", applicationId);
                return;
            }
            var organizationId = eventData.OrganizationId.Value;

            try
            {
                _logger.LogInformation("Handling ApplicationDeletedEvent: AppId={ApplicationId}, OrgId={OrganizationId}, IsSoftDelete={IsSoftDelete}",
                    applicationId, organizationId, eventData.IsSoftDelete);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: eventData.IsSoftDelete ? "APPLICATION_SOFT_DELETED" : "APPLICATION_DELETED",
                    connectedId: eventData.DeletedByConnectedId,
                    resourceType: "Application",
                    resourceId: applicationId.ToString(),
                    metadata: new Dictionary<string, object> { ["IsSoftDelete"] = eventData.IsSoftDelete },
                    cancellationToken: cancellationToken);

                await CleanupApplicationCacheAsync(applicationId, organizationId, cancellationToken);
                await InvalidateOrganizationApplicationListCacheAsync(organizationId, cancellationToken);

                if (eventData.IsSoftDelete)
                {
                    // 외부 클래스 사용 및 Correlation/Causation 전달
                    await _eventBus.PublishAsync(new ApplicationDeactivatedNotification(
                        applicationId,
                        eventData.DeletedAt,
                        eventData.CorrelationId, // 원본 이벤트의 CorrelationId 사용
                        eventData.EventId        // 원본 이벤트를 CausationId로 사용
                    ), cancellationToken);
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApplicationDeletedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApplicationDeletedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }

        public async Task HandleApplicationStatusChangedAsync(ApplicationStatusChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            if (!eventData.OrganizationId.HasValue || eventData.OrganizationId.Value == Guid.Empty)
            {
                _logger.LogError("Cannot handle ApplicationStatusChangedEvent: OrganizationId is missing for ApplicationId {ApplicationId}.", applicationId);
                return;
            }
            var organizationId = eventData.OrganizationId.Value;

            try
            {
                _logger.LogInformation("Handling ApplicationStatusChangedEvent: AppId={ApplicationId}, OrgId={OrganizationId}, {OldStatus} -> {NewStatus}",
                    applicationId, organizationId, eventData.OldStatus, eventData.NewStatus);

                if (IsImportantStatusChange(eventData.OldStatus, eventData.NewStatus))
                {
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.StatusChange,
                        action: "APPLICATION_STATUS_CHANGED",
                        connectedId: eventData.ChangedByConnectedId,
                        resourceType: "Application",
                        resourceId: applicationId.ToString(),
                        metadata: new Dictionary<string, object>
                        {
                            ["OldStatus"] = eventData.OldStatus.ToString(),
                            ["NewStatus"] = eventData.NewStatus.ToString(),
                            ["Reason"] = eventData.Reason ?? (object)"" // null 처리
                        },
                        cancellationToken: cancellationToken);
                }

                // 상태별 처리 (알림 발행 포함)
                await ProcessStatusChangeAsync(eventData, cancellationToken);

                // 캐시 업데이트
                await UpdateApplicationStatusInCacheAsync(applicationId, organizationId, eventData.NewStatus, eventData.ChangedAt, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApplicationStatusChangedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApplicationStatusChangedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
        }

        #endregion

        #region Settings Events (Implement IApplicationEventHandler)

        public async Task HandleApplicationSettingsChangedAsync(ApplicationSettingsChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            // OrganizationId는 이 이벤트에 없을 수 있으므로, 필요하다면 Repository에서 조회해야 함

            try
            {
                var cacheKey = GetApplicationSettingsCacheKey(applicationId);

                // 기존 설정 가져오기 (Locking 고려 필요)
                // 실제 환경에서는 설정 업데이트 시 Race Condition 방지를 위해 Locking 메커니즘이 필요할 수 있음
                var settings = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken)
                    ?? new Dictionary<string, object>();

                // 설정 업데이트
                if (eventData.NewValue != null)
                {
                    settings[eventData.SettingKey] = eventData.NewValue;
                }
                else
                {
                    settings.Remove(eventData.SettingKey); // 값이 null이면 설정 제거
                }

                // 캐시 업데이트
                await _cacheService.SetAsync(cacheKey, settings, SettingsCacheTTL, cancellationToken);

                // 중요한 설정 변경만 로깅 및 감사 (감사 로그 추가)
                if (IsImportantSetting(eventData.SettingKey))
                {
                    _logger.LogInformation("Important application setting changed: AppId={ApplicationId}, Key={Key}",
                        applicationId, eventData.SettingKey);

                    // 감사 로그 기록
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Configuration,
                        action: "APPLICATION_SETTING_CHANGED",
                        connectedId: eventData.ChangedByConnectedId, // eventData에 ChangedByConnectedId가 있어야 함
                        resourceType: "ApplicationSetting",
                        resourceId: $"{applicationId}:{eventData.SettingKey}",
                        metadata: new Dictionary<string, object>
                        {
                            ["SettingKey"] = eventData.SettingKey,
                            ["OldValue"] = eventData.OldValue ?? "N/A", // null 처리
                            ["NewValue"] = eventData.NewValue ?? "N/A"  // null 처리
                        },
                        cancellationToken: cancellationToken);
                }
                // Commit은 보통 요청 단위로 이루어지므로, 이벤트 핸들러에서 매번 Commit하는 것이 적절한지는 설계에 따라 다름
                // 여기서는 각 핸들러가 독립적인 트랜잭션 단위라고 가정
                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApplicationSettingsChangedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // 설정 변경 실패는 크리티컬하지 않을 수 있으므로, throw 여부 결정 필요
                // throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApplicationSettingsChangedEvent for AppId={ApplicationId}, Key={Key}",
                                 applicationId, eventData.SettingKey);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // 설정 변경 실패는 크리티컬하지 않을 수 있으므로, throw 여부 결정 필요
            }
        }

        public async Task HandleOAuthSettingsChangedAsync(OAuthSettingsChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                _logger.LogInformation("Handling OAuthSettingsChangedEvent for AppId={ApplicationId}", applicationId);

                // OAuth 설정은 보안상 중요하므로 항상 감사
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration,
                    action: "OAUTH_SETTINGS_CHANGED",
                    connectedId: eventData.ChangedByConnectedId,
                    resourceType: "ApplicationOAuthSettings",
                    resourceId: applicationId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        // List 비교 결과를 문자열로 저장하거나, 변경된 항목만 저장하는 방식 고려
                        ["CallbackUrlsChanged"] = !AreListsEqual(eventData.OldCallbackUrls, eventData.NewCallbackUrls),
                        ["AllowedOriginsChanged"] = !AreListsEqual(eventData.OldAllowedOrigins, eventData.NewAllowedOrigins),
                        // 필요시 ["OldCallbackUrls"], ["NewCallbackUrls"] 등 추가 (단, 데이터 크기 주의)
                    },
                    cancellationToken: cancellationToken);

                // OAuth 관련 캐시 무효화 (보안상 즉시 적용)
                await InvalidateOAuthCacheAsync(applicationId, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling OAuthSettingsChangedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling OAuthSettingsChangedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // OAuth 설정 실패는 중요할 수 있음
            }
        }

        public async Task HandleResourceQuotaChangedAsync(ResourceQuotaChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                _logger.LogInformation("Handling ResourceQuotaChangedEvent: AppId={ApplicationId}, Type={Type}, {Old} -> {New}",
                    applicationId, eventData.ResourceType, eventData.OldQuota, eventData.NewQuota);

                // 할당량 캐시 업데이트
                var quotaKey = GetResourceQuotaCacheKey(applicationId, eventData.ResourceType);
                // SetAsync의 제네릭 타입을 object로 지정하거나, NewQuota의 타입에 맞게 조정 필요
                await _cacheService.SetAsync<object>(quotaKey, eventData.NewQuota, TimeSpan.FromHours(24), cancellationToken);

                // 할당량 감소 시 경고 이벤트 발행 (외부 클래스 사용)
                if (eventData.NewQuota < eventData.OldQuota)
                {
                    await _eventBus.PublishAsync(new ResourceQuotaReducedWarning(
                        applicationId,
                        eventData.ResourceType,
                        eventData.NewQuota, // decimal로 가정
                        eventData.CorrelationId,
                        eventData.EventId
                    ), cancellationToken);
                }

                // 감사 로그 (할당량 변경도 감사 대상일 수 있음)
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration, // 또는 Update
                    action: "RESOURCE_QUOTA_CHANGED",
                    // eventData에 ChangedByConnectedId가 필요함 (없다면 시스템 ID 등 사용)
                    connectedId: eventData.TriggeredBy ?? Guid.Empty, // BaseEvent의 TriggeredBy 사용 (Nullable)
                    resourceType: "ApplicationQuota",
                    resourceId: $"{applicationId}:{eventData.ResourceType}",
                    metadata: new Dictionary<string, object>
                    {
                        ["ResourceType"] = eventData.ResourceType,
                        ["OldQuota"] = eventData.OldQuota,
                        ["NewQuota"] = eventData.NewQuota
                    },
                    cancellationToken: cancellationToken);


                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ResourceQuotaChangedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ResourceQuotaChangedEvent for AppId={ApplicationId}, Type={Type}",
                                 applicationId, eventData.ResourceType);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // 할당량 변경 실패는 중요할 수 있음
            }
        }

        #endregion

        #region Usage Events (Implement IApplicationEventHandler)

        public async Task HandleApiUsageThresholdReachedAsync(ApiUsageThresholdEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                // Quota가 0인 경우 나누기 오류 방지
                if (eventData.Quota <= 0)
                {
                    _logger.LogWarning("Cannot process ApiUsageThresholdEvent for AppId={ApplicationId}: Quota is zero or negative.", applicationId);
                    return;
                }
                var usagePercentage = (decimal)eventData.CurrentUsage / eventData.Quota;

                _logger.LogWarning("API usage threshold reached: AppId={ApplicationId}, Usage={Percentage:P2}, Type={Type}",
                    applicationId, usagePercentage, eventData.ThresholdType);

                // 임계값별 처리
                if (usagePercentage >= 1.0m) // 100% 도달
                {
                    // API 차단 이벤트 발행 (외부 클래스 사용)
                    await _eventBus.PublishAsync(new ApiQuotaExceededEvent(
                        applicationId,
                        eventData.ThresholdType,
                        _dateTimeProvider.UtcNow, // BlockedAt 시간
                        eventData.CorrelationId,
                        eventData.EventId
                    ), cancellationToken);
                }
                // 설정된 임계값 (eventData.ThresholdPercentage)과 비교
                else if (usagePercentage >= eventData.ThresholdPercentage)
                {
                    // 경고 알림 발송 (외부 클래스 사용)
                    await SendUsageWarningNotificationAsync(eventData, cancellationToken);
                }

                // 사용량 통계 캐싱 (대시보드용)
                await UpdateUsageStatsCacheAsync(eventData, cancellationToken);

                // 사용량 이벤트는 Commit이 필요 없을 수 있음 (다른 트랜잭션에서 처리될 수 있음)
                // await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling ApiUsageThresholdReachedAsync for AppId={ApplicationId} was canceled.", applicationId);
                // 롤백할 트랜잭션이 없을 수 있음
                // await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // throw; // 사용량 이벤트는 취소되어도 괜찮을 수 있음
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling ApiUsageThresholdReachedAsync for AppId={ApplicationId}", applicationId);
                // 사용량 추적 실패는 서비스를 중단시키지 않음, throw 하지 않음
            }
        }

        public async Task HandleStorageUsageThresholdReachedAsync(StorageUsageThresholdEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                // QuotaGB가 0인 경우 나누기 오류 방지
                if (eventData.QuotaGB <= 0)
                {
                    _logger.LogWarning("Cannot process StorageUsageThresholdReachedAsync for AppId={ApplicationId}: QuotaGB is zero or negative.", applicationId);
                    return;
                }
                var usagePercentage = eventData.CurrentUsageGB / eventData.QuotaGB;

                _logger.LogWarning("Storage usage threshold reached: AppId={ApplicationId}, Usage={Current:F2}GB/{Quota:F2}GB ({Percentage:P2})",
                    applicationId, eventData.CurrentUsageGB, eventData.QuotaGB, usagePercentage);

                // 설정된 임계값 (eventData.ThresholdPercentage) 이상 시 정리 제안
                if (usagePercentage >= eventData.ThresholdPercentage)
                {
                    // 기본 제안 액션 (나중에 설정에서 가져오도록 변경 가능)
                    var defaultActions = new[] { "Archive old data", "Delete temporary files", "Compress large files" };

                    await _eventBus.PublishAsync(new StorageCleanupSuggestionEvent(
                        applicationId,
                        eventData.CurrentUsageGB,
                        defaultActions, // 설정이나 기본값 사용
                        eventData.CorrelationId,
                        eventData.EventId
                    ), cancellationToken);
                }

                // 이 이벤트도 Commit이 필요 없을 수 있음
                // await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling StorageUsageThresholdReachedAsync for AppId={ApplicationId} was canceled.", applicationId);
                // await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling StorageUsageThresholdReachedAsync for AppId={ApplicationId}", applicationId);
                // 스토리지 사용량 이벤트 실패도 throw하지 않음
            }
        }

        public async Task HandleUsageResetAsync(UsageResetEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                _logger.LogInformation("Handling UsageResetEvent: AppId={ApplicationId}, Type={Type}, PreviousUsage={Usage}",
                    applicationId, eventData.ResetType, eventData.PreviousUsage);

                // 사용량 리셋 전 통계 저장 (캐시 또는 DB)
                await StoreUsageHistoryAsync(eventData, cancellationToken);

                // 관련 사용량 캐시 초기화
                var usageKey = GetUsageCacheKey(applicationId, eventData.ResetType);
                await _cacheService.RemoveAsync(usageKey, cancellationToken);
                // 관련된 통계 캐시도 제거할 수 있음
                var statsKey = $"app:{applicationId}:stats:usage:{eventData.ResetType}"; // 예시 키
                await _cacheService.RemoveAsync(statsKey, cancellationToken);


                // 리셋 알림 이벤트 발행 (외부 클래스 사용)
                await _eventBus.PublishAsync(new UsageResetNotification(
                    applicationId,
                    eventData.ResetType,
                    CalculateNextResetDate(eventData.ResetType), // 다음 리셋 날짜 계산
                    eventData.CorrelationId,
                    eventData.EventId
                ), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling UsageResetEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling UsageResetEvent for AppId={ApplicationId}, Type={Type}",
                                 applicationId, eventData.ResetType);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // 사용량 리셋 실패는 중요할 수 있음
            }
        }

        #endregion

        #region Point Events (Implement IApplicationEventHandler)

        public async Task HandleApiBlockedDueToInsufficientPointsAsync(InsufficientPointsEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                _logger.LogWarning("API blocked due to insufficient points: AppId={ApplicationId}, Required={Required}, Available={Available}, Endpoint={Endpoint}",
                    applicationId, eventData.RequiredPoints, eventData.AvailablePoints, eventData.ApiEndpoint);

                // 즉시 API 차단 상태 캐싱
                var blockKey = GetApiBlockCacheKey(applicationId);
                await _cacheService.SetAsync(blockKey, new ApiBlockInfo // 외부 클래스 사용
                {
                    IsBlocked = true,
                    BlockedAt = _dateTimeProvider.UtcNow,
                    Reason = "InsufficientPoints",
                    RequiredPoints = eventData.RequiredPoints,
                    AvailablePoints = eventData.AvailablePoints
                }, TimeSpan.FromMinutes(5), cancellationToken); // 5분 후 재시도 허용 (TTL 설정)

                // 긴급 알림 이벤트 발송 (외부 클래스 사용)
                await SendInsufficientPointsAlertAsync(eventData, cancellationToken);

                // 감사 로그
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Blocked,
                    action: "API_BLOCKED_INSUFFICIENT_POINTS",
                    // InsufficientPointsEvent에 ConnectedId가 필요함
                    connectedId: eventData.ConnectedId, // eventData에 ConnectedId 속성 가정
                    resourceType: "ApiCall", // 리소스 타입을 ApiCall 등으로 구체화
                    resourceId: $"{applicationId}:{eventData.ApiEndpoint}", // 리소스 ID 구체화
                    success: false, // 실패한 작업으로 기록
                    errorMessage: "Insufficient points", // 에러 메시지 추가
                    metadata: new Dictionary<string, object>
                    {
                        ["ApiEndpoint"] = eventData.ApiEndpoint,
                        ["RequiredPoints"] = eventData.RequiredPoints,
                        ["AvailablePoints"] = eventData.AvailablePoints,
                        ["ApplicationId"] = applicationId // 명시적으로 추가
                    },
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling InsufficientPointsEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling InsufficientPointsEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // API 차단은 중요하므로 예외 전파
            }
        }

        public async Task HandlePointSettingsChangedAsync(PointSettingsChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            var applicationId = eventData.AggregateId;
            try
            {
                _logger.LogInformation("Handling PointSettingsChangedEvent: AppId={ApplicationId}, UsePoints={Old}->{New}, Rate={OldRate}->{NewRate}",
                    applicationId,
                    eventData.OldUsePointsForApiCalls, eventData.NewUsePointsForApiCalls,
                    eventData.OldPointsPerApiCall, eventData.NewPointsPerApiCall);

                // 중요 변경사항 감사
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration,
                    action: "POINT_SETTINGS_CHANGED",
                    connectedId: eventData.ChangedByConnectedId,
                    resourceType: "ApplicationPointSettings",
                    resourceId: applicationId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        ["UsePointsChanged"] = eventData.OldUsePointsForApiCalls != eventData.NewUsePointsForApiCalls,
                        ["RateChanged"] = eventData.OldPointsPerApiCall != eventData.NewPointsPerApiCall,
                        ["OldUsePoints"] = eventData.OldUsePointsForApiCalls,
                        ["NewUsePoints"] = eventData.NewUsePointsForApiCalls,
                        ["OldRate"] = eventData.OldPointsPerApiCall,
                        ["NewRate"] = eventData.NewPointsPerApiCall
                    },
                    cancellationToken: cancellationToken);

                // 포인트 설정 캐시 업데이트
                await UpdatePointSettingsCacheAsync(eventData, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Handling PointSettingsChangedEvent for AppId={ApplicationId} was canceled.", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling PointSettingsChangedEvent for AppId={ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                throw; // 포인트 설정 변경 실패는 중요할 수 있음
            }
        }

        #endregion

        #region Private Helper Methods - SaaS Optimized & Async/Cancellation Token

        // 캐시 키 생성 메서드들
        private string GetApplicationCacheKey(Guid organizationId, Guid applicationId) => $"tenant:{organizationId}:app:{applicationId}";
        private string GetOrganizationApplicationListCacheKey(Guid organizationId) => $"tenant:{organizationId}:apps";
        private string GetApplicationSettingsCacheKey(Guid applicationId) => $"app:{applicationId}:settings";
        private string GetResourceQuotaCacheKey(Guid applicationId, string resourceType) => $"app:{applicationId}:quota:{resourceType}";
        private string GetUsageCacheKey(Guid applicationId, string usageType) => $"app:{applicationId}:usage:{usageType}"; // 사용량 유형별 키
        private string GetUsageStatsCacheKey(Guid applicationId, string thresholdType) => $"app:{applicationId}:stats:usage:{thresholdType}"; // 통계 유형별 키
        private string GetApiBlockCacheKey(Guid applicationId) => $"app:{applicationId}:api:blocked";
        private string GetOAuthCachePattern(Guid applicationId) => $"app:{applicationId}:oauth:*"; // OAuth 패턴
        private string GetApiKeyCachePattern(Guid applicationId) => $"app:{applicationId}:apikeys:*"; // API 키 패턴
        private string GetApplicationReactivationKey(Guid applicationId) => $"app:{applicationId}:needs-reactivation"; // 활성화 플래그 키
        private string GetPointSettingsCacheKey(Guid applicationId) => $"app:{applicationId}:points:settings"; // 포인트 설정 키
        private string GetUsageHistoryCacheKey(Guid applicationId, string resetType, DateTime resetAt) => $"app:{applicationId}:history:{resetType}:{resetAt:yyyyMMdd}"; // 사용량 히스토리 키


        // 감사 데이터 생성 (더 이상 사용하지 않을 수 있음, LogActionAsync에 Dictionary 직접 전달)
        // private Dictionary<string, object> BuildDynamicAuditData(object eventData, Dictionary<string, object> baseData) { ... }
        // private bool IsJsonSerializable(object value) { ... }

        private async Task CacheApplicationWithTenantIsolationAsync(Guid applicationId, Guid organizationId, ApplicationCreatedEvent eventData, CancellationToken cancellationToken)
        {
            var appCacheKey = GetApplicationCacheKey(organizationId, applicationId);

            // 캐시할 최소 정보
            var appData = new Dictionary<string, object>
            {
                ["Id"] = applicationId,
                ["OrganizationId"] = organizationId,
                ["ApplicationKey"] = eventData.ApplicationKey,
                ["ApplicationType"] = eventData.ApplicationType.ToString(),
                ["CreatedAt"] = eventData.CreatedAt,
                ["Status"] = ApplicationStatus.Active.ToString() // 생성 시 기본 상태
            };
            await _cacheService.SetAsync(appCacheKey, appData, ApplicationCacheTTL, cancellationToken);

            // 조직별 앱 목록 업데이트 (동시성 문제 고려 필요 - Lock 또는 원자적 연산 사용)
            var orgAppsKey = GetOrganizationApplicationListCacheKey(organizationId);
            // 이 부분은 Lock 또는 Redis의 SetAdd 같은 원자적 연산으로 개선 필요
            var appList = await _cacheService.GetAsync<List<Guid>>(orgAppsKey, cancellationToken) ?? new List<Guid>();
            if (!appList.Contains(applicationId))
            {
                appList.Add(applicationId);
                await _cacheService.SetAsync(orgAppsKey, appList, TimeSpan.FromDays(1), cancellationToken); // TTL 적절히 설정
            }
        }

        private async Task UpdateApplicationCacheAsync(Guid applicationId, Guid organizationId, Dictionary<string, object?> changedProperties, CancellationToken cancellationToken)
        {
            var cacheKey = GetApplicationCacheKey(organizationId, applicationId);
            var cachedData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken);

            if (cachedData != null)
            {
                bool updated = false;
                foreach (var change in changedProperties)
                {
                    // 캐시 데이터 타입과 호환되는지, 직렬화 가능한지 확인
                    if (change.Value != null /* && IsJsonSerializable(change.Value) */) // IsJsonSerializable은 단순 Dictionary에서는 불필요
                    {
                        // 기존 값과 다를 경우 업데이트
                        if (!cachedData.TryGetValue(change.Key, out var existingValue) || !Equals(existingValue, change.Value))
                        {
                            cachedData[change.Key] = change.Value;
                            updated = true;
                        }
                    }
                    else if (cachedData.ContainsKey(change.Key)) // 값이 null이면 키 제거
                    {
                        cachedData.Remove(change.Key);
                        updated = true;
                    }
                }

                if (updated)
                {
                    await _cacheService.SetAsync(cacheKey, cachedData, ApplicationCacheTTL, cancellationToken);
                    _logger.LogDebug("Updated application cache for AppId={ApplicationId}", applicationId);
                }
            }
            else
            {
                _logger.LogWarning("Application cache data not found for AppId={ApplicationId} during update.", applicationId);
                // 필요하다면 DB에서 다시 로드하여 캐시 설정
                // await ReloadAndCacheApplicationAsync(applicationId, organizationId, cancellationToken);
            }
        }

        private async Task UpdateApplicationStatusInCacheAsync(Guid applicationId, Guid organizationId, ApplicationStatus newStatus, DateTime changedAt, CancellationToken cancellationToken)
        {
            var cacheKey = GetApplicationCacheKey(organizationId, applicationId);
            var cachedData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey, cancellationToken);

            if (cachedData != null)
            {
                cachedData["Status"] = newStatus.ToString();
                cachedData["StatusChangedAt"] = changedAt;
                await _cacheService.SetAsync(cacheKey, cachedData, ApplicationCacheTTL, cancellationToken);
                _logger.LogDebug("Updated application status in cache for AppId={ApplicationId} to {Status}", applicationId, newStatus);
            }
            else
            {
                _logger.LogWarning("Application cache data not found for AppId={ApplicationId} during status update.", applicationId);
            }
        }

        // Cleanup 시에는 OrganizationId가 필요함 (Repository 조회 또는 이벤트 데이터 활용)
        private async Task CleanupApplicationCacheAsync(Guid applicationId, Guid organizationId, CancellationToken cancellationToken)
        {
            // 애플리케이션 기본 캐시 제거
            var appKey = GetApplicationCacheKey(organizationId, applicationId);
            await _cacheService.RemoveAsync(appKey, cancellationToken);

            // 관련 설정/통계 등 다른 캐시 키 제거
            await _cacheService.RemoveAsync(GetApplicationSettingsCacheKey(applicationId), cancellationToken);
            await _cacheService.RemoveAsync(GetApiBlockCacheKey(applicationId), cancellationToken);
            await _cacheService.RemoveAsync(GetPointSettingsCacheKey(applicationId), cancellationToken);
            // 패턴 기반 삭제 (지원하는 경우)
            await _cacheService.RemoveByPatternAsync(GetOAuthCachePattern(applicationId), cancellationToken);
            await _cacheService.RemoveByPatternAsync(GetApiKeyCachePattern(applicationId), cancellationToken);
            await _cacheService.RemoveByPatternAsync($"app:{applicationId}:quota:*", cancellationToken);
            await _cacheService.RemoveByPatternAsync($"app:{applicationId}:usage:*", cancellationToken);
            await _cacheService.RemoveByPatternAsync($"app:{applicationId}:stats:*", cancellationToken);
            await _cacheService.RemoveByPatternAsync($"app:{applicationId}:history:*", cancellationToken);

            _logger.LogDebug("Cleaned up caches related to AppId={ApplicationId}", applicationId);
        }

        private async Task InvalidateOrganizationApplicationListCacheAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var orgAppsKey = GetOrganizationApplicationListCacheKey(organizationId);
            await _cacheService.RemoveAsync(orgAppsKey, cancellationToken);
            _logger.LogDebug("Invalidated organization application list cache for OrgId={OrganizationId}", organizationId);
        }

        private async Task InvalidateOAuthCacheAsync(Guid applicationId, CancellationToken cancellationToken)
        {
            await _cacheService.RemoveByPatternAsync(GetOAuthCachePattern(applicationId), cancellationToken);
            _logger.LogDebug("Invalidated OAuth cache for AppId={ApplicationId}", applicationId);
        }

        private async Task InitializeApplicationDefaultsAsync(Guid applicationId, ApplicationType applicationType, CancellationToken cancellationToken)
        {
            var defaultSettings = await GetDefaultSettingsForApplicationTypeAsync(applicationType);
            if (defaultSettings.Any())
            {
                var settingsKey = GetApplicationSettingsCacheKey(applicationId);
                await _cacheService.SetAsync(settingsKey, defaultSettings, SettingsCacheTTL, cancellationToken);
                _logger.LogDebug("Initialized default settings in cache for AppId={ApplicationId}", applicationId);
            }
        }

        // 기본 설정 조회 (비동기 불필요 시 Task 제거 가능)
        private Task<Dictionary<string, object>> GetDefaultSettingsForApplicationTypeAsync(ApplicationType type)
        {
            var settings = type switch
            {
                ApplicationType.Web => new Dictionary<string, object> { ["MaxSessionDuration"] = 3600, ["EnableCors"] = true, ["DefaultApiRateLimit"] = 1000 },
                ApplicationType.Mobile => new Dictionary<string, object> { ["MaxSessionDuration"] = 86400, ["EnablePushNotifications"] = true, ["DefaultApiRateLimit"] = 500 },
                ApplicationType.Api => new Dictionary<string, object> { ["MaxSessionDuration"] = 7200, ["RequireApiKey"] = true, ["DefaultApiRateLimit"] = 10000 },
                _ => new Dictionary<string, object>()
            };
            return Task.FromResult(settings); // 비동기가 아니므로 Task.FromResult 사용
        }

        // 상태 변경에 따른 추가 처리 및 알림 발행
        private async Task ProcessStatusChangeAsync(ApplicationStatusChangedEvent eventData, CancellationToken cancellationToken)
        {
            switch (eventData.NewStatus)
            {
                case ApplicationStatus.Suspended:
                    await _eventBus.PublishAsync(new ApplicationSuspendedNotification(
                        eventData.AggregateId,
                        eventData.ChangedAt,
                        eventData.Reason,
                        eventData.CorrelationId,
                        eventData.EventId
                    ), cancellationToken);
                    // 관련된 API 키 캐시 무효화
                    await _cacheService.RemoveByPatternAsync(GetApiKeyCachePattern(eventData.AggregateId), cancellationToken);
                    _logger.LogInformation("Published ApplicationSuspendedNotification and invalidated API key cache for AppId={ApplicationId}", eventData.AggregateId);
                    break;

                case ApplicationStatus.Active:
                    // 비활성 상태에서 활성 상태로 변경된 경우 알림
                    if (eventData.OldStatus != ApplicationStatus.Active)
                    {
                        await _eventBus.PublishAsync(new ApplicationActivatedNotification(
                            eventData.AggregateId,
                            eventData.ChangedAt,
                            eventData.CorrelationId,
                            eventData.EventId
                        ), cancellationToken);
                        // API 키 캐시 재구성 필요 플래그 설정 (백그라운드 작업 등에서 사용)
                        var reactivateKey = GetApplicationReactivationKey(eventData.AggregateId);
                        await _cacheService.SetAsync<object>(reactivateKey, true, TimeSpan.FromMinutes(5), cancellationToken);
                        _logger.LogInformation("Published ApplicationActivatedNotification and set reactivation flag for AppId={ApplicationId}", eventData.AggregateId);
                    }
                    break;

                    // Deleted 상태는 HandleApplicationDeletedAsync에서 처리되므로 여기서는 특별한 처리 없음
                    // case ApplicationStatus.Deleted:
                    //     break;
            }
        }

        private async Task UpdateUsageStatsCacheAsync(ApiUsageThresholdEvent eventData, CancellationToken cancellationToken)
        {
            // Quota가 0 이하이면 계산 불가
            if (eventData.Quota <= 0) return;

            var statsKey = GetUsageStatsCacheKey(eventData.AggregateId, eventData.ThresholdType);
            var stats = new Dictionary<string, object>
            {
                ["CurrentUsage"] = eventData.CurrentUsage,
                ["Quota"] = eventData.Quota,
                ["Percentage"] = (decimal)eventData.CurrentUsage / eventData.Quota,
                ["UpdatedAt"] = eventData.OccurredAt, // 이벤트 발생 시간 사용
                ["ThresholdType"] = eventData.ThresholdType
            };
            await _cacheService.SetAsync(statsKey, stats, UsageStatsCacheTTL, cancellationToken);
            _logger.LogDebug("Updated usage stats cache for AppId={ApplicationId}, Type={Type}", eventData.AggregateId, eventData.ThresholdType);
        }

        private async Task UpdatePointSettingsCacheAsync(PointSettingsChangedEvent eventData, CancellationToken cancellationToken)
        {
            var pointKey = GetPointSettingsCacheKey(eventData.AggregateId);
            var settings = new Dictionary<string, object>
            {
                ["UsePointsForApiCalls"] = eventData.NewUsePointsForApiCalls,
                ["PointsPerApiCall"] = eventData.NewPointsPerApiCall,
                ["UpdatedAt"] = eventData.OccurredAt // 이벤트의 변경 시간 사용
            };
            await _cacheService.SetAsync(pointKey, settings, TimeSpan.FromHours(12), cancellationToken); // TTL 적절히 설정
            _logger.LogDebug("Updated point settings cache for AppId={ApplicationId}", eventData.AggregateId);
        }

        private async Task StoreUsageHistoryAsync(UsageResetEvent eventData, CancellationToken cancellationToken)
        {
            // 캐시를 사용한 히스토리 저장 (만료 시간 설정)
            var historyKey = GetUsageHistoryCacheKey(eventData.AggregateId, eventData.ResetType, eventData.OccurredAt);
            var historyData = new
            {
                PreviousUsage = eventData.PreviousUsage,
                ResetAt = eventData.OccurredAt,
                ResetType = eventData.ResetType
            };
            // 장기 보관이 필요하면 DB 사용 고려
            await _cacheService.SetAsync(historyKey, historyData, TimeSpan.FromDays(90), cancellationToken); // 90일 보관 예시
            _logger.LogDebug("Stored usage history in cache for AppId={ApplicationId}, Type={Type}", eventData.AggregateId, eventData.ResetType);
        }

        private async Task SendUsageWarningNotificationAsync(ApiUsageThresholdEvent eventData, CancellationToken cancellationToken)
        {
            // Quota가 0 이하이면 계산 불가
            if (eventData.Quota <= 0) return;

            await _eventBus.PublishAsync(new UsageWarningNotification(
                eventData.AggregateId,
                eventData.CurrentUsage,
                eventData.Quota,
                eventData.ThresholdPercentage,
                $"API_USAGE_{eventData.ThresholdType.ToUpper()}_WARNING", // 알림 타입 구체화
                eventData.CorrelationId,
                eventData.EventId
            ), cancellationToken);
            _logger.LogInformation("Published UsageWarningNotification for AppId={ApplicationId}, Type={Type}", eventData.AggregateId, eventData.ThresholdType);
        }

        private async Task SendInsufficientPointsAlertAsync(InsufficientPointsEvent eventData, CancellationToken cancellationToken)
        {
            await _eventBus.PublishAsync(new InsufficientPointsAlert(
                eventData.AggregateId, // ApplicationId
                eventData.ConnectedId,
                eventData.RequiredPoints,
                eventData.AvailablePoints,
                eventData.ApiEndpoint,
                "CRITICAL", // AlertLevel
                eventData.CorrelationId,
                eventData.EventId
            ), cancellationToken);
            _logger.LogCritical("Published InsufficientPointsAlert for AppId={ApplicationId}, UserContext={ConnectedId}", eventData.AggregateId, eventData.ConnectedId);
        }

        // 리스트 비교 헬퍼
        // [FIX] CS1503: Change parameter type from List<string>? to IReadOnlyList<string>?
        private bool AreListsEqual(IReadOnlyList<string>? list1, IReadOnlyList<string>? list2)
        {
            if (ReferenceEquals(list1, list2)) return true; // Same instance or both null
            if (list1 is null || list2 is null) return false; // One is null, the other isn't
            if (list1.Count != list2.Count) return false; // Different counts

            // SequenceEqual works with IEnumerable<T>, which IReadOnlyList<T> implements
            return list1.SequenceEqual(list2);
        }
        // 업데이트 감사 대상 필드 확인
        private bool ShouldAuditUpdate(Dictionary<string, object?> changes)
        {
            var importantFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "ApplicationKey", "ApplicationType", "OrganizationId", "Status", /* 다른 중요 필드 */ };
            return changes.Keys.Any(importantFields.Contains);
        }

        // 감사 대상 상태 변경 확인
        private bool IsImportantStatusChange(ApplicationStatus oldStatus, ApplicationStatus newStatus)
        {
            // Active 상태 변경 또는 Active로의 복귀는 중요
            return oldStatus != newStatus &&
                   (oldStatus == ApplicationStatus.Active || newStatus == ApplicationStatus.Active);
        }

        // 감사 대상 설정 키 확인
        private bool IsImportantSetting(string settingKey)
        {
            var importantSettings = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "ApiRateLimit", "MaxSessionDuration", "RequireApiKey", "SecurityLevel", /* 다른 중요 설정 */ };
            return importantSettings.Contains(settingKey);
        }

        // 다음 사용량 리셋 날짜 계산
        private DateTime CalculateNextResetDate(string resetType)
        {
            var now = _dateTimeProvider.UtcNow.Date; // 날짜 기준으로 계산
            return resetType.ToLowerInvariant() switch // ToLowerInvariant 사용
            {
                "daily" => now.AddDays(1),
                "weekly" => now.AddDays(7 - (int)now.DayOfWeek % 7), // 주의 시작을 일요일(0)로 가정
                "monthly" => new DateTime(now.Year, now.Month, 1).AddMonths(1),
                _ => now.AddDays(1) // 알 수 없는 타입은 기본값으로 다음 날
            };
        }

        #endregion
    }
}