// File: authhive.auth/services/handlers/User/Activity/LogUserActivityHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - ❗️ 확장 메서드 사용 최종본]
// ❗️ 내부 헬퍼 메서드 MergeDynamicMetadata를 삭제합니다.
// ❗️ 대신 DictionaryExtensions.MergeMetadata 확장 메서드를 사용합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Activity;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // ❗️ 확장 메서드에서 사용 안 하므로 필요 없을 수 있음 (확인 필요)
using System.Threading;
using System.Threading.Tasks;
 // ❗️ 확장 메서드 사용 위한 using 추가

namespace AuthHive.Auth.Handlers.User.Activity
{
    /// <summary>
    /// 사용자 활동을 기록하고, 플랜 기반 임계값을 검사하며, 중요 활동을 감사합니다.
    /// (제약 조건 1, 4, 6 적용)
    /// </summary>
    public class LogUserActivityHandler :
        IDomainEventHandler<ActivityLoggedEvent>,
        IService
    {
        private readonly ILogger<LogUserActivityHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IConnectedIdService _connectedIdService;

        private const string CACHE_KEY_PREFIX = "activity";

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogUserActivityHandler(
            ILogger<LogUserActivityHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IPlanRestrictionService planRestrictionService,
            IConnectedIdService connectedIdService)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _planRestrictionService = planRestrictionService;
            _connectedIdService = connectedIdService;
        }

        /// <summary>
        /// (한글 주석) 사용자 활동 기록 이벤트를 @event.RiskScore > 50 이상일떄 처리합니다.
        /// </summary>
        public async Task HandleAsync(ActivityLoggedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var dateKey = _dateTimeProvider.UtcNow.ToString("yyyy-MM-dd");
                var countKey = $"{CACHE_KEY_PREFIX}:count:{@event.UserId:N}:{dateKey}";
                var count = await _cacheService.IncrementAsync(countKey, 1, cancellationToken);
                if (count == 1) { await _cacheService.ExpireAsync(countKey, TimeSpan.FromHours(25), cancellationToken); }
                var threshold = await GetTenantThresholdAsync(@event, "daily_activity_limit", cancellationToken);
                if (count > threshold) { /* LogWarning */ }


                // 3. (한글 주석) 중요 활동 감사 로그 기록 (❗️ 확장 메서드 사용)
                if (@event.RiskScore > 50 || IsImportantActivity(@event.ActivityType))
                {
                    // (한글 주석) ❗️ 확장 메서드를 사용하도록 PrepareAuditMetadata 메서드를 수정합니다.
                    var activityData = PrepareAuditMetadataUsingExtension(@event);
                    await _auditService.LogActionAsync(
                        DetermineAuditActionType(@event.ActivityType),
                        @event.ActivityType.ToString(),
                        @event.ConnectedId,
                        resourceId: @event.ResourceId,
                        metadata: activityData, // ❗️ Dictionary 전달
                        cancellationToken: cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Activity logging processing failed for event {EventId}, User {UserId}", @event.EventId, @event.UserId);
            }
        }

        #region Helper Methods

        // GetTenantThresholdAsync, IsImportantActivity, DetermineAuditActionType 메서드는 변경 없음
        private async Task<int> GetTenantThresholdAsync(ActivityLoggedEvent @event, string thresholdKey, CancellationToken cancellationToken)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:threshold:{@event.UserId:N}:{thresholdKey}";
            const int defaultLimit = 10000;

            // 1. 캐시 조회 (문자열 사용)
            string? cachedLimitString = await _cacheService.GetStringAsync(cacheKey, cancellationToken);
            if (!string.IsNullOrEmpty(cachedLimitString) && int.TryParse(cachedLimitString, out int cachedLimit))
            {
                return cachedLimit;
            }

            // 2. OrgId 조회 (제약 1)
            Guid organizationId = Guid.Empty; // 👈 [CS0165 수정] 여기서 기본값으로 초기화합니다.
            try
            {
                var result = await _connectedIdService.GetByIdAsync(@event.ConnectedId, cancellationToken);
                if (!result.IsSuccess || result.Data == null || result.Data.OrganizationId == Guid.Empty)
                {
                    // (한글 주석) 조회 실패 시 예외를 던져 catch 블록으로 보냅니다.
                    throw new InvalidOperationException($"OrganizationId lookup failed for ConnectedId {@event.ConnectedId}.");
                }
                organizationId = result.Data.OrganizationId; // (한글 주석) 성공 시 여기서 값이 할당됩니다.
            }
            catch (Exception ex)
            {
                // (한글 주석) OrgId 조회 실패 시 기본 임계값을 반환하고 함수를 종료합니다.
                _logger.LogWarning(ex, "Failed to resolve OrganizationId from ConnectedId {ConnectedId}. Using default threshold.", @event.ConnectedId);
                return defaultLimit;
            }

            // (한글 주석) 이 코드 줄에 도달했다면, organizationId는 try 블록에서 유효한 값으로 할당되었음이 보장됩니다.
            // (한글 주석) (만약 실패했다면 이전 catch에서 이미 return 되었을 것입니다.)

            // 3. PlanService 조회 (제약 6)
            int limitValue;
            try
            {
                // (한글 주석) 이제 organizationId는 할당이 보장되므로 여기서 사용해도 안전합니다.
                limitValue = await _planRestrictionService.GetNumericLimitAsync(
          organizationId, // 👈 오류 없이 사용 가능
                    thresholdKey,
          defaultLimit,
          cancellationToken);
            }
            catch (Exception planEx)
            {
                _logger.LogError(planEx, "Failed to get threshold '{ThresholdKey}' from PlanService for Org {OrganizationId}. Using default.", thresholdKey, organizationId);
                limitValue = defaultLimit;
            }

            // 4. 캐시 저장 (문자열 사용)
            try
            {
                await _cacheService.SetStringAsync(cacheKey, limitValue.ToString(), TimeSpan.FromHours(1), cancellationToken);
            }
            catch (Exception cacheEx)
            {
                _logger.LogWarning(cacheEx, "Failed to set threshold in cache for key {CacheKey}", cacheKey);
            }
            return limitValue;
        }
        /// <summary>
        /// (한글 주석) ❗️ 확장 메서드를 사용하여 감사 메타데이터를 준비하는 수정된 헬퍼 메서드
        /// </summary>
        private Dictionary<string, object> PrepareAuditMetadataUsingExtension(ActivityLoggedEvent @event)
        {
            var activityData = new Dictionary<string, object>
            {
                ["type"] = @event.ActivityType.ToString(),
                ["timestamp"] = @event.OccurredAt,
                ["successful"] = @event.IsSuccessful,
                ["risk_score"] = @event.RiskScore,
                ["resource_id"] = @event.ResourceId ?? "N/A",
                ["resource_type"] = @event.ResourceType ?? "N/A",
                ["description"] = @event.ActivityDescription ?? "N/A"
            };
            // (한글 주석) ❗️ 확장 메서드를 호출하여 BaseEvent의 Metadata를 병합합니다.
            activityData.MergeMetadata(@event.Metadata, _logger); // ❗️ 수정됨
            return activityData;
        }

        // (한글 주석) ❗️ 클래스 내부에 있던 MergeDynamicMetadata 헬퍼 메서드는 삭제되었습니다.
        // private void MergeDynamicMetadata(...) { ... } // <--- 삭제

        private bool IsImportantActivity(UserActivityType activityType)
        {
            // ... (이전 코드와 동일) ...
            return activityType == UserActivityType.LoginFailed ||
                   activityType == UserActivityType.PasswordChanged ||
                   activityType == UserActivityType.AccountLocked ||
                   activityType == UserActivityType.RoleAssigned ||
                   activityType == UserActivityType.PermissionGranted;
        }

        private AuditActionType DetermineAuditActionType(UserActivityType activityType)
        {
            // ... (이전 코드와 동일) ...
            return activityType switch
            {
                UserActivityType.Login => AuditActionType.Login,
                UserActivityType.LoginFailed => AuditActionType.FailedLogin,
                UserActivityType.PasswordChanged => AuditActionType.PasswordChange,
                UserActivityType.AccountLocked => AuditActionType.Blocked,
                UserActivityType.RoleAssigned => AuditActionType.Grant,
                UserActivityType.PermissionGranted => AuditActionType.Grant,
                UserActivityType.FileDownload => AuditActionType.Read,
                UserActivityType.FileUpload => AuditActionType.Create,
                _ => AuditActionType.Read
            };
        }
        #endregion

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return IsEnabled &&
                   await _cacheService.IsHealthyAsync(cancellationToken) &&
                   await _planRestrictionService.IsHealthyAsync(cancellationToken) &&
                   await _connectedIdService.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}