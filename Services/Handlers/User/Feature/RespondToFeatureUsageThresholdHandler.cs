// File: authhive.auth/services/handlers/User/Features/RespondToFeatureUsageThresholdHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IEventBus 사용 및 IDomainEventHandler/IService 구현으로 리팩토링했습니다.
// 목적: 기능 사용량 임계값 도달 시, 명시적인 후속 이벤트를 발행(Publish)합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Interfaces.Infra; // IEventBus, IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Features; // Source Event
// (참고) 아래 이벤트들은 Core 모델에 신규 정의가 필요합니다.
// using AuthHive.Core.Models.User.Events.System; 
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// 기능 사용량 임계값 도달 시 대응합니다. (감사 로그, 캐시, ❗️IEventBus 발행)
    /// </summary>
    public class RespondToFeatureUsageThresholdHandler : 
        IDomainEventHandler<FeatureUsageThresholdReachedEvent>, // ❗️ 수정됨
        IService
    {
        private readonly ILogger<RespondToFeatureUsageThresholdHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEventBus _eventBus; // 제약 조건: IEventBus 사용

        private const string CACHE_KEY_PREFIX = "feature";

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;
        
        public RespondToFeatureUsageThresholdHandler(
            ILogger<RespondToFeatureUsageThresholdHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IEventBus eventBus)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _eventBus = eventBus;
        }

        /// <summary>
        /// (한글 주석) 기능 사용량 임계값 도달 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(FeatureUsageThresholdReachedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var usageData = new Dictionary<string, object>
                {
                    ["feature"] = @event.FeatureKey,
                    ["type"] = @event.ThresholdType,
                    ["current"] = @event.CurrentValue,
                    ["threshold"] = @event.ThresholdValue,
                    ["percentage"] = (@event.CurrentValue * 100.0) / @event.ThresholdValue,
                    ["severity"] = @event.CurrentValue >= @event.ThresholdValue
                                     ? AuditEventSeverity.Warning.ToString()
                                     : AuditEventSeverity.Info.ToString()
                };

                // (한글 주석) 현재 사용량 정보를 캐시에 업데이트합니다.
                var usageKey = $"{CACHE_KEY_PREFIX}:usage:{@event.UserId:N}:{@event.FeatureKey}:{@event.ThresholdType}";
                await _cacheService.SetAsync(usageKey, usageData, TimeSpan.FromHours(1), cancellationToken);

                // (한글 주석) 임계값을 초과한 경우에만 후속 조치를 진행합니다.
                if (@event.CurrentValue >= @event.ThresholdValue)
                {
                    // 1. 감사 로그
                    await _auditService.LogActionAsync(
                        AuditActionType.Execute,
                        "USAGE_THRESHOLD_EXCEEDED",
                        @event.UserId,
                        resourceId: @event.FeatureKey,
                        metadata: usageData);
                    
                    // 2. ❗️ IEventBus로 후속 조치 발행 (리팩토링된 핵심)
                    var exceedPercentage = ((@event.CurrentValue - @event.ThresholdValue) * 100.0) / @event.ThresholdValue;
                    await HandleThresholdExceededAsync(@event, exceedPercentage, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Usage threshold processing failed for feature {Feature}, user {UserId}",
                    @event.FeatureName, @event.UserId);
            }
        }

        /// <summary>
        /// (한글 주석) ❗️ IEventBus를 사용하여 초과 수준에 따라 다른 이벤트를 발행합니다.
        /// </summary>
        private async Task HandleThresholdExceededAsync(FeatureUsageThresholdReachedEvent @event, double exceedPercentage, CancellationToken cancellationToken)
        {
            string reason = $"Exceeded by {exceedPercentage:F1}%";
            
            // 50% 이상 초과 시: 기능 차단 이벤트 발행
            if (exceedPercentage > 50)
            {
                _logger.LogError("Feature {Feature} blocked for user {UserId} - {Reason}",
                    @event.FeatureName, @event.UserId, reason);
                    
                // (한글 주석) ❗️ 캐시에 플래그를 심는 대신, 명시적인 '차단' 이벤트를 발행합니다.
                // (가정) FeatureAccessBlockedEvent는 Core에 정의되어 있어야 합니다.
                // var blockEvent = new FeatureAccessBlockedEvent(
                //     @event.UserId,
                //     @event.ConnectedId,
                //     @event.OrganizationId,
                //     @event.FeatureKey,
                //     reason,
                //     @event.CorrelationId
                // );
                // await _eventBus.PublishAsync(blockEvent, cancellationToken);
            }
            // 20% 이상 초과 시: 기능 조절(Throttle) 이벤트 발행
            else if (exceedPercentage > 20)
            {
                 _logger.LogWarning("Feature {Feature} throttled for user {UserId} - {Reason}",
                    @event.FeatureName, @event.UserId, reason);

                // (한글 주석) ❗️ '속도 저하' 이벤트를 발행합니다.
                // (가정) FeatureAccessThrottledEvent는 Core에 정의되어 있어야 합니다.
                // var throttleEvent = new FeatureAccessThrottledEvent(
                //     @event.UserId,
                //     @event.ConnectedId,
                //     @event.OrganizationId,
                //     @event.FeatureKey,
                //     reason,
                //     "medium", // Throttle Level
                //     @event.CorrelationId
                // );
                // await _eventBus.PublishAsync(throttleEvent, cancellationToken);
            }
            else
            {
                 _logger.LogWarning("Feature {Feature} exceeded for user {UserId} - {Reason}",
                    @event.FeatureName, @event.UserId, reason);
            }
            
            // (한글 주석) 현재는 가상 이벤트이므로 Task.CompletedTask를 사용합니다.
            await Task.CompletedTask;
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // (가정) IEventBus가 IService를 구현
            return IsEnabled && 
                   await _cacheService.IsHealthyAsync(cancellationToken) &&
                   await _eventBus.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}