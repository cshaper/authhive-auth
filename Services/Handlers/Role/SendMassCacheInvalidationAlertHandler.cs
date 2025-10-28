// File: AuthHive.Auth/Services/Handlers/Role/SendMassCacheInvalidationAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // MassRoleCacheInvalidationEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 대규모 캐시 무효화 발생 시 성능 담당팀에 알림을 발송합니다.
    /// (특정 임계치 초과 시에만 발송하도록 로직 추가 가능)
    /// </summary>
    public class SendMassCacheInvalidationAlertHandler :
        IDomainEventHandler<MassRoleCacheInvalidationEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendMassCacheInvalidationAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendMassCacheInvalidationAlertHandler(
            INotificationService notificationService,
            ILogger<SendMassCacheInvalidationAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(MassRoleCacheInvalidationEvent @event, CancellationToken cancellationToken = default)
        {
            // 임계치 체크: 1000명 이상의 사용자에게 영향을 미치는 경우에만 알림
            if (@event.AffectedConnectedIds < 1000)
            {
                _logger.LogDebug("Skipping mass cache invalidation alert. Affected users below threshold.");
                return;
            }

            try
            {
                var devOpsTeamId = new Guid("{00000000-0000-0000-0000-000000000005}"); // 성능/DevOps 담당자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "RoleId", @event.AggregateId.ToString() },
                    { "OrganizationId", @event.OrganizationId?.ToString() ?? "N/A" },
                    { "AffectedUsers", @event.AffectedConnectedIds.ToString() },
                    { "AffectedSessions", @event.AffectedSessions.ToString() },
                    { "Reason", @event.InvalidationReason },
                    { "TriggeredBy", @event.TriggeredBy.HasValue ? @event.TriggeredBy.Value.ToString() : "System/Unknown" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { devOpsTeamId.ToString() }, 
                    TemplateKey = "PERFORMANCE_MASS_CACHE_INVALIDATION", // 성능 경고 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Low, // Low Priority 이벤트에 대한 알림은 Low
                    SendImmediately = false // 비동기/배치 처리 선호
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Performance alert queued for mass cache invalidation for RoleId {RoleId}", @event.AggregateId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send mass cache invalidation alert for RoleId: {RoleId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}