// File: AuthHive.Auth/Services/Handlers/Permission/SendPermissionAnomalyAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionAnomalyDetectedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 사용 이상 패턴 감지 시 보안팀에 알림을 발송합니다.
    /// </summary>
    public class SendPermissionAnomalyAlertHandler :
        IDomainEventHandler<PermissionAnomalyDetectedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendPermissionAnomalyAlertHandler> _logger;
        // TODO: 알림 대상을 조회하기 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendPermissionAnomalyAlertHandler(
            INotificationService notificationService,
            ILogger<SendPermissionAnomalyAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionAnomalyDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "ConnectedId", @event.ConnectedId.ToString() },
                    { "OrganizationId", @event.AggregateId.ToString() },
                    { "AnomalyType", @event.AnomalyType },
                    { "Details", @event.Details },
                    { "LookbackDays", @event.LookbackDays.ToString() }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_PERMISSION_ANOMALY", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.High,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Security alert queued for permission anomaly for ConnectedId {ConnectedId}", @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send permission anomaly alert for ConnectedId: {ConnectedId}", @event.ConnectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}