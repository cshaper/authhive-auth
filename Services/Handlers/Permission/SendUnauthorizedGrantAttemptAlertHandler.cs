// File: AuthHive.Auth/Services/Handlers/Permission/SendUnauthorizedGrantAttemptAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Permissions.Events; // UnauthorizedPermissionGrantAttemptedEvent
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
    /// 권한 없는 권한 부여 시도 시 보안팀에 알림을 발송합니다.
    /// </summary>
    public class SendUnauthorizedGrantAttemptAlertHandler :
        IDomainEventHandler<UnauthorizedPermissionGrantAttemptedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendUnauthorizedGrantAttemptAlertHandler> _logger;
        // TODO: 보안팀 연락처/ConnectedId 조회를 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendUnauthorizedGrantAttemptAlertHandler(
            INotificationService notificationService,
            ILogger<SendUnauthorizedGrantAttemptAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(UnauthorizedPermissionGrantAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "GranterId", @event.GranterConnectedId.ToString() },
                    { "TargetId", @event.TargetConnectedId.ToString() },
                    { "AppId", @event.AggregateId.ToString() },
                    { "GranterLevel", @event.GranterLevel.ToString() },
                    { "RequestedLevel", @event.RequestedLevel.ToString() }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_UNAUTHORIZED_GRANT_ATTEMPT", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Security alert queued for unauthorized grant attempt by {GranterId}", @event.GranterConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send unauthorized grant attempt alert for Granter: {GranterId}", @event.GranterConnectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}