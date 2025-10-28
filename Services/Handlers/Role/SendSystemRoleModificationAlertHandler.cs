// File: AuthHive.Auth/Services/Handlers/Role/SendSystemRoleModificationAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // SystemRoleModificationAttemptedEvent
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
    /// 시스템 역할 수정 시도 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendSystemRoleModificationAlertHandler :
        IDomainEventHandler<SystemRoleModificationAttemptedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendSystemRoleModificationAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendSystemRoleModificationAlertHandler(
            INotificationService notificationService,
            ILogger<SendSystemRoleModificationAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(SystemRoleModificationAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "TargetRoleId", @event.AggregateId.ToString() },
                    { "RoleName", @event.RoleName }, // ❗️ RoleName 사용
                    { "Action", @event.Action },
                    { "AttemptedBy", @event.AttemptedBy.ToString() },
                    { "IsAuthorized", @event.IsAuthorized.ToString() }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_SYSTEM_ROLE_MOD_ATTEMPT", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for system role modification attempt by {AttemptedBy}", @event.AttemptedBy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send system role modification alert for RoleId: {RoleId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}