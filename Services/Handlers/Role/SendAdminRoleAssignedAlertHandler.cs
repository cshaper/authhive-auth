// File: AuthHive.Auth/Services/Handlers/Role/SendAdminRoleAssignedAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // AdminRoleAssignedEvent
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
    /// 관리자 역할 할당 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendAdminRoleAssignedAlertHandler :
        IDomainEventHandler<AdminRoleAssignedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendAdminRoleAssignedAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendAdminRoleAssignedAlertHandler(
            INotificationService notificationService,
            ILogger<SendAdminRoleAssignedAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(AdminRoleAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "TargetConnectedId", @event.ConnectedId.ToString() },
                    { "RoleName", @event.RoleName },
                    { "PermissionLevel", @event.PermissionLevel.ToString() },
                    { "AssignedBy", @event.AssignedBy.ToString() },
                    { "ExpiresAt", @event.ExpiresAt?.ToString() ?? "Never" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_ADMIN_ROLE_ASSIGNED", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for Admin Role assignment to {ConnectedId}", @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send admin role assignment alert for ConnectedId: {ConnectedId}", @event.ConnectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}