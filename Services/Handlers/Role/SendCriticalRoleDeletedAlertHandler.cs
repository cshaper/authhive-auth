// File: AuthHive.Auth/Services/Handlers/Role/SendCriticalRoleDeletedAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // CriticalRoleDeletedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 중요 역할 삭제 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendCriticalRoleDeletedAlertHandler :
        IDomainEventHandler<CriticalRoleDeletedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendCriticalRoleDeletedAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendCriticalRoleDeletedAlertHandler(
            INotificationService notificationService,
            ILogger<SendCriticalRoleDeletedAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(CriticalRoleDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "RoleName", @event.RoleName },
                    { "RoleId", @event.AggregateId.ToString() },
                    { "DeletedBy", @event.DeletedBy.ToString() },
                    { "AffectedUsers", @event.AffectedUsers.ToString() },
                    { "ReplacementRoleId", @event.ReplacementRoleId?.ToString() ?? "None" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_CRITICAL_ROLE_DELETED", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for deleted Role {RoleName}", @event.RoleName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send critical role deletion alert for Role: {RoleName}", @event.RoleName);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}