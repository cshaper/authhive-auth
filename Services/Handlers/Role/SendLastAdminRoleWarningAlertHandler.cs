// File: AuthHive.Auth/Services/Handlers/Role/SendLastAdminRoleWarningAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // LastAdminRoleWarningEvent
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
    /// 마지막 관리자 역할 관련 경고 시 보안팀과 조직 관리자에게 알림을 발송합니다.
    /// </summary>
    public class SendLastAdminRoleWarningAlertHandler :
        IDomainEventHandler<LastAdminRoleWarningEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendLastAdminRoleWarningAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendLastAdminRoleWarningAlertHandler(
            INotificationService notificationService,
            ILogger<SendLastAdminRoleWarningAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(LastAdminRoleWarningEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.TriggeredBy ?? @event.ConnectedId;

            try
            {
                // 알림 대상: 1. 보안팀 (ConnectedId: {0000..0001}), 2. 현재 작업 시도자 (ConnectedId)
                var securityTeamId = new Guid("{00000000-0000-0000-0000-000000000001}"); 
                var recipients = new List<string> { securityTeamId.ToString(), initiator.ToString() }; 
                
                var templateVariables = new Dictionary<string, string>
                {
                    { "OrganizationId", organizationId.ToString() },
                    { "ActionAttempted", @event.Action },
                    { "RoleId", @event.RoleId.ToString() },
                    { "AttemptedBy", initiator.ToString() },
                    { "RemainingAdmins", @event.RemainingAdmins.ToString() }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = recipients, 
                    TemplateKey = "SECURITY_LAST_ADMIN_WARNING", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security warning alert queued for Org {OrgId}", organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send last admin role warning alert for Org: {OrgId}", organizationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}