// File: AuthHive.Auth/Services/Handlers/Role/SendRoleAuditRequiredAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // RoleAuditRequiredEvent
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
    /// 역할 감사 요구 이벤트 발생 시 보안팀 또는 승인 담당자에게 알림을 발송합니다.
    /// </summary>
    public class SendRoleAuditRequiredAlertHandler :
        IDomainEventHandler<RoleAuditRequiredEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendRoleAuditRequiredAlertHandler> _logger;
        // TODO: 승인 담당자 ConnectedId 조회를 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendRoleAuditRequiredAlertHandler(
            INotificationService notificationService,
            ILogger<SendRoleAuditRequiredAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleAuditRequiredEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 알림 대상: 승인 담당자 (ConnectedId 가정)
                var approvalTeamId = new Guid("{00000000-0000-0000-0000-000000000006}"); 

                var templateVariables = new Dictionary<string, string>
                {
                    { "RoleId", @event.RoleId.ToString() },
                    { "RoleName", @event.RoleName },
                    { "OperationType", @event.OperationType },
                    { "InitiatorId", @event.InitiatorConnectedId.ToString() },
                    { "Reason", @event.AuditReason },
                    { "RequiresApproval", @event.RequiresExternalApproval.ToString() }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { approvalTeamId.ToString() }, 
                    TemplateKey = "ROLE_AUDIT_APPROVAL_REQUIRED", // 감사/승인 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical alert queued for Role Audit Required: Role {RoleId}", @event.RoleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send role audit required alert for Role: {RoleId}", @event.RoleId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}