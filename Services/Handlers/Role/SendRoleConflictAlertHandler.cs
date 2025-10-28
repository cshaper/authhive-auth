// File: AuthHive.Auth/Services/Handlers/Role/SendRoleConflictAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // RoleConflictDetectedEvent
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
    /// 역할 충돌 감지 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendRoleConflictAlertHandler :
        IDomainEventHandler<RoleConflictDetectedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendRoleConflictAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendRoleConflictAlertHandler(
            INotificationService notificationService,
            ILogger<SendRoleConflictAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleConflictDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "ConnectedId", @event.ConnectedId.ToString() },
                    { "ExistingRoleId", @event.ExistingRoleId.ToString() },
                    { "NewRoleId", @event.NewRoleId.ToString() },
                    { "ConflictType", @event.ConflictType },
                    { "ConflictDetails", string.Join(" | ", @event.ConflictDetails) },
                   { "TriggeredBy", @event.TriggeredBy.HasValue ? @event.TriggeredBy.Value.ToString() : "System/Unknown" }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId,
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() },
                    TemplateKey = "SECURITY_ROLE_CONFLICT_CRITICAL", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical alert queued for role conflict for ConnectedId {ConnectedId}", @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send role conflict alert for ConnectedId: {ConnectedId}", @event.ConnectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}