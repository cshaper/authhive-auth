// File: AuthHive.Auth/Services/Handlers/Role/SendCriticalRoleAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // CriticalRoleCreatedEvent
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
    /// 중요 역할 생성 시 보안팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendCriticalRoleAlertHandler :
        IDomainEventHandler<CriticalRoleCreatedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendCriticalRoleAlertHandler> _logger;
        // TODO: 알림 대상을 조회하기 위한 서비스 주입 필요 (예: 보안팀 목록)

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendCriticalRoleAlertHandler(
            INotificationService notificationService,
            ILogger<SendCriticalRoleAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(CriticalRoleCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "RoleName", @event.RoleName },
                    { "RoleId", @event.AggregateId.ToString() },
                    { "CreatedBy", @event.CreatedBy.ToString() },
                    { "Scope", @event.Scope.ToString() },
                    { "CriticalPermissions", string.Join(", ", @event.CriticalPermissions) }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, // 보안팀 대상
                    TemplateKey = "SECURITY_CRITICAL_ROLE_CREATED", // Critical 알림 템플릿
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Critical security alert queued for Role {RoleName}", @event.RoleName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send critical role alert for Role: {RoleName}", @event.RoleName);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}