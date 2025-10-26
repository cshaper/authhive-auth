// File: AuthHive.Auth/Services/Handlers/Permission/SendDangerousCombinationAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Permissions.Events; // DangerousPermissionCombinationDetectedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 위험한 권한 조합 감지 시 보안팀에 알림을 발송합니다.
    /// </summary>
    public class SendDangerousCombinationAlertHandler :
        IDomainEventHandler<DangerousPermissionCombinationDetectedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendDangerousCombinationAlertHandler> _logger;
        // TODO: 보안팀 연락처/ConnectedId 조회를 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendDangerousCombinationAlertHandler(
            INotificationService notificationService,
            ILogger<SendDangerousCombinationAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(DangerousPermissionCombinationDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 알림 대상: 시스템 관리자 또는 보안팀의 ConnectedId (가정)
                var securityTeamConnectedId = new Guid("{00000000-0000-0000-0000-000000000001}"); // 시스템 관리자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "TargetConnectedId", @event.ConnectedId.ToString() },
                    { "OrganizationId", @event.AggregateId.ToString() },
                    { "RiskLevel", @event.RiskLevel },
                    { "Scopes", string.Join(", ", @event.Scopes) },
                    { "Details", string.Join(" | ", @event.DangerousCombinations) }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { securityTeamConnectedId.ToString() }, 
                    TemplateKey = "SECURITY_DANGEROUS_PERMISSION_COMBINATION", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Security alert queued for dangerous permission combination for ConnectedId {ConnectedId}", @event.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send dangerous permission combination alert for ConnectedId: {ConnectedId}", @event.ConnectedId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}