// File: AuthHive.Auth/Services/Handlers/Role/SendRoleHierarchyPerformanceAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // RoleHierarchyPerformanceIssueEvent
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
    /// 역할 계층 구조 성능 문제 발생 시 DevOps 담당자에게 알림을 발송합니다.
    /// </summary>
    public class SendRoleHierarchyPerformanceAlertHandler :
        IDomainEventHandler<RoleHierarchyPerformanceIssueEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendRoleHierarchyPerformanceAlertHandler> _logger;

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendRoleHierarchyPerformanceAlertHandler(
            INotificationService notificationService,
            ILogger<SendRoleHierarchyPerformanceAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleHierarchyPerformanceIssueEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;

            try
            {
                var devOpsTeamId = new Guid("{00000000-0000-0000-0000-000000000005}"); // DevOps 담당자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "RoleId", @event.AggregateId.ToString() },
                    { "OrganizationId", organizationId.ToString() },
                    { "Depth", @event.HierarchyDepth.ToString() },
                    { "Nodes", @event.TotalNodes.ToString() },
                    { "QueryTime", @event.QueryTimeMs.ToString() },
                    { "Impact", @event.PerformanceImpact }
                };

                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { devOpsTeamId.ToString() }, 
                    TemplateKey = "PERFORMANCE_ROLE_HIERARCHY_ISSUE", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Normal, // 시스템 성능 이슈는 Medium/High
                    SendImmediately = true 
                };

                await _notificationService.QueueNotificationAsync(notificationRequest, cancellationToken);
                _logger.LogInformation("Performance alert queued for Role Hierarchy Issue for Org {OrgId}", organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send performance alert for Role Hierarchy Issue for Org: {OrgId}", organizationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}