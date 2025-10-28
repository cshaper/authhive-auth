// File: AuthHive.Auth/Services/Handlers/Role/SendMemberLimitNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Role.Events; // MemberLimitReachedEvent
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
    /// 멤버 수 한도 초과 시 조직 관리자 및 영업팀에 알림을 발송합니다.
    /// </summary>
    public class SendMemberLimitNotificationHandler :
        IDomainEventHandler<MemberLimitReachedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendMemberLimitNotificationHandler> _logger;
        // TODO: 조직 관리자 및 영업팀 ConnectedId 조회를 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendMemberLimitNotificationHandler(
            INotificationService notificationService,
            ILogger<SendMemberLimitNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(MemberLimitReachedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;

            try
            {
                // 알림 대상: 조직 관리자 및 영업팀 ConnectedId (가정)
                var adminConnectedId = new Guid("{00000000-0000-0000-0000-000000000002}"); 
                var salesConnectedId = new Guid("{00000000-0000-0000-0000-000000000003}"); 

                var templateVariables = new Dictionary<string, string>
                {
                    { "OrganizationId", organizationId.ToString() },
                    { "PlanKey", @event.PlanKey },
                    { "CurrentMembers", @event.CurrentMembers.ToString() },
                    { "MemberLimit", @event.MemberLimit.ToString() },
                    { "AttemptedBy", @event.AttemptedBy.ToString() }
                };

                // 1. 조직 관리자 알림 (회원 추가 실패 및 업그레이드 권유)
                var adminRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { adminConnectedId.ToString() }, 
                    TemplateKey = "BUSINESS_MEMBER_LIMIT_ADMIN_ALERT", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.High,
                    SendImmediately = true
                };

                // 2. 영업/CRM 시스템 알림 (업그레이드 유도 기회)
                var salesRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { salesConnectedId.ToString() }, 
                    TemplateKey = "BUSINESS_MEMBER_LIMIT_SALES_ALERT", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Normal,
                    SendImmediately = false 
                };

                await Task.WhenAll(
                    _notificationService.QueueNotificationAsync(adminRequest, cancellationToken),
                    _notificationService.QueueNotificationAsync(salesRequest, cancellationToken)
                );
                
                _logger.LogInformation("Member limit reached notification queued for Organization {OrgId}", organizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send member limit notification for Organization: {OrganizationId}", organizationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}