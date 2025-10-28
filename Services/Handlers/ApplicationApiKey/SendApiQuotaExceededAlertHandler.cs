// File: AuthHive.Auth/Services/Handlers/ApplicationApi/SendApiQuotaExceededAlertHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiQuotaExceededEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApi
{
    /// <summary>
    /// API 할당량 초과 시 조직 관리자 및 영업팀에 Critical 알림을 발송합니다.
    /// </summary>
    public class SendApiQuotaExceededAlertHandler :
        IDomainEventHandler<ApplicationApiQuotaExceededEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendApiQuotaExceededAlertHandler> _logger;
        // TODO: 조직 관리자 및 영업팀 ConnectedId 조회를 위한 서비스 주입 필요

        public int Priority => 30; // 알림 핸들러
        public bool IsEnabled => true;

        public SendApiQuotaExceededAlertHandler(
            INotificationService notificationService,
            ILogger<SendApiQuotaExceededAlertHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiQuotaExceededEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;

            try
            {
                var adminConnectedId = new Guid("{00000000-0000-0000-0000-000000000002}"); // 조직 관리자 ID 가정
                var salesConnectedId = new Guid("{00000000-0000-0000-0000-000000000003}"); // 영업 담당자 ID 가정

                var templateVariables = new Dictionary<string, string>
                {
                    { "ApplicationId", applicationId.ToString() },
                    { "OrganizationId", organizationId.ToString() },
                    { "QuotaType", @event.QuotaType },
                    { "BlockedAt", @event.BlockedAt.ToString("o") }
                };

                // 1. 조직 관리자 알림 (서비스 중단 고지)
                var adminRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { adminConnectedId.ToString() }, 
                    TemplateKey = "APPLICATION_API_QUOTA_EXCEEDED_ADMIN", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Critical,
                    SendImmediately = true
                };

                // 2. 영업/CRM 시스템 알림 (업그레이드 유도 기회)
                var salesRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.ConnectedId, 
                    RecipientIdentifiers = new List<string> { salesConnectedId.ToString() }, 
                    TemplateKey = "APPLICATION_API_QUOTA_EXCEEDED_SALES", 
                    TemplateVariables = templateVariables,
                    Priority = NotificationPriority.Normal,
                    SendImmediately = true 
                };

                await Task.WhenAll(
                    _notificationService.QueueNotificationAsync(adminRequest, cancellationToken),
                    _notificationService.QueueNotificationAsync(salesRequest, cancellationToken)
                );
                
                _logger.LogInformation("API Quota Exceeded notification queued for AppId {AppId}", applicationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send API Quota Exceeded notification for AppId: {AppId}", applicationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}