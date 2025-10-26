// File: AuthHive.Auth/Services/Handlers/Authentication/Password/SendPasswordResetEmailHandler.cs
using AuthHive.Core.Enums.Infra.UserExperience;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events;
// [수정] CS0246: EmailRequest -> NotificationSendRequest 사용
using AuthHive.Core.Models.Infra.UserExperience.Requests; 
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Password
{
    /// <summary>
    /// 비밀번호 재설정 요청 이벤트를 받아 사용자에게 재설정 이메일을 발송합니다.
    /// </summary>
    public class SendPasswordResetEmailHandler :
        IDomainEventHandler<PasswordResetRequestedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SendPasswordResetEmailHandler> _logger;

        public int Priority => 20; 
        public bool IsEnabled => true;

        public SendPasswordResetEmailHandler(
            INotificationService notificationService,
            IConfiguration configuration,
            ILogger<SendPasswordResetEmailHandler> logger)
        {
            _notificationService = notificationService;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task HandleAsync(PasswordResetRequestedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var resetUrlTemplate = _configuration["AuthHive:Urls:PasswordResetUrl"];
                if (string.IsNullOrWhiteSpace(resetUrlTemplate))
                {
                    _logger.LogCritical("PasswordResetUrl is not configured in AuthHive:Urls settings. Cannot send reset email.");
                    return;
                }

                var resetUrl = resetUrlTemplate.Replace("{token}", @event.ResetToken);

                var parameters = new Dictionary<string, string>
                {
                    { "displayName", @event.DisplayName ?? @event.Email },
                    { "resetUrl", resetUrl }
                };

                // [수정] CS0246: EmailRequest 대신 NotificationSendRequest DTO 사용
                // (이 DTO가 UserId, TemplateId, Parameters를 속성으로 갖는다고 가정)
           // [수정] NotificationSendRequest DTO의 올바른 속성 사용
                var notificationRequest = new NotificationSendRequest
                {
                    // 수신자 유형을 'User'로 지정
                    RecipientType = RecipientType.User,
                    // 'UserId' 대신 'RecipientIdentifiers'에 사용자 ID 목록 전달
                    RecipientIdentifiers = new List<string> { @event.AggregateId.ToString() },
                    // 'TemplateId' 대신 'TemplateKey' 사용
                    TemplateKey = "PasswordResetTemplate", // 알림 서비스에 정의된 템플릿 키 (가정)
                    // 'Parameters' 대신 'TemplateVariables' 사용
                    TemplateVariables = parameters,
                    // 이메일은 이 템플릿 키의 기본 채널로 설정되어 있다고 가정합니다.
                    // 필요시 Channels = new List<NotificationChannel> { NotificationChannel.Email } 추가
                    Priority = NotificationPriority.High, // 비밀번호 재설정은 높은 우선순위
                    SendImmediately = true // 즉시 발송
                };

                // [수정] CS1061: SendEmailAsync 대신 QueueNotificationAsync 메서드 사용
                await _notificationService.QueueNotificationAsync(
                    notificationRequest, 
                    cancellationToken
                );

                _logger.LogInformation(
                    "Successfully queued password reset email for User {UserId} to {Email}.",
                    @event.AggregateId, @event.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email for User {UserId}: {EventId}", 
                    @event.AggregateId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}