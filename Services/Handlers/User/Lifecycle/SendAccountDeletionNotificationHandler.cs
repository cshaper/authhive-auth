// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendAccountDeletionNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountDeletedEvent를 처리하는 핸들러입니다.
// 목적: 사용자에게 계정 삭제 완료 및 데이터 정책 안내 알림을 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest, EmailRequestDetails
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using Microsoft.Extensions.Logging;

// (참고) 계정 삭제 시점에는 UserRepository를 통해 User 정보를 조회하기 어려울 수 있으나, 
// 이메일 주소는 이벤트 페이로드에 포함되어야 발송 가능합니다. 
// 여기서는 알림 대상 이메일이 이벤트에 포함되어 있다고 가정하고 UserRepository 주입을 제거합니다.

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountDeletedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 사용자에게 계정 삭제 완료 알림을 발송합니다.
    /// </summary>
    public class SendAccountDeletionNotificationHandler
        : IDomainEventHandler<UserAccountDeletedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly ILogger<SendAccountDeletionNotificationHandler> _logger;

        public SendAccountDeletionNotificationHandler(
            INotificationService notificationService,
            ILogger<SendAccountDeletionNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 삭제 이벤트를 처리하여 최종 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            // (가정) 삭제 알림을 보낼 이메일 주소는 이벤트에 포함되어 있거나,
            //        특정 템플릿 로직이 UserId만으로 처리할 수 있다고 가정합니다.
            //        (실제로는 이벤트 발생 전 이메일 주소를 캡처하는 것이 안전합니다.)
            const string fallbackEmail = "[[USER_EMAIL_FALLBACK]]"; // 이벤트에서 이메일을 읽어와야 합니다.
            string targetEmail = @event.Email ?? fallbackEmail; 

            try
            {
                _logger.LogCritical( // Critical 이벤트 알림
                    "Sending Critical Alert: Account Deletion Notification to {Email} (Reason: {Reason})",
                    targetEmail, @event.DeletionReason);

                // 1. 템플릿 변수 준비
                // (가정) 이벤트 모델에 Email 속성이 추가되어 있다고 가정합니다.
                // (가정) 데이터 영구 삭제 예정일(RetentionDate)은 이벤트에 포함되어 있거나, 여기서 계산합니다.
                DateTime retentionDate = @event.DeletedAt.AddDays(90); 
                
                var templateVariables = new Dictionary<string, string>
                {
                    { "DeletionReason", @event.DeletionReason ?? "" },
                    { "IsPermanentDeletion", @event.IsPermanentDeletion.ToString() },
                    { "DeletionDate", @event.DeletedAt.ToString("yyyy-MM-dd HH:mm UTC") },
                    { "RetentionDate", retentionDate.ToString("yyyy-MM-dd") }, // 데이터 영구 삭제 예정일
                    { "SupportLink", "[[REPLACE_WITH_SUPPORT_LINK]]" }
                };

                // 2. 알림 요청 생성
                var notificationRequest = new NotificationSendRequest
                {
                    // RecipientConnectedIds는 삭제되었으므로 UserId를 사용하거나, 알림 시스템이 이메일을 직접 사용하도록 설정합니다.
                    RecipientConnectedIds = new List<Guid> { @event.UserId }, 
                    
                    TemplateKey = "USER_ACCOUNT_DELETED_FINAL_NOTICE", // 최종 삭제 알림 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.Critical, // 최우선 순위
                    SendImmediately = true,
                    
                    EmailDetails = new EmailRequestDetails 
                    { 
                        ToEmail = targetEmail,
                        DisableLogging = false // Critical Alert는 반드시 로깅되어야 함
                    }
                };

                // 3. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Account Deletion Final Notice sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendAccountDeletionNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
