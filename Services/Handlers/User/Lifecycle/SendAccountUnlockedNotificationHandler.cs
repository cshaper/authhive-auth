// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendAccountUnlockedNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountUnlockedEvent를 처리하는 핸들러입니다.
// 목적: 계정 잠금 해제 발생 시 사용자에게 알림을 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest, EmailRequestDetails
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountUnlockedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 계정 잠금 해제 시 사용자에게 알림을 발송합니다.
    /// </summary>
    public class SendAccountUnlockedNotificationHandler
        : IDomainEventHandler<UserAccountUnlockedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendAccountUnlockedNotificationHandler> _logger;

        public SendAccountUnlockedNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendAccountUnlockedNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 잠금 해제 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림 대상 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for unlocked event.", @event.UserId);
                    return;
                }
                
                // 2. 알림 발송 로깅
                _logger.LogWarning( // 잠금 해제는 보안 상태 변경이므로 Warning 레벨로 로깅
                    "Sending Security Alert: Account Unlocked Notification to User {Email} (Reason: {Reason}, Method: {Method})",
                    user.Email, @event.UnlockReason, @event.UnlockMethod);

                // 3. 템플릿 변수 준비
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "User" },
                    { "UnlockReason", @event.UnlockReason },
                    { "UnlockMethod", @event.UnlockMethod },
                    { "UnlockedAt", @event.UnlockedAt.ToString("o") }, // ISO 8601
                    { "IpAddress", @event.ClientIpAddress ?? "Unknown" },
                    { "SupportLink", "[[REPLACE_WITH_SUPPORT_LINK]]" } 
                };

                // 4. 알림 요청 생성
                var notificationRequest = new NotificationSendRequest
                {
                    // 행위자(TriggeredBy)가 있다면 그 ConnectedId를 수신자로 사용 (시스템이 보낸 경우)
                    RecipientConnectedIds = @event.TriggeredBy.HasValue ? new List<Guid> { @event.TriggeredBy.Value } : new List<Guid> { @event.UserId },
                    
                    TemplateKey = "USER_ACCOUNT_UNLOCKED_ALERT", // 잠금 해제 알림 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.High, // 보안 알림은 중요도가 높음
                    SendImmediately = true,
                    
                    EmailDetails = new EmailRequestDetails 
                    { 
                        ToEmail = user.Email,
                        DisableLogging = false // 보안 관련 알림은 반드시 로깅되어야 함
                    }
                };

                // 5. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Account Unlocked Notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Account Unlocked notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendAccountUnlockedNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
