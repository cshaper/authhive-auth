// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendAccountSuspensionNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountSuspendedEvent를 처리하는 핸들러입니다.
// 목적: 계정 일시 정지 발생 시 사용자에게 보안 알림을 즉시 발송합니다.
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
    /// <see cref="UserAccountSuspendedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 계정 정지 시 사용자에게 보안 알림을 즉시 발송합니다.
    /// </summary>
    public class SendAccountSuspensionNotificationHandler
        : IDomainEventHandler<UserAccountSuspendedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendAccountSuspensionNotificationHandler> _logger;

        public SendAccountSuspensionNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendAccountSuspensionNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 정지 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림 대상 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for suspension event.", @event.UserId);
                    return;
                }

                // 2. 정지 해제 예정 시간 표시 (SuspendedUntil이 있는 경우만)
                string suspendedUntilDisplay = @event.SuspendedUntil.HasValue 
                    ? @event.SuspendedUntil.Value.ToString("yyyy-MM-dd HH:mm UTC") 
                    : "indefinitely (contact support)"; // 영구 정지 혹은 무기한 정지 표시
                
                _logger.LogWarning(
                    "Sending Critical Alert: Account Suspension Notification to User {Email} (Reason: {Reason})",
                    user.Email, @event.SuspensionReason);

                // 3. 템플릿 변수 준비
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "User" },
                    { "SuspensionReason", @event.SuspensionReason },
                    { "SuspendedUntil", suspendedUntilDisplay },
                    { "SuspendedBy", @event.SuspendedByConnectedId?.ToString() ?? "System" }, // 정지 주체
                    { "SupportLink", "[[REPLACE_WITH_SUPPORT_LINK]]" } // 지원 링크는 템플릿에 필요
                };

                // 4. 알림 요청 생성 (Critical Security Alert)
                var notificationRequest = new NotificationSendRequest
                {
                    // ConnectedId 또는 UserId를 수신자로 사용
                    RecipientConnectedIds = @event.TriggeredBy.HasValue ? new List<Guid> { @event.TriggeredBy.Value } : new List<Guid> { @event.UserId },
                    
                    TemplateKey = "USER_ACCOUNT_SUSPENDED_CRITICAL", // 정지 보안 경고 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.Critical, // 최우선 순위
                    SendImmediately = true,
                    
                    EmailDetails = new EmailRequestDetails 
                    { 
                        ToEmail = user.Email,
                        DisableLogging = false // Critical Alert는 반드시 로깅되어야 함
                    }
                };

                // 5. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Account Suspension Critical Notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Account Suspension notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendAccountSuspensionNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
