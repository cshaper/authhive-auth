// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendAccountLockedNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountLockedEvent를 처리하는 핸들러입니다.
// 목적: 계정 잠금 발생 시 사용자에게 보안 알림을 즉시 발송합니다.
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
    /// <see cref="UserAccountLockedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 계정 잠금 시 사용자에게 보안 알림을 즉시 발송합니다.
    /// </summary>
    public class SendAccountLockedNotificationHandler
        : IDomainEventHandler<UserAccountLockedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendAccountLockedNotificationHandler> _logger;

        public SendAccountLockedNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendAccountLockedNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 잠금 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountLockedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림 대상 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for locked event.", @event.UserId);
                    return;
                }

                // 2. 잠금 해제 예정 시간 표시 (수정: Nullable DateTime? 타입에 맞춰 안전하게 처리)
                string lockedUntilDisplay = @event.LockedUntil.HasValue 
                    ? @event.LockedUntil.Value.ToString("yyyy-MM-dd HH:mm UTC") 
                    : "indefinitely"; // Null이면 영구 잠금 표시
                
                _logger.LogWarning(
                    "Sending Critical Alert: Account Locked Notification to User {Email} (Reason: {Reason})",
                    user.Email, @event.LockReason);

                // 3. 템플릿 변수 준비
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "User" },
                    { "LockReason", @event.LockReason },
                    { "LockedUntil", lockedUntilDisplay },
                    { "LockedSource", @event.LockSource },
                    { "IpAddress", @event.ClientIpAddress ?? "Unknown" },
                    { "SupportLink", "[[REPLACE_WITH_SUPPORT_LINK]]" } // 지원 링크는 템플릿에 필요
                };

                // 4. 알림 요청 생성 (Critical Security Alert)
                var notificationRequest = new NotificationSendRequest
                {
                    // RecipientConnectedIds는 ConnectedId가 없는 경우를 대비하여 UserId로 대체
                    RecipientConnectedIds = @event.TriggeredBy.HasValue ? new List<Guid> { @event.TriggeredBy.Value } : new List<Guid> { @event.UserId },
                    
                    TemplateKey = "USER_ACCOUNT_LOCKED_CRITICAL", // 잠금 보안 경고 템플릿
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
                    "Account Locked Critical Notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Account Locked notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendAccountLockedNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
