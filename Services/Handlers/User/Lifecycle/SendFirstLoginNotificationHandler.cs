// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendFirstLoginNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// FirstLoginEvent의 두 번째 핸들러입니다.
// 목적: 사용자에게 첫 로그인 환영/온보딩 알림을 발송합니다.
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
    /// <see cref="FirstLoginEvent"/>를 처리하는 알림 핸들러입니다.
    /// </summary>
    public class SendFirstLoginNotificationHandler 
        : IDomainEventHandler<FirstLoginEvent>
    {
        // 감사 로그(150) 이후 실행
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendFirstLoginNotificationHandler> _logger;

        public SendFirstLoginNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendFirstLoginNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 첫 로그인 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(FirstLoginEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림에 필요한 사용자 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);

                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for first login event.", @event.UserId);
                    return; // 사용자를 찾을 수 없으면 알림 발송 불가
                }
                
                string userName = user.DisplayName ?? user.Username ?? "User";
                string userEmail = user.Email ?? string.Empty;

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogWarning("Notification skipped: User({UserId}) has no valid email address.", @event.UserId);
                    return;
                }

                _logger.LogInformation(
                    "Sending welcome/onboarding notification to User {Email} on first login. Source: {Source}",
                    userEmail, @event.RegistrationSource);

                // 2. 템플릿 기반 알림 요청 생성 (영어로)
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", userName },
                    { "LoginTime", DateTime.UtcNow.ToString("o") },
                    { "RegistrationSource", @event.RegistrationSource }
                };
                
                var notificationRequest = new NotificationSendRequest
                {
                    // RecipientConnectedIds는 비워두고, EmailDetails를 사용합니다.
                    RecipientConnectedIds = new List<Guid>(), 
                    
                    TemplateKey = "FIRST_LOGIN_WELCOME", // 첫 로그인 환영 템플릿
                    TemplateVariables = templateVariables,
                    
                    ChannelOverride = NotificationChannel.Email, // 이메일 채널 사용
                    Priority = NotificationPriority.Normal,
                    SendImmediately = true,

                    // 이메일 주소로 수신자를 지정합니다. (CS0246 오류 수정)
                    // EmailRequestDetails는 AuthHive.Core.Models.Infra.UserExperience.Requests 네임스페이스에 있다고 가정
                    EmailDetails = new EmailRequestDetails { ToEmail = userEmail }
                };

                // 3. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "First login notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("First login notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendFirstLoginNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
