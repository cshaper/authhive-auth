// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/SendUserProfileNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserProfileCreatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 프로필 생성 완료 후, 환영/온보딩 알림을 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events.Profile; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest, EmailRequestDetails
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Profile
{
    /// <summary>
    /// <see cref="UserProfileCreatedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 주로 환영 메시지 발송 및 온보딩 시작을 담당합니다.
    /// </summary>
    public class SendUserProfileNotificationHandler
        : IDomainEventHandler<UserProfileCreatedEvent>
    {
        // 감사 로그(150) 이후 실행
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendUserProfileNotificationHandler> _logger;

        public SendUserProfileNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendUserProfileNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 생성 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserProfileCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            // 이 핸들러는 IsFirstCreation 플래그가 true일 경우에만 온보딩 알림을 보냅니다.
            if (@event.IsFirstCreation != true)
            {
                _logger.LogInformation("UserProfileCreatedEvent is not the first creation. Skipping welcome notification. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                // 1. 알림에 필요한 정보 조회 (ConnectedId는 없으므로 UserId로 조회)
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);

                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for profile creation event.", @event.UserId);
                    return;
                }

                string userName = user.Username ?? user.Email.Split('@')[0];

                _logger.LogInformation(
                    "Sending welcome notification to User {Email} after profile creation. (Source: {Source})",
                    user.Email, @event.Source);

                // 2. 템플릿 기반 알림 요청 생성
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", userName },
                    { "ProfileCompletionPercentage", @event.CompletionPercentage.ToString() },
                    { "PreferredLanguage", @event.PreferredLanguage ?? "en" },
                    { "RegistrationSource", @event.InitialOnboardingStep ?? "Self-Registration" }
                };

                // 3. NotificationSendRequest DTO 구성
                var notificationRequest = new NotificationSendRequest
                {
                    // (한글 주석) ❗️ 수정됨: RecipientType과 RecipientIdentifiers 사용
                    RecipientType = RecipientType.User, // 수신자 타입: 사용자
                                                        // (한글 주석) ❗️ EmailDetails.ToEmail을 사용하므로 식별자는 빈 리스트로 둘 수 있음 (NotificationService 구현에 따라 다름)
                                                        // 또는 UserId를 식별자로 제공할 수 있음: RecipientIdentifiers = new List<string> { user.Id.ToString() },
                    RecipientIdentifiers = new List<string>(), // ❗️ 수정됨 (비워둠)

                    TemplateKey = "USER_PROFILE_CREATED_WELCOME", // 템플릿 키
                    TemplateVariables = templateVariables, // 템플릿 변수

                    // (한글 주석) ❗️ 수정됨: ChannelOverride 대신 Channels (List) 사용
                    Channels = new List<NotificationChannel> { NotificationChannel.Email }, // ❗️ 수정됨

                    Priority = NotificationPriority.Normal, // 우선 순위
                    SendImmediately = true, // 즉시 발송

                    // 이메일 상세 정보 설정
                    EmailDetails = new EmailRequestDetails
                    {
                        ToEmail = user.Email, // 직접 이메일 주소 지정
                                              // DisableLogging = false // EmailRequestDetails에 이 속성이 있다면 사용
                    }
                };

                // 4. 알림 서비스 호출
                // ConnectedId가 없는 경우, UserId의 기본 이메일 설정에 따라 전송되어야 합니다.
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "User profile creation notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Profile creation notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendUserProfileNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
