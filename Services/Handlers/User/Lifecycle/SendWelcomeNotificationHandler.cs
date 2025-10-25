// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendWelcomeNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// (수정) CS8604 (null 참조 경고) 수정
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationPriority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using AuthHive.Core.Entities.Organization; // (Organization 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserJoinedOrganizationEvent"/>를 처리하는 알림 핸들러입니다.
    /// (수정) 실제 DTO를 사용하여 템플릿 기반 알림을 호출합니다.
    /// </summary>
    public class SendWelcomeNotificationHandler 
        : IDomainEventHandler<UserJoinedOrganizationEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<SendWelcomeNotificationHandler> _logger;

        public SendWelcomeNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<SendWelcomeNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 합류 이벤트를 처리하여 환영 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserJoinedOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("SendWelcomeNotificationHandler received. OrganizationId is null. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                // 1. 알림에 필요한 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                var organization = await _organizationRepository.GetByIdAsync(@event.OrganizationId.Value, cancellationToken);

                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found.", @event.UserId);
                    return;
                }
                
                if (organization == null)
                {
                    _logger.LogError("Notification failed: Organization({OrgId}) not found.", @event.OrganizationId.Value);
                    return;
                }

                _logger.LogInformation(
                    "Sending welcome notification to User {Email} for joining Org {OrgName}.",
                    user.Email, organization.Name);

                // 2. 실제 NotificationSendRequest DTO를 사용하여 요청 생성
                
                // --- (수정 CS8604) ---
                // user.Username과 user.DisplayName이 모두 null일 수 있으므로, 
                // "User" 또는 "Member"와 같은 null이 아닌 기본값을 제공합니다.
                var userName = user.DisplayName ?? user.Username ?? "User";
                // ---------------------

                var templateVariables = new Dictionary<string, string>
                {
                    // (수정) 이제 userName 변수는 절대 null이 아님
                    { "UserName", userName },
                    { "OrganizationName", organization.Name }
                };
                
                var notificationRequest = new NotificationSendRequest
                {
                    RecipientConnectedIds = new List<Guid> { @event.ConnectedId },
                    TemplateKey = "USER_JOINED_ORGANIZATION",
                    TemplateVariables = templateVariables, 
                    SendImmediately = true,
                    Priority = NotificationPriority.Normal
                };

                // 3. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(
                    notificationRequest, 
                    cancellationToken);

                _logger.LogInformation(
                    "Welcome notification sent successfully. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId.Value);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Welcome notification was cancelled. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
                throw; 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendWelcomeNotificationHandler. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
            }
        }
    }
}

