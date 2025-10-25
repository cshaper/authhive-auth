// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendRoleChangeNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserRoleChangedEvent의 세 번째 핸들러입니다.
// 목적: 사용자에게 역할 변경 알림을 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events; // *** 올바른 이벤트 ***
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using AuthHive.Core.Entities.Organization; // (Organization 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserRoleChangedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 사용자에게 역할 변경 알림을 보냅니다.
    /// </summary>
    public class SendRoleChangeNotificationHandler 
        : IDomainEventHandler<UserRoleChangedEvent>
    {
        // 읽기 모델(100), 감사 로그(150) 이후 실행
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<SendRoleChangeNotificationHandler> _logger;

        public SendRoleChangeNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<SendRoleChangeNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 역할 변경 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserRoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // 조직 역할 변경에만 관심
            if (@event.OrganizationId == null)
            {
                _logger.LogInformation("SendRoleChangeNotificationHandler received non-organizational role change. Skipping. (UserId: {UserId})", @event.UserId);
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
                    "Sending role change notification to User {Email} for Org {OrgName}.",
                    user.Email, organization.Name);

                // 2. 템플릿 기반 알림 요청 생성 (영어로)
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "Member" },
                    { "OrganizationName", organization.Name ?? "the organization" },
                    { "OldRole", @event.OldRole ?? "your previous role" }, // 이전 역할이 없을 수 있음
                    { "NewRole", @event.NewRole }
                };
                
                var notificationRequest = new NotificationSendRequest
                {
                    // 수신자는 역할이 변경된 멤버십
                    RecipientConnectedIds = new List<Guid> { @event.ConnectedId },
                    
                    TemplateKey = "USER_ROLE_CHANGED", // 역할 변경 알림 템플릿
                    
                    TemplateVariables = templateVariables,
                    
                    ChannelOverride = NotificationChannel.Email, // (가정) 이메일 채널 사용
                    Priority = NotificationPriority.Normal,
                    SendImmediately = true
                };

                // 3. 알림 서비스 호출
                // (참고) SendImmediateNotificationAsync는 인터페이스 정의상 CancellationToken을 받지 않으나,
                // 만약 인터페이스가 수정되었다면 토큰을 전달해야 합니다. 현재는 전달 가정.
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Role change notification sent successfully. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId.Value);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Role change notification was cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw; 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendRoleChangeNotificationHandler. (ConnectedId: {ConnectedId})",
                    @event.ConnectedId);
                // 알림 실패는 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
