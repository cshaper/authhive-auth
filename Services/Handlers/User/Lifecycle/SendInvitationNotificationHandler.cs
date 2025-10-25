// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendInvitationNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserInvitedToOrganizationEvent의 첫 번째 핸들러입니다.
// 목적: 초대받은 사용자에게 조직 초대 이메일/알림을 발송합니다.
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
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using AuthHive.Core.Entities.Organization; // (Organization 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;
// (가정) 초대 링크 생성을 위한 설정 또는 서비스
using Microsoft.Extensions.Options;
// using AuthHive.Core.Configuration;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserInvitedToOrganizationEvent"/>를 처리하는 알림 핸들러입니다.
    /// 초대 대상자에게 초대 이메일을 발송합니다.
    /// </summary>
    public class SendInvitationNotificationHandler
        : IDomainEventHandler<UserInvitedToOrganizationEvent>
    {
        // 초대 이메일 발송은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<SendInvitationNotificationHandler> _logger;
        // (가정) 초대 수락 URL 생성을 위한 설정값 (예: Base URL)
        // private readonly InvitationSettings _invitationSettings;

        public SendInvitationNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<SendInvitationNotificationHandler> logger
            // IOptions<InvitationSettings> invitationSettingsOptions
            )
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            // _invitationSettings = invitationSettingsOptions?.Value ?? throw new ArgumentNullException(nameof(invitationSettingsOptions));
        }

        /// <summary>
        /// 초대 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserInvitedToOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("SendInvitationNotificationHandler received. OrganizationId is null. (InvitationId: {InvitationId})", @event.InvitationId);
                return;
            }

            try
            {
                // 1. 알림에 필요한 정보 조회
                // 초대한 사람 정보 (이름 표시용)
                var inviterUser = await _userRepository.GetByConnectedIdAsync(@event.InvitedByUserConnectedId, cancellationToken);
                // 초대된 조직 정보 (이름 표시용)
                var organization = await _organizationRepository.GetByIdAsync(@event.OrganizationId.Value, cancellationToken);

                string inviterName = inviterUser?.Username ?? "Someone"; // 초대한 사람 이름이 없으면 기본값
                string orgName = organization?.Name ?? "an organization"; // 조직 이름이 없으면 기본값

                if (organization == null)
                {
                    _logger.LogError("Notification failed: Organization({OrgId}) not found for Invitation({InvitationId}).",
                        @event.OrganizationId.Value, @event.InvitationId);
                    return; // 조직 정보를 찾을 수 없음
                }

                _logger.LogInformation(
                   "Sending invitation notification to {InviteeEmail} for Org {OrgName} from {InviterName}.",
                   @event.InvitedUserEmail, orgName, inviterName);

                // 2. 템플릿 기반 알림 요청 생성 (영어로)

                // (가정) 초대 수락 URL 생성 로직
                // string acceptUrl = $"{_invitationSettings.AcceptBaseUrl}?token={@event.InvitationToken}";
                string acceptUrl = $"https://your-app.com/accept-invitation?token={@event.InvitationToken}"; // 임시 URL

                var templateVariables = new Dictionary<string, string>
                {
                    { "InviteeEmail", @event.InvitedUserEmail },
                    { "InviterName", inviterName },
                    { "OrganizationName", orgName },
                    { "InvitationLink", acceptUrl },
                    // (수정) DateTime.ToString(string format) 사용 확인
                    { "ExpiryDate", $"{@event.ExpiresAt:o}" }, // 만료 시간 형식
                    { "InitialRole", @event.InitialRole ?? "Member" } // 초기 역할 (없으면 기본값)
                };

                var notificationRequest = new NotificationSendRequest
                {
                    // 수신자는 초대받는 사람의 이메일 주소
                    TemplateKey = "USER_INVITED_TO_ORGANIZATION", // 초대 알림 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email, // 이메일 채널 사용
                    Priority = NotificationPriority.High, // 초대는 중요함
                    SendImmediately = true,
                };
                // (대안) TemplateVariables에 'ToEmail' 키 추가? 서비스 구현에 따라 다름
                templateVariables.Add("ToEmail", @event.InvitedUserEmail);


                // 3. 알림 서비스 호출
                // CancellationToken 전달 가정 (인터페이스 수정되었다고 가정)
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Invitation notification sent successfully to {InviteeEmail}. (InvitationId: {InvitationId})",
                    @event.InvitedUserEmail, @event.InvitationId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Invitation notification was cancelled. (InvitationId: {InvitationId})", @event.InvitationId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendInvitationNotificationHandler. (InvitationId: {InvitationId})",
                    @event.InvitationId);
                // 알림 실패는 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}

