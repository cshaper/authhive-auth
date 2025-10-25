// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/SendGoodbyeNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLeftOrganizationEvent의 두 번째 핸들러입니다.
// 목적: 사용자에게 조직 탈퇴/제외 알림을 발송합니다.
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

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserLeftOrganizationEvent"/>를 처리하는 알림 핸들러입니다.
    /// 사용자에게 조직 탈퇴/제외 알림을 보냅니다.
    /// </summary>
    public class SendGoodbyeNotificationHandler 
        : IDomainEventHandler<UserLeftOrganizationEvent>
    {
        // 읽기 모델 핸들러(100)보다 늦게 실행
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<SendGoodbyeNotificationHandler> _logger;

        public SendGoodbyeNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<SendGoodbyeNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 탈퇴 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(UserLeftOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("SendGoodbyeNotificationHandler received. OrganizationId is null. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                // 1. 알림에 필요한 정보 조회
                // (참고) 사용자가 시스템에서 완전히 탈퇴한(삭제된) 경우 user가 null일 수 있습니다.
                // 이메일 주소 등이 필요하므로 조회를 시도합니다.
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                var organization = await _organizationRepository.GetByIdAsync(@event.OrganizationId.Value, cancellationToken);

                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found (might be already deleted).", @event.UserId);
                    return; // 사용자를 찾을 수 없으면 알림 발송 불가
                }
                
                if (organization == null)
                {
                    _logger.LogError("Notification failed: Organization({OrgId}) not found.", @event.OrganizationId.Value);
                    return; // 조직 정보를 찾을 수 없음
                }

                _logger.LogInformation(
                    "Sending 'left organization' notification to User {Email} for Org {OrgName}.",
                    user.Email, organization.Name);

                // 2. 템플릿 기반 알림 요청 생성 (영어로)
                var templateVariables = new Dictionary<string, string>
                {
                    // (CS8604 경고 방지) null일 경우 기본값 "Member" 사용
                    { "UserName", user.DisplayName ?? user.Username ?? "Member" },
                    { "OrganizationName", organization.Name ?? "the organization" },
                    { "LeaveReason", @event.LeaveReason } // (예: "Voluntary", "RemovedByAdmin")
                };
                
                var notificationRequest = new NotificationSendRequest
                {
                    // 수신자는 탈퇴한 멤버십 ID
                    RecipientConnectedIds = new List<Guid> { @event.ConnectedId },
                    
                    TemplateKey = "USER_LEFT_ORGANIZATION", // 탈퇴 알림 템플릿
                    
                    TemplateVariables = templateVariables,
                    
                    ChannelOverride = NotificationChannel.Email, // (가정) 이메일 채널 사용
                    Priority = NotificationPriority.Normal,
                    SendImmediately = true
                };

                // 3. 알림 서비스 호출
                // (참고) SendImmediateNotificationAsync는 인터페이스 정의상 CancellationToken을 받지 않습니다.
                await _notificationService.SendImmediateNotificationAsync(notificationRequest);

                _logger.LogInformation(
                    "'Left organization' notification sent successfully. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId.Value);
            }
            catch (OperationCanceledException)
            {
                // 리포지토리 조회 중 취소된 경우
                _logger.LogWarning("Goodbye notification was cancelled. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
                throw; 
            }
            catch (Exception ex)
            {
                // 알림 실패는 치명적인 오류는 아니므로, 로그만 남기고 예외를 다시 던지지 않습니다.
                _logger.LogError(ex,
                    "Error in SendGoodbyeNotificationHandler. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
                
                // 알림 실패가 감사 로그(다음 핸들러)에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
