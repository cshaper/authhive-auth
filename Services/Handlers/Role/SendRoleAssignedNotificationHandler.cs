// File: AuthHive.Auth/Services/Handlers/Role/SendRoleAssignedNotificationHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience; // INotificationService
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository (이메일 조회용)
using AuthHive.Core.Models.Auth.Role.Events; // RoleAssignedEvent
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 사용자에게 역할이 할당되었을 때 알림을 발송합니다.
    /// </summary>
    public class SendRoleAssignedNotificationHandler :
        IDomainEventHandler<RoleAssignedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository; // 사용자 정보 조회
        private readonly ILogger<SendRoleAssignedNotificationHandler> _logger;

        public int Priority => 30; // 감사 로그(10), 캐시(20) 이후 알림 발송
        public bool IsEnabled => true;

        public SendRoleAssignedNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendRoleAssignedNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _userRepository = userRepository;
            _logger = logger;
        }

        public async Task HandleAsync(RoleAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                 // 알림 대상 사용자 정보 조회 (이메일 등)
                // ConnectedId로 User 엔티티 조회 (가정)
                var user = await _userRepository.GetByConnectedIdAsync(@event.ConnectedId, cancellationToken);

                if (user?.Email == null)
                {
                    _logger.LogWarning("Cannot send role assignment notification: User or email not found for ConnectedId {ConnectedId}", @event.ConnectedId);
                    return;
                }

                _logger.LogInformation(
                    "Sending role assignment notification to User {Email} for Role {RoleName}",
                    user.Email, @event.RoleName);

                // 알림 템플릿 변수 준비
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "Member" },
                    { "RoleName", @event.RoleName ?? "a new role" }
                    // 필요시 조직 이름 등 추가 정보 포함 가능 (@event.OrganizationId 활용)
                };

                // 알림 요청 DTO 생성
                var notificationRequest = new NotificationSendRequest
                {
                    RecipientType = RecipientType.User, // 또는 ConnectedId
                    RecipientIdentifiers = new List<string> { @event.ConnectedId.ToString() },
                    TemplateKey = "USER_ROLE_ASSIGNED", // 템플릿 키
                    TemplateVariables = templateVariables,
                    Channels = new List<NotificationChannel> { NotificationChannel.Email }, // 이메일 채널 사용
                    Priority = NotificationPriority.Normal,
                    SendImmediately = true
                };

                // 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Sending role assignment notification for ConnectedId {ConnectedId} was canceled.", @event.ConnectedId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send role assignment notification for ConnectedId: {ConnectedId}", @event.ConnectedId);
                // 알림 실패는 로깅만 하고 계속 진행
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}