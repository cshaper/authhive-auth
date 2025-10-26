// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/SendAccountUnlockedNotificationHandler.cs
// ----------------------------------------------------------------------
// [수정된 핸들러]
// ❗️ NotificationMessageDto 대신 실제 존재하는 NotificationSendRequest DTO를 사용합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience.Service; // INotificationService
using AuthHive.Core.Models.Auth.Authentication.Events;
// ❗️ 실제 DTO 네임스페이스로 수정 (경로 확인 필요)
using AuthHive.Core.Models.Infra.UserExperience.Requests; // NotificationSendRequest 사용
using AuthHive.Core.Enums.Infra.UserExperience; // NotificationChannel, NotificationPriority 등 사용 (가정)
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // Dictionary 사용
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra.UserExperience;

namespace AuthHive.Auth.Handlers.Authentication.AccountState
{
    /// <summary>
    /// (한글 주석) 계정 잠금 해제 시 사용자에게 알림을 보내는 핸들러입니다.
    /// </summary>
    public class SendAccountUnlockedNotificationHandler :
        IDomainEventHandler<AccountUnlockedEvent>,
        IService
    {
        private readonly INotificationService _notificationService;
        private readonly ILogger<SendAccountUnlockedNotificationHandler> _logger;

        public int Priority => 100;
        public bool IsEnabled => true;

        public SendAccountUnlockedNotificationHandler(
            INotificationService notificationService,
            ILogger<SendAccountUnlockedNotificationHandler> logger)
        {
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 계정 잠금 해제 이벤트를 처리하여 알림을 보냅니다.
        /// </summary>
        public async Task HandleAsync(AccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            if (!IsEnabled) return;

            var userId = @event.AggregateId;
            try
            {
                _logger.LogInformation("Sending account unlocked notification to User {UserId}.", userId);

                // (한글 주석) ❗️ NotificationSendRequest DTO를 사용하여 알림 요청 생성
                var request = new NotificationSendRequest
                {
                     // (한글 주석) 수신자 정보 설정 (UserId 또는 ConnectedId 등 필요에 따라)
                    RecipientIdentifiers = new List<string> { userId.ToString() }, // ID 목록 전달
                    RecipientType = RecipientType.User, // 수신자 타입 (User, Group 등)

                    // (한글 주석) 알림 내용 설정
                    Subject = "Your Account Has Been Unlocked",
                    Body = $"Your account was unlocked. Reason: {@event.UnlockReason ?? "Not specified"}. If you did not request this or suspect suspicious activity, please contact support.",
                    // TemplateKey = "AccountUnlockedNotification", // 또는 템플릿 키 사용
                    // Parameters = new Dictionary<string, string> { {"Reason", @event.UnlockReason ?? "N/A"} }, // 템플릿 파라미터

                    // (한글 주석) 발송 옵션 설정
                    Channels = new List<NotificationChannel> { NotificationChannel.Email }, 
                    Priority = NotificationPriority.High, // 우선 순위
                    // CorrelationId = @event.CorrelationId.ToString(), // 필요 시 상관관계 ID 전달
                    // SendImmediately = true // 즉시 발송 여부 (인터페이스에 따라 다름)
                };

                // (한글 주석) ❗️ INotificationService의 SendImmediateNotificationAsync 또는 QueueNotificationAsync 호출
                // (한글 주석) 여기서는 즉시 발송 메서드를 사용한다고 가정합니다.
                await _notificationService.SendImmediateNotificationAsync(request, cancellationToken);

                // (한글 주석) SendImmediateNotificationAsync가 결과를 반환하지 않는다고 가정
                _logger.LogInformation("Successfully requested account unlocked notification for User {UserId}.", userId);

                // 만약 SendImmediateNotificationAsync가 ServiceResult 등을 반환한다면 결과 처리 로직 추가
                // var result = await _notificationService.SendImmediateNotificationAsync(request, cancellationToken);
                // if (result.IsSuccess) { ... } else { ... }

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending account unlocked notification for User {UserId}, Event: {EventId}", userId, @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("SendAccountUnlockedNotificationHandler initialized.");
             return Task.CompletedTask;
        }
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => IsEnabled && await _notificationService.IsHealthyAsync(cancellationToken);
        #endregion
    }
}