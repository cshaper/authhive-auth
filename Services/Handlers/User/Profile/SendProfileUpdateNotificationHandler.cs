// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/SendProfileUpdateNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ProfileUpdatedEvent를 처리하는 두 번째 핸들러입니다.
// 목적: 민감한 프로필 변경(전화번호 등) 발생 시 사용자에게 보안 알림을 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json; // JSON 처리 추가
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
    /// <see cref="ProfileUpdatedEvent"/>를 처리하는 알림 핸들러입니다.
    /// 민감 정보 변경 시 사용자에게 보안 알림을 발송합니다.
    /// </summary>
    public class SendProfileUpdateNotificationHandler
        : IDomainEventHandler<ProfileUpdatedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendProfileUpdateNotificationHandler> _logger;

        public SendProfileUpdateNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendProfileUpdateNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 업데이트 이벤트를 처리하여 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(ProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림 대상 및 변경 내용 확인
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found.", @event.UserId);
                    return;
                }

                // 2. 민감한 정보 변경 확인 (현재 Changes 모델에 맞게 수정)
                // PII 필드 목록을 하드코딩하고, 이 필드들이 Changes에 있는지 확인합니다.
                // (IsSensitive 플래그가 없으므로 PII 관련 필드를 명시적으로 확인)
                var sensitiveFields = new[] { "PhoneNumber", "DateOfBirth", "Location" }; 
                
                var sensitiveChanges = @event.Changes
                    .Where(c => sensitiveFields.Contains(c.Key))
                    .Select(c => new { Field = c.Key, Details = (JsonElement)c.Value }) // JsonElement로 캐스팅하여 데이터 추출 준비
                    .ToList();

                if (!sensitiveChanges.Any())
                {
                    _logger.LogInformation("Profile update for {UserId} contained no sensitive changes. Skipping notification.", @event.UserId);
                    return;
                }
                
                // 3. 알림 발송 로직 (템플릿 변수 준비)
                _logger.LogWarning(
                    "Sending security alert for sensitive profile update to User {Email} (Changes: {Fields})",
                    user.Email, string.Join(", ", sensitiveChanges.Select(c => c.Field)));

                // 변경 내역 문자열 생성
                var sensitiveChangesString = string.Join(
                    "; ", 
                    sensitiveChanges.Select(c => 
                    {
                        // JsonElement에서 Old/New 값 추출 시도 (실제 값은 감사 로그에 남김)
                        var oldVal = c.Details.TryGetProperty("old", out var oldProp) ? oldProp.ToString() : "N/A";
                        var newVal = c.Details.TryGetProperty("new", out var newProp) ? newProp.ToString() : "N/A";
                        return $"{c.Field}: {oldVal} -> {newVal}";
                    }));
                
                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "Member" },
                    { "ProfileOwnerEmail", user.Email },
                    { "ChangeList", sensitiveChangesString }, // 변경 내역 리스트
                    { "IpAddress", @event.ClientIpAddress ?? "Unknown" },
                    { "UserAgent", @event.UserAgent ?? "Unknown" }
                };

                // CS0019 오류 수정: RecipientConnectedIds는 Guid 목록을 받습니다.
                // UpdatedByConnectedId는 Guid 타입이므로 Guid 목록에 추가하고, ConnectedId가 없는 경우를 대비하여
                // UserId를 목록에 추가하는 방식 대신, UpdatedByConnectedId만 전달합니다.
                // (일반적으로 알림은 ConnectedId가 아닌 UserId에 연결된 이메일로 발송되지만, ConnectedId가 주체이므로 사용합니다.)
                var recipientId = @event.UpdatedByConnectedId != Guid.Empty ? @event.UpdatedByConnectedId : @event.UserId; // Guid.Empty 체크 추가
                
                var notificationRequest = new NotificationSendRequest
                {
                    // (수정) RecipientConnectedIds는 List<Guid>를 받으므로, UpdatedByConnectedId만 사용하고 UserId는 사용하지 않습니다.
                    RecipientConnectedIds = new List<Guid> { recipientId }, 
                    TemplateKey = "USER_PROFILE_UPDATED_ALERT", // 보안 경고 템플릿
                    TemplateVariables = templateVariables,
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.High, // 보안 알림은 중요도가 높음
                    SendImmediately = true,
                    // 이메일 상세 설정: 사용자 이메일로 발송
                    EmailDetails = new EmailRequestDetails 
                    { 
                        ToEmail = user.Email,
                        // 이 알림 자체는 중요하므로 감사 로그에 남겨야 함 (DisableLogging = false)
                        DisableLogging = false 
                    }
                };
                
                // 4. 알림 서비스 호출
                await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);

                _logger.LogInformation(
                    "Sensitive profile update notification sent successfully. (UserId: {UserId})",
                    @event.UserId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Profile update notification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendProfileUpdateNotificationHandler. (UserId: {UserId})",
                    @event.UserId);
                // 알림 실패는 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
