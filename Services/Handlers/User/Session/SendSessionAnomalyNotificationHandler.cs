// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Session/SendSessionAnomalyNotificationHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// SessionAnomalyDetectedEvent를 처리하는 핸들러입니다.
// 목적: 세션 이상 감지 시 사용자에게 보안 경고 알림을 즉시 발송합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Models.User.Events; // SessionAnomalyDetectedEvent
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest, EmailRequestDetails
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel/Priority
using AuthHive.Core.Enums.Infra.Security; // For SecurityEnums
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Session
{
    /// <summary>
    /// <see cref="SessionAnomalyDetectedEvent"/>를 처리하는 보안 알림 핸들러입니다.
    /// </summary>
    public class SendSessionAnomalyNotificationHandler
        : IDomainEventHandler<SessionAnomalyDetectedEvent>
    {
        public int Priority => 200;
        public bool IsEnabled => true;

        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SendSessionAnomalyNotificationHandler> _logger;

        public SendSessionAnomalyNotificationHandler(
            INotificationService notificationService,
            IUserRepository userRepository,
            ILogger<SendSessionAnomalyNotificationHandler> logger)
        {
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 비정상 세션 감지 이벤트를 처리하여 보안 알림을 발송합니다.
        /// </summary>
        public async Task HandleAsync(SessionAnomalyDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 알림 대상 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                if (user == null)
                {
                    _logger.LogError("Notification failed: User({UserId}) not found for session anomaly event.", @event.UserId);
                    return;
                }

                // 2. 알림 발송 로깅
                _logger.LogCritical(
                    "Sending Critical Alert: Session Anomaly Notification to User {Email} (Type: {Type}, Risk: {Risk})",
                    user.Email, @event.AnomalyType, @event.RiskLevel);
                
                // 3. 템플릿 변수 준비
                string terminationStatus = @event.SessionTerminated ? "TERMINATED" : "ACTIVE";

                var templateVariables = new Dictionary<string, string>
                {
                    { "UserName", user.Username ?? "User" },
                    { "AnomalyType", @event.AnomalyType },
                    { "Description", @event.Description },
                    { "RiskLevel", @event.RiskLevel.ToString() },
                    { "IpAddress", @event.ClientIpAddress ?? "Unknown" },
                    // (수정) BaseEvent의 Timestamp 대신 CreatedAt(BaseEvent의 기본 시간 속성)을 사용하도록 수정
                    { "Time", @event.OccurredAt.ToString("yyyy-MM-dd HH:mm UTC") }, 
                    { "TerminationStatus", terminationStatus }, // 세션 종료 여부
                    { "ConnectedId", @event.ConnectedId.ToString() },
                    { "ReviewLink", "[[REPLACE_WITH_ACCOUNT_REVIEW_LINK]]" } // 계정 검토 페이지 링크
                };

                // 4. 알림 요청 생성 (Critical Security Alert)
                var notificationRequest = new NotificationSendRequest
                {
                    RecipientConnectedIds = new List<Guid> { @event.ConnectedId },
                    TemplateKey = "SESSION_ANOMALY_CRITICAL_ALERT", // 세션 이상 보안 경고 템플릿
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
                    "Session Anomaly Critical Alert sent successfully. (ConnectedId: {ConnectedId})",
                    @event.ConnectedId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Session Anomaly notification was cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in SendSessionAnomalyNotificationHandler. (ConnectedId: {ConnectedId})",
                    @event.ConnectedId);
                // 알림 실패는 Write Model에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
