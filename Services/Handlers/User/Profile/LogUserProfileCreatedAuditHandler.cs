// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/LogUserProfileCreatedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserProfileCreatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 프로필 생성에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Profile; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

// (수정) 프로필 생성 이벤트는 OrganizationId가 없을 수 있으므로 IOrganizationRepository는 주입하지 않습니다.
// (수정) UserId를 이용한 감사 로그 기록은 가능하므로 IUserRepository도 주입하지 않습니다.

namespace AuthHive.Auth.Services.Handlers.User.Profile
{
    /// <summary>
    /// <see cref="UserProfileCreatedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserProfileCreatedAuditHandler
        : IDomainEventHandler<UserProfileCreatedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserProfileCreatedAuditHandler> _logger;

        public LogUserProfileCreatedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserProfileCreatedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 생성 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserProfileCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for UserProfile creation. (UserId: {UserId}, ProfileId: {ProfileId})",
                    @event.UserId, @event.ProfileId);

                // 1. 감사 로그 요청 DTO 생성 (새 이벤트 모델 반영)
                var details = new Dictionary<string, string?>
                {
                    // (수정) DefaultTimeZone/Language 대신 새 속성 사용
                    { "ProfileId", @event.ProfileId.ToString() },
                    { "PhoneNumber", @event.PhoneNumber },
                    { "TimeZone", @event.TimeZone },
                    { "PreferredLanguage", @event.PreferredLanguage },
                    { "CompletionPercentage", @event.CompletionPercentage.ToString() },
                    { "CreatedAt", @event.CreatedAt.ToString("o") }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ApplicationId = @event.ApplicationId,
                    ActionType = AuditActionType.Create, // 프로필 '생성' 액션
                    Action = "user.profile.created",
                    ResourceType = "UserProfile",
                    // (수정) ResourceId를 ProfileId로 사용
                    ResourceId = @event.ProfileId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Low, // 초기 설정 이벤트
                    RequestId = @event.CorrelationId.ToString(),
                    // ClientIpAddress 및 UserAgent는 BaseEvent에서 직접 사용 가능
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // (수정) TriggeredBy 대신 명시적인 CreatedByConnectedId를 우선 사용합니다.
                Guid? performerId = @event.CreatedByConnectedId ?? @event.TriggeredBy;

                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    performerId
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for UserProfile creation. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for UserProfile creation. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for UserProfile creation was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserProfileCreatedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
                // 감사 로그 실패가 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
