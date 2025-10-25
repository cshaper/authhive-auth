// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/LogUserAccountVerifiedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountVerifiedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 계정 검증 완료에 대한 감사 로그를 기록합니다.
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

namespace AuthHive.Auth.Services.Handlers.User.Profile
{
    /// <summary>
    /// <see cref="UserAccountVerifiedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserAccountVerifiedAuditHandler
        : IDomainEventHandler<UserAccountVerifiedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserAccountVerifiedAuditHandler> _logger;

        public LogUserAccountVerifiedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserAccountVerifiedAuditHandler> logger)
        {
            this._auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 검증 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for User Account Verification. (UserId: {UserId}, Type: {Type}, Method: {Method})",
                    // (수정) VerificationField -> VerificationType
                    @event.UserId, @event.VerificationType, @event.VerificationMethod); 

                // 1. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    // (수정) VerificationField -> VerificationType
                    { "VerificationType", @event.VerificationType }, 
                    { "VerificationMethod", @event.VerificationMethod },
                    { "VerifiedAt", @event.VerifiedAt.ToString("o") },
                    // (수정) ProfileId는 이벤트 모델에 없으므로 UserId를 사용하거나,
                    // ResourceId는 UserId로, Metadata는 VerificationType으로 대체합니다.
                    // 기존 로직 유지 (이벤트 모델에 ProfileId가 없으므로 임시로 UserId를 ResourceId로 사용)
                    { "VerifiedByConnectedId", @event.VerifiedByConnectedId?.ToString() },
                    { "IsManual", @event.IsManualVerification.ToString() }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Update, // 상태 '업데이트' 액션 (검증 상태 변경)
                    // (수정) Action 이름에 VerificationField -> VerificationType 반영
                    Action = $"user.profile.verified.{@event.VerificationType.ToLower()}", 
                    ResourceType = "UserProfile",
                    // ResourceId는 UserProfile의 키인 UserId를 사용합니다.
                    ResourceId = @event.UserId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // TriggeredBy를 행위자로 사용 (VerifiedByConnectedId 또는 UserId)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.TriggeredBy
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        // (수정) ProfileId -> UserId
                        "Audit log recorded successfully for account verification. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for account verification. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                // (수정) ProfileId -> UserId
                _logger.LogWarning("Audit log recording for account verification was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    // (수정) ProfileId -> UserId
                    "Error in LogUserAccountVerifiedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
