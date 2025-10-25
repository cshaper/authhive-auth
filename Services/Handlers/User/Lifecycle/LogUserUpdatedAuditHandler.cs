// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserUpdatedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserUpdatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 정보 변경(이름, 이메일 등)에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserUpdatedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserUpdatedAuditHandler
        : IDomainEventHandler<UserUpdatedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserUpdatedAuditHandler> _logger;

        public LogUserUpdatedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserUpdatedAuditHandler> logger)
        {
            this._auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 사용자 업데이트 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for User information update. (UserId: {UserId}, Changes: {Count})",
                    @event.UserId, @event.UpdatedFields.Count());

                // 1. 감사 로그 요청 DTO 생성
                // 이 이벤트는 변경된 필드의 상세 내용(Changes)을 메타데이터에 포함해야 합니다.
                var metadata = new Dictionary<string, object>
                {
                    // Changes 딕셔너리를 포함하여 JSON으로 직렬화
                    { "Changes", @event.UpdatedFields } 
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Update, // '업데이트' 액션
                    Action = "user.information.updated",
                    ResourceType = "UserAccount",
                    ResourceId = @event.UserId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Warning, // 개인 정보 변경은 Warning 레벨
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(metadata)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자는 BaseEvent의 TriggeredBy를 사용합니다.
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.TriggeredBy
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for User update. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for User update. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for User update was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserUpdatedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
                // 감사 로그 실패는 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
