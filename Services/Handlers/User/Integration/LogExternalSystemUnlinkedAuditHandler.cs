// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Integration/LogExternalSystemUnlinkedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ExternalSystemUnlinkedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 계정에서 외부 시스템 연동이 해제될 때 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Integration; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Integration
{
    /// <summary>
    /// <see cref="ExternalSystemUnlinkedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogExternalSystemUnlinkedAuditHandler
        : IDomainEventHandler<ExternalSystemUnlinkedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogExternalSystemUnlinkedAuditHandler> _logger;

        public LogExternalSystemUnlinkedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogExternalSystemUnlinkedAuditHandler> logger)
        {
            this._auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 외부 시스템 연동 해제 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ExternalSystemUnlinkedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning(
                    "Recording audit log for external system unlinking. (UserId: {UserId}, System: {SystemType}, Reason: {Reason})",
                    @event.UserId, @event.ExternalSystemType, @event.Reason);

                // 1. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "ExternalSystemType", @event.ExternalSystemType },
                    { "ExternalUserId", @event.ExternalUserId },
                    { "UnlinkReason", @event.Reason },
                    // BaseEvent에서 상속받는 이벤트 발생 시각
                    { "UnlinkedAt", @event.OccurredAt.ToString("o") } 
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Delete, // 관계 '삭제' 액션
                    Action = $"user.integration.unlinked.{@event.ExternalSystemType.ToLower()}",
                    ResourceType = "ExternalAccountLink",
                    // 리소스 ID는 User ID를 주 리소스로 사용합니다.
                    ResourceId = @event.UserId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress, // BaseEvent에서 상속
                    UserAgent = @event.UserAgent, // BaseEvent에서 상속
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // TriggeredBy는 User 본인(@event.UserId)입니다.
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.TriggeredBy 
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for external system unlinking. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for external system unlinking. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for external system unlinking was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogExternalSystemUnlinkedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
