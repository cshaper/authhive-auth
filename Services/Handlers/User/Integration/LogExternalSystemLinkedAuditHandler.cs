// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Integration/LogExternalSystemLinkedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ExternalSystemLinkedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 계정에 외부 시스템(Social, SSO 등)이 연동될 때 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Integration; // The Event (Integration 폴더에 있다고 가정)
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
    /// <see cref="ExternalSystemLinkedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogExternalSystemLinkedAuditHandler
        : IDomainEventHandler<ExternalSystemLinkedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogExternalSystemLinkedAuditHandler> _logger;

        public LogExternalSystemLinkedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogExternalSystemLinkedAuditHandler> logger)
        {
            this._auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 외부 시스템 연동 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ExternalSystemLinkedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for external system linkage. (UserId: {UserId}, System: {SystemType}, ExternalId: {ExternalId})",
                    @event.UserId, @event.ExternalSystemType, @event.ExternalUserId);

                // 1. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "ExternalSystemType", @event.ExternalSystemType },
                    { "ExternalUserId", @event.ExternalUserId },
                    { "LinkedAt", @event.LinkedAt.ToString("o") }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Create, // 새로운 관계 '생성' 액션
                    Action = $"user.integration.linked.{@event.ExternalSystemType.ToLower()}",
                    ResourceType = "ExternalAccountLink",
                    // 리소스 ID는 User ID와 External System Type의 조합을 사용하는 것이 일반적이나, 
                    // 여기서는 User ID를 주 리소스로 사용합니다.
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
                        "Audit log recorded successfully for external system linkage. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for external system linkage. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for external system linkage was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogExternalSystemLinkedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
