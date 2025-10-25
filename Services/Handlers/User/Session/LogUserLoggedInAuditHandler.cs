// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Session/LogUserLoggedInAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLoggedInEvent를 처리하는 핸들러입니다.
// 목적: 사용자 로그인 성공에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Session; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Session
{
    /// <summary>
    /// <see cref="UserLoggedInEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserLoggedInAuditHandler
        : IDomainEventHandler<UserLoggedInEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserLoggedInAuditHandler> _logger;

        public LogUserLoggedInAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserLoggedInAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 로그인 성공 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserLoggedInEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for successful User login. (UserId: {UserId}, Method: {Method}, IP: {IpAddress})",
                    @event.UserId, @event.AuthenticationMethod.ToString(), @event.ClientIpAddress); // Fixed: LoginMethod to AuthenticationMethod

                // 1. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
        {
            { "LoginMethod", @event.AuthenticationMethod.ToString() }, // Fixed: LoginMethod to AuthenticationMethod
            { "SessionId", @event.SessionId.ToString() },
            { "ConnectedId", @event.ConnectedId?.ToString() }, // Added null-safe ToString
            { "AuthenticationContext", @event.AuthenticationContext }
        };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ApplicationId = @event.ApplicationId,
                    ActionType = AuditActionType.Read, // 세션 시작/인증 성공은 Read/Access에 해당
                    Action = "user.login.success",
                    ResourceType = "UserSession",
                    // 로그인 세션 자체를 리소스로 지정
                    ResourceId = @event.SessionId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자는 ConnectedId (세션이 ConnectedId를 기준으로 생성되었으므로)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.ConnectedId
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for successful login. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for successful login. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for login was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserLoggedInAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
