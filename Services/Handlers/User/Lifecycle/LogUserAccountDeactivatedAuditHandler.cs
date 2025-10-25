// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserAccountDeactivatedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountDeactivatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 계정 비활성화에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository (이름 조회용)
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountDeactivatedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserAccountDeactivatedAuditHandler
        : IDomainEventHandler<UserAccountDeactivatedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository; // 사용자 이름 조회를 위해 주입
        private readonly ILogger<LogUserAccountDeactivatedAuditHandler> _logger;

        public LogUserAccountDeactivatedAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            ILogger<LogUserAccountDeactivatedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 비활성화 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 로그에 필요한 추가 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                string userName = user?.Username ?? @event.UserId.ToString();

                _logger.LogWarning( // 비활성화는 Warning 레벨로 기록 (상태 변경)
                    "Recording audit log for Account Deactivation. (User: {UserName}, Reason: {Reason})",
                    userName, @event.DeactivationReason);

                // 2. 감사 로그 요청 DTO 생성
                // 2. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "DeactivationReason", @event.DeactivationReason },
                    { "DeactivationType", @event.DeactivationType.ToString() }, // Convert enum to string
                    { "DeactivatedByConnectedId", @event.DeactivatedByConnectedId?.ToString() }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Update, // 상태 '업데이트' 액션
                    Action = "user.account.deactivated",
                    ResourceType = "UserAccount",
                    ResourceId = @event.UserId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Warning, // 비활성화는 Warning 이벤트
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 3. 감사 로그 서비스의 CreateAsync 메서드 호출
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.DeactivatedByConnectedId ?? @event.TriggeredBy // 비활성화를 수행한 ConnectedId
                );

                // 4. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for account deactivation. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for account deactivation. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for account deactivation was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserAccountDeactivatedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
