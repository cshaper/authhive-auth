// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserAccountDeletedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountDeletedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 계정 영구 삭제에 대한 감사 로그를 기록합니다.
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
    /// <see cref="UserAccountDeletedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserAccountDeletedAuditHandler
        : IDomainEventHandler<UserAccountDeletedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository; // 사용자 이름 조회를 위해 주입
        private readonly ILogger<LogUserAccountDeletedAuditHandler> _logger;

        public LogUserAccountDeletedAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            ILogger<LogUserAccountDeletedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 삭제 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 로그에 필요한 추가 정보 조회 (사용자는 이미 삭제되었을 수 있으므로 안전하게 처리)
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                string userName = user?.Username ?? @event.UserId.ToString();

                _logger.LogCritical(
                    "Recording audit log for Critical Security Event: Account Deleted. (User: {UserName}, Reason: {Reason})",
                    userName, @event.DeletionReason);

                // 2. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "DeletionReason", @event.DeletionReason },
                  
                    { "DeletedByConnectedId", @event.DeletedByConnectedId?.ToString() },
                    { "DeletedAt", @event.DeletedAt.ToString("o") }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Delete, // '삭제' 액션
                    Action = "user.account.deleted",
                    ResourceType = "UserAccount",
                    ResourceId = @event.UserId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Critical, // 계정 삭제는 Critical 이벤트
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 3. 감사 로그 서비스의 CreateAsync 메서드 호출
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.DeletedByConnectedId ?? @event.TriggeredBy // 삭제 주체 사용
                );

                // 4. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogCritical( // Critical 로그 레벨에 맞춰 성공 메시지도 Critical로 기록
                        "Audit log recorded successfully for account deletion. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for account deletion. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for account deletion was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserAccountDeletedAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
