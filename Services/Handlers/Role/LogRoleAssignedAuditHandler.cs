// File: AuthHive.Auth/Services/Handlers/Role/LogRoleAssignedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleAssignedEvent
using AuthHive.Core.Models.Audit.Requests; // CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // AuditLogResponse
using AuthHive.Core.Models.Common; // ServiceResult
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role // (네임스페이스 가정)
{
    /// <summary>
    /// 사용자에게 역할이 할당되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogRoleAssignedAuditHandler :
        IDomainEventHandler<RoleAssignedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleAssignedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleAssignedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleAssignedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.ConnectedId;
            var roleId = @event.RoleId;
            // 역할 할당 작업을 수행한 주체 (ConnectedId 가정)
            var initiator = @event.AssignedByUserId; // 이벤트의 AssignedByUserId가 ConnectedId라고 가정

            try
            {
                 _logger.LogInformation(
                    "Recording audit log for RoleAssigned event. ConnectedId: {ConnectedId}, Role: {RoleName} ({RoleId})",
                    connectedId, @event.RoleName, roleId);

                // 감사 로그 요청 DTO 생성 (기존 RoleChangeEventHandler 로직 참고)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_ASSIGNED: {@event.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Update, // 역할 할당은 멤버십 정보 업데이트
                    OrganizationId = @event.OrganizationId ?? Guid.Empty, // Nullable 처리
                    ResourceType = "Membership", // 대상 리소스는 멤버십
                    ResourceId = connectedId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Info, // Info 레벨 사용
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                // 감사 로그 서비스 호출 (CreateAsync는 CancellationToken을 받지 않음)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator // performedByConnectedId
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role assignment: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleAssignedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}