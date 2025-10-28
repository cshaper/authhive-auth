// File: AuthHive.Auth/Services/Handlers/Role/LogUserRoleChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleChangedEvent
using AuthHive.Core.Models.Audit.Requests; // CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // AuditLogResponse
using AuthHive.Core.Models.Common; // ServiceResult
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 사용자에게 할당된 역할이 변경되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogUserRoleChangedAuditHandler :
        IDomainEventHandler<RoleChangedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserRoleChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogUserRoleChangedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserRoleChangedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedByUserId; // 역할을 변경한 주체 (ConnectedId 가정)

            try
            {
                 _logger.LogInformation(
                    "Recording audit log for RoleChanged event. ConnectedId: {ConnectedId}, Role: {OldName} -> {NewName}",
                    connectedId, @event.OldRoleName, @event.NewRoleName);

                // 감사 로그 요청 DTO 생성 (기존 RoleChangeEventHandler 로직 참고)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"USER_ROLE_CHANGED: {@event.OldRoleName} -> {@event.NewRoleName}",
                    ActionType = AuditActionType.Update,
                    OrganizationId = organizationId,
                    ResourceType = "Membership", // 대상 리소스는 멤버십
                    ResourceId = connectedId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.High, // 역할 변경은 중요 이벤트
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                // 감사 로그 서비스 호출
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for user role change: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}