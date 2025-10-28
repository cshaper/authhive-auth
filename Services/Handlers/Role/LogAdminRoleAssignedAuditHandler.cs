// File: AuthHive.Auth/Services/Handlers/Role/LogAdminRoleAssignedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // AdminRoleAssignedEvent
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
    /// 관리자 역할 할당 이벤트 발생 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogAdminRoleAssignedAuditHandler :
        IDomainEventHandler<AdminRoleAssignedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogAdminRoleAssignedAuditHandler> _logger;

        public int Priority => 5; // 일반 로깅(10)보다 높은 우선순위
        public bool IsEnabled => true;

        public LogAdminRoleAssignedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogAdminRoleAssignedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(AdminRoleAssignedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // AggregateId가 OrganizationId
            var initiator = @event.AssignedBy; // 할당 주체 ConnectedId

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for AdminRoleAssigned event. User: {ConnectedId}, Role: {RoleName}, AssignedBy: {Initiator}",
                    @event.ConnectedId, @event.RoleName, initiator);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ADMIN_ROLE_ASSIGNED: {@event.RoleName}",
                    ActionType = AuditActionType.Security, // 보안 액션 타입
                    OrganizationId = organizationId,
                    ResourceType = "AdminMembership", 
                    ResourceId = @event.ConnectedId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Critical, // ❗️ Critical 심각도
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for critical role assignment: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AdminRoleAssignedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}