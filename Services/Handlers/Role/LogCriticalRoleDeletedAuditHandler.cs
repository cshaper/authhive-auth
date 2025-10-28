// File: AuthHive.Auth/Services/Handlers/Role/LogCriticalRoleDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // CriticalRoleDeletedEvent
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
    /// 중요 역할(Critical Role) 삭제 이벤트 발생 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogCriticalRoleDeletedAuditHandler :
        IDomainEventHandler<CriticalRoleDeletedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogCriticalRoleDeletedAuditHandler> _logger;

        public int Priority => 5; // 일반 로깅보다 높은 우선순위
        public bool IsEnabled => true;

        public LogCriticalRoleDeletedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogCriticalRoleDeletedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(CriticalRoleDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.DeletedBy; // 삭제 주체 ConnectedId

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for CriticalRoleDeleted event. Role: {RoleName} ({RoleId}), Affected: {Affected}, DeletedBy: {Initiator}",
                    @event.RoleName, roleId, @event.AffectedUsers, initiator);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"CRITICAL_ROLE_DELETED: {@event.RoleName}",
                    ActionType = AuditActionType.Delete,
                    OrganizationId = organizationId,
                    ResourceType = "CriticalRoleDefinition", 
                    ResourceId = roleId.ToString(),
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
                    _logger.LogWarning("Failed to create audit log for critical role deletion: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for CriticalRoleDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}