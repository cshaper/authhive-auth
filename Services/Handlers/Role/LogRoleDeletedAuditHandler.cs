// File: AuthHive.Auth/Services/Handlers/Role/LogRoleDeletedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleDeletedEvent
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
    /// 역할 정의 삭제 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogRoleDeletedAuditHandler :
        IDomainEventHandler<RoleDeletedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleDeletedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleDeletedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleDeletedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.DeletedByConnectedId; 

            try
            {
                 _logger.LogCritical(
                    "Recording audit log for RoleDeleted event. Role: {RoleName} ({RoleId}), AffectedUsers: {Affected}, DeletedBy: {Initiator}",
                    @event.RoleName, roleId, @event.AffectedUsers, initiator);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_DELETED: {@event.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Delete,
                    OrganizationId = organizationId,
                    ResourceType = "RoleDefinition", 
                    ResourceId = roleId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Critical,
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
                    _logger.LogWarning("Failed to create audit log for role deletion: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}