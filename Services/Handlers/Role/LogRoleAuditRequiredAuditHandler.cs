// File: AuthHive.Auth/Services/Handlers/Role/LogRoleAuditRequiredAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleAuditRequiredEvent
using AuthHive.Core.Models.Audit.Requests; // CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // AuditLogResponse
using AuthHive.Core.Models.Common; // ServiceResult
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 역할 감사 요구 이벤트 발생 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogRoleAuditRequiredAuditHandler :
        IDomainEventHandler<RoleAuditRequiredEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleAuditRequiredAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogRoleAuditRequiredAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleAuditRequiredAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleAuditRequiredEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.InitiatorConnectedId;

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for RoleAuditRequired event. Role: {RoleName}, Operation: {Operation}, RequiresApproval: {Approval}",
                    @event.RoleName, @event.OperationType, @event.RequiresExternalApproval);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_AUDIT_REQUIRED: {@event.OperationType}",
                    ActionType = AuditActionType.Security, 
                    OrganizationId = organizationId,
                    ResourceType = "RoleModificationAttempt", 
                    ResourceId = roleId.ToString(),
                    Success = false, // 작업은 보류 중이므로 성공 아님
                    Severity = AuditEventSeverity.Critical, 
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role audit required: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleAuditRequiredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}