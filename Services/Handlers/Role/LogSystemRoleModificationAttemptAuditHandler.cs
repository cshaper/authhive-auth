// File: AuthHive.Auth/Services/Handlers/Role/LogSystemRoleModificationAttemptAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // SystemRoleModificationAttemptedEvent
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
    /// 시스템 역할(System Role) 수정 시도 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogSystemRoleModificationAttemptAuditHandler :
        IDomainEventHandler<SystemRoleModificationAttemptedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogSystemRoleModificationAttemptAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogSystemRoleModificationAttemptAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogSystemRoleModificationAttemptAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(SystemRoleModificationAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId; // 수정 대상 RoleId
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.AttemptedBy; // 시도한 ConnectedId

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for SystemRoleModificationAttempted event. Role: {RoleName}, Action: {Action}, By: {Initiator}",
                    @event.RoleName, @event.Action, initiator); // ❗️ RoleName 사용

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"SYSTEM_ROLE_MOD_ATTEMPT: {@event.Action}",
                    ActionType = AuditActionType.UnauthorizedAccess,
                    OrganizationId = organizationId,
                    ResourceType = "SystemRole", 
                    ResourceId = roleId.ToString(),
                    Success = false, 
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
                    _logger.LogWarning("Failed to create audit log for system role modification attempt: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SystemRoleModificationAttemptedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}