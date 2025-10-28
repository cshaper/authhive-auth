// File: AuthHive.Auth/Services/Handlers/Role/LogLastAdminRoleWarningAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // LastAdminRoleWarningEvent
using AuthHive.Core.Models.Audit.Requests; 
using AuthHive.Core.Models.Audit.Responses; 
using AuthHive.Core.Models.Common; 
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// 마지막 관리자 역할 관련 경고 이벤트 발생 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogLastAdminRoleWarningAuditHandler :
        IDomainEventHandler<LastAdminRoleWarningEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogLastAdminRoleWarningAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogLastAdminRoleWarningAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogLastAdminRoleWarningAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(LastAdminRoleWarningEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // OrganizationId
            var initiator = @event.TriggeredBy ?? @event.ConnectedId; 

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for LastAdminRoleWarning event. Org: {OrgId}, Action: {Action}, Remaining: {Remaining}",
                    organizationId, @event.Action, @event.RemainingAdmins);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"LAST_ADMIN_ROLE_WARNING: {@event.Action}",
                    ActionType = AuditActionType.Security,
                    OrganizationId = organizationId,
                    ResourceType = "OrganizationSecurity", 
                    ResourceId = organizationId.ToString(),
                    Success = false, // 경고/위험 상황은 실패/부정으로 기록
                    Severity = AuditEventSeverity.Critical, 
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for last admin role warning: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for LastAdminRoleWarningEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}