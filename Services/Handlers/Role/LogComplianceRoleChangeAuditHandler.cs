// File: AuthHive.Auth/Services/Handlers/Role/LogComplianceRoleChangeAuditHandler.cs
using AuthHive.Core.Enums.Audit; // ComplianceReportType
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // ComplianceRoleChangeEvent
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
    /// 규정 준수 요건으로 인한 역할 변경 요청 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogComplianceRoleChangeAuditHandler :
        IDomainEventHandler<ComplianceRoleChangeEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogComplianceRoleChangeAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogComplianceRoleChangeAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogComplianceRoleChangeAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(ComplianceRoleChangeEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedBy; 

            try
            {
                 _logger.LogWarning(
                    "Recording audit log for ComplianceRoleChange event. RoleId: {RoleId}, Compliance: {ComplianceType}, RequiresApproval: {Approval}",
                    roleId, @event.ComplianceReportType, @event.RequiresApproval);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"COMPLIANCE_ROLE_CHANGE: {@event.ChangeType}",
                    ActionType = AuditActionType.Compliance, // 규정 준수 액션 타입
                    OrganizationId = organizationId,
                    ResourceType = "RoleDefinition", 
                    ResourceId = roleId.ToString(),
                    Success = true, // 이벤트 발생 자체는 성공
                    Severity = AuditEventSeverity.Warning,
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for compliance role change: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ComplianceRoleChangeEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}