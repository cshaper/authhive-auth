// File: AuthHive.Auth/Services/Handlers/Role/LogOrganizationRolesChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // OrganizationRolesChangedEvent
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
    /// 조직 역할 구성 변경 이벤트 발생 시 감사 로그를 기록합니다.
    /// (대규모 또는 복합 변경의 최종 결과를 로깅)
    /// </summary>
    public class LogOrganizationRolesChangedAuditHandler :
        IDomainEventHandler<OrganizationRolesChangedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogOrganizationRolesChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogOrganizationRolesChangedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogOrganizationRolesChangedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(OrganizationRolesChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // 변경을 유발한 주체 (알려지지 않으면 Empty)

            try
            {
                 _logger.LogInformation(
                    "Recording audit log for OrganizationRolesChanged event. Org: {OrgId}. (Reason in Metadata)",
                    organizationId);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ORGANIZATION_ROLES_BULK_CHANGED",
                    ActionType = AuditActionType.Configuration,
                    OrganizationId = organizationId,
                    ResourceType = "OrganizationRoleList", 
                    ResourceId = organizationId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Medium,
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
                    _logger.LogWarning("Failed to create audit log for organization roles change: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for OrganizationRolesChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}