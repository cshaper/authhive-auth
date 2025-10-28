// File: AuthHive.Auth/Services/Handlers/Role/LogRoleUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleUpdatedEvent
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
    /// 역할 정의 업데이트 이벤트 발생 시 감사 로그를 기록합니다.
    /// (주로 RoleService 내에서 변경이 발생한 후 발행되며, 변경된 속성 목록이 Metadata에 포함되어야 함)
    /// </summary>
    public class LogRoleUpdatedAuditHandler :
        IDomainEventHandler<RoleUpdatedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleUpdatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleUpdatedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleUpdatedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var roleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            // 업데이트 주체는 이벤트 발행 서비스에서 TriggeredBy에 설정해야 함

            try
            {
                 _logger.LogInformation(
                    "Recording audit log for RoleUpdated event. RoleId: {RoleId}, Org: {OrgId}",
                    roleId, organizationId);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_UPDATED: {roleId}",
                    ActionType = AuditActionType.Update,
                    OrganizationId = organizationId,
                    ResourceType = "RoleDefinition", // 대상 리소스는 역할 정의
                    ResourceId = roleId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    // 이벤트 객체 전체 및 Metadata를 직렬화하여 저장 (변경된 속성 정보가 Metadata에 포함된다고 가정)
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                // 감사 로그 서비스 호출
                // 업데이트 주체(TriggeredBy)가 ConnectedId라고 가정
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.TriggeredBy ?? Guid.Empty 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role update: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}