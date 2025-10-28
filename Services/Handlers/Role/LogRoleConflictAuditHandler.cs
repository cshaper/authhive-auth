// File: AuthHive.Auth/Services/Handlers/Role/LogRoleConflictAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleConflictDetectedEvent
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
    /// 역할 충돌 감지 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogRoleConflictAuditHandler :
        IDomainEventHandler<RoleConflictDetectedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleConflictAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleConflictAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleConflictAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleConflictDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // OrganizationId
            var initiator = @event.TriggeredBy ?? Guid.Empty;

            try
            {
                 _logger.LogCritical(
                    "Recording audit log for RoleConflictDetected event. Org: {OrgId}, User: {ConnectedId}, Type: {ConflictType}",
                    organizationId, @event.ConnectedId, @event.ConflictType);

                // 감사 로그 요청 DTO 생성
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_CONFLICT_DETECTED: {@event.ConflictType}",
                    ActionType = AuditActionType.Security,
                    OrganizationId = organizationId,
                    ResourceType = "RoleAssignment",
                    ResourceId = @event.ConnectedId.ToString(), // 충돌 발생 대상 ConnectedId
                    Success = false, // 충돌 감지 자체는 보안 위협이므로 실패/부정으로 기록
                    Severity = AuditEventSeverity.Critical,
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                // 감사 로그 서비스 호출
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator // performedByConnectedId
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role conflict: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleConflictDetectedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}