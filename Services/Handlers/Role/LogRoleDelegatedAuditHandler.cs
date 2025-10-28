// File: AuthHive.Auth/Services/Handlers/Role/LogRoleDelegatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleDelegatedEvent
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
    /// 역할 위임 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogRoleDelegatedAuditHandler :
        IDomainEventHandler<RoleDelegatedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleDelegatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleDelegatedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleDelegatedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleDelegatedEvent @event, CancellationToken cancellationToken = default)
        {
            var delegationId = @event.AggregateId; // 위임 행위 ID
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            // 위임 작업을 수행한 주체 (FromConnectedId)
            var initiator = @event.FromConnectedId; 

            try
            {
                 _logger.LogInformation(
                    "Recording audit log for RoleDelegated event. Delegator: {FromId}, Delegate: {ToId}, Role: {RoleName}",
                    @event.FromUserId, @event.ToUserId, @event.RoleName);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_DELEGATED: {@event.RoleName}",
                    ActionType = AuditActionType.Update, // 역할 할당 변경으로 간주
                    OrganizationId = organizationId,
                    ResourceType = "RoleDelegation", // 대상 리소스는 위임 관계
                    ResourceId = delegationId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.High, // 역할 위임은 높은 중요도
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
                    _logger.LogWarning("Failed to create audit log for role delegation: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleDelegatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}