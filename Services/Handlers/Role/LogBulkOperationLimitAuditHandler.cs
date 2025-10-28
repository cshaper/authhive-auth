// File: AuthHive.Auth/Services/Handlers/Role/LogBulkOperationLimitAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // BulkOperationLimitReachedEvent
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
    /// 대량 작업 한도 초과 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogBulkOperationLimitAuditHandler :
        IDomainEventHandler<BulkOperationLimitReachedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogBulkOperationLimitAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogBulkOperationLimitAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogBulkOperationLimitAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(BulkOperationLimitReachedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.AttemptedBy; // 작업을 시도한 주체 ConnectedId

            try
            {
                 _logger.LogWarning(
                    "Recording audit log for BulkOperationLimitReached event. Org: {OrgId}, Operation: {OpType}, Requested: {Requested}, Allowed: {Allowed}",
                    organizationId, @event.OperationType, @event.RequestedCount, @event.AllowedCount);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"LIMIT_REACHED: {@event.OperationType}",
                    ActionType = AuditActionType.LimitExceeded,
                    OrganizationId = organizationId,
                    ResourceType = "OrganizationOperation", // 대상 리소스는 조직의 운영
                    ResourceId = organizationId.ToString(),
                    Success = false, // 한도 초과는 부정적 상황
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
                    _logger.LogWarning("Failed to create audit log for bulk operation limit: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BulkOperationLimitReachedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}