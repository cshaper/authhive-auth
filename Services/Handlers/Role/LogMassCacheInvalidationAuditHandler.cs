// File: AuthHive.Auth/Services/Handlers/Role/LogMassCacheInvalidationAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // MassRoleCacheInvalidationEvent
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
    /// 대규모 역할 캐시 무효화 이벤트 발생 시 감사 로그를 기록합니다.
    /// (주로 성능 모니터링 용도)
    /// </summary>
    public class LogMassCacheInvalidationAuditHandler :
        IDomainEventHandler<MassRoleCacheInvalidationEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogMassCacheInvalidationAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogMassCacheInvalidationAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogMassCacheInvalidationAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(MassRoleCacheInvalidationEvent @event, CancellationToken cancellationToken = default)
        {
            var triggeringRoleId = @event.AggregateId; // 캐시 무효화를 유발한 역할 ID
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy; // 작업을 유발한 ConnectedId

            try
            {
                 _logger.LogWarning(
                    "Recording audit log for MassRoleCacheInvalidation event. Org: {OrgId}, RoleId: {RoleId}, AffectedUsers: {Users}, AffectedSessions: {Sessions}",
                    organizationId, triggeringRoleId, @event.AffectedConnectedIds, @event.AffectedSessions);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"MASS_CACHE_INVALIDATION: {@event.InvalidationReason}",
                    ActionType = AuditActionType.System, // 시스템 액션 타입
                    OrganizationId = organizationId,
                    ResourceType = "RoleCache", // 대상 리소스는 역할 캐시
                    ResourceId = triggeringRoleId.ToString(),
                    Success = true, // 캐시 무효화 시도 자체는 성공
                    Severity = AuditEventSeverity.Low, // Low Priority 이벤트이므로 Low Severity
                    // 이벤트 객체 전체를 직렬화하여 메타데이터로 저장
                    Metadata = JsonSerializer.Serialize(@event, new JsonSerializerOptions { WriteIndented = false })
                };

                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    initiator 
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for mass cache invalidation: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for MassRoleCacheInvalidationEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}