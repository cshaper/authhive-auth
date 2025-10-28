// File: AuthHive.Auth/Services/Handlers/Role/LogRoleHierarchyPerformanceIssueAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // RoleHierarchyPerformanceIssueEvent
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
    /// 역할 계층 구조 성능 문제 이벤트 발생 시 감사 로그를 기록합니다.
    /// (시스템 모니터링 및 감사 용도)
    /// </summary>
    public class LogRoleHierarchyPerformanceIssueAuditHandler :
        IDomainEventHandler<RoleHierarchyPerformanceIssueEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogRoleHierarchyPerformanceIssueAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogRoleHierarchyPerformanceIssueAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogRoleHierarchyPerformanceIssueAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(RoleHierarchyPerformanceIssueEvent @event, CancellationToken cancellationToken = default)
        {
            var rootRoleId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = Guid.Empty; // 시스템 이벤트

            try
            {
                 _logger.LogWarning(
                    "Recording audit log for RoleHierarchyPerformanceIssue event. Org: {OrgId}, Depth: {Depth}, QueryTime: {Time}ms",
                    organizationId, @event.HierarchyDepth, @event.QueryTimeMs);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_HIERARCHY_PERF_ISSUE: {@event.PerformanceImpact}",
                    ActionType = AuditActionType.System, // 시스템 액션 타입
                    OrganizationId = organizationId,
                    ResourceType = "RoleHierarchy", 
                    ResourceId = rootRoleId.ToString(),
                    Success = false, // 성능 문제는 부정적 상황
                    Severity = AuditEventSeverity.Warning, // Warning 레벨
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
                    _logger.LogWarning("Failed to create audit log for role hierarchy issue: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for RoleHierarchyPerformanceIssueEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}