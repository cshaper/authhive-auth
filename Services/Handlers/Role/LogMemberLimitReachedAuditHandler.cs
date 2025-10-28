// File: AuthHive.Auth/Services/Handlers/Role/LogMemberLimitReachedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditLogService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Role.Events; // MemberLimitReachedEvent
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
    /// 멤버 수 한도 초과 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogMemberLimitReachedAuditHandler :
        IDomainEventHandler<MemberLimitReachedEvent>,
        IService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogMemberLimitReachedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogMemberLimitReachedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogMemberLimitReachedAuditHandler> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task HandleAsync(MemberLimitReachedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var initiator = @event.AttemptedBy; // 작업을 시도한 주체 ConnectedId

            try
            {
                 _logger.LogWarning(
                    "Recording audit log for MemberLimitReached event. Org: {OrgId}, Plan: {PlanKey}, Current: {Current}, Limit: {Limit}",
                    organizationId, @event.PlanKey, @event.CurrentMembers, @event.MemberLimit);

                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"LIMIT_REACHED: MEMBER_COUNT",
                    ActionType = AuditActionType.LimitExceeded,
                    OrganizationId = organizationId,
                    ResourceType = "OrganizationMembership", 
                    ResourceId = organizationId.ToString(),
                    Success = false, // 한도 초과는 부정적 상황
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
                    _logger.LogWarning("Failed to create audit log for member limit: {Error}", auditResult.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for MemberLimitReachedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}