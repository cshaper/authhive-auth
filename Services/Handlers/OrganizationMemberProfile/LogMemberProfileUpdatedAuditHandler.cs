// File: AuthHive.Auth/Services/Handlers/OrganizationMemberProfile/LogMemberProfileUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events; // MemberProfileUpdatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationMemberProfile // ❗️ 신규 네임스페이스
{
    /// <summary>
    /// [신규] 조직 멤버 프로필 업데이트 시(MemberProfileUpdatedEvent) 감사 로그를 기록합니다.
    /// </summary>
    public class LogMemberProfileUpdatedAuditHandler :
        IDomainEventHandler<MemberProfileUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogMemberProfileUpdatedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogMemberProfileUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogMemberProfileUpdatedAuditHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task HandleAsync(MemberProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var targetConnectedId = @event.AggregateId; // ❗️ 프로필 대상 멤버 ID
            var initiator = @event.TriggeredBy; // ❗️ 프로필 변경자 ID (Guid?)
            var organizationId = @event.OrganizationId; // ❗️ BaseEvent에서 가져옴

            try
            {
                const string action = "ORGANIZATION_MEMBER_PROFILE_UPDATED";
                var severity = AuditEventSeverity.Info;

                _logger.LogInformation(
                    "Recording audit log for {Action} event. TargetConnectedId: {TargetId}, OrgId: {OrgId}, Initiator: {InitiatorId}",
                    action, targetConnectedId, organizationId, initiator ?? Guid.Empty);

                var auditData = new Dictionary<string, object>
                {
                    ["target_connected_id"] = targetConnectedId,
                    ["organization_id"] = organizationId ?? Guid.Empty,
                    // ❗️ 중요: 실제 변경된 프로필 필드(예: 직책, 부서)는 이벤트 자체에 없으므로,
                    // ❗️ 감사 로그만으로는 '무엇이' 변경되었는지 알기 어렵습니다.
                    // ❗️ 필요하다면 MemberProfileUpdatedEvent에 변경 내용을 포함하도록 모델 수정이 필요합니다.
                    ["updated_by_connected_id"] = initiator ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };

                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: action,
                    connectedId: initiator ?? Guid.Empty, // 행위자
                    success: true,
                    resourceType: "OrganizationMemberProfile", // ❗️ 리소스 타입: 멤버 프로필
                    resourceId: targetConnectedId.ToString(), // ❗️ 리소스 ID: 대상 멤버 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for MemberProfileUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}