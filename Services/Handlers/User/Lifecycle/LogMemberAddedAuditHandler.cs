// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/LogMemberAddedAuditHandler.cs
// (MemberJoined와 유사하게 User/Lifecycle 경로에 생성)
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.ConnectedId.Events; // MemberAddedToOrganizationEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Lifecycle
{
    /// <summary>
    /// 사용자가 조직 멤버로 추가되었을 때(ConnectedId 생성) 감사 로그를 기록합니다.
    /// </summary>
    public class LogMemberAddedAuditHandler :
        IDomainEventHandler<MemberAddedToOrganizationEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogMemberAddedAuditHandler> _logger;

        public int Priority => 150; // LogUserJoined와 유사한 우선순위
        public bool IsEnabled => true;

        public LogMemberAddedAuditHandler(
            IAuditService auditService,
            ILogger<LogMemberAddedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(MemberAddedToOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            var connectedId = @event.AggregateId; // ConnectedId
            var userId = @event.UserId;
            var organizationId = @event.OrganizationId ?? Guid.Empty; // Non-nullable Guid 필요
            // 작업 수행 주체 (관리자 등). null이면 시스템으로 간주
            var initiator = @event.AddedByConnectedId ?? Guid.Empty; 

            try
            {
                _logger.LogInformation(
                    "Recording audit log for MemberAddedToOrganization event. User: {UserId}, Org: {OrgId}, ConnectedId: {ConnectedId}, AddedBy: {AddedBy}",
                    userId, organizationId, connectedId, initiator);

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["organization_id"] = organizationId,
                    ["connected_id"] = connectedId,
                    ["added_by_connected_id"] = initiator, // 작업 수행자 기록
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 멤버 추가는 정보 수준
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Create, // 멤버십 생성
                    "USER_MEMBERSHIP_CREATED", // ActionKey
                    initiator, // connectedId (작업 수행 주체)
                    success: true,
                    errorMessage: null,
                    resourceType: "Membership", // 리소스는 '멤버십 (ConnectedId)'
                    resourceId: connectedId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for MemberAddedToOrganizationEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}