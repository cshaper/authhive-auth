// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionDelegatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionDelegatedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For string.Join
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 위임 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionDelegatedAuditHandler :
        IDomainEventHandler<PermissionDelegatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionDelegatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionDelegatedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionDelegatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionDelegatedEvent @event, CancellationToken cancellationToken = default)
        {
            var delegationId = @event.AggregateId; // Delegation ID
            var delegatorUserId = @event.DelegatorUserId;
            var delegateUserId = @event.DelegateUserId;
            // 위임 작업을 수행한 주체 (위임자 본인)
            var initiator = @event.TriggeredBy ?? delegatorUserId; // TriggeredBy가 DelegatorUserId와 같음

            try
            {
                 var delegatedScopes = string.Join(", ", @event.DelegatedPermissions ?? new List<string>());
                _logger.LogInformation(
                    "Recording audit log for PermissionDelegated event. Delegator: {Delegator}, Delegate: {Delegate}, Scopes: [{Scopes}]",
                    delegatorUserId, delegateUserId, delegatedScopes);

                var auditData = new Dictionary<string, object>
                {
                    ["delegator_user_id"] = delegatorUserId,
                    ["delegate_user_id"] = delegateUserId,
                    ["delegated_permissions"] = @event.DelegatedPermissions ?? new List<string>(),
                    ["delegation_type"] = @event.DelegationType.ToString(),
                    ["delegation_scope"] = @event.DelegationScope.ToString(),
                    ["can_sub_delegate"] = @event.CanSubDelegate,
                    ["reason"] = @event.Reason ?? "N/A",
                    ["expires_at"] = @event.OccurredAt, // 만료 시간
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator, // 위임자 ID
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 위임은 정보 수준
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.PermissionUpdated, // 위임은 권한 상태 업데이트
                    "USER_PERMISSION_DELEGATED",
                    initiator, // connectedId (위임자)
                    success: true,
                    errorMessage: null,
                    resourceType: "PermissionDelegation", // 리소스는 '권한 위임' 행위
                    resourceId: delegationId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionDelegatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}