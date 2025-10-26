// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionCreatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionCreatedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission // (네임스페이스 가정)
{
    /// <summary>
    /// 새로운 권한 정의 생성 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionCreatedAuditHandler :
        IDomainEventHandler<PermissionCreatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionCreatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionCreatedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionCreatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionId = @event.AggregateId; // PermissionId
            var initiator = @event.CreatedBy ?? Guid.Empty; // 생성 주체 ConnectedId

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PermissionCreated event. PermissionId: {PermissionId}, Scope: {Scope}, Name: {Name}",
                    permissionId, @event.Scope, @event.Name);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = permissionId,
                    ["scope"] = @event.Scope,
                    ["name"] = @event.Name,
                    ["category"] = @event.Category,
                    ["created_by_connected_id"] = initiator,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty, // 조직별 권한일 수 있음
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Create,
                    "PERMISSION_DEFINITION_CREATED",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "PermissionDefinition", // 리소스는 '권한 정의'
                    resourceId: permissionId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionCreatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}