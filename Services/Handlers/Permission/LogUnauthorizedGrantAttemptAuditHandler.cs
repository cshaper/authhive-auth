// File: AuthHive.Auth/Services/Handlers/Permission/LogUnauthorizedGrantAttemptAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // UnauthorizedPermissionGrantAttemptedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 없는 사용자의 권한 부여 시도 이벤트 발생 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogUnauthorizedGrantAttemptAuditHandler :
        IDomainEventHandler<UnauthorizedPermissionGrantAttemptedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogUnauthorizedGrantAttemptAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogUnauthorizedGrantAttemptAuditHandler(IAuditService auditService, ILogger<LogUnauthorizedGrantAttemptAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(UnauthorizedPermissionGrantAttemptedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var initiator = @event.GranterConnectedId; // 권한 부여를 시도한 주체

            try
            {
                _logger.LogCritical(
                    "Recording audit log for UnauthorizedPermissionGrantAttempted event. Granter: {Granter}, Target: {Target}, AppId: {AppId}",
                    initiator, @event.TargetConnectedId, applicationId);

                var auditData = new Dictionary<string, object>
                {
                    ["granter_connected_id"] = initiator,
                    ["target_connected_id"] = @event.TargetConnectedId,
                    ["granter_level"] = @event.GranterLevel.ToString(),
                    ["requested_level"] = @event.RequestedLevel.ToString(),
                    ["application_id"] = applicationId,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.UnauthorizedAccess,
                    "UNAUTHORIZED_PERMISSION_GRANT_ATTEMPT",
                    initiator,
                    success: false, // 시도 자체는 실패로 기록 (차단 성공 가정)
                    errorMessage: $"User {@event.GranterConnectedId} attempted to grant unauthorized level to {@event.TargetConnectedId}",
                    resourceType: "ApplicationAccess",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for UnauthorizedPermissionGrantAttemptedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}