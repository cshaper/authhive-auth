// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/LogAccessExpiredAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // AccessExpiredEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 애플리케이션 접근 권한이 만료되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogAccessExpiredAuditHandler :
        IDomainEventHandler<AccessExpiredEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAccessExpiredAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogAccessExpiredAuditHandler(
            IAuditService auditService,
            ILogger<LogAccessExpiredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(AccessExpiredEvent @event, CancellationToken cancellationToken = default)
        {
            var accessId = @event.AggregateId; // The ID of the access record itself
            var connectedId = @event.ConnectedId; // The user whose access expired
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System-triggered (Empty Guid)

            try
            {
                _logger.LogInformation( // 만료는 정보성
                    "Recording audit log for AccessExpired event. ConnectedId: {ConnectedId}, AppId: {AppId}",
                    connectedId, applicationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["target_connected_id"] = connectedId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    // ❗️ [수정] 요청하신 대로 .Info 사용
                    ["severity"] = AuditEventSeverity.Info.ToString() 
                };
                // auditData.MergeMetadata(@event.Metadata, _logger); // 필요시 BaseEvent 메타데이터 병합

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.System, // 시스템에 의한 자동 만료
                    action: "APPLICATION_ACCESS_EXPIRED",
                    connectedId: initiator, // 행위자 (System)
                    success: true, // 만료 처리 자체는 성공
                    resourceType: "UserApplicationAccess",
                    resourceId: accessId.ToString(), // 접근 권한 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AccessExpiredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}