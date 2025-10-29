// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogApplicationPointSettingsChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationPointSettingsChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 포인트 설정(과금 정책) 변경 시 감사 로그를 기록합니다.
    /// (ApplicationEventHandler 로직 분리)
    /// </summary>
    public class LogApplicationPointSettingsChangedAuditHandler :
        IDomainEventHandler<ApplicationPointSettingsChangedEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationPointSettingsChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationPointSettingsChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationPointSettingsChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationPointSettingsChangedEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.ChangedByConnectedId;

            try
            {
                _logger.LogWarning( // 과금 정책 변경은 Warning
                    "Recording audit log for ApplicationPointSettingsChanged event. AppId: {AppId}, OrgId: {OrgId}",
                    applicationId, organizationId);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["changed_by_connected_id"] = initiator,
                    ["old_use_points"] = @event.OldUsePointsForApiCalls,
                    ["new_use_points"] = @event.NewUsePointsForApiCalls,
                    ["old_rate"] = @event.OldPointsPerApiCall,
                    ["new_rate"] = @event.NewPointsPerApiCall,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 과금 변경은 Warning
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Configuration, // 설정 변경
                    action: "APPLICATION_POINT_SETTINGS_CHANGED",
                    connectedId: initiator, // 행위자
                    success: true,
                    resourceType: "ApplicationPointSettings",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationPointSettingsChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}