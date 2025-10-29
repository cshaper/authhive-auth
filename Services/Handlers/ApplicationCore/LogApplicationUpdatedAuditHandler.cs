// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogApplicationUpdatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationUpdatedEvent
using AuthHive.Core.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Linq; // ToDictionary

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// 애플리케이션 정보가 업데이트되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationUpdatedAuditHandler :
        IDomainEventHandler<ApplicationUpdatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationUpdatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationUpdatedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationUpdatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.UpdatedByConnectedId;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for ApplicationUpdated event. AppId: {AppId}, OrgId: {OrgId}, Changes: {ChangeCount}",
                    applicationId, organizationId, @event.ChangedProperties?.Count ?? 0);

                // ❗️ [수정] CS8619 경고 수정:
                // ToDictionary를 사용하여 Dictionary<string, object?>를 Dictionary<string, object>로 변환
                // (null 값은 DBNull.Value로 치환)
                var changesAsObject = @event.ChangedProperties?.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value ?? (object)DBNull.Value // null을 DBNull.Value로 변환
                ) ?? new Dictionary<string, object>(); // null일 경우 빈 Dictionary<string, object> 반환

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["updated_by_connected_id"] = initiator,
                    ["occurred_at"] = @event.UpdatedAt, 
                    ["severity"] = AuditEventSeverity.Info.ToString(),
                    ["changed_properties"] = changesAsObject // ❗️ 수정된 딕셔너리 할당
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "APPLICATION_UPDATED",
                    connectedId: initiator, 
                    success: true,
                    resourceType: "Application",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationUpdatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}