// File: AuthHive.Auth/Services/Handlers/ApplicationCore/LogInsufficientPointsAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // InsufficientPointsEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationCore // ❗️ 네임스페이스 수정
{
    /// <summary>
    /// API 호출 시 포인트 부족으로 차단되었을 때 Critical 감사 로그를 기록합니다.
    /// (ApplicationEventHandler 로직 분리)
    /// </summary>
    public class LogInsufficientPointsAuditHandler :
        IDomainEventHandler<InsufficientPointsEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogInsufficientPointsAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogInsufficientPointsAuditHandler(
            IAuditService auditService,
            ILogger<LogInsufficientPointsAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(InsufficientPointsEvent @event, CancellationToken cancellationToken = default)
        {
            var applicationId = @event.AggregateId;
            var initiator = @event.TriggeredBy ?? @event.ConnectedId; // ConnectedId

            try
            {
                 _logger.LogCritical(
                    "Recording CRITICAL audit log for InsufficientPoints event. AppId: {AppId}, ConnectedId: {ConnectedId}, Required: {Required}",
                    applicationId, @event.ConnectedId, @event.RequiredPoints);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["connected_id"] = @event.ConnectedId,
                    ["required_points"] = @event.RequiredPoints,
                    ["available_points"] = @event.AvailablePoints,
                    ["api_endpoint"] = @event.ApiEndpoint,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Blocked, // 차단됨
                    action: "API_BLOCKED_INSUFFICIENT_POINTS",
                    connectedId: initiator, // 행위자 (API 호출 시도자)
                    success: false, // 호출 실패
                    errorMessage: $"Insufficient points: Required {@event.RequiredPoints}, Available {@event.AvailablePoints}",
                    resourceType: "ApiCall",
                    resourceId: $"{applicationId}:{@event.ApiEndpoint}",
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for InsufficientPointsEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}