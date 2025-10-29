// File: AuthHive.Auth/Services/Handlers/ApplicationApi/LogApiQuotaExceededAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Extensions;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiQuotaExceededEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApi // (새 네임스페이스 가정)
{
    /// <summary>
    /// 애플리케이션 API 할당량(Quota) 초과 시 Critical 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogApiQuotaExceededAuditHandler :
        IDomainEventHandler<ApplicationApiQuotaExceededEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApiQuotaExceededAuditHandler> _logger;

        public int Priority => 5; // 높은 우선순위 로깅
        public bool IsEnabled => true;

        public LogApiQuotaExceededAuditHandler(
            IAuditService auditService,
            ILogger<LogApiQuotaExceededAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiQuotaExceededEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // 시스템 이벤트 (Empty Guid)

            try
            {
                _logger.LogCritical(
                    "Recording CRITICAL audit log for ApplicationApiQuotaExceeded event. AppId: {AppId}, OrgId: {OrgId}, QuotaType: {QuotaType}",
                    applicationId, organizationId, @event.QuotaType);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["quota_type"] = @event.QuotaType,
                    ["blocked_at"] = @event.BlockedAt,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Critical.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger); 

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.LimitExceeded, // 제한 초과
                    action: "APPLICATION_API_QUOTA_EXCEEDED",
                    connectedId: initiator, // 시스템
                    success: false, // 할당량 초과는 부정적 상황
                    errorMessage: $"API Quota Exceeded for type '{@event.QuotaType}'. API calls blocked.",
                    resourceType: "ApplicationApiQuota",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiQuotaExceededEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}