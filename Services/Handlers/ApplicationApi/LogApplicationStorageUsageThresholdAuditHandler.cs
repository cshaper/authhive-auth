// File: AuthHive.Auth/Services/Handlers/ApplicationApi/LogApplicationStorageUsageThresholdAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationStorageUsageThresholdEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApi // (네임스페이스 가정)
{
    /// <summary>
    /// 애플리케이션 스토리지 사용량 임계값 도달 시 Warning 레벨로 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationStorageUsageThresholdAuditHandler :
        IDomainEventHandler<ApplicationStorageUsageThresholdEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationStorageUsageThresholdAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationStorageUsageThresholdAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationStorageUsageThresholdAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationStorageUsageThresholdEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var applicationId = @event.AggregateId;
            var organizationId = @event.OrganizationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System

            var usagePercent = @event.QuotaGB > 0 ? @event.CurrentUsageGB / @event.QuotaGB : 0m;

            try
            {
                _logger.LogWarning(
                    "Recording audit log for ApplicationStorageUsageThreshold event. AppId: {AppId}, OrgId: {OrgId}, Usage: {UsagePercent:P1}",
                    applicationId, organizationId, usagePercent);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = organizationId,
                    ["threshold_percentage"] = @event.ThresholdPercentage,
                    ["current_usage_gb"] = @event.CurrentUsageGB,
                    ["quota_gb"] = @event.QuotaGB,
                    ["usage_percentage"] = usagePercent,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.LimitExceeded, // 임계값 도달 (LimitExceeded 또는 ThresholdReached)
                    action: "APPLICATION_STORAGE_USAGE_THRESHOLD",
                    connectedId: initiator, // 시스템
                    success: true, // 이벤트 발생 자체는 성공
                    resourceType: "ApplicationStorageUsage",
                    resourceId: applicationId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationStorageUsageThresholdEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}