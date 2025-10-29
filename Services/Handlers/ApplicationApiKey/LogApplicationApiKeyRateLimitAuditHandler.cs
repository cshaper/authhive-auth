// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyRateLimitAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyRateLimitEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// 애플리케이션 API 키가 요청 제한(Rate Limit)에 도달했을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogApplicationApiKeyRateLimitAuditHandler :
        IDomainEventHandler<ApplicationApiKeyRateLimitEvent>, // ❗️ 이벤트 이름 변경
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyRateLimitAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogApplicationApiKeyRateLimitAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyRateLimitAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyRateLimitEvent @event, CancellationToken cancellationToken = default) // ❗️ 이벤트 이름 변경
        {
            var apiKeyId = @event.AggregateId;
            var applicationId = @event.ApplicationId ?? Guid.Empty;
            var initiator = @event.TriggeredBy ?? Guid.Empty; // System

            try
            {
                _logger.LogWarning(
                    "Recording audit log for ApplicationApiKeyRateLimit event. ApiKeyId: {ApiKeyId}, Limit: {Limit}, Current: {Current}",
                    apiKeyId, @event.RateLimitPerMinute, @event.CurrentRequests);

                var auditData = new Dictionary<string, object>
                {
                    ["application_id"] = applicationId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["rate_limit_per_minute"] = @event.RateLimitPerMinute,
                    ["current_requests"] = @event.CurrentRequests,
                    ["client_ip"] = @event.ClientIpAddress ?? "N/A", // BaseEvent에서 IP 가져오기
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Warning.ToString() // 요청 제한 도달은 Warning
                }; // ❗️ [수정] CS1073/CS1525 오류 수정: 딕셔너리 닫는 중괄호 누락 수정
                
                auditData.MergeMetadata(@event.Metadata, _logger); // ❗️ [수정] CS1073/CS1525 오류 수정: 별도 라인으로 분리

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.LimitExceeded, // 제한 초과
                    action: "APPLICATION_API_KEY_RATE_LIMITED",
                    connectedId: initiator, // 시스템 (Empty Guid)
                    success: false, // 요청이 차단되었으므로 실패(부정)
                    errorMessage: $"Rate limit exceeded ({@event.RateLimitPerMinute}/min). Current: {@event.CurrentRequests}",
                    resourceType: "ApplicationApiKey",
                    resourceId: apiKeyId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyRateLimitEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}