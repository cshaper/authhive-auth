// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/LogNewDeviceLoggedInAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // NewDeviceLoggedInEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// 새 기기 로그인 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogNewDeviceLoggedInAuditHandler :
        IDomainEventHandler<NewDeviceLoggedInEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogNewDeviceLoggedInAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogNewDeviceLoggedInAuditHandler(
            IAuditService auditService,
            ILogger<LogNewDeviceLoggedInAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(NewDeviceLoggedInEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // UserId
            var initiator = @event.TriggeredBy ?? userId;

            try
            {
                _logger.LogWarning( // 새 기기 로그인은 보안 경고 사항
                    "Recording audit log for NewDeviceLoggedIn event. User: {UserId}, DeviceId: {DeviceId}, IP: {IpAddress}",
                    userId, @event.DeviceId, @event.IpAddress);

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["device_id"] = @event.DeviceId,
                    ["ip_address"] = @event.IpAddress,
                    ["user_agent"] = @event.UserAgent ?? "Unknown",
                    ["location"] = @event.Location ?? "Unknown",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.High.ToString() // 높은 중요도
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Security, 
                    "USER_LOGIN_NEW_DEVICE", // 새 기기 로그인
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "UserSession",
                    resourceId: @event.DeviceId, // 리소스 ID를 DeviceId로 설정
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for NewDeviceLoggedInEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}