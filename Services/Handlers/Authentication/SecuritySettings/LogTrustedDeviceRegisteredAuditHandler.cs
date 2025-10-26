// File: AuthHive.Auth/Services/Handlers/Authentication/SecuritySettings/LogTrustedDeviceRegisteredAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // TrustedDeviceRegisteredEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // for Tags.Contains
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.SecuritySettings
{
    /// <summary>
    /// 신뢰할 수 있는 기기 등록 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogTrustedDeviceRegisteredAuditHandler :
        IDomainEventHandler<TrustedDeviceRegisteredEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogTrustedDeviceRegisteredAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogTrustedDeviceRegisteredAuditHandler(
            IAuditService auditService,
            ILogger<LogTrustedDeviceRegisteredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(TrustedDeviceRegisteredEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            var initiator = @event.TriggeredBy ?? userId;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for TrustedDeviceRegistered event. User: {UserId}, DeviceId: {DeviceId}, IP: {IpAddress}",
                    userId, @event.DeviceId, @event.IpAddress);

                // 이벤트 태그를 기반으로 감사 로그 심각도 결정
                var severity = @event.Tags.Contains("UsageCritical") ? AuditEventSeverity.High : AuditEventSeverity.Medium;

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["device_id"] = @event.DeviceId,
                    ["device_name"] = @event.DeviceName,
                    ["device_type"] = @event.DeviceType,
                    ["device_fingerprint"] = @event.DeviceFingerprint, // 보안 추적용
                    ["ip_address"] = @event.IpAddress,
                    ["plan_type"] = @event.PlanType,
                    ["current_device_count"] = @event.CurrentDeviceCount,
                    ["max_device_limit"] = @event.MaxDeviceLimit,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.RegisteredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Security, 
                    "USER_DEVICE_TRUSTED", // 신뢰 기기 등록
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "UserDevice", // 리소스는 '사용자 기기'
                    resourceId: @event.DeviceId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for TrustedDeviceRegisteredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}