// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionValidatedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionValidatedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 유효성 검사 완료 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionValidatedAuditHandler :
        IDomainEventHandler<PermissionValidatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionValidatedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionValidatedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionValidatedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionValidatedEvent @event, CancellationToken cancellationToken = default)
        {
            // 이벤트 AggregateId는 OrganizationId
            var organizationId = @event.AggregateId;
            // 검증 요청 주체
            var initiator = @event.ConnectedId; // ConnectedId 속성 사용

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PermissionValidated event. ConnectedId: {ConnectedId}, Scope: {Scope}, Type: {ValidationType}",
                    initiator, @event.Scope, @event.ValidationType);

                // ValidationResult에 따라 성공/실패 및 심각도 결정 (가정)
                bool validationSuccess = @event.ValidationResult?.Contains("Success", StringComparison.OrdinalIgnoreCase) ?? false;
                var severity = validationSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning;

                var auditData = new Dictionary<string, object>
                {
                    ["connected_id"] = initiator,
                    ["organization_id"] = organizationId,
                    ["scope"] = @event.Scope,
                    ["validation_type"] = @event.ValidationType,
                    ["validation_result"] = @event.ValidationResult ?? "N/A",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = severity.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Validation, // 유효성 검사 액션 타입
                    "PERMISSION_VALIDATED",
                    initiator, // connectedId (검증 요청 주체)
                    success: validationSuccess, // 검증 결과 반영
                    errorMessage: validationSuccess ? null : @event.ValidationResult, // 실패 시 결과 메시지
                    resourceType: "PermissionValidation", // 리소스 타입
                    resourceId: @event.Scope, // 검증 대상 스코프
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionValidatedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}