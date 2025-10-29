// File: AuthHive.Auth/Services/Handlers/Authentication/Password/LogPasswordResetRequestedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events;

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Password
{
    /// <summary>
    /// 사용자가 비밀번호 재설정을 요청했을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogPasswordResetRequestedAuditHandler :
        IDomainEventHandler<PasswordResetRequestedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPasswordResetRequestedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPasswordResetRequestedAuditHandler(
            IAuditService auditService,
            ILogger<LogPasswordResetRequestedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// PasswordResetRequestedEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(PasswordResetRequestedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            // 재설정은 항상 사용자가 직접 요청
            var initiator = @event.TriggeredBy ?? userId; 

            try
            {
                _logger.LogWarning( // 보안 이벤트
                    "Recording audit log for PasswordResetRequested event. User: {UserId}, Email: {Email}, TriggeredBy: {TriggeredBy}",
                    userId, @event.Email, initiator);

                // 감사 로그 메타데이터 준비
                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["email"] = @event.Email,
                    ["display_name"] = @event.DisplayName ?? string.Empty,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.High.ToString()
                };
                auditData.MergeMetadata(@event.Metadata, _logger);
                
                // (중요) 토큰 자체를 로그에 남기지 않습니다.

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Security,
                    "USER_PASSWORD_RESET_REQUESTED",
                    initiator, // connectedId (작업 수행 주체)
                    success: true,
                    errorMessage: null,
                    resourceType: "User", // 리소스는 '사용자'
                    resourceId: userId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PasswordResetRequestedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}