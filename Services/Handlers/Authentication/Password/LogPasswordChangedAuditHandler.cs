// File: AuthHive.Auth/Services/Handlers/Authentication/Password/LogPasswordChangedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Password
{
    /// <summary>
    /// 사용자의 비밀번호가 변경되었을 때 감사 로그를 기록합니다.
    /// </summary>
    public class LogPasswordChangedAuditHandler :
        IDomainEventHandler<PasswordChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPasswordChangedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPasswordChangedAuditHandler(
            IAuditService auditService,
            ILogger<LogPasswordChangedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// PasswordChangedEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(PasswordChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            // 사용자가 직접 변경했거나(TriggeredBy=null), 관리자가 변경했거나(TriggeredBy=AdminId)
            var initiator = @event.TriggeredBy ?? userId; 

            try
            {
                _logger.LogWarning( // 보안 이벤트이므로 Warning 레벨로 로깅
                    "Recording audit log for PasswordChanged event. User: {UserId}, ConnectedId: {ConnectedId}, TriggeredBy: {TriggeredBy}",
                    userId, @event.ConnectedId, initiator);

                // 감사 로그 메타데이터 준비
                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty, // 작업이 수행된 컨텍스트
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.High.ToString() // 비밀번호 변경은 높은 중요도
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Security, // 보안 관련 액션
                    "USER_PASSWORD_CHANGED",
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
                _logger.LogError(ex, "Failed to log audit for PasswordChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}