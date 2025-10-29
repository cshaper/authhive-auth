// File: AuthHive.Auth/Services/Handlers/Authentication/Session/LogTokenRevokedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // TokenRevokedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Session
{
    /// <summary>
    /// 토큰 폐기 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogTokenRevokedAuditHandler :
        IDomainEventHandler<TokenRevokedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogTokenRevokedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogTokenRevokedAuditHandler(
            IAuditService auditService,
            ILogger<LogTokenRevokedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// TokenRevokedEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(TokenRevokedEvent @event, CancellationToken cancellationToken = default)
        {
            var tokenId = @event.AggregateId; // JTI (Token ID)
            var userId = @event.UserId;
            var initiator = @event.TriggeredBy ?? userId;

            try
            {
                _logger.LogWarning( // 토큰 폐기는 높은 중요도의 보안 이벤트
                    "Recording audit log for TokenRevoked event. User: {UserId}, TokenId: {TokenId}, Reason: {Reason}",
                    userId, tokenId, @event.RevokeReason);

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["token_id"] = tokenId.ToString(),
                    ["revoke_reason"] = @event.RevokeReason,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.High.ToString() // 이벤트 우선순위에 따름
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Security, 
                    "USER_TOKEN_REVOKED",
                    initiator,
                    success: true, // 이벤트 자체가 "폐기 성공"을 의미
                    errorMessage: null,
                    resourceType: "Token", // 리소스는 '토큰'
                    resourceId: tokenId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for TokenRevokedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}