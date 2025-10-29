// File: AuthHive.Auth/Services/Handlers/Authentication/Session/LogTokenIssuedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // TokenIssuedEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Session
{
    /// <summary>
    /// 새로운 토큰(Access, Refresh) 발급 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogTokenIssuedAuditHandler :
        IDomainEventHandler<TokenIssuedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogTokenIssuedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogTokenIssuedAuditHandler(
            IAuditService auditService,
            ILogger<LogTokenIssuedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// TokenIssuedEvent를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(TokenIssuedEvent @event, CancellationToken cancellationToken = default)
        {
            var tokenId = @event.AggregateId; // JTI (Token ID)
            var userId = @event.UserId;
            var initiator = @event.TriggeredBy ?? userId;

            try
            {
                _logger.LogInformation(
                    "Recording audit log for TokenIssued event. User: {UserId}, Type: {TokenType}, TokenId: {TokenId}",
                    userId, @event.TokenType, tokenId);

                var auditData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["token_id"] = tokenId.ToString(),
                    ["token_type"] = @event.TokenType,
                    ["expires_at"] = @event.ExpiresAt ?? (object)DBNull.Value,
                    ["scopes"] = @event.Scopes != null ? string.Join(",", @event.Scopes) : "N/A",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["triggered_by"] = initiator,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 토큰 발급은 정보 수준
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Authentication, 
                    "USER_TOKEN_ISSUED",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "Token", // 리소스는 '토큰'
                    resourceId: tokenId.ToString(), // 리소스 ID
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for TokenIssuedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}