// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/LogAccountLockedAuditHandler.cs
// ----------------------------------------------------------------------
// [New Handler]
// Logs an audit entry when an AccountLockedEvent occurs.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // Extension method for MergeMetadata

namespace AuthHive.Auth.Handlers.Authentication.AccountState // Folder: Authentication/AccountState
{
    /// <summary>
    /// (한글 주석) 계정 잠금 이벤트 발생 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAccountLockedAuditHandler :
        IDomainEventHandler<AccountLockedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAccountLockedAuditHandler> _logger;

        // --- IDomainEventHandler Implementation ---
        public int Priority => 10; // High priority for security events logging
        public bool IsEnabled => true;

        public LogAccountLockedAuditHandler(
            IAuditService auditService,
            ILogger<LogAccountLockedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 계정 잠금 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AccountLockedEvent @event, CancellationToken cancellationToken = default)
        {
            // Note: UserId is accessed via @event.AggregateId as UserId property is redundant
            var userId = @event.AggregateId;
            try
            {
                _logger.LogWarning("Recording audit log for AccountLocked event. User: {UserId}, Reason: {Reason}, LockedBy: {LockedBy}",
                    userId, @event.Reason, @event.LockedBy ?? Guid.Empty); // Lock events logged as Warning

                // (한글 주석) 감사 로그 메타데이터 준비
                var lockData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["reason"] = @event.Reason,
                    ["locked_until"] = (object?)@event.LockedUntil ?? DBNull.Value, // Handle nullable DateTime
                    ["locked_by"] = @event.LockedBy ?? Guid.Empty, // System lock might be Empty Guid
                    ["ip_address"] = @event.IpAddress ?? "N/A", // Ensure IP is included
                    ["failed_attempts"] = @event.FailedAttempts,
                    ["occurred_at"] = @event.OccurredAt
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                lockData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // Account lock is a 'Blocked' action
                    "ACCOUNT_LOCKED",
                    @event.LockedBy ?? Guid.Empty, // Actor who locked (could be System via Empty Guid)
                    success: true, // The locking action itself was successful
                    resourceType: "UserAccount",
                    resourceId: userId.ToString(), // The user account affected
                    metadata: lockData,
                    cancellationToken: cancellationToken);

                 // Add severity to metadata to avoid CS1739
                 lockData["severity"] = AuditEventSeverity.Warning.ToString();


            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AccountLockedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService Implementation (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogAccountLockedAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // Assume IAuditService implements IHealthCheckable
             // return Task.FromResult(IsEnabled && await _auditService.IsHealthyAsync(cancellationToken));
             return Task.FromResult(IsEnabled); // Placeholder until AuditService health check is confirmed
        }
        #endregion
    }
}