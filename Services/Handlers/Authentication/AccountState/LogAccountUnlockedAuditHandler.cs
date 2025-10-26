// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/LogAccountUnlockedAuditHandler.cs
// ----------------------------------------------------------------------
// [수정된 핸들러]
// ❗️ 실제 AccountUnlockedEvent 정의에 맞춰 속성 이름 (UnlockReason, UnlockedByConnectedId)을 사용합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // 실제 이벤트
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions;

namespace AuthHive.Auth.Handlers.Authentication.AccountState
{
    /// <summary>
    /// (한글 주석) 계정 잠금 해제 이벤트 발생 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAccountUnlockedAuditHandler :
        IDomainEventHandler<AccountUnlockedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAccountUnlockedAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAccountUnlockedAuditHandler(
            IAuditService auditService,
            ILogger<LogAccountUnlockedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 계정 잠금 해제 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // BaseEvent의 AggregateId 사용
            try
            {
                // (한글 주석) ❗️ 실제 이벤트 속성 이름 사용
                _logger.LogInformation("Recording audit log for AccountUnlocked event. User: {UserId}, Reason: {Reason}, UnlockedBy: {UnlockedBy}",
                    userId, @event.UnlockReason ?? "N/A", @event.UnlockedByConnectedId ?? Guid.Empty);

                // (한글 주석) 감사 로그 메타데이터 준비 (❗️ 실제 이벤트 속성 이름 사용)
                var unlockData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["reason"] = @event.UnlockReason ?? "N/A", // ❗️ 수정됨
                    ["unlocked_at"] = @event.OccurredAt, // ❗️ 이벤트에 UnlockedAt이 없으므로 OccurredAt 사용
                    ["unlocked_by"] = @event.UnlockedByConnectedId ?? Guid.Empty // ❗️ 수정됨
                };

                unlockData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록 (❗️ 실제 이벤트 속성 이름 사용)
                await _auditService.LogActionAsync(
                    AuditActionType.System,
                    "ACCOUNT_UNLOCKED",
                    @event.UnlockedByConnectedId ?? Guid.Empty, // ❗️ 수정됨
                    success: true,
                    resourceType: "UserAccount",
                    resourceId: userId.ToString(),
                    metadata: unlockData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AccountUnlockedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogAccountUnlockedAuditHandler initialized.");
             return Task.CompletedTask;
        }
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}