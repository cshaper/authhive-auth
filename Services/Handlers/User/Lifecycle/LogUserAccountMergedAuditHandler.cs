// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserAccountMergedAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// UserAccountMergedEvent 발생 시 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // 확장 메서드 사용 (선택적)

namespace AuthHive.Auth.Handlers.User.Lifecycle
{
    /// <summary>
    /// (한글 주석) 사용자 계정 병합 이벤트 발생 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogUserAccountMergedAuditHandler :
        IDomainEventHandler<UserAccountMergedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogUserAccountMergedAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogUserAccountMergedAuditHandler(
            IAuditService auditService,
            ILogger<LogUserAccountMergedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 사용자 계정 병합 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountMergedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Recording audit log for UserAccountMerged event. Source: {SourceUserId}, Target: {TargetUserId}",
                    @event.SourceUserId, @event.TargetUserId);

                // (한글 주석) 감사 로그에 기록할 메타데이터 준비
                var mergeData = new Dictionary<string, object>
                {
                    ["source_user_id"] = @event.SourceUserId,
                    ["target_user_id"] = @event.TargetUserId, // AggregateId와 동일
                    ["merged_at"] = @event.MergedAt,
                    ["merged_by"] = @event.MergedByConnectedId ?? Guid.Empty, // 시스템 병합 시 Empty
                    ["reason"] = @event.MergeReason,
                    ["merged_data_types"] = @event.MergedData ?? Array.Empty<string>()
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                mergeData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Update, // 병합은 TargetUser 관점에서는 '업데이트'로 볼 수 있음 (또는 Delete+Create)
                    "USER_ACCOUNT_MERGED",
                    @event.MergedByConnectedId ?? Guid.Empty, // 행위자 (Admin 또는 System)
                    resourceType: "UserAccount",
                    resourceId: @event.TargetUserId.ToString(), // 대상(Target) 사용자 ID
                    metadata: mergeData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for UserAccountMergedEvent: {EventId}", @event.EventId);
                // (한글 주석) 감사 로그 실패는 일반적으로 다른 핸들러를 중단시키지 않습니다.
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogUserAccountMergedAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (가정) IAuditService가 IHealthCheckable을 구현
             // return Task.FromResult(IsEnabled && await _auditService.IsHealthyAsync(cancellationToken));
             return Task.FromResult(IsEnabled); // AuditService 헬스 체크 구현 전까지 임시
        }
        #endregion
    }
}