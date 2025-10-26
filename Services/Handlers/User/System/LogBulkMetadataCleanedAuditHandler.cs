// File: AuthHive.Auth/Services/Handlers/User/System/LogBulkMetadataCleanedAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// BulkMetadataCleanedEvent 발생 시 감사 로그를 기록합니다. (시스템 작업)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.System; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.User.System // (한글 주석) System 폴더 경로
{
    /// <summary>
    /// (한글 주석) 대량 메타데이터 정리 작업 완료 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogBulkMetadataCleanedAuditHandler :
        IDomainEventHandler<BulkMetadataCleanedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogBulkMetadataCleanedAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 100; // 시스템 이벤트는 우선순위 낮게 설정
        public bool IsEnabled => true;

        public LogBulkMetadataCleanedAuditHandler(
            IAuditService auditService,
            ILogger<LogBulkMetadataCleanedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 대량 메타데이터 정리 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        // File: AuthHive.Auth/Services/Handlers/User/System/LogBulkMetadataCleanedAuditHandler.cs
        public async Task HandleAsync(BulkMetadataCleanedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Recording audit log for BulkMetadataCleaned event. Mode: {Mode}, Count: {Count}, UserCount: {UserCount}",
                @event.Mode, @event.CleanedCount, @event.CleanedUserIds?.Count ?? 0); // <-- Arguments are here

                // (한글 주석) ❗️ 감사 로그 메타데이터 준비 (CS8601 수정 - GetValueOrDefault 사용)
                var cleanupData = new Dictionary<string, object>
                {
                    ["mode"] = @event.Mode.ToString(),
                    ["cleaned_count"] = @event.CleanedCount,
                    ["cleaned_user_ids_count"] = @event.CleanedUserIds?.Count ?? 0,
                    ["cutoff_date"] = @event.CutoffDate,
                    ["cleaned_at"] = @event.CleanedAt,
                    // (한글 주석) ❗️ TriggeredByAdminId가 null일 경우 Guid.Empty를 반환하는 GetValueOrDefault() 사용
                    ["triggered_by_admin_id"] = @event.TriggeredByAdminId.GetValueOrDefault() // ❗️ 수정됨
                };

                cleanupData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.System,
                    "BULK_METADATA_CLEANED",
                    @event.TriggeredByAdminId ?? Guid.Empty,
                    resourceType: "SystemOperation",
                    resourceId: "BulkMetadataCleanup",
                    metadata: cleanupData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for BulkMetadataCleanedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("LogBulkMetadataCleanedAuditHandler initialized.");
            return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(IsEnabled); // AuditService 헬스 체크 구현 전까지 임시
        }
        #endregion
    }
}