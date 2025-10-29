// File: AuthHive.Auth/Services/Handlers/User/Profile/LogDataExportAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// DataExportedEvent 발생 시 감사 로그를 기록합니다. (GDPR 등 규정 준수 목적)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.Profile; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.User.Profile
{
    /// <summary>
    /// (한글 주석) 사용자 데이터 내보내기 완료 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogDataExportAuditHandler :
        IDomainEventHandler<DataExportedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogDataExportAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogDataExportAuditHandler(
            IAuditService auditService,
            ILogger<LogDataExportAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 데이터 내보내기 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(DataExportedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Recording audit log for DataExported event. User: {UserId}, Format: {Format}, Size: {Size}",
                    @event.UserId, @event.Format, @event.DataSize);

                // (한글 주석) 감사 로그 메타데이터 준비
                var exportData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId,
                    ["format"] = @event.Format,
                    ["exported_at"] = @event.ExportedAt,
                    ["data_size_bytes"] = @event.DataSize,
                    ["exported_by"] = @event.ExportedByConnectedId // GDPR 요청자 또는 관리자
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                exportData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Export, // 데이터 내보내기 액션
                    "USER_DATA_EXPORTED",
                    @event.ExportedByConnectedId, // 행위자 (요청자)
                    resourceType: "UserData",
                    resourceId: @event.UserId.ToString(), // 대상 사용자 ID
                    metadata: exportData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for DataExportedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogDataExportAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (가정) IAuditService가 IHealthCheckable을 구현
             // return Task.FromResult(IsEnabled && await _auditService.IsHealthyAsync(cancellationToken));
             return Task.FromResult(IsEnabled);
        }
        #endregion
    }
}