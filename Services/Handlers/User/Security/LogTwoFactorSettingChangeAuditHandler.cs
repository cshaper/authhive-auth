// File: AuthHive.Auth/Services/Handlers/User/Security/LogTwoFactorSettingChangeAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// TwoFactorSettingChangedEvent 발생 시 감사 로그를 기록합니다.
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
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.User.Security // (한글 주석) Security 폴더 경로
{
    /// <summary>
    /// (한글 주석) 2단계 인증 설정 변경 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogTwoFactorSettingChangeAuditHandler :
        IDomainEventHandler<TwoFactorSettingChangedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogTwoFactorSettingChangeAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogTwoFactorSettingChangeAuditHandler(
            IAuditService auditService,
            ILogger<LogTwoFactorSettingChangeAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 2단계 인증 설정 변경 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(TwoFactorSettingChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Recording audit log for TwoFactorSettingChanged event. User: {UserId}, Enabled: {IsEnabled}, Type: {Type}",
                    @event.UserId, @event.Enabled, @event.TwoFactorType);

                // (한글 주석) 감사 로그 메타데이터 준비. 민감 정보(BackupCodes)는 제외합니다.
                var settingData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId,
                    ["enabled"] = @event.Enabled,
                    ["two_factor_type"] = @event.TwoFactorType,
                    ["changed_at"] = @event.ChangedAt,
                    ["changed_by"] = @event.ChangedByConnectedId ?? @event.UserId
                    // ["backup_codes"] = "[MASKED]" // 필요 시 마스킹하여 포함 가능
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                settingData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Update, // 설정 변경은 '업데이트'
                    "TWO_FACTOR_SETTING_CHANGED",
                    @event.ChangedByConnectedId ?? @event.UserId, // 행위자
                    resourceType: "UserSecuritySetting",
                    resourceId: @event.UserId.ToString(), // 대상 사용자 ID
                    metadata: settingData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for TwoFactorSettingChangedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogTwoFactorSettingChangeAuditHandler initialized.");
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