// File: authhive.auth/services/handlers/User/Features/LogAddonToggleAuditHandler.cs
// ----------------------------------------------------------------------
// [최종 수정본]
// ❗️ 내부 헬퍼 메서드 MergeDynamicMetadata를 삭제합니다.
// ❗️ 대신 DictionaryExtensions.MergeMetadata 확장 메서드를 사용합니다.
// ❗️ IAuditService.LogActionAsync에는 Dictionary를 직접 전달합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.Features;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // ❗️ 확장 메서드 사용을 위한 using 추가

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// 애드온 상태 변경 시 감사 로그를 기록합니다. (IAuditService 사용)
    /// </summary>
    public class LogAddonToggleAuditHandler :
        IDomainEventHandler<AddonActivatedEvent>,
        IDomainEventHandler<AddonDeactivatedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAddonToggleAuditHandler> _logger; // (한글 주석) 확장 메서드에 로거 전달 위해 사용

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAddonToggleAuditHandler(
            IAuditService auditService,
            ILogger<LogAddonToggleAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 애드온 '활성화' 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AddonActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // (한글 주석) 감사 로그에 기록할 기본 정보를 담는 딕셔너리
                var addonData = new Dictionary<string, object>
                {
                    ["addon_key"] = @event.AddonKey,
                    ["addon_name"] = @event.AddonName,
                    ["activated_at"] = @event.ActivatedAt,
                    ["activated_by"] = @event.ActivatedByConnectedId ?? @event.UserId,
                    ["reason"] = @event.ActivationReason ?? "N/A"
                };

                // (한글 주석) ❗️ 확장 메서드를 사용하여 BaseEvent의 Metadata를 addonData에 병합합니다.
                addonData.MergeMetadata(@event.Metadata, _logger); // ❗️ 수정됨 (로거 전달은 선택 사항)

                // (한글 주석) ❗️ 완성된 딕셔너리 객체를 AuditService에 직접 전달합니다.
                await _auditService.LogActionAsync(
                    AuditActionType.Create,
                    "ADDON_ACTIVATED",
                    @event.ActivatedByConnectedId ?? @event.UserId,
                    resourceId: @event.AddonKey ?? "UnknownAddon",
                    metadata: addonData); 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AddonActivatedEvent: {EventId}", @event.EventId);
            }
        }

        /// <summary>
        /// (한글 주석) 애드온 '비활성화' 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AddonDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // (한글 주석) 감사 로그에 기록할 기본 정보를 담는 딕셔너리
                var metadata = new Dictionary<string, object>
                {
                    ["addon_key"] = @event.AddonKey,
                    ["reason"] = @event.DeactivationReason ?? "not_specified"
                };

                // (한글 주석) ❗️ 필요 시 확장 메서드를 사용하여 BaseEvent의 Metadata를 병합합니다.
                // metadata.MergeMetadata(@event.Metadata, _logger); // ❗️ 필요 시 주석 해제

                // (한글 주석) ❗️ 완성된 딕셔너리 객체를 AuditService에 직접 전달합니다.
                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    "ADDON_DEACTIVATED",
                    @event.DeactivatedByConnectedId ?? @event.UserId,
                    resourceId: @event.AddonKey ?? "UnknownAddon",
                    metadata: metadata); // ❗️ Dictionary 전달
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AddonDeactivatedEvent: {EventId}", @event.EventId);
            }
        }

        // (한글 주석) ❗️ 클래스 내부에 있던 MergeDynamicMetadata 헬퍼 메서드는 삭제되었습니다.

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogAddonToggleAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // (한글 주석) AuditService의 상태 확인 로직 추가 필요 시 여기에 구현
            return Task.FromResult(IsEnabled);
        }
        #endregion
    }
}