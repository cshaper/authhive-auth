// File: AuthHive.Auth/Services/Handlers/Authentication/Configuration/LogSSOConfiguredAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth; // For ConfigurationActionType
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Events; // SSOConfiguredEvent

using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Authentication.Configuration
{
    /// <summary>
    /// 조직의 SSO 설정 변경(생성, 수정, 삭제) 이벤트를 구독하여 감사 로그를 기록합니다.
    /// </summary>
    public class LogSSOConfiguredAuditHandler :
        IDomainEventHandler<SSOConfiguredEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogSSOConfiguredAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogSSOConfiguredAuditHandler(
            IAuditService auditService,
            ILogger<LogSSOConfiguredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// SSOConfiguredEvent를 처리하여 성공/실패 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(SSOConfiguredEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId; // 조직 ID
            var initiator = @event.TriggeredBy ?? Guid.Empty; // @event.ConfiguredBy와 동일

            try
            {
                var severity = @event.IsSuccessful ? AuditEventSeverity.Medium : AuditEventSeverity.High;
                var actionKey = $"SECURITY_SSO_{@event.ActionType.ToString().ToUpper()}"; // 예: SECURITY_SSO_CREATED

                if (@event.IsSuccessful)
                {
                    _logger.LogInformation(
                        "Recording audit log for {ActionKey} success. Organization: {OrganizationId}, Provider: {Provider}, TriggeredBy: {TriggeredBy}",
                        actionKey, organizationId, @event.Provider, initiator);
                }
                else
                {
                    _logger.LogWarning(
                        "Recording audit log for {ActionKey} failure. Organization: {OrganizationId}, Provider: {Provider}, TriggeredBy: {TriggeredBy}, Error: {Error}",
                        actionKey, organizationId, @event.Provider, initiator, @event.ErrorMessage);
                }

                // 감사 로그 메타데이터 준비
                var auditData = new Dictionary<string, object>
                {
                    ["organization_id"] = organizationId,
                    ["triggered_by"] = initiator,
                    ["provider"] = @event.Provider.ToString(),
                    ["protocol"] = @event.Protocol?.ToString() ?? "N/A",
                    ["action_type"] = @event.ActionType.ToString(),
                    ["domain"] = @event.Domain ?? "N/A",
                    ["configured_at"] = @event.ConfiguredAt,
                    ["severity"] = severity.ToString()
                };

                // BaseEvent.Metadata와 SSOMetadata 모두 병합
                auditData.MergeMetadata(@event.Metadata, _logger);
                auditData.MergeMetadata(@event.SSOMetadata, _logger); 

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Configuration, 
                    actionKey,
                    initiator,
                    success: @event.IsSuccessful,
                    errorMessage: @event.ErrorMessage, // 실패 시 에러 메시지 기록
                    resourceType: "OrganizationSSO", // 리소스는 'SSO 설정'
                    resourceId: organizationId.ToString(), // 리소스 ID는 '조직 ID'
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for SSOConfiguredEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}