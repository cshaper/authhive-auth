// File: AuthHive.Auth/Services/Handlers/Authentication/Configuration/LogAuthenticationMethodConfiguredAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// AuthenticationMethodConfiguredEvent 발생 시 감사 로그를 기록합니다.
// (OAuth, SAML 등 인증 방식 설정 변경 추적)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Auth; // ConfigurationActionType
using AuthHive.Core.Enums.Core; // AuditActionType
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.Auth.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.Configuration // (한글 주석) Authentication/Configuration 폴더 경로
{
    /// <summary>
    /// (한글 주석) 인증 방식 설정 변경 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAuthenticationMethodConfiguredAuditHandler :
        IDomainEventHandler<AuthenticationMethodConfiguredEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAuthenticationMethodConfiguredAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogAuthenticationMethodConfiguredAuditHandler(
            IAuditService auditService,
            ILogger<LogAuthenticationMethodConfiguredAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 인증 방식 설정 변경 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AuthenticationMethodConfiguredEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var actionString = @event.ActionType.ToString().ToUpperInvariant(); // CREATED, UPDATED, REMOVED
                _logger.LogInformation("Recording audit log for AuthenticationMethodConfigured event. Org: {OrgId}, Method: {Method}, Action: {Action}, Success: {Success}",
                    @event.OrganizationId, @event.Method, actionString, @event.IsSuccessful);

                // (한글 주석) 감사 로그 메타데이터 준비
                var configData = new Dictionary<string, object>
                {
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty, // 이벤트는 조직 ID 기준 (AggregateId)
                    ["authentication_method"] = @event.Method.ToString(),
                    ["action_type"] = actionString,
                    ["configured_at"] = @event.ConfiguredAt,
                    ["configured_by"] = @event.ConfiguredBy,
                    ["is_successful"] = @event.IsSuccessful,
                    ["error_message"] = @event.ErrorMessage ?? ( @event.IsSuccessful ? "N/A" : "Unknown Error" )
                };

                // (한글 주석) BaseEvent의 Metadata 병합 (확장 메서드 사용)
                // (주의: 이벤트 생성 시 additionalMetadata가 올바르게 전달되었어야 함)
                configData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    // (한글 주석) 이벤트의 ActionType을 AuditActionType으로 변환
                    MapToActionType(@event.ActionType),
                    $"AUTH_METHOD_{actionString}", // 예: AUTH_METHOD_CREATED
                    @event.ConfiguredBy, // 행위자 (설정을 변경한 관리자)
                    success: @event.IsSuccessful,
                    errorMessage: @event.ErrorMessage, // 실패 시 에러 메시지 전달
                    resourceType: "AuthenticationMethodConfiguration",
                    // (한글 주석) 리소스 ID는 '조직ID-메서드타입' 조합 또는 설정 엔티티 ID 사용 가능
                    resourceId: $"{@event.OrganizationId}-{@event.Method}",
                    metadata: configData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AuthenticationMethodConfiguredEvent: {EventId}", @event.EventId);
            }
        }

        /// <summary>
        /// (한글 주석) ConfigurationActionType을 AuditActionType으로 매핑합니다.
        /// </summary>
        private AuditActionType MapToActionType(ConfigurationActionType actionType)
        {
            return actionType switch
            {
                ConfigurationActionType.Created => AuditActionType.Create,
                ConfigurationActionType.Updated => AuditActionType.Update,
                ConfigurationActionType.Removed => AuditActionType.Delete,
                _ => AuditActionType.Configuration // 그 외는 일반 설정 변경으로 처리
            };
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogAuthenticationMethodConfiguredAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return Task.FromResult(IsEnabled); // AuditService 헬스 체크 구현 전까지 임시
        }
        #endregion
    }
}