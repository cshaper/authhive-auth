// File: AuthHive.Auth/Services/Handlers/Authentication/Audit/LogAuthenticationSuccessAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// AuthenticationSuccessEvent 발생 시 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;


namespace AuthHive.Auth.Handlers.Authentication.Audit
{
    /// <summary>
    /// (한글 주석) 인증 성공 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogAuthenticationSuccessAuditHandler :
        IDomainEventHandler<AuthenticationSuccessEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogAuthenticationSuccessAuditHandler> _logger;

        public int Priority => 11; // Attempt 핸들러 다음에 실행될 수 있도록
        public bool IsEnabled => true;

        public LogAuthenticationSuccessAuditHandler(
            IAuditService auditService,
            ILogger<LogAuthenticationSuccessAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 인증 성공 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(AuthenticationSuccessEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // BaseEvent의 AggregateId 사용
            try
            {
                _logger.LogInformation("Recording audit log for AuthenticationSuccess event. User: {UserId}, Username: {Username}, Method: {Method}",
                    userId, @event.Username, @event.AuthMethod);

                // (한글 주석) 감사 로그 메타데이터 준비
                var successData = new Dictionary<string, object>
                {
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["user_id"] = userId,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty,
                    ["username"] = @event.Username ?? "N/A",
                    ["auth_method"] = @event.AuthMethod ?? "N/A",
                    ["ip_address"] = @event.ClientIpAddress ?? "N/A",
                    ["user_agent"] = @event.UserAgent ?? "N/A",
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString() // 심각도 포함
                };
                // (한글 주석) 이벤트의 AdditionalData도 메타데이터에 병합
                if(@event.AdditionalData != null)
                {
                     foreach(var kvp in @event.AdditionalData)
                     {
                          // 키 충돌 방지 위해 접두사 추가 고려
                          successData[$"auth_{kvp.Key}"] = kvp.Value;
                     }
                }
                successData.MergeMetadata(@event.Metadata, _logger); // BaseEvent Metadata 병합

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Login, // 명확한 성공 타입 사용
                    "AUTHENTICATION_SUCCEEDED",
                    @event.ConnectedId ?? userId, // 행위자 (ConnectedId 우선, 없으면 UserId)
                    success: true,
                    resourceType: "UserSession", // 성공 시 세션과 관련됨
                    resourceId: userId.ToString(), // 대상 사용자
                    metadata: successData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for AuthenticationSuccessEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}