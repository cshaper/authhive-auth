// File: AuthHive.Auth/Services/Handlers/Authentication/MFA/LogMfaSuccessAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// MfaSuccessEvent 발생 시 MFA 성공 사실을 감사 로그에 기록합니다.
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


namespace AuthHive.Auth.Handlers.Authentication.MFA
{
    /// <summary>
    /// (한글 주석) 사용자가 다단계 인증에 성공했음을 감사 로그에 기록하는 핸들러입니다.
    /// </summary>
    public class LogMfaSuccessAuditHandler :
        IDomainEventHandler<MfaSuccessEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogMfaSuccessAuditHandler> _logger;

        public int Priority => 15; // LogMfaRequiredAuditHandler보다 약간 높게 설정
        public bool IsEnabled => true;

        public LogMfaSuccessAuditHandler(
            IAuditService auditService,
            ILogger<LogMfaSuccessAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) MFA 성공 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(MfaSuccessEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.UserId;

            try
            {
                _logger.LogInformation("Recording audit log for MfaSuccess event. User: {UserId}, Method: {Method}",
                    userId, @event.MfaMethod);

                var metadata = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["mfa_method"] = @event.MfaMethod,
                    ["status"] = "SUCCESS"
                };
                metadata.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Mfa, 
                    "MFA_SUCCESS",
                    userId, // 행위자는 사용자 본인
                    success: true, // 성공
                    resourceType: "AuthenticationFlow",
                    resourceId: userId.ToString(),
                    metadata: metadata,
                    cancellationToken: cancellationToken);
                
                // (한글 주석) MFA 성공으로 인해 세션 보안 레벨을 올리거나, 임시 MFA 플래그를 제거하는 추가 이벤트 발행 가능
                // 예: await _eventBus.PublishAsync(new MfaSessionCompletedEvent(...));

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for MfaSuccessEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}