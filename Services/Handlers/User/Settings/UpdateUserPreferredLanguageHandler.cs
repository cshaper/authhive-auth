// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Settings/LogUserLanguageChangeAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// LanguageChangedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 선호 언어 변경에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Settings; // The Event (Settings 폴더에 있다고 가정)
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Settings
{
    /// <summary>
    /// <see cref="LanguageChangedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserLanguageChangeAuditHandler
        : IDomainEventHandler<LanguageChangedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogUserLanguageChangeAuditHandler> _logger;

        public LogUserLanguageChangeAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogUserLanguageChangeAuditHandler> logger)
        {
            this._auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 언어 변경 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(LanguageChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for User preferred language change. (UserId: {UserId}, Old: {Old}, New: {New})",
                    @event.UserId, @event.OldLanguage, @event.NewLanguage);

                // 1. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "OldLanguage", @event.OldLanguage },
                    { "NewLanguage", @event.NewLanguage },
                    { "ChangedAt", @event.ChangedAt.ToString("o") }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId,
                    ActionType = AuditActionType.Update, // 설정 '업데이트' 액션
                    Action = "user.settings.language_changed",
                    ResourceType = "UserProfile",
                    // UserId를 ResourceId로 사용
                    ResourceId = @event.UserId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 2. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자는 ChangedByConnectedId를 사용합니다.
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.ChangedByConnectedId 
                );

                // 3. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for language change. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for language change. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for language change was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserLanguageChangeAuditHandler. (UserId: {UserId})",
                    @event.UserId);
            }
        }
    }
}
