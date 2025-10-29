// File: AuthHive.Auth/Services/Handlers/ApplicationApiKey/LogApplicationApiKeyUsedAuditHandler.cs
using AuthHive.Core.Interfaces.Audit; // IAuditService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationApiKeyUsedEvent
using AuthHive.Core.Enums.Audit; // AuditActionType
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.Audit;
using AuthHive.Core.Enums.Core; // ServiceResult<AuditLogDto> (LogActionAsync 반환 타입)

namespace AuthHive.Auth.Handlers.ApplicationApiKey
{
    /// <summary>
    /// ApplicationApiKeyUsedEvent를 처리하여 API 키 사용 활동을 감사 추적에 기록합니다.
    /// 이 핸들러는 "Hot Path"에서 실행되므로 효율적이어야 합니다.
    /// </summary>
    public class LogApplicationApiKeyUsedAuditHandler :
        IDomainEventHandler<ApplicationApiKeyUsedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApplicationApiKeyUsedAuditHandler> _logger;

        public int Priority => 1;
        public bool IsEnabled => true;

        public LogApplicationApiKeyUsedAuditHandler(
            IAuditService auditService,
            ILogger<LogApplicationApiKeyUsedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(ApplicationApiKeyUsedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 감사 로그를 위한 메타데이터 준비
                // ❗️❗️❗️ 수정된 부분: object? -> object ❗️❗️❗️
                var metadata = new Dictionary<string, object>()
                {
                    // 딕셔너리에 추가하는 값들이 null이 아님을 확인해야 합니다.
                    { "Endpoint", @event.Endpoint ?? string.Empty }, // null일 경우 빈 문자열로 대체
                    { "ClientIp", @event.ClientIp ?? "N/A" },         // null일 경우 "N/A"로 대체
                    { "Source", @event.Source ?? "Unknown" },       // null일 경우 "Unknown"으로 대체
                    { "OrganizationId", @event.OrganizationId ?? Guid.Empty }, // null일 경우 Guid.Empty로 대체
                    { "ApplicationId", @event.ApplicationId ?? Guid.Empty },   // null일 경우 Guid.Empty로 대체
                    { "Description", $"API Key used for endpoint {@event.Endpoint}" }
                };

                // 수정된 LogActionAsync 시그니처에 맞춰 호출
                var auditResult = await _auditService.LogActionAsync(
                    actionType: AuditActionType.Execute,
                    action: "API_KEY_USED",
                    connectedId: Guid.Empty, // 시스템 작업
                    success: true,
                    errorMessage: null,
                    resourceType: "ApiKey",
                    resourceId: @event.AggregateId.ToString(),
                    metadata: metadata, // 수정된 타입의 딕셔너리 전달
                    cancellationToken: cancellationToken);

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to log audit for ApplicationApiKeyUsed event. Reason: {Reason}, ErrorCode: {Code}",
                        auditResult.ErrorMessage, auditResult.ErrorCode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApplicationApiKeyUsed event for ApiKeyId: {ApiKeyId}", @event.AggregateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}