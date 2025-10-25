// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Profile/LogProfileUpdatedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// ProfileUpdatedEvent를 처리하는 핸들러입니다.
// 목적: 프로필 변경 내역에 대한 상세 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Profile; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Profile
{
    /// <summary>
    /// <see cref="ProfileUpdatedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogProfileUpdatedAuditHandler
        : IDomainEventHandler<ProfileUpdatedEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogProfileUpdatedAuditHandler> _logger;

        public LogProfileUpdatedAuditHandler(
            IAuditLogService auditLogService,
            ILogger<LogProfileUpdatedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 프로필 업데이트 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Recording audit log for UserProfile update. (UserId: {UserId}, ProfileId: {ProfileId}, Changes: {Count})",
                    @event.UserId, @event.ProfileId, @event.Changes.Count);

                // 1. 감사 로그 메타데이터 (변경 상세 내역) 생성
                // 이벤트를 JSON으로 직렬화하여 Metadata에 저장합니다.
                var metadata = new Dictionary<string, object>
                {
                    { "Changes", @event.Changes },
                    { "CompletionChange", $"{@event.OldCompletionPercentage}% -> {@event.NewCompletionPercentage}%" }
                };

                // 2. 감사 로그 요청 DTO 생성
                var auditRequest = new CreateAuditLogRequest
                {
                    // OrganizationId와 ApplicationId는 null (전역 이벤트)
                    ActionType = AuditActionType.Update, // 프로필 '업데이트' 액션
                    Action = "user.profile.updated",
                    ResourceType = "UserProfile",
                    ResourceId = @event.ProfileId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    IpAddress = @event.ClientIpAddress,
                    UserAgent = @event.UserAgent,
                    Metadata = JsonSerializer.Serialize(metadata)
                };

                // 3. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자: UpdatedByConnectedId (변경을 수행한 주체)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.UpdatedByConnectedId
                );

                // 4. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for Profile update. (ProfileId: {ProfileId})",
                        @event.ProfileId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for Profile update. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for Profile update was cancelled. (ProfileId: {ProfileId})", @event.ProfileId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogProfileUpdatedAuditHandler. (ProfileId: {ProfileId})",
                    @event.ProfileId);
                // 감사 로그 실패가 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
