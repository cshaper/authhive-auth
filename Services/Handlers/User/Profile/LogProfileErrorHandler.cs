// File: AuthHive.Auth/Services/Handlers/User/Profile/LogProfileErrorHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// ProfileErrorEvent 발생 시 오류 로그를 기록합니다. (모니터링 및 디버깅 목적)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core; // AuditEventSeverity 사용 위해 추가
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.Profile; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.User.Profile
{
    /// <summary>
    /// (한글 주석) 프로필 관련 오류 발생 시 로그(에러 로그 및/또는 감사 로그)를 기록하는 핸들러입니다.
    /// </summary>
    public class LogProfileErrorHandler :
        IDomainEventHandler<ProfileErrorEvent>,
        IService
    {
        private readonly IAuditService _auditService; // 오류 감사 로깅용 (선택적)
        private readonly ILogger<LogProfileErrorHandler> _logger; // 에러 로깅용

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogProfileErrorHandler(
            IAuditService auditService, // 감사 로그 남길 경우 주입
            ILogger<LogProfileErrorHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 프로필 오류 이벤트를 처리하여 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ProfileErrorEvent @event, CancellationToken cancellationToken = default)
        {
            // (한글 주석) 1. 기본 에러 로깅 (ILogger 사용) - 항상 수행
            _logger.LogError("Profile error occurred for User {UserId}. Type: {ErrorType}, Message: {ErrorMessage}, CorrelationId: {CorrelationId}",
                @event.UserId, @event.ErrorType, @event.ErrorMessage, @event.CorrelationId);

            // (한글 주석) 2. 감사 로그 기록 (선택적 - 시스템 오류도 감사 추적이 필요할 경우)
            try
            {
                // (한글 주석) 감사 로그 메타데이터 준비
                var errorData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId,
                    ["error_type"] = @event.ErrorType,
                    ["error_message"] = @event.ErrorMessage,
                    ["source_service"] = @event.Source,
                    ["occurred_at"] = @event.OccurredAt
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                errorData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록 - 심각도는 Warning 또는 Error
                await _auditService.LogActionAsync(
                    AuditActionType.System, // 시스템 오류 이벤트
                    $"PROFILE_ERROR_{@event.ErrorType.ToUpperInvariant()}", // 액션 이름에 타입 포함
                    @event.TriggeredBy ?? @event.UserId, // 오류를 유발한 사용자 또는 대상 사용자
                    success: false, // 오류이므로 false
                    errorMessage: @event.ErrorMessage, // 에러 메시지 필드 사용
                    resourceType: "UserProfile",
                    resourceId: @event.UserId.ToString(), // 대상 사용자 ID
                    metadata: errorData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception auditEx)
            {
                // (한글 주석) 감사 로깅 자체에서 오류 발생 시 추가 에러 로깅
                _logger.LogError(auditEx, "Failed to record audit log for ProfileErrorEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogProfileErrorHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (한글 주석) 로거는 보통 헬스 체크 불필요, AuditService는 필요 시 추가
             return Task.FromResult(IsEnabled);
        }
        #endregion
    }
}