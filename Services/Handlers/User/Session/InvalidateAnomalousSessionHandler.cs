// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Session/InvalidateAnomalousSessionHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// SessionAnomalyDetectedEvent를 처리하는 핸들러입니다.
// 목적: 감지된 비정상적인 세션(ConnectedId의 모든 세션)을 즉시 무효화(강제 로그아웃)합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events; // SessionAnomalyDetectedEvent
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.Auth.Service; // ISessionService (가정)
using AuthHive.Core.Models.Common; // ServiceResult
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;
// using AuthHive.Core.Enums.Auth; // SessionEndReason Enum이 있다고 가정

namespace AuthHive.Auth.Services.Handlers.User.Session
{
    /// <summary>
    /// <see cref="SessionAnomalyDetectedEvent"/>를 처리하는 보안 조치 핸들러입니다.
    /// ConnectedId의 모든 세션을 종료합니다.
    /// </summary>
    public class InvalidateAnomalousSessionHandler
        : IDomainEventHandler<SessionAnomalyDetectedEvent>
    {
        // 보안 조치는 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly ISessionService _sessionService;
        private readonly ILogger<InvalidateAnomalousSessionHandler> _logger;

        public InvalidateAnomalousSessionHandler(
            ISessionService sessionService,
            ILogger<InvalidateAnomalousSessionHandler> logger)
        {
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 비정상 세션 감지 이벤트를 처리하여 해당 세션을 즉시 무효화합니다.
        /// </summary>
        public async Task HandleAsync(SessionAnomalyDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            // (수정) ConnectedId가 Guid (not nullable)이므로 Guid.Empty 체크로 대체합니다.
            // 하지만 이벤트 모델상 ConnectedId가 필수이므로, Guid.Empty라면 심각한 오류로 간주합니다.
            if (@event.ConnectedId == Guid.Empty)
            {
                _logger.LogError("Cannot invalidate session: ConnectedId is Guid.Empty in SessionAnomalyDetectedEvent (SessionId: {SessionId})", @event.SessionId);
                return;
            }

            try
            {
                _logger.LogCritical(
                    // (수정) RiskScore 대신 RiskLevel 사용
                    "Starting immediate invalidation for ALL sessions linked to ConnectedId {ConnectedId} due to anomaly. (SessionId: {SessionId}, RiskLevel: {RiskLevel})",
                    @event.ConnectedId, @event.SessionId, @event.RiskLevel);

                // 1. 모든 세션 무효화 로직 호출 (새 시그니처 반영)
                // (수정) .Value 제거 (ConnectedId는 Guid이므로)
                // (가정) SessionEndReason.AnomalyDetected Enum이 존재하며, AuthHive.Core.Enums.Auth에 정의되어 있습니다.
                var invalidateResult = await _sessionService.EndAllSessionsAsync(
                    @event.ConnectedId, // ConnectedId의 모든 세션 종료
                    (SessionEndReason)Enum.Parse(typeof(SessionEndReason), "AnomalyDetected"), // Enum 값 사용 가정
                    cancellationToken
                );
                
                // 2. 결과 확인
                if (invalidateResult.IsSuccess) // ServiceResult 반환 가정
                {
                     _logger.LogCritical(
                        "Anomalous session and all linked sessions successfully invalidated. (ConnectedId: {ConnectedId})",
                        @event.ConnectedId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to invalidate all sessions for ConnectedId {ConnectedId}. Reason: {Error}",
                        @event.ConnectedId, invalidateResult.ErrorMessage);
                    // 실패해도 다른 핸들러(알림, 감사 로그)는 계속 진행합니다.
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Anomalous session invalidation cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw;
            }
            catch (Exception ex)
            {
                // 치명적인 보안 조치 실패이므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogCritical(ex,
                    "Fatal error during anomalous session invalidation. (ConnectedId: {ConnectedId})",
                    @event.ConnectedId);
                throw;
            }
        }
    }
}
