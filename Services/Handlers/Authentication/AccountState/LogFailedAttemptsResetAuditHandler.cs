// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/LogFailedAttemptsResetAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// FailedAttemptsResetEvent 발생 시 감사 로그를 기록합니다.
// (로그인 실패 횟수 초기화 추적)
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
using AuthHive.Auth.Extensions; // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.Authentication.AccountState // (한글 주석) Authentication/AccountState 폴더 경로
{
    /// <summary>
    /// (한글 주석) 로그인 실패 횟수 초기화 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogFailedAttemptsResetAuditHandler :
        IDomainEventHandler<FailedAttemptsResetEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogFailedAttemptsResetAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogFailedAttemptsResetAuditHandler(
            IAuditService auditService,
            ILogger<LogFailedAttemptsResetAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 로그인 실패 횟수 초기화 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(FailedAttemptsResetEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Recording audit log for FailedAttemptsReset event. User: {UserId}",
                    @event.UserId); // UserId는 BaseEvent의 AggregateId에서 가져옴

                // (한글 주석) 감사 로그 메타데이터 준비
                var resetData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.AggregateId, // 이벤트의 AggregateId 사용
                    ["reset_at"] = @event.OccurredAt // 이벤트 발생 시각
                    // 필요 시 초기화 이유 등의 정보 추가 가능
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                resetData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.System, // 시스템(또는 성공적 로그인)에 의한 상태 변경
                    "FAILED_ATTEMPTS_RESET",
                    @event.TriggeredBy ?? @event.AggregateId, // 행위자 (초기화를 유발한 주체, 없으면 사용자 자신)
                    resourceType: "UserAccountSecurity",
                    resourceId: @event.AggregateId.ToString(), // 대상 사용자 ID
                    metadata: resetData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for FailedAttemptsResetEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogFailedAttemptsResetAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return Task.FromResult(IsEnabled); // AuditService 헬스 체크 구현 전까지 임시
        }
        #endregion
    }
}