// File: AuthHive.Auth/Services/Handlers/Authentication/AccountState/LogConsecutiveFailureResetAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// ConsecutiveFailureResetEvent 발생 시 감사 로그 기록 및 DB 상태 업데이트를 수행합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService, IUnitOfWork
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository (상태 업데이트용)
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using AuthHive.Core.Entities.User; // User 엔티티

namespace AuthHive.Auth.Handlers.Authentication.AccountState
{
    /// <summary>
    /// (한글 주석) 연속 인증 실패 횟수 초기화 시 감사 로그 기록 및 사용자 엔티티의 실패 횟수를 0으로 업데이트합니다.
    /// </summary>
    public class LogConsecutiveFailureResetAuditHandler :
        IDomainEventHandler<ConsecutiveFailureResetEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<LogConsecutiveFailureResetAuditHandler> _logger;

        public int Priority => 10;
        public bool IsEnabled => true;

        public LogConsecutiveFailureResetAuditHandler(
            IAuditService auditService,
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<LogConsecutiveFailureResetAuditHandler> logger)
        {
            _auditService = auditService;
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 연속 실패 횟수 초기화 이벤트를 처리합니다. (감사 로그 및 DB 업데이트)
        /// </summary>
        public async Task HandleAsync(ConsecutiveFailureResetEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId; // UserId는 AggregateId
            try
            {
                _logger.LogInformation("Processing ConsecutiveFailureReset event for User {UserId}. Reason: {Reason}, PreviousCount: {Count}",
                    userId, @event.ResetReason, @event.PreviousFailureCount);

                // 1. (한글 주석) 사용자 엔티티의 실패 횟수 초기화 (DB 업데이트)
                await UpdateUserFailureCountAsync(userId, @event.ResetReason, cancellationToken);

                // 2. (한글 주석) 감사 로그 기록
                var resetData = new Dictionary<string, object>
                {
                    ["user_id"] = userId,
                    ["reset_reason"] = @event.ResetReason,
                    ["previous_failure_count"] = @event.PreviousFailureCount,
                    ["reset_by"] = @event.TriggeredBy ?? userId, // 행위자
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString()
                };
                resetData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.System, // 시스템에 의한 상태 초기화
                    "CONSECUTIVE_FAILURE_RESET",
                    @event.TriggeredBy ?? userId, // 행위자
                    success: true,
                    resourceType: "UserAccountSecurity",
                    resourceId: userId.ToString(),
                    metadata: resetData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process ConsecutiveFailureResetEvent for User {UserId}: {EventId}", userId, @event.EventId);
                // (한글 주석) 여기서 롤백할 필요는 없습니다. (UpdateUserFailureCountAsync 내부에서 롤백을 처리해야 함)
            }
        }

        /// <summary>
        /// (한글 주석) 사용자 엔티티의 FailedLoginAttempts를 0으로 설정하고 커밋합니다.
        /// </summary>
        private async Task UpdateUserFailureCountAsync(Guid userId, string reason, CancellationToken cancellationToken)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    _logger.LogWarning("User {UserId} not found for failure count reset.", userId);
                    return;
                }

                // (한글 주석) ❗️ User 엔티티의 FailedLoginAttempts 속성 사용
                user.FailedLoginAttempts = 0;
                // (한글 주석) LockReason도 초기화
                user.LockReason = reason; // 잠금 해제 사유를 마지막 LockReason으로 기록하는 방식으로 사용

                // _userRepository.Update(user); // ORM이 변경 감지
                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogDebug("User {UserId} FailedLoginAttempts reset to 0. Reason: {Reason}", userId, reason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DB update failed during consecutive failure reset for User {UserId}.", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // (한글 주석) 예외는 호출자(HandleAsync)로 전파되어야 합니다.
                throw;
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}