// File: AuthHive.Auth/Services/Handlers/Authentication/Session/TerminateUserSessionsOnLogoutAllDevicesHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// LogoutAllDevicesEvent 발생 시 해당 User의 모든 활성 세션을 종료합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService, IUnitOfWork
using AuthHive.Core.Interfaces.Auth.Repository; // ISessionRepository
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using System.Collections.Generic;

namespace AuthHive.Auth.Handlers.Authentication.Session
{
    /// <summary>
    /// (한글 주석) LogoutAllDevicesEvent를 처리하여 해당 사용자 ID와 관련된 모든 활성 세션을 종료하고 감사 로그를 기록합니다.
    /// </summary>
    public class TerminateUserSessionsOnLogoutAllDevicesHandler :
        IDomainEventHandler<LogoutAllDevicesEvent>,
        IService
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<TerminateUserSessionsOnLogoutAllDevicesHandler> _logger;

        public int Priority => 10; // Critical 보안 이벤트이므로 높음
        public bool IsEnabled => true;

        public TerminateUserSessionsOnLogoutAllDevicesHandler(
            ISessionRepository sessionRepository,
            IAuditService auditService,
            IUnitOfWork unitOfWork,
            ILogger<TerminateUserSessionsOnLogoutAllDevicesHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _auditService = auditService;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) LogoutAllDevices 이벤트를 처리하여 세션을 무효화합니다.
        /// </summary>
        public async Task HandleAsync(LogoutAllDevicesEvent @event, CancellationToken cancellationToken = default)
        {
            var userId = @event.AggregateId;
            var triggeredBy = @event.TriggeredBy;
            
            if (userId == Guid.Empty)
            {
                _logger.LogError("LogoutAllDevicesEvent received with empty UserId (AggregateId). EventId: {EventId}", @event.EventId);
                return;
            }

            // (한글 주석) 1. 세션 종료 작업 시작
            try
            {
                _logger.LogInformation("Starting bulk termination of sessions for User {UserId} due to reason: {Reason}. TriggeredBy: {TriggeredBy}", 
                    userId, @event.Reason, triggeredBy);
                
                // (한글 주석) 2. 활성 세션 조회
                // (참고: ISessionRepository에 GetActiveSessionsByUserAsync가 존재한다고 가정)
                var activeSessions = await _sessionRepository.GetActiveSessionsByUserAsync(userId, cancellationToken);
                var sessionIdsToTerminate = activeSessions.Select(s => s.Id).ToList();

                int terminatedCount = 0;
                if (sessionIdsToTerminate.Any())
                {
                    // (한글 주석) 3. 세션 벌크 종료 (SessionEndReason.LogoutAllDevices 사용)
                    terminatedCount = await _sessionRepository.BulkEndSessionsAsync(
                        sessionIdsToTerminate, 
                        SessionEndReason.LogoutAllDevices, 
                        cancellationToken);
                    
                    // (한글 주석) 4. DB 커밋
                    await _unitOfWork.CommitTransactionAsync(cancellationToken);

                    _logger.LogInformation("Successfully terminated {Count} sessions for User {UserId}.", terminatedCount, userId);
                }
                else
                {
                    _logger.LogInformation("No active sessions found to terminate for User {UserId}.", userId);
                }
                
                // (한글 주석) 5. 감사 로그 기록
                await LogAuditAsync(
                    userId, 
                    terminatedCount, 
                    @event.Reason, 
                    triggeredBy, 
                    @event.ClientIpAddress,
                    cancellationToken);

            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "FATAL: Failed to terminate all sessions for User {UserId}. Rolling back transaction.", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                
                // (한글 주석) 예외 발생 시에도 감사 로그 기록 (작업 실패 명시)
                await LogAuditAsync(
                    userId, 
                    0, 
                    @event.Reason + " (Operation Failed)", 
                    triggeredBy, 
                    @event.ClientIpAddress, 
                    cancellationToken, 
                    success: false, 
                    errorMessage: ex.Message);
            }
        }

        /// <summary>
        /// (한글 주석) 감사 로그를 기록하는 헬퍼 메서드
        /// </summary>
        private Task LogAuditAsync(
            Guid userId, 
            int count, 
            string reason, 
            Guid? triggeredBy, 
            string? ipAddress,
            CancellationToken cancellationToken,
            bool success = true,
            string? errorMessage = null)
        {
            var metadata = new Dictionary<string, object>
            {
                ["session_count_terminated"] = count,
                ["reason"] = reason,
                ["triggered_by"] = triggeredBy ?? Guid.Empty
            };

            return _auditService.LogActionAsync(
                AuditActionType.Security, 
                "LOGOUT_ALL_DEVICES",
                triggeredBy ?? userId, // 행위자
                success: success, 
                errorMessage: errorMessage,
                resourceType: "UserSessions",
                resourceId: userId.ToString(),
                metadata: metadata,
                cancellationToken: cancellationToken);
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}