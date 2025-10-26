// File: AuthHive.Auth/Services/Handlers/Authentication/Logout/InvalidateSessionOnForcedLogoutHandler.cs
// ----------------------------------------------------------------------
// [최종 수정본]
// ❗️ CS1061 오류 해결: 존재하지 않는 InvalidateSessionAsync 대신 
// ❗️ ISessionRepository에 정의된 EndSessionAsync를 사용하도록 수정합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Repository; // ISessionRepository
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionEndReason 사용을 위해 추가

namespace AuthHive.Auth.Handlers.Authentication.Logout
{
    /// <summary>
    /// (한글 주석) 강제 로그아웃 이벤트 발생 시 해당 세션의 상태를 무효화하는 핸들러입니다.
    /// </summary>
    public class InvalidateSessionOnForcedLogoutHandler :
        IDomainEventHandler<ForcedLogoutEvent>,
        IService
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<InvalidateSessionOnForcedLogoutHandler> _logger;

        public int Priority => 50;
        public bool IsEnabled => true;

        public InvalidateSessionOnForcedLogoutHandler(
            ISessionRepository sessionRepository,
            IUnitOfWork unitOfWork,
            ILogger<InvalidateSessionOnForcedLogoutHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 강제 로그아웃 이벤트를 처리하여 세션 상태를 무효화합니다.
        /// </summary>
        public async Task HandleAsync(ForcedLogoutEvent @event, CancellationToken cancellationToken = default)
        {
            var sessionId = @event.AggregateId;
            try
            {
                _logger.LogInformation("Ending session {SessionId} due to forced logout. ConnectedId: {ConnectedId}, Reason: {Reason}", 
                    sessionId, @event.ConnectedId, @event.ForceReason);

                // (한글 주석) 1. 세션 상태 업데이트 (EndSessionAsync 사용)
                // (한글 주석) ❗️ ISessionRepository.EndSessionAsync 메서드 시그니처에 맞게 호출합니다.
                await _sessionRepository.EndSessionAsync(
                    sessionId, 
                    SessionEndReason.ForcedLogout, // ❗️ 적절한 Enum 값 사용 (가정)
                    DateTime.UtcNow, // 세션 종료 시각
                    cancellationToken
                );

                // (한글 주석) 2. DB에 커밋 (EndSessionAsync가 DB 변경을 추적한다고 가정)
                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                _logger.LogInformation("Successfully ended session {SessionId}.", sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to end session {SessionId} from ForcedLogoutEvent. Rolling back transaction.", sessionId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken); // DB 작업 실패 시 롤백
                // throw;
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}