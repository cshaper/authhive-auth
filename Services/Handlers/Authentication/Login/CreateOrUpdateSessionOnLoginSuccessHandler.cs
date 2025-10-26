// File: AuthHive.Auth/Services/Handlers/Authentication/Login/CreateOrUpdateSessionOnLoginSuccessHandler.cs
// ----------------------------------------------------------------------
// [최종 오류 수정본]
// ❗️ CS1503, CS0266, CS8629 오류를 해결하기 위해 Nullable 타입에 대한 명시적인 처리 로직을 적용합니다.
// ❗️ CS4014 오류 해결: Add(entity) 대신 await AddAsync(entity)를 사용합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Auth.Authentication.Events;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth; // SessionEntity
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionStatus, SessionType, SessionLevel 등 사용
using AuthHive.Core.Entities.User; // ❗️ User 엔티티의 ConnectedId를 확인하기 위해 추가 (가정)

namespace AuthHive.Auth.Handlers.Authentication.Login
{
    /// <summary>
    /// (한글 주석) 로그인 성공 시 새로운 세션을 생성하거나 기존 세션 정보를 업데이트하는 핸들러입니다.
    /// </summary>
    public class CreateOrUpdateSessionOnLoginSuccessHandler :
        IDomainEventHandler<LoginSuccessEvent>,
        IService
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<CreateOrUpdateSessionOnLoginSuccessHandler> _logger;

        public int Priority => 30;
        public bool IsEnabled => true;

        public CreateOrUpdateSessionOnLoginSuccessHandler(
            ISessionRepository sessionRepository,
            IUnitOfWork unitOfWork,
            ILogger<CreateOrUpdateSessionOnLoginSuccessHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }


        /// <summary>
        /// (한글 주석) 로그인 성공 이벤트를 처리하여 세션 정보를 DB에 반영합니다.
        /// </summary>
        public async Task HandleAsync(LoginSuccessEvent @event, CancellationToken cancellationToken = default)
        {
            // (한글 주석) ❗️ SessionId가 null인 경우 (세션 생성이 아직 안 된 경우 등) 처리를 스킵합니다.
            if (!@event.SessionId.HasValue)
            {
                _logger.LogWarning("LoginSuccessEvent received without SessionId for User {UserId}. Skipping session creation/update.", @event.UserId);
                return;
            }

            // (한글 주석) Non-nullable Guid로 변환 (null 체크 완료 후 안전하게 .Value 사용)
            var sessionId = @event.SessionId.Value;

            try
            {
                _logger.LogInformation("Creating/Updating session for User {UserId} (SessionId: {SessionId}).",
                    @event.UserId, sessionId);

                // (한글 주석) 1. 기존 세션 조회 (GetByIdAsync는 Guid를 받으므로 sessionId를 직접 전달)
                var existingSession = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);

                var currentTimeUtc = @event.OccurredAt.ToUniversalTime();
                var expirationTimeUtc = currentTimeUtc.AddMinutes(60);

                if (existingSession == null)
                {
                    // (한글 주석) 세션 생성 (첫 생성 시)
                    var newSession = new SessionEntity
                    {
                        Id = sessionId, // ❗️ 안전하게 할당
                        UserId = @event.UserId,
                        ConnectedId = @event.ConnectedId,
                        OrganizationId = @event.OrganizationId,

                        SessionToken = Guid.NewGuid().ToString(),
                        ExpiresAt = expirationTimeUtc,
                        LastActivityAt = currentTimeUtc,

                        IpAddress = @event.ClientIpAddress,
                        UserAgent = @event.UserAgent,
                        Status = SessionStatus.Active,
                        SessionType = SessionType.Web,
                        Level = @event.ConnectedId.HasValue ? SessionLevel.Organization : SessionLevel.Global
                    };

                    await _sessionRepository.AddAsync(newSession, cancellationToken);
                    _logger.LogInformation("Session {SessionId} created for User {UserId}.", sessionId, @event.UserId);
                }
                else
                {
                    // (한글 주석) 세션 업데이트
                    existingSession.LastActivityAt = currentTimeUtc;
                    existingSession.ExpiresAt = expirationTimeUtc;
                    existingSession.IpAddress = @event.ClientIpAddress;
                    existingSession.UserAgent = @event.UserAgent;
                    existingSession.Status = SessionStatus.Active;
                    _logger.LogInformation("Session {SessionId} updated and TTL refreshed for User {UserId}.", sessionId, @event.UserId);
                }

                // (한글 주석) 3. DB에 커밋
                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create/update session for User {UserId}, Session {SessionId}. Rolling back transaction.",
                    @event.UserId, sessionId); // sessionId 변수 사용
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}