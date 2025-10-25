// File: D:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UserJoinedOrganizationEventHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserJoinedOrganizationEvent를 처리합니다.
// (수정) 네비게이션 구조를 사용하도록 변경.
//        이제 이 핸들러는 '관계'만 생성하고 사용자 정보를 복사하지 않습니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
// using AuthHive.Core.Interfaces.User.Repository; // <-- 사용자 정보 조회가 필요 없으므로 삭제
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationMemberProfileRepository
using AuthHive.Core.Entities.Organization;         // The Entity
using Microsoft.Extensions.Logging;

// (네임스페이스는 사용자의 파일 경로에 맞게 가정합니다)
namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserJoinedOrganizationEvent"/>를 처리하는 핸들러입니다.
    /// (수정) 사용자 합류 시, '조직 멤버 프로필' 관계 레코드를 생성합니다.
    /// </summary>
    public class UserJoinedOrganizationEventHandler 
        : IDomainEventHandler<UserJoinedOrganizationEvent>
    {
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IOrganizationMemberProfileRepository _memberProfileRepository;
        // private readonly IUserRepository _userRepository; // <-- 의존성 제거
        private readonly ILogger<UserJoinedOrganizationEventHandler> _logger;

        public UserJoinedOrganizationEventHandler(
            IOrganizationMemberProfileRepository memberProfileRepository, // <-- 의존성 축소
            ILogger<UserJoinedOrganizationEventHandler> logger)
        {
            _memberProfileRepository = memberProfileRepository ?? throw new ArgumentNullException(nameof(memberProfileRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 합류 이벤트를 처리합니다.
        /// </summary>
        public async Task HandleAsync(UserJoinedOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("UserJoinedOrganizationEvent 수신. OrganizationId가 null입니다. (UserId: {UserId})", @event.UserId);
                return;
            }
            
            try
            {
                // --- 1. (수정) 사용자 조회 로직 삭제 ---
                _logger.LogInformation(
                    "[Lifecycle] User {UserId}가 Org {OrganizationId}에 합류. 프로필 관계 생성 시작. (ConnectedId: {ConnectedId})",
                    @event.UserId, @event.OrganizationId.Value, @event.ConnectedId);

                // --- 2. 읽기 모델 엔티티 생성 ---
                // (수정) Id, CreatedAt, UpdatedAt은 BaseEntity 또는 DB에서 처리한다고 가정합니다.
                //        이 핸들러는 3개의 핵심 FK만 할당합니다.
                var newProfileLink = new OrganizationMemberProfile
                {
                    OrganizationId = @event.OrganizationId.Value,
                    ConnectedId = @event.ConnectedId,
                    UserId = @event.UserId, // <-- User/UserProfile과 연결하는 FK
                    CreatedAt = @event.JoinedAt,
                    UpdatedAt = @event.JoinedAt
                };

                // --- 3. 읽기 모델 저장 ---
                // IOrganizationMemberProfileRepository의 UpsertAsync를 호출합니다.
                await _memberProfileRepository.UpsertAsync(newProfileLink, cancellationToken);

                _logger.LogInformation(
                    "조직 멤버 프로필(읽기 모델) 관계 생성 완료. (User: {UserId}, Org: {OrganizationId})",
                    @event.UserId,
                    @event.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "UserJoinedOrganizationEvent 처리 실패. (User: {UserId}, Org: {OrganizationId})",
                    @event.UserId,
                    @event.OrganizationId);
                
                throw; // 이벤트 버스의 재시도 메커니즘을 위해 예외를 다시 던집니다.
            }
        }
    }
}