// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UserLeftOrganizationEventHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLeftOrganizationEvent의 첫 번째 핸들러입니다.
// 목적: OrganizationMemberProfile 읽기 모델을 삭제(정리)합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic; // For List<Guid>
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationMemberProfileRepository
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserLeftOrganizationEvent"/>를 처리하는 핸들러입니다.
    /// 사용자가 조직을 떠나면 '조직 멤버 프로필' 읽기 모델을 삭제(또는 비활성화)합니다.
    /// </summary>
    public class UserLeftOrganizationEventHandler 
        : IDomainEventHandler<UserLeftOrganizationEvent>
    {
        // 가장 먼저 실행되어야 하는 데이터 정리 작업
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IOrganizationMemberProfileRepository _memberProfileRepository;
        private readonly ILogger<UserLeftOrganizationEventHandler> _logger;

        public UserLeftOrganizationEventHandler(
            IOrganizationMemberProfileRepository memberProfileRepository,
            ILogger<UserLeftOrganizationEventHandler> logger)
        {
            _memberProfileRepository = memberProfileRepository ?? throw new ArgumentNullException(nameof(memberProfileRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 탈퇴 이벤트를 처리하여 읽기 모델을 삭제합니다.
        /// </summary>
        public async Task HandleAsync(UserLeftOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("UserLeftOrganizationEventHandler received. OrganizationId is null. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                _logger.LogInformation(
                    "[Lifecycle] User {UserId} left Org {OrganizationId}. Deleting read model profile... (ConnectedId: {ConnectedId}, Reason: {Reason})",
                    @event.UserId, 
                    @event.OrganizationId.Value, 
                    @event.ConnectedId,
                    @event.LeaveReason);

                // --- 1. 읽기 모델(Read Model) 삭제 ---
                // IOrganizationMemberProfileRepository에 정의된 벌크 삭제 메서드를 사용합니다.
                // (이 메서드가 IsDeleted 플래그를 설정하거나 물리적 삭제를 처리한다고 가정)
                var connectedIdsToRemove = new List<Guid> { @event.ConnectedId };

                int removeCount = await _memberProfileRepository.BulkRemoveFromOrganizationAsync(
                    connectedIdsToRemove,
                    @event.OrganizationId.Value,
                    cancellationToken
                );

                if (removeCount > 0)
                {
                    _logger.LogInformation(
                        "Organization member profile read model deleted successfully. (ConnectedId: {ConnectedId}, Org: {OrgId})",
                        @event.ConnectedId,
                        @event.OrganizationId.Value);
                }
                else
                {
                    // 이벤트는 발생했으나 읽기 모델이 이미 없는 경우 (데이터 불일치 또는 중복 처리)
                    _logger.LogWarning(
                        "Organization member profile read model was not found or not deleted. (ConnectedId: {ConnectedId}, Org: {OrgId})",
                        @event.ConnectedId,
                        @event.OrganizationId.Value);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Read model deletion was cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw; // 상위 작업이 취소되었으므로 다시 throw
            }
            catch (Exception ex)
            {
                // 읽기 모델 삭제 실패는 데이터 불일치를 초래할 수 있으므로 심각한 오류입니다.
                _logger.LogError(ex,
                    "Error in UserLeftOrganizationEventHandler. (ConnectedId: {ConnectedId}, Org: {OrgId})",
                    @event.ConnectedId,
                    @event.OrganizationId.Value);
                
                throw; // 이벤트 버스의 재시도 메커니즘을 위해 예외를 다시 던집니다.
            }
        }
    }
}
