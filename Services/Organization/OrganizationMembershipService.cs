// --- 1. 필요한 네임스페이스 선언 ---
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AutoMapper;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Auth.Service; // IAuthorizationService를 위해 추가
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Auth.ConnectedId.Events; // IConnectedIdRepository를 위해 추가

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 멤버십 관리 서비스 구현체 - AuthHive v16 최종 아키텍처 적용
    /// 이 서비스는 멤버십의 '생성, 조회, 수정, 삭제(CRUD)'와 관련된 핵심 비즈니스 로직을 담당합니다.
    /// '초대' 기능은 IInvitationService로 책임이 분리되었습니다.
    /// </summary>
    public class OrganizationMembershipService : IOrganizationMembershipService
    {
        // --- 2. 의존성 필드 선언: 이 서비스가 동작하기 위해 필요한 모든 부품들 ---
        private readonly IOrganizationMembershipRepository _membershipRepository; // 멤버십 데이터베이스 작업을 위한 레포지토리
        private readonly IConnectedIdRepository _connectedIdRepository;        // ConnectedId 조회를 위한 레포지토리 (UserId를 얻기 위함)
        private readonly IUnitOfWork _unitOfWork;                                 // 여러 DB 작업을 하나의 트랜잭션으로 묶기 위한 Unit of Work
        private readonly IMapper _mapper;                                         // 엔티티와 DTO 간의 데이터 변환을 위한 AutoMapper
        private readonly ICacheService _cacheService;                             // 분산 캐시(예: Redis) 작업을 위한 서비스
        private readonly ILogger<OrganizationMembershipService> _logger;          // 로그 기록을 위한 로거
        private readonly IEventBus _eventBus;                                     // 이메일 발송 등 부가 작업을 분리하기 위한 이벤트 버스
        private readonly IAuditService _auditService;                             // 주요 활동을 기록하기 위한 감사 서비스
        private readonly IAuthorizationService _authorizationService;             // 행위자의 권한을 검증하기 위한 서비스
        private readonly IPrincipalAccessor _principalAccessor;                    // 현재 요청을 수행하는 사용자의 정보(ID)에 접근하기 위한 객체

        /// <summary>
        /// 3. 생성자: 의존성 주입(DI) 컨테이너로부터 모든 의존성을 주입받습니다.
        /// </summary>
        public OrganizationMembershipService(
            IOrganizationMembershipRepository membershipRepository,
            IConnectedIdRepository connectedIdRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ICacheService cacheService,
            ILogger<OrganizationMembershipService> logger,
            IEventBus eventBus,
            IAuditService auditService,
            IAuthorizationService authorizationService,
            IPrincipalAccessor principalAccessor)
        {
            _membershipRepository = membershipRepository;
            _connectedIdRepository = connectedIdRepository;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _cacheService = cacheService;
            _logger = logger;
            _eventBus = eventBus;
            _auditService = auditService;
            _authorizationService = authorizationService;
            _principalAccessor = principalAccessor;
        }

        #region IService 기본 구현 (서비스 상태 점검 및 초기화)

        /// <summary>
        /// 서비스의 상태를 확인합니다. (주로 DB 연결 상태를 점검)
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Unit of Work를 통해 데이터베이스 연결이 가능한지 확인합니다.
                return await _unitOfWork.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                // 오류 발생 시 로그를 남기고 비정상 상태(false)를 반환합니다.
                _logger.LogError(ex, "OrganizationMembershipService health check failed.");
                return false;
            }
        }

        /// <summary>
        /// 서비스를 초기화합니다. (이 서비스는 별도 초기화 로직이 필요 없습니다)
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationMembershipService initialized.");
            // 즉시 완료된 작업을 반환합니다.
            return Task.CompletedTask;
        }
        #endregion

        #region 핵심 로직: 멤버십 활성화 (InvitationService로부터 호출)

        /// <summary>
        /// [중요] 초대 수락이 완료된 후, 실제 멤버십을 생성하고 활성화하는 메서드입니다.
        /// 이 메서드는 오직 IInvitationService에 의해서만 호출되어야 합니다.
        /// </summary>
        public async Task<ServiceResult<OrganizationMembershipDto>> ActivateInvitedMemberAsync(
            Guid organizationId,
            Guid connectedId,
            OrganizationMemberRole role,
            Guid invitedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // 방어 로직: 혹시 이미 활성화된 멤버인지 최종적으로 확인합니다.
            if (await _membershipRepository.IsMemberAsync(organizationId, connectedId, cancellationToken))
            {
                _logger.LogWarning("Attempted to activate an already active member. OrgId: {OrgId}, ConnId: {ConnId}", organizationId, connectedId);
                return ServiceResult<OrganizationMembershipDto>.Failure("User is already an active member.", "ALREADY_ACTIVE");
            }

            // 데이터베이스에 저장할 새로운 멤버십 엔티티 객체를 생성합니다.
            var membership = new OrganizationMembership
            {
                OrganizationId = organizationId,
                ConnectedId = connectedId,
                MemberRole = role,
                Status = OrganizationMembershipStatus.Active, // 상태를 '활성'으로 즉시 설정합니다.
                JoinedAt = DateTime.UtcNow,
                AcceptedAt = DateTime.UtcNow, // 초대 수락 시점을 기록합니다.
                CreatedByConnectedId = invitedByConnectedId
            };

            try
            {
                // 1. 데이터베이스에 새 멤버십 레코드를 추가합니다.
                var createdMembership = await _membershipRepository.AddAsync(membership, cancellationToken);
                // 2. Unit of Work를 통해 모든 변경사항을 하나의 트랜잭션으로 최종 저장(Commit)합니다.
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 3. 캐시 무효화: 데이터가 변경되었으므로, 관련된 캐시를 삭제하여 데이터 정합성을 유지합니다.
                await InvalidateMemberCachesAsync(organizationId, connectedId, cancellationToken);

                // 4. 이벤트 발행: '멤버가 합류함' 이벤트를 발행하기 위해 UserId를 조회합니다.
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                if (connectedIdEntity?.UserId == null)
                {
                    // UserId가 없는 치명적인 상황. 롤백을 고려해야 할 수 있으나, 여기서는 로그만 남기고 진행합니다.
                    _logger.LogError("Failed to publish MemberJoinedEvent: UserId not found for ConnectedId {ConnectedId}", connectedId);
                }
                else
                {
                    // ✅ CS7036 오류 해결: 생성자에 'userId'를 정확히 전달합니다.
                    await _eventBus.PublishAsync(new MemberJoinedEvent(organizationId, connectedId, connectedIdEntity.UserId.Value), cancellationToken);
                }

                // 5. 감사 로그 기록: "누가, 언제, 무엇을 했다"는 중요한 활동 기록을 남깁니다.
                await _auditService.LogActionAsync(
                    AuditActionType.Create,
                    "Member Activated",
                    invitedByConnectedId,
                    true,
                    errorMessage: null,
                    resourceType: "OrganizationMembership",
                    resourceId: createdMembership.Id.ToString(),
                    cancellationToken: cancellationToken);

                // 6. 성공 응답 반환: 생성된 엔티티를 클라이언트에게 전달할 DTO로 변환하여 성공 결과를 반환합니다.
                var dto = _mapper.Map<OrganizationMembershipDto>(createdMembership);
                return ServiceResult<OrganizationMembershipDto>.Success(dto);
            }
            catch (Exception ex)
            {
                // 예외 발생 시 로그를 남기고 실패 결과를 반환합니다.
                _logger.LogError(ex, "Failed to activate invited member for OrgId: {OrgId}, ConnId: {ConnId}", organizationId, connectedId);
                return ServiceResult<OrganizationMembershipDto>.Failure("An unexpected error occurred while activating the member.");
            }
        }

        #endregion

        #region 멤버 관리 (조회, 역할 변경, 제거)

        /// <summary>
        /// 멤버의 역할을 변경합니다.
        /// </summary>
        public async Task<ServiceResult<bool>> ChangeMemberRoleAsync(
            Guid organizationId,
            Guid targetConnectedId,
            OrganizationMemberRole newRole,
            CancellationToken cancellationToken = default) // 'changedByConnectedId' 파라미터 제거
        {
            // IPrincipalAccessor를 통해 현재 요청을 수행하는 사용자의 ID를 직접 가져옵니다.
            var changedByConnectedId = _principalAccessor.ConnectedId;
            if (changedByConnectedId == null)
            {
                // 401 Unauthorized 또는 403 Forbidden 반환
                return ServiceResult<bool>.Unauthorized("User is not authenticated.");
            }

            // 1. 권한 검증: 이 작업을 수행할 권한이 있는지 확인합니다.
            var canChange = await _authorizationService.CanManageMemberRoleAsync(changedByConnectedId.Value, targetConnectedId, newRole, cancellationToken);
            if (!canChange)
            {
                _logger.LogWarning("Permission denied: {ChangerId} tried to change role of {TargetId} in org {OrgId}", changedByConnectedId.Value, targetConnectedId, organizationId);
                return ServiceResult<bool>.Forbidden("You do not have permission to change this member's role.");
            }

            // 2. 대상 멤버십 정보를 조회합니다.
            var membership = await _membershipRepository.GetMembershipAsync(organizationId, targetConnectedId, cancellationToken);
            if (membership == null)
            {
                return ServiceResult<bool>.NotFound("Target member not found.");
            }

            // 3. 비즈니스 로직 수행: 엔티티의 역할을 변경하고 변경 정보를 기록합니다.
            var oldRole = membership.MemberRole;
            membership.MemberRole = newRole;
            membership.UpdatedByConnectedId = changedByConnectedId;

            // 4. 데이터베이스에 변경사항을 반영합니다.
            await _membershipRepository.UpdateAsync(membership, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 5. 후속 작업: 캐시 무효화 및 감사 로그 기록
            await InvalidateMemberCachesAsync(organizationId, targetConnectedId, cancellationToken);
            await _auditService.LogActionAsync(
                AuditActionType.Update,
                "Member Role Changed",
                connectedId: changedByConnectedId.Value,
                true,
                errorMessage: null,
                resourceType: "OrganizationMembership",
                resourceId: membership.Id.ToString(),
                metadata: new Dictionary<string, object> { { "OldRole", oldRole.ToString() }, { "NewRole", newRole.ToString() } },
                cancellationToken: cancellationToken);

            // 6. 성공 결과를 반환합니다.
            return ServiceResult<bool>.Success(true);
        }

        /// <summary>
        /// 멤버를 조직에서 제거합니다 (Soft Delete).
        /// </summary>
        public async Task<ServiceResult<bool>> RemoveMemberAsync(
            Guid organizationId,
            Guid targetConnectedId,
            string reason,
            CancellationToken cancellationToken = default)
        {
            // IPrincipalAccessor를 통해 현재 요청을 수행하는 사용자의 ID를 직접 가져옵니다.
            var removedByConnectedId = _principalAccessor.ConnectedId;
            if (removedByConnectedId == null)
            {
                // 401 Unauthorized 또는 403 Forbidden 반환
                return ServiceResult<bool>.Unauthorized("User is not authenticated.");
            }
            // 1. 권한 검증: 멤버를 제거할 수 있는 관리자인지 확인합니다.
            var canRemove = await _authorizationService.CanManageMembersAsync(removedByConnectedId.Value, organizationId, cancellationToken);
            if (!canRemove)
            {
                return ServiceResult<bool>.Forbidden("You do not have permission to remove members from this organization.");
            }

            // 2. 대상 멤버십 정보를 조회합니다.
            var membership = await _membershipRepository.GetMembershipAsync(organizationId, targetConnectedId, cancellationToken);
            if (membership == null)
            {
                return ServiceResult<bool>.NotFound("Member not found.");
            }

            // 3. 비즈니스 규칙: 조직의 소유자(Owner)는 제거할 수 없도록 방어합니다.
            if (membership.MemberRole == OrganizationMemberRole.Owner)
            {
                return ServiceResult<bool>.Failure("Organization owner cannot be removed. Transfer ownership first.", "OWNER_CANNOT_BE_REMOVED");
            }

            // 4. 데이터베이스 작업: 실제 데이터를 삭제하는 대신 'IsDeleted' 플래그를 true로 설정합니다 (Soft Delete).
            await _membershipRepository.SoftDeleteAsync(membership.Id, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 5. 후속 작업: 캐시 무효화 및 감사 로그 기록
            await InvalidateMemberCachesAsync(organizationId, targetConnectedId, cancellationToken);
            await _auditService.LogActionAsync(
                AuditActionType.Delete,
                "Member Removed",
                connectedId: removedByConnectedId.Value,
                true,
                errorMessage: null,
                resourceType: "OrganizationMembership",
                resourceId: membership.Id.ToString(),
                metadata: new Dictionary<string, object> { { "Reason", reason } },
                cancellationToken: cancellationToken);

            // 6. 성공 결과를 반환합니다.
            return ServiceResult<bool>.Success(true);
        }

        #endregion

        #region Private Helper Methods (내부 지원 메서드)

        /// <summary>
        /// 멤버 정보가 변경되었을 때 관련된 캐시(개별 멤버, 멤버 목록)를 모두 삭제하여 데이터 일관성을 유지합니다.
        /// </summary>
        private async Task InvalidateMemberCachesAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken)
        {
            // 특정 멤버의 상세 정보 캐시 키 (예: org_member:ORG_ID:CONN_ID)
            var memberCacheKey = $"org_member:{organizationId}:{connectedId}";
            // 조직의 전체 멤버 목록 캐시를 위한 패턴 (예: org_members:ORG_ID:*)
            var memberListCacheKeyPattern = $"org_members:{organizationId}:*";

            _logger.LogDebug("Invalidating caches for OrgId: {OrgId}, ConnId: {ConnId}", organizationId, connectedId);

            // 개별 멤버 캐시와 목록 캐시를 모두 삭제합니다.
            await _cacheService.RemoveAsync(memberCacheKey, cancellationToken);
            await _cacheService.RemoveByPatternAsync(memberListCacheKeyPattern, cancellationToken);
        }

        #endregion

        #region 미구현 메서드 (인터페이스 계약 유지를 위함)
        // 아래 메서드들은 위에서 보여준 패턴(권한 검증 -> DB 작업 -> 캐시 무효화 -> 이벤트/감사)에 따라 구현되어야 합니다.
        public Task<ServiceResult<PagedResult<OrganizationMembershipDto>>> GetMembersAsync(Guid organizationId, OrganizationMembershipStatus? status, OrganizationMemberRole? role, int pageNumber, int pageSize, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<OrganizationMembershipDto>> GetMemberAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ChangeMemberStatusAsync(Guid organizationId, Guid targetConnectedId, OrganizationMembershipStatus newStatus, string? reason, Guid changedByConnectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<BulkOperationResult>> BulkInviteMembersAsync(Guid organizationId, BulkInviteRequest request, Guid invitedByConnectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<MemberPermissionsDto>> GetMemberPermissionsAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> LeaveOrganizationAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> RenewMembershipAsync(Guid organizationId, Guid connectedId, DateTime newExpiryDate, Guid renewedByConnectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<OrganizationMemberStatistics>> GetStatisticsAsync(Guid organizationId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<int>> CleanupInactiveMembersAsync(Guid organizationId, int inactiveDays, Guid cleanedByConnectedId, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ChangeMembershipTypeAsync(Guid organizationId, Guid connectedId, OrganizationMembershipType newType, Guid changedByConnectedId, CancellationToken cancellationToken) => throw new NotImplementedException();

        // 이 메서드들은 InvitationService로 책임이 이전되었으므로 여기서는 구현하지 않습니다.
        // 인터페이스에서 제거하는 것이 가장 좋습니다.
        public Task<ServiceResult<OrganizationMembershipDto>> InviteMemberAsync(Guid organizationId, string email, OrganizationMemberRole role, Guid invitedByConnectedId, DateTime? expiresAt = null, CancellationToken cancellationToken = default) => throw new NotSupportedException("Use IInvitationService to invite members.");
        public Task<ServiceResult<OrganizationMembershipDto>> AcceptInvitationAsync(string invitationToken, Guid connectedId, CancellationToken cancellationToken = default) => throw new NotSupportedException("Use IInvitationService to accept invitations.");
        public Task<bool> UpdateMemberStatusAsync(Guid organizationId, Guid connectedId, OrganizationMembershipStatus newStatus, Guid updatedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        #endregion
    }
}