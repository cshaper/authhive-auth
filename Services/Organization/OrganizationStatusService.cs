using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
// Organization 엔티티를 별칭으로 사용
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Organization.Events;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 상태 관리 서비스 구현체 - AuthHive v15
    /// 조직의 활성화, 정지, 종료 등 상태 변경 비즈니스 로직 담당
    /// </summary>
    public class OrganizationStatusService : IOrganizationStatusService
    {
        private readonly IOrganizationStatusRepository _statusRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IMapper _mapper;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus;
        private readonly ILogger<OrganizationStatusService> _logger;

        public OrganizationStatusService(
            IOrganizationStatusRepository statusRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationHierarchyRepository hierarchyRepository,
            IDateTimeProvider dateTimeProvider,
            IMapper mapper,
            IUnitOfWork unitOfWork,
            IEventBus eventBus,
            ILogger<OrganizationStatusService> logger)
        {
            _statusRepository = statusRepository;
            _organizationRepository = organizationRepository;
            _hierarchyRepository = hierarchyRepository;
            _dateTimeProvider = dateTimeProvider;
            _mapper = mapper;
            _unitOfWork = unitOfWork;
            _eventBus = eventBus;
            _logger = logger;
        }

        #region IService Implementation
/// <summary>
/// 서비스 헬스 체크
/// </summary>
public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
{
    try
    {
        // Repository가 정상적으로 동작하는지 간단한 쿼리로 확인
        // CancellationToken을 CountAsync에 전달합니다. (일반적으로 CountAsync(predicate, token) 시그니처를 가정하고 null을 명시)
        _ = await _organizationRepository.CountAsync(null, cancellationToken); 
        return true;
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "OrganizationStatusService health check failed");
        return false;
    }
}

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken 추가
        {
            // 메서드 본문은 이미 최적화되어 Task.CompletedTask를 반환합니다.
            _logger.LogInformation("OrganizationStatusService initialized");
            return Task.CompletedTask;
        }
 
        #endregion

        #region IOrganizationStatusService Implementation

        /// <summary>
        /// 조직 활성화
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> ActivateAsync(
            Guid organizationId,
            Guid activatedByConnectedId)
        {
            try
            {
                _logger.LogInformation(
                    "Attempting to activate organization {OrganizationId} by {ConnectedId}",
                    organizationId, activatedByConnectedId);

                // 조직 조회
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found");
                }

                // 이미 활성화된 경우
                if (organization.Status == OrganizationStatus.Active)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization is already active");
                }

                // 삭제된 조직은 활성화 불가
                if (organization.IsDeleted)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        "Cannot activate a deleted organization");
                }

                // 상태 변경
                var updated = await _statusRepository.ChangeStatusAsync(
                    organizationId,
                    OrganizationStatus.Active,
                    activatedByConnectedId,
                    "Organization activated");

                if (updated == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Failed to activate organization");
                }

                // 응답 생성
                var response = await BuildDetailResponseAsync(updated);

                _logger.LogInformation(
                    "Organization {OrganizationId} activated successfully by {ConnectedId}",
                    organizationId, activatedByConnectedId);

                return ServiceResult<OrganizationDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to activate organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDetailResponse>.Failure(
                    "An error occurred while activating organization");
            }
        }

        /// <summary>
        /// 조직 정지
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> SuspendAsync(
            Guid organizationId,
            Guid suspendedByConnectedId,
            string reason)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(reason))
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        "Suspension reason is required");
                }

                _logger.LogInformation(
                    "Attempting to suspend organization {OrganizationId} by {ConnectedId}. Reason: {Reason}",
                    organizationId, suspendedByConnectedId, reason);

                // 조직 조회
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found");
                }

                // 이미 정지된 경우
                if (organization.Status == OrganizationStatus.Suspended)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization is already suspended");
                }

                // 삭제된 조직은 정지 불가
                if (organization.IsDeleted)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        "Cannot suspend a deleted organization");
                }

                // 활성 애플리케이션 확인 (경고만)
                var hasActiveApps = await _statusRepository.HasActiveApplicationsAsync(organizationId);
                if (hasActiveApps)
                {
                    _logger.LogWarning(
                        "Organization {OrganizationId} has active applications. They will be affected by suspension.",
                        organizationId);
                }

                // 상태 변경
                var updated = await _statusRepository.ChangeStatusAsync(
                    organizationId,
                    OrganizationStatus.Suspended,
                    suspendedByConnectedId,
                    reason);

                if (updated == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Failed to suspend organization");
                }

                // 정책에 따라 하위 조직도 정지할 수 있음
                if (organization.PolicyInheritanceMode == PolicyInheritanceMode.Merge)
                {
                    var affectedCount = await _statusRepository.UpdateChildOrganizationStatusAsync(
                        organizationId,
                        OrganizationStatus.Suspended,
                        suspendedByConnectedId,
                        $"Parent organization suspended: {reason}");

                    if (affectedCount > 0)
                    {
                        _logger.LogInformation(
                            "Suspended {Count} child organizations of {OrganizationId}",
                            affectedCount, organizationId);
                    }
                }

                // 응답 생성
                var response = await BuildDetailResponseAsync(updated);

                _logger.LogInformation(
                    "Organization {OrganizationId} suspended successfully by {ConnectedId}",
                    organizationId, suspendedByConnectedId);

                return ServiceResult<OrganizationDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to suspend organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDetailResponse>.Failure(
                    "An error occurred while suspending organization");
            }
        }

        /// <summary>
        /// 조직 상태 변경
        /// </summary>
        /// <summary>
        /// 조직의 상태를 변경하는 핵심 로직입니다.
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> ChangeStatusAsync(
            Guid organizationId,
            OrganizationStatus newStatus,
            Guid changedByConnectedId,
            string? reason = null)
        {
            try
            {
                _logger.LogInformation(
                    "Attempting to change status of organization {OrganizationId} to {NewStatus} by {ConnectedId}",
                    organizationId, newStatus, changedByConnectedId);

                var organization = await _organizationRepository.GetByIdAsync(organizationId);

                // 1. 기본 검증: 조직 존재 여부, 삭제 여부, 동일 상태 변경 방지
                if (organization == null || organization.IsDeleted)
                {
                    _logger.LogWarning("Organization {OrganizationId} not found or has been deleted.", organizationId);
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found or has been deleted");
                }
                if (organization.Status == newStatus)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure($"Organization is already in {newStatus} status");
                }

                // 2. 상태 전환 규칙 검증
                if (!IsValidStatusTransition(organization.Status, newStatus))
                {
                    _logger.LogWarning("Invalid status transition from {OldStatus} to {NewStatus} for organization {OrganizationId}",
                        organization.Status, newStatus, organizationId);
                    return ServiceResult<OrganizationDetailResponse>.Failure($"Invalid status transition from {organization.Status} to {newStatus}");
                }

                // ================================================================
                //              상세 비즈니스 규칙 구현 (TODO 완료)
                // ================================================================

                // 3. '해지(Terminated)' 상태로 변경 시, 삭제 전 추가 검증 수행
                if (newStatus == OrganizationStatus.Terminated)
                {
                    // 3-1. 활성 구독/결제 확인 (실제 구독 리포지토리가 필요합니다)
                    // if (await _subscriptionRepository.HasActiveSubscriptionsAsync(organizationId))
                    // {
                    //     _logger.LogWarning("Attempted to terminate organization {OrganizationId} with active subscriptions.", organizationId);
                    //     return ServiceResult<OrganizationDetailResponse>.Failure("Cannot terminate organization with active subscriptions");
                    // }

                    // 3-2. 삭제되지 않은 하위 조직이 있는지 확인
                    var children = await _hierarchyRepository.GetChildrenAsync(organizationId, true);
                    if (children?.Any(c => !c.IsDeleted) == true)
                    {
                        _logger.LogWarning("Attempted to terminate organization {OrganizationId} with active child organizations.", organizationId);
                        return ServiceResult<OrganizationDetailResponse>.Failure("Cannot terminate organization with child organizations that are not deleted");
                    }
                }

                // 4. 상태 변경 적용 및 연쇄 처리
                var oldStatus = organization.Status;
                organization.Status = newStatus;

                // 4-1. '해지' 상태이면 소프트 삭제(Soft Delete) 처리
                if (newStatus == OrganizationStatus.Terminated)
                {
                    organization.IsDeleted = true;
                    organization.DeletedAt = _dateTimeProvider.UtcNow;
                    organization.DeletedByConnectedId = changedByConnectedId;
                }

                var entitiesToUpdate = new List<AuthHive.Core.Entities.Organization.Organization> { organization };

                // 4-2. '정지' 또는 '해지' 상태이면 모든 하위 조직에 상태를 연쇄적으로 적용
                if (newStatus == OrganizationStatus.Suspended || newStatus == OrganizationStatus.Terminated)
                {
                    var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId);
                    foreach (var descendant in descendants.Where(d => !d.IsDeleted))
                    {
                        descendant.Status = newStatus;
                        if (newStatus == OrganizationStatus.Terminated)
                        {
                            descendant.IsDeleted = true;
                            descendant.DeletedAt = _dateTimeProvider.UtcNow;
                            descendant.DeletedByConnectedId = changedByConnectedId;
                        }
                        entitiesToUpdate.Add(descendant);
                    }
                }

                // 5. 데이터베이스에 모든 변경사항을 한번에 저장 (트랜잭션)
                foreach (var entity in entitiesToUpdate)
                {
                    await _organizationRepository.UpdateAsync(entity);
                }
                await _unitOfWork.CommitTransactionAsync();

                // 6. 상태별로 적절한 이벤트 발행
                // 6. 상태별로 적절한 이벤트 발행
                switch (newStatus)
                {
                    case OrganizationStatus.Active:
                        var activatedEvent = new OrganizationActivatedEvent(
                            organizationId,
                            oldStatus,
                            reason ?? "Organization activated",
                            changedByConnectedId);
                        await _eventBus.PublishAsync(activatedEvent);
                        break;

                    case OrganizationStatus.Suspended:
                        var suspendedEvent = new OrganizationSuspendedEvent(
                            organizationId,
                            oldStatus,
                            reason ?? "Organization suspended",
                            changedByConnectedId);
                        await _eventBus.PublishAsync(suspendedEvent);
                        break;

                    case OrganizationStatus.Terminated:
                        var deletedEvent = new OrganizationDeletedEvent(
                            organizationId,
                            reason ?? "Organization terminated",
                            true,  // isSoftDelete = true (소프트 삭제)
                            changedByConnectedId);
                        await _eventBus.PublishAsync(deletedEvent);
                        break;

                    case OrganizationStatus.Inactive:
                        var deactivatedEvent = new OrganizationDeactivatedEvent(
                            organizationId,
                            oldStatus,
                            reason ?? "Organization deactivated",
                            changedByConnectedId);
                        await _eventBus.PublishAsync(deactivatedEvent);
                        break;

                    default:
                        _logger.LogWarning("No specific event defined for status {Status}", newStatus);
                        break;
                }

                _logger.LogInformation("Successfully changed organization {OrganizationId} status from {OldStatus} to {NewStatus} and published event.",
                    organizationId, oldStatus, newStatus);

                var response = new OrganizationDetailResponse { Id = organization.Id, Name = organization.Name, Status = organization.Status };
                return ServiceResult<OrganizationDetailResponse>.Success(response, "Organization status changed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while changing status for organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDetailResponse>.Failure("An internal error occurred while changing organization status.");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 상태 전환 규칙 검증
        /// </summary>
        /// <summary>
        /// 조직 상태 전환이 유효한지 비즈니스 규칙에 따라 검증합니다.
        /// </summary>
        private bool IsValidStatusTransition(OrganizationStatus fromStatus, OrganizationStatus toStatus)
        {
            // 기존 코드의 간결한 switch 표현식 문법을 사용합니다.
            var validTransitions = fromStatus switch
            {
                // 로직은 제가 제안한 'Terminated'를 최종 상태로 사용하는 방식을 따릅니다.
                OrganizationStatus.Pending or OrganizationStatus.Rejected =>
                    new[] { OrganizationStatus.Active, OrganizationStatus.Approved },

                OrganizationStatus.Active or OrganizationStatus.Inactive =>
                    new[] { OrganizationStatus.Active, OrganizationStatus.Inactive, OrganizationStatus.Suspended, OrganizationStatus.Terminated },

                OrganizationStatus.Suspended =>
                    new[] { OrganizationStatus.Active, OrganizationStatus.Terminated },

                OrganizationStatus.Approved =>
                    new[] { OrganizationStatus.Active, OrganizationStatus.Suspended },

                // Terminated 상태에서는 더 이상 다른 상태로 전환할 수 없습니다.
                OrganizationStatus.Terminated => Array.Empty<OrganizationStatus>(),

                _ => Array.Empty<OrganizationStatus>()
            };

            return validTransitions.Contains(toStatus);
        }
        /// <summary>
        /// OrganizationDetailResponse 생성
        /// </summary>
        private Task<OrganizationDetailResponse> BuildDetailResponseAsync(OrganizationEntity organization)
        {
            var response = _mapper.Map<OrganizationDetailResponse>(organization);

            // 추가 정보 설정
            response.SuspendedAt = organization.SuspendedAt;
            response.SuspensionReason = organization.SuspensionReason;

            // 통계 정보는 간단하게
            response.Statistics = new Core.Models.Organization.Common.OrganizationStatistics
            {
                OrganizationId = organization.Id,
                OrganizationName = organization.Name,
                OrganizationStatus = organization.Status.ToString(),
                GeneratedAt = DateTime.UtcNow,
                NextRefreshAt = DateTime.UtcNow.AddMinutes(10)
            };

            return Task.FromResult(response);
        }

        #endregion
    }
}