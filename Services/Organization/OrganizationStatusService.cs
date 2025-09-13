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
        private readonly IMapper _mapper;
        private readonly ILogger<OrganizationStatusService> _logger;

        public OrganizationStatusService(
            IOrganizationStatusRepository statusRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationHierarchyRepository hierarchyRepository,
            IMapper mapper,
            ILogger<OrganizationStatusService> logger)
        {
            _statusRepository = statusRepository;
            _organizationRepository = organizationRepository;
            _hierarchyRepository = hierarchyRepository;
            _mapper = mapper;
            _logger = logger;
        }

        #region IService Implementation

        /// <summary>
        /// 서비스 헬스 체크
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository가 정상적으로 동작하는지 간단한 쿼리로 확인
                _ = await _organizationRepository.CountAsync();
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
        public Task InitializeAsync()
        {
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
                if (organization.Status == OrganizationStatus.Deleted)
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
                if (organization.Status == OrganizationStatus.Deleted)
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
        public async Task<ServiceResult<OrganizationDetailResponse>> ChangeStatusAsync(
            Guid organizationId,
            OrganizationStatus newStatus,
            Guid changedByConnectedId,
            string? reason = null)
        {
            try
            {
                _logger.LogInformation(
                    "Attempting to change organization {OrganizationId} status to {NewStatus} by {ConnectedId}",
                    organizationId, newStatus, changedByConnectedId);

                // 조직 조회
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found");
                }

                // 동일 상태로의 변경 방지
                if (organization.Status == newStatus)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        $"Organization is already in {newStatus} status");
                }

                // 상태 전환 규칙 검증
                if (!await ValidateStatusTransitionAsync(organization, newStatus))
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        $"Invalid status transition from {organization.Status} to {newStatus}");
                }

                // 삭제 시 추가 검증
                if (newStatus == OrganizationStatus.Deleted)
                {
                    // 활성 구독 확인
                    if (await _statusRepository.HasActiveSubscriptionsAsync(organizationId))
                    {
                        return ServiceResult<OrganizationDetailResponse>.Failure(
                            "Cannot delete organization with active subscriptions");
                    }

                    // 하위 조직 확인
                    var children = await _hierarchyRepository.GetChildrenAsync(organizationId, false);
                    if (children?.Any(c => c.Status != OrganizationStatus.Deleted) == true)
                    {
                        return ServiceResult<OrganizationDetailResponse>.Failure(
                            "Cannot delete organization with active child organizations");
                    }
                }

                // 상태 변경
                var updated = await _statusRepository.ChangeStatusAsync(
                    organizationId,
                    newStatus,
                    changedByConnectedId,
                    reason);

                if (updated == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure(
                        "Failed to change organization status");
                }

                // 응답 생성
                var response = await BuildDetailResponseAsync(updated);

                _logger.LogInformation(
                    "Organization {OrganizationId} status changed to {NewStatus} by {ConnectedId}",
                    organizationId, newStatus, changedByConnectedId);

                // TODO: 이벤트 발행 (Platform 서비스로)
                // await _eventPublisher.PublishAsync(new OrganizationStatusChangedEvent {...});

                return ServiceResult<OrganizationDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to change organization {OrganizationId} status to {NewStatus}",
                    organizationId, newStatus);
                return ServiceResult<OrganizationDetailResponse>.Failure(
                    "An error occurred while changing organization status");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 상태 전환 규칙 검증
        /// </summary>
        private async Task<bool> ValidateStatusTransitionAsync(
            OrganizationEntity organization,
            OrganizationStatus newStatus)
        {
            // 상태 전환 규칙
            var validTransitions = organization.Status switch
            {
                OrganizationStatus.Pending => new[] { 
                    OrganizationStatus.Active, 
                    OrganizationStatus.Approved,
                    OrganizationStatus.Rejected,
                    OrganizationStatus.Deleted 
                },
                OrganizationStatus.Active => new[] { 
                    OrganizationStatus.Suspended, 
                    OrganizationStatus.Inactive,
                    OrganizationStatus.Deleted 
                },
                OrganizationStatus.Suspended => new[] { 
                    OrganizationStatus.Active, 
                    OrganizationStatus.Deleted 
                },
                OrganizationStatus.Inactive => new[] { 
                    OrganizationStatus.Active,
                    OrganizationStatus.Deleted 
                },
                OrganizationStatus.Approved => new[] {
                    OrganizationStatus.Active,
                    OrganizationStatus.Suspended
                },
                OrganizationStatus.Rejected => new[] {
                    OrganizationStatus.Pending,
                    OrganizationStatus.Deleted
                },
                OrganizationStatus.Deleted => Array.Empty<OrganizationStatus>(),
                _ => Array.Empty<OrganizationStatus>()
            };

            var isValid = validTransitions.Contains(newStatus);

            if (isValid)
            {
                // Repository를 통한 추가 검증
                isValid = await _statusRepository.CanChangeStatusAsync(
                    organization.Id, 
                    organization.Status, 
                    newStatus);
            }

            return isValid;
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