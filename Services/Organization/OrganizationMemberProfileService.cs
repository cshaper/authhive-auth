using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Models.Organization.Requests;
using AutoMapper;
using Microsoft.Extensions.Logging;
using OrganizationMemberProfileEntity = AuthHive.Core.Entities.Organization.OrganizationMemberProfile;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 멤버 프로필 관리 서비스 구현체 - AuthHive v16
    /// 멤버의 직책, 부서, 관리자 등 조직 내 '인사 정보'에 대한 비즈니스 로직을 담당합니다.
    /// </summary>
    public class OrganizationMemberProfileService : IOrganizationMemberProfileService
    {
        private readonly IOrganizationMemberProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ICacheService _cacheService;
        private readonly ILogger<OrganizationMemberProfileService> _logger;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IAuthorizationService _authorizationService;
        private readonly IPrincipalAccessor _principalAccessor;

        public OrganizationMemberProfileService(
            IOrganizationMemberProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ICacheService cacheService,
            ILogger<OrganizationMemberProfileService> logger,
            IEventBus eventBus,
            IAuditService auditService,
            IAuthorizationService authorizationService,
            IPrincipalAccessor principalAccessor)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _cacheService = cacheService;
            _logger = logger;
            _eventBus = eventBus;
            _auditService = auditService;
            _authorizationService = authorizationService;
            _principalAccessor = principalAccessor;
        }

        #region IService Implementation
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                return await _unitOfWork.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationMemberProfileService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationMemberProfileService initialized.");
            return Task.CompletedTask;
        }
        #endregion

        #region Profile Read Operations

        public async Task<ServiceResult<OrganizationMemberProfileDto>> GetProfileAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canView = await _authorizationService.CanViewMemberProfileAsync(performingConnectedId, organizationId, connectedId, cancellationToken);
            if (!canView)
            {
                return ServiceResult<OrganizationMemberProfileDto>.Forbidden("Permission denied to view member profile.");
            }

            var cacheKey = $"org_member_profile:{organizationId}:{connectedId}";
            var cachedProfile = await _cacheService.GetAsync<OrganizationMemberProfileDto>(cacheKey, cancellationToken);
            if (cachedProfile != null) return ServiceResult<OrganizationMemberProfileDto>.Success(cachedProfile);

            var profile = await _profileRepository.GetByConnectedIdAsync(connectedId, organizationId, cancellationToken);
            if (profile == null)
            {
                return ServiceResult<OrganizationMemberProfileDto>.NotFound("Member profile not found.");
            }

            var dto = _mapper.Map<OrganizationMemberProfileDto>(profile);
            await _cacheService.SetAsync(cacheKey, dto, TimeSpan.FromMinutes(15), cancellationToken);

            return ServiceResult<OrganizationMemberProfileDto>.Success(dto);
        }

        public async Task<ServiceResult<PagedResult<OrganizationMemberProfileDto>>> GetProfilesAsync(Guid organizationId, GetOrganizationProfileRequest request, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canView = await _authorizationService.CanViewMembersAsync(performingConnectedId, organizationId, cancellationToken);
            if (!canView)
            {
                return ServiceResult<PagedResult<OrganizationMemberProfileDto>>.Forbidden("Permission denied to view member profiles.");
            }

            // TODO: request 객체의 SearchTerm, SortBy 등을 사용하여 동적 Predicate를 구성하는 로직 추가 필요
            var (items, totalCount) = await _profileRepository.GetPagedByOrganizationAsync(
                organizationId,
                request.PageNumber,
                request.PageSize,
                cancellationToken: cancellationToken
            );

            var dtos = _mapper.Map<IEnumerable<OrganizationMemberProfileDto>>(items);
            var pagedResult = new PagedResult<OrganizationMemberProfileDto>(dtos, totalCount, request.PageNumber, request.PageSize);

            return ServiceResult<PagedResult<OrganizationMemberProfileDto>>.Success(pagedResult);
        }

        #endregion

        #region Profile Write Operations

        public async Task<ServiceResult<OrganizationMemberProfileDto>> UpdateProfileAsync(Guid organizationId, Guid targetConnectedId, UpdateOrganizationProfileRequest request, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canManage = await _authorizationService.CanManageMemberProfileAsync(performingConnectedId, organizationId, targetConnectedId, cancellationToken);
            if (!canManage)
            {
                return ServiceResult<OrganizationMemberProfileDto>.Forbidden("Permission denied to update member profile.");
            }

            var profile = await _profileRepository.GetByConnectedIdAsync(targetConnectedId, organizationId, cancellationToken);
            if (profile == null)
            {
                return ServiceResult<OrganizationMemberProfileDto>.NotFound("Member profile not found.");
            }

            _mapper.Map(request, profile);

            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            await InvalidateProfileCacheAsync(organizationId, targetConnectedId, cancellationToken);
            await _eventBus.PublishAsync(new MemberProfileUpdatedEvent(organizationId, targetConnectedId, performingConnectedId), cancellationToken);
            await _auditService.LogActionAsync(
                AuditActionType.Update, "Member Profile Updated", performingConnectedId, true,
                resourceType: "OrganizationMemberProfile", resourceId: profile.Id.ToString(), cancellationToken: cancellationToken);

            var dto = _mapper.Map<OrganizationMemberProfileDto>(profile);
            return ServiceResult<OrganizationMemberProfileDto>.Success(dto, "Profile updated successfully.");
        }

        public async Task<ServiceResult<OrganizationMemberProfileDto>> UpsertProfileAsync(Guid organizationId, Guid targetConnectedId, UpdateOrganizationProfileRequest request, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canManage = await _authorizationService.CanManageMemberProfileAsync(performingConnectedId, organizationId, targetConnectedId, cancellationToken);
            if (!canManage)
            {
                return ServiceResult<OrganizationMemberProfileDto>.Forbidden("Permission denied to create or update member profile.");
            }

            var profile = await _profileRepository.GetByConnectedIdAsync(targetConnectedId, organizationId, cancellationToken);
            bool isNew = profile == null;

            if (isNew)
            {
                // isNew가 true이면, 새 인스턴스를 생성하므로 'profile'은 더 이상 null이 아닙니다.
                profile = new OrganizationMemberProfileEntity
                {
                    OrganizationId = organizationId,
                    ConnectedId = targetConnectedId
                };
                _mapper.Map(request, profile);
                await _profileRepository.AddAsync(profile, cancellationToken);
            }
            else
            {
                // isNew가 false이면, 'profile'은 이 블록에서 null이 아님이 보장됩니다.
                _mapper.Map(request, profile);

                // --- 수정된 부분 ---
                // '!' 연산자를 사용하여 컴파일러에게 null이 아님을 명시적으로 알려줍니다.
                await _profileRepository.UpdateAsync(profile!, cancellationToken);
            }

            await _unitOfWork.SaveChangesAsync(cancellationToken);
            await InvalidateProfileCacheAsync(organizationId, targetConnectedId, cancellationToken);
            await _eventBus.PublishAsync(new MemberProfileUpdatedEvent(organizationId, targetConnectedId, performingConnectedId), cancellationToken);

            var auditAction = isNew ? "Member Profile Created" : "Member Profile Updated";
            var auditType = isNew ? AuditActionType.Create : AuditActionType.Update;

            // if/else 블록 이후 'profile'은 null이 아니므로 '!'를 사용하여 경고를 제거합니다.
            await _auditService.LogActionAsync(auditType, auditAction, performingConnectedId, true,
                resourceType: "OrganizationMemberProfile", resourceId: profile!.Id.ToString(), cancellationToken: cancellationToken);

            var dto = _mapper.Map<OrganizationMemberProfileDto>(profile);
            return ServiceResult<OrganizationMemberProfileDto>.Success(dto, isNew ? "Profile created successfully." : "Profile updated successfully.");
        }

        public async Task<ServiceResult<bool>> ChangeManagerAsync(Guid organizationId, Guid targetConnectedId, Guid? newManagerId, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canManage = await _authorizationService.CanManageMemberProfileAsync(performingConnectedId, organizationId, targetConnectedId, cancellationToken);
            if (!canManage)
            {
                return ServiceResult<bool>.Forbidden("Permission denied to change manager.");
            }

            if (newManagerId.HasValue)
            {
                bool isCircular = await _profileRepository.CheckCircularReferenceAsync(targetConnectedId, newManagerId.Value, organizationId, cancellationToken);
                if (isCircular)
                {
                    return ServiceResult<bool>.Failure("Changing manager would create a circular reference.", "CIRCULAR_REFERENCE");
                }
            }

            var profile = await _profileRepository.GetByConnectedIdAsync(targetConnectedId, organizationId, cancellationToken);
            if (profile == null)
            {
                return ServiceResult<bool>.NotFound("Member profile not found.");
            }

            var oldManagerId = profile.ManagerConnectedId;
            profile.ManagerConnectedId = newManagerId;

            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            await InvalidateProfileCacheAsync(organizationId, targetConnectedId, cancellationToken);
            await _eventBus.PublishAsync(new MemberProfileUpdatedEvent(organizationId, targetConnectedId, performingConnectedId), cancellationToken);
            await _auditService.LogActionAsync(
                     AuditActionType.Update,
                     "Manager Changed",
                     performingConnectedId,
                     true,
                     resourceType: "OrganizationMemberProfile",
                     resourceId: profile.Id.ToString(),
                     metadata: new Dictionary<string, object>
                     {
                        { "OldManagerId", (object?)oldManagerId ?? "N/A" },
                        { "NewManagerId", (object?)newManagerId ?? "N/A" }
                     },
                     cancellationToken: cancellationToken);

            return ServiceResult<bool>.Success(true, "Manager changed successfully.");
        }

        #endregion

        #region Hierarchy & Statistics

        public async Task<ServiceResult<IEnumerable<OrganizationMemberProfileDto>>> GetOrganizationHierarchyAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canView = await _authorizationService.CanViewOrganizationDashboardAsync(performingConnectedId, organizationId, cancellationToken);
            if (!canView)
            {
                return ServiceResult<IEnumerable<OrganizationMemberProfileDto>>.Forbidden("Permission denied to view organization member hierarchy.");
            }

            var profiles = await _profileRepository.GetOrganizationHierarchyAsync(organizationId, null, cancellationToken);
            var dtos = _mapper.Map<IEnumerable<OrganizationMemberProfileDto>>(profiles);

            return ServiceResult<IEnumerable<OrganizationMemberProfileDto>>.Success(dtos);
        }

        // --- Corrected Method Name ---
        public async Task<ServiceResult<OrganizationProfileStatisticsDto>> GetProfileStatisticsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;

            var canView = await _authorizationService.CanViewOrganizationDashboardAsync(performingConnectedId, organizationId, cancellationToken);
            if (!canView)
            {
                return ServiceResult<OrganizationProfileStatisticsDto>.Forbidden("Permission denied to view profile statistics.");
            }

            var stats = new OrganizationProfileStatisticsDto
            {
                OrganizationId = organizationId,
                TotalProfiles = await _profileRepository.CountByOrganizationAsync(organizationId, cancellationToken: cancellationToken),
                ProfilesByDepartment = await _profileRepository.GetDepartmentStatisticsAsync(organizationId, cancellationToken),
                ProfilesByJobTitle = await _profileRepository.GetJobTitleStatisticsAsync(organizationId, cancellationToken),
                ProfilesByOfficeLocation = await _profileRepository.GetOfficeLocationStatisticsAsync(organizationId, cancellationToken),
                GeneratedAt = DateTime.UtcNow
            };

            return ServiceResult<OrganizationProfileStatisticsDto>.Success(stats);
        }

        #endregion

        #region Private Helpers
        private async Task InvalidateProfileCacheAsync(Guid organizationId, Guid connectedId, CancellationToken cancellationToken)
        {
            var memberCacheKey = $"org_member_profile:{organizationId}:{connectedId}";
            var memberListCachePattern = $"org_member_profiles:{organizationId}:*";

            await _cacheService.RemoveAsync(memberCacheKey, cancellationToken);
            await _cacheService.RemoveByPatternAsync(memberListCachePattern, cancellationToken);

            _logger.LogDebug("Invalidated profile caches for OrgId: {OrgId}, ConnId: {ConnId}", organizationId, connectedId);
        }
        #endregion
    }
}

