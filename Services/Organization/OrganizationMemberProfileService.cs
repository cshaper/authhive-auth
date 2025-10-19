using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Reflection;
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
            if (performingConnectedId == null)
            {
                return ServiceResult<OrganizationMemberProfileDto>.Unauthorized("Unauthenticated access.");
            }

            var canView = await _authorizationService.CanViewMemberProfileAsync(performingConnectedId.Value, organizationId, connectedId, cancellationToken);
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
            if (performingConnectedId == null)
            {
                return ServiceResult<PagedResult<OrganizationMemberProfileDto>>.Unauthorized("Unauthenticated access.");
            }

            var canView = await _authorizationService.CanViewMembersAsync(performingConnectedId.Value, organizationId, cancellationToken);
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
            if (performingConnectedId == null)
            {
                return ServiceResult<OrganizationMemberProfileDto>.Unauthorized("Unauthenticated access.");
            }
            var canManage = await _authorizationService.CanManageMemberProfileAsync(performingConnectedId.Value, organizationId, targetConnectedId, cancellationToken);
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
            await _eventBus.PublishAsync(new MemberProfileUpdatedEvent(organizationId, targetConnectedId, performingConnectedId.Value), cancellationToken);
            await _auditService.LogActionAsync(
                AuditActionType.Update, "Member Profile Updated", performingConnectedId.Value, true,
                resourceType: "OrganizationMemberProfile", resourceId: profile.Id.ToString(), cancellationToken: cancellationToken);

            var dto = _mapper.Map<OrganizationMemberProfileDto>(profile);
            return ServiceResult<OrganizationMemberProfileDto>.Success(dto, "Profile updated successfully.");
        }

        public async Task<ServiceResult<OrganizationMemberProfileDto>> UpsertProfileAsync(
                    Guid organizationId,
                    Guid targetConnectedId,
                    UpdateOrganizationMemberProfileRequest request,
                    Guid updatedByConnectedId,
                    CancellationToken cancellationToken = default)
        {
            if (targetConnectedId != updatedByConnectedId)
            {
                // TODO: 관리자인지 확인하는 권한 검사 로직 필요
                return ServiceResult<OrganizationMemberProfileDto>.Forbidden("You do not have permission to update this profile.");
            }

            try
            {
                var profile = await _profileRepository.GetByConnectedIdAsync(organizationId, targetConnectedId, cancellationToken)
                              ?? new OrganizationMemberProfileEntity { ConnectedId = targetConnectedId, OrganizationId = organizationId };

                var changes = new Dictionary<string, (object? Old, object? New)>();

                UpdateProperty(profile, p => p.JobTitle, request.JobTitle, changes);
                UpdateProperty(profile, p => p.Department, request.Department, changes);
                UpdateProperty(profile, p => p.EmployeeId, request.EmployeeId, changes);
                UpdateProperty(profile, p => p.OfficeLocation, request.OfficeLocation, changes);
                UpdateProperty(profile, p => p.ManagerConnectedId, request.ManagerConnectedId, changes);

                if (!changes.Any())
                {
                    return ServiceResult<OrganizationMemberProfileDto>.Success(MapToDto(profile));
                }

                if (profile.Id == Guid.Empty) await _profileRepository.AddAsync(profile, cancellationToken);
                else await _profileRepository.UpdateAsync(profile, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await _auditService.LogActionAsync(
                    actionType: profile.Id == Guid.Empty ? AuditActionType.Create : AuditActionType.Update,
                    action: "MemberProfile.Upserted",
                    connectedId: updatedByConnectedId,
                    success: true,
                    resourceType: "OrganizationMemberProfile",
                    resourceId: profile.Id.ToString(),
                    metadata: changes.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value),
                    cancellationToken: cancellationToken);

                return ServiceResult<OrganizationMemberProfileDto>.Success(MapToDto(profile));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while upserting profile for {TargetConnectedId}", targetConnectedId);
                return ServiceResult<OrganizationMemberProfileDto>.Failure("An unexpected error occurred.");
            }
        }
        public async Task<ServiceResult<bool>> ChangeManagerAsync(Guid organizationId, Guid targetConnectedId, Guid? newManagerId, CancellationToken cancellationToken = default)
        {
            var performingConnectedId = _principalAccessor.ConnectedId;
            if (performingConnectedId == null)
            {
                return ServiceResult<bool>.Unauthorized("Unauthenticated access.");
            }
            var canManage = await _authorizationService.CanManageMemberProfileAsync(performingConnectedId.Value, organizationId, targetConnectedId, cancellationToken);
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
            await _eventBus.PublishAsync(new MemberProfileUpdatedEvent(organizationId, targetConnectedId, performingConnectedId.Value), cancellationToken);
            await _auditService.LogActionAsync(
                     AuditActionType.Update,
                     "Manager Changed",
                     performingConnectedId.Value,
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
            if (performingConnectedId == null)
            {
                return ServiceResult<IEnumerable<OrganizationMemberProfileDto>>.Unauthorized("Unauthenticated access.");
            }
            var canView = await _authorizationService.CanViewOrganizationDashboardAsync(performingConnectedId.Value, organizationId, cancellationToken);
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
            if (performingConnectedId == null)
            {
                return ServiceResult<OrganizationProfileStatisticsDto>.Unauthorized("Unauthenticated access.");
            }
            var canView = await _authorizationService.CanViewOrganizationDashboardAsync(performingConnectedId.Value, organizationId, cancellationToken);
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

        private static OrganizationMemberProfileDto MapToDto(OrganizationMemberProfileEntity profile)
        {
            return new OrganizationMemberProfileDto
            {
                Id = profile.Id, OrganizationId = profile.OrganizationId, ConnectedId = profile.ConnectedId,
                JobTitle = profile.JobTitle, Department = profile.Department, EmployeeId = profile.EmployeeId,
                OfficeLocation = profile.OfficeLocation, ManagerConnectedId = profile.ManagerConnectedId
            };
        }

        /// <summary>
        /// 속성 업데이트를 위한 헬퍼 메서드. 변경된 경우에만 값을 업데이트하고 changes 딕셔너리에 기록합니다.
        /// CS0103 오류를 해결하기 위해 이 메서드를 클래스 내부에 추가합니다.
        /// </summary>
        private static void UpdateProperty<T>(
              OrganizationMemberProfileEntity profile,
              Expression<Func<OrganizationMemberProfileEntity, T?>> propertyExpression,
              T? newValue,
              Dictionary<string, (object? Old, object? New)> changes)
        {
            if (propertyExpression.Body is not MemberExpression memberExpression)
                throw new ArgumentException("Expression must be a member expression.");

            var propertyInfo = (PropertyInfo)memberExpression.Member;
            var propertyName = propertyInfo.Name;
            var oldValue = (T?)propertyInfo.GetValue(profile);

            if (newValue != null && !EqualityComparer<T>.Default.Equals(oldValue, newValue))
            {
                changes[propertyName] = (oldValue, newValue);
                propertyInfo.SetValue(profile, newValue);
            }
        }

        /// <summary>
        /// Nullable 값 타입(예: Guid?, DateTime?)을 위한 UpdateProperty 오버로드입니다.
        /// </summary>
        private static void UpdateProperty<T>(
             OrganizationMemberProfileEntity profile,
             Expression<Func<OrganizationMemberProfileEntity, T?>> propertyExpression,
             T? newValue,
             Dictionary<string, (object? Old, object? New)> changes) where T : struct
        {
            if (propertyExpression.Body is not MemberExpression memberExpression)
                throw new ArgumentException("Expression must be a member expression.");

            var propertyInfo = (PropertyInfo)memberExpression.Member;
            var propertyName = propertyInfo.Name;
            var oldValue = (T?)propertyInfo.GetValue(profile);

            if (newValue.HasValue && !EqualityComparer<T?>.Default.Equals(oldValue, newValue))
            {
                changes[propertyName] = (oldValue, newValue);
                propertyInfo.SetValue(profile, newValue);
            }
        }
        #endregion
    }
}

