using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Base.Summaries.Organization;
using AutoMapper;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 기본 관리 서비스 - AuthHive v15
    /// 조직의 생성, 조회, 수정, 삭제 기본 작업만 담당
    /// 복잡한 기능은 다른 전문 서비스로 분리 (계층구조, 정책, SSO 등)
    /// </summary>
    public class OrganizationService : IOrganizationService
    {
        private readonly IOrganizationRepository _repository;
        private readonly IOrganizationCapabilityRepository _capabilityRepository;
        private readonly AuthDbContext _context;
        private readonly IMapper _mapper;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_PREFIX = "org:";
        private const string CACHE_KEY_BY_KEY = "org:key:";
        private const int CACHE_DURATION_MINUTES = 10;

        public OrganizationService(
            IOrganizationRepository repository,
            IOrganizationCapabilityRepository capabilityRepository,
            AuthDbContext context,
            IMapper mapper,
            IMemoryCache cache,
            ILogger<OrganizationService> logger)
        {
            _repository = repository;
            _capabilityRepository = capabilityRepository;
            _context = context;
            _mapper = mapper;
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Organization service health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region IOrganizationService Implementation

        /// <summary>
        /// 조직 ID로 조회
        /// </summary>
        public async Task<ServiceResult<OrganizationDto>> GetByIdAsync(
            Guid organizationId,
            bool includeInactive = false)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_PREFIX}{organizationId}";
                if (_cache.TryGetValue<OrganizationDto>(cacheKey, out var cachedOrg) && cachedOrg != null)
                {
                    if (!includeInactive && cachedOrg.Status != OrganizationStatus.Active)
                    {
                        return ServiceResult<OrganizationDto>.Failure("Organization is not active");
                    }
                    return ServiceResult<OrganizationDto>.Success(cachedOrg);
                }

                // Repository를 통해 조회 (Include로 Capabilities도 로드)
                var organization = await _context.Organizations
                    .Include(o => o.Capabilities)
                    .ThenInclude(c => c.Capability)
                    .FirstOrDefaultAsync(o => o.Id == organizationId);

                if (organization == null)
                {
                    return ServiceResult<OrganizationDto>.Failure($"Organization not found: {organizationId}");
                }

                // 상태 확인
                if (!includeInactive && organization.Status != OrganizationStatus.Active)
                {
                    return ServiceResult<OrganizationDto>.Failure("Organization is not active");
                }

                var dto = _mapper.Map<OrganizationDto>(organization);

                // 추가 계산 필드 설정
                dto.AdditionalCapabilitiesCount = organization.Capabilities?.Count ?? 0;
                dto.ApplicationsCount = await CountApplicationsAsync(organizationId);
                dto.ActiveMembersCount = await CountActiveMembersAsync(organizationId);

                // 캐시 저장
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(CACHE_DURATION_MINUTES),
                    Priority = CacheItemPriority.Normal
                };
                _cache.Set(cacheKey, dto, cacheOptions);

                return ServiceResult<OrganizationDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization by ID: {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDto>.Failure("Failed to retrieve organization");
            }
        }

        /// <summary>
        /// 조직 키로 조회
        /// </summary>
        public async Task<ServiceResult<OrganizationDto>> GetByKeyAsync(string organizationKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(organizationKey))
                {
                    return ServiceResult<OrganizationDto>.Failure("Organization key is required");
                }

                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_BY_KEY}{organizationKey}";
                if (_cache.TryGetValue<OrganizationDto>(cacheKey, out var cachedOrg) && cachedOrg != null)
                {
                    return ServiceResult<OrganizationDto>.Success(cachedOrg);
                }

                // Repository를 통해 조회
                var organization = await _repository.GetByOrganizationKeyAsync(organizationKey);
                if (organization == null)
                {
                    return ServiceResult<OrganizationDto>.Failure($"Organization not found: {organizationKey}");
                }

                var dto = _mapper.Map<OrganizationDto>(organization);

                // 추가 계산 필드 설정
                dto.AdditionalCapabilitiesCount = organization.Capabilities?.Count ?? 0;
                dto.ApplicationsCount = await CountApplicationsAsync(organization.Id);
                dto.ActiveMembersCount = await CountActiveMembersAsync(organization.Id);

                // 캐시 저장
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(CACHE_DURATION_MINUTES),
                    Priority = CacheItemPriority.Normal
                };
                _cache.Set(cacheKey, dto, cacheOptions);

                return ServiceResult<OrganizationDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization by key: {OrganizationKey}", organizationKey);
                return ServiceResult<OrganizationDto>.Failure("Failed to retrieve organization");
            }
        }

        /// <summary>
        /// 조직 상세 정보 조회
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> GetDetailAsync(Guid organizationId)
        {
            try
            {
                // Include로 관련 데이터 모두 로드
                var organization = await _context.Organizations
                    .Include(o => o.Capabilities)
                    .ThenInclude(c => c.Capability)
                    .FirstOrDefaultAsync(o => o.Id == organizationId);

                if (organization == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found");
                }

                var response = _mapper.Map<OrganizationDetailResponse>(organization);

                // 추가 정보 설정
                response.ParentId = organization.ParentId;
                response.Path = organization.Path ?? "/";
                response.Level = organization.Level;
                response.SortOrder = organization.SortOrder;
                response.EstablishedDate = organization.EstablishedDate;
                response.EmployeeRange = organization.EmployeeRange;
                response.Industry = organization.Industry;
                response.SuspendedAt = organization.SuspendedAt;
                response.SuspensionReason = organization.SuspensionReason;
                response.PolicyInheritanceMode = organization.PolicyInheritanceMode;
                response.UpdatedAt = organization.UpdatedAt;
                response.CreatedByConnectedId = organization.CreatedByConnectedId;
                response.UpdatedByConnectedId = organization.UpdatedByConnectedId;

                // 부모 조직 정보 조회
                if (organization.ParentId.HasValue)
                {
                    var parent = await _repository.GetByIdAsync(organization.ParentId.Value);
                    if (parent != null)
                    {
                        response.ParentOrganization = new OrganizationBasicInfo
                        {
                            OrganizationId = parent.Id,
                            Code = parent.OrganizationKey,
                            Name = parent.Name
                        };
                    }
                }

                // 추가 역할 정보 - Capability 엔티티가 로드되었다면 사용
                if (organization.Capabilities != null)
                {
                    foreach (var cap in organization.Capabilities.Where(c => !c.IsPrimary && c.IsActive))
                    {
                        // Capability navigation property가 로드되었는지 확인
                        var capabilityEnum = cap.Capability != null
                            ? MapToCapabilityEnum(cap.Capability.Code)
                            : OrganizationCapabilityEnum.Customer;

                        response.AdditionalCapabilities.Add(new OrganizationCapabilityInfo
                        {
                            CapabilityAssignmentId = cap.Id,
                            Capability = capabilityEnum,
                            IsActive = cap.IsActive,
                            IsInherited = false,
                            AssignedAt = cap.AssignedAt,
                            AssignedByConnectedId = cap.AssignedByConnectedId,
                            Settings = null
                        });
                    }
                }

                // 통계 정보
                var primaryCapability = organization.Capabilities?.FirstOrDefault(c => c.IsPrimary);
                var primaryCapabilityEnum = primaryCapability?.Capability?.Code != null
                    ? MapToCapabilityEnum(primaryCapability.Capability.Code)
                    : OrganizationCapabilityEnum.Customer;

                response.Statistics = new OrganizationStatistics
                {
                    OrganizationId = organizationId,
                    OrganizationName = organization.Name,
                    PrimaryCapability = primaryCapabilityEnum,
                    ApplicationCount = await CountApplicationsAsync(organizationId),
                    ActiveApplicationCount = await CountActiveApplicationsAsync(organizationId),
                    MemberCount = await CountTotalMembersAsync(organizationId),
                    ActiveMemberCount = await CountActiveMembersAsync(organizationId),
                    ChildOrganizationCount = await CountChildOrganizationsAsync(organizationId),
                    HierarchyDepth = organization.Level,
                    ActiveCapabilityCount = organization.Capabilities?.Count(c => c.IsActive) ?? 0,
                    LastActivityAt = organization.UpdatedAt,
                    GeneratedAt = DateTime.UtcNow,
                    NextRefreshAt = DateTime.UtcNow.AddHours(1),
                    OrganizationStatus = organization.Status.ToString()
                };

                return ServiceResult<OrganizationDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization detail: {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDetailResponse>.Failure("Failed to retrieve organization detail");
            }
        }

        /// <summary>
        /// 조직 생성
        /// </summary>
        public async Task<ServiceResult<CreateOrganizationResponse>> CreateAsync(
           CreateOrganizationRequest request,
           Guid createdByConnectedId)
        {
            try
            {
                // 유효성 검사
                var validationResult = await ValidateCreateRequestAsync(request);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<CreateOrganizationResponse>.Failure(validationResult.ErrorMessage!);
                }

                // 엔티티 생성
                var organization = new Core.Entities.Organization.Organization
                {
                    OrganizationKey = request.OrganizationKey,
                    Name = request.Name,
                    Description = request.Description,
                    Type = request.Type,
                    Status = OrganizationStatus.Active,
                    ParentId = request.ParentId,
                    Region = request.Region ?? "US",
                    LogoUrl = request.LogoUrl,
                    BrandColor = request.BrandColor,
                    Website = request.Website,
                    Industry = request.Industry,
                    EmployeeRange = request.EmployeeRange,
                    EstablishedDate = request.EstablishedDate,
                    Metadata = request.Metadata,
                    PolicyInheritanceMode = request.PolicyInheritanceMode ?? PolicyInheritanceMode.Inherit,
                    ActivatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = createdByConnectedId
                };

                // PrimaryCapability 설정 - enum을 기반으로 Capability 엔티티 조회
                if (request.PrimaryCapability.HasValue)
                {
                    var capabilityCode = request.PrimaryCapability.Value.ToString().ToUpper();
                    var capability = await _capabilityRepository.GetByCodeAsync(capabilityCode);

                    if (capability != null)
                    {
                        organization.Capabilities = new List<OrganizationCapabilityAssignment>
                        {
                            new OrganizationCapabilityAssignment
                            {
                                OrganizationId = organization.Id,
                                CapabilityId = capability.Id,
                                IsPrimary = true,
                                IsActive = true,
                                EnabledAt = DateTime.UtcNow,
                                AssignedAt = DateTime.UtcNow,
                                AssignedByConnectedId = createdByConnectedId
                            }
                        };
                    }
                }

                // Repository를 통해 저장
                var created = await _repository.AddAsync(organization);

                var response = new CreateOrganizationResponse
                {
                    Id = created.Id,
                    Name = created.Name,
                    OrganizationCode = created.OrganizationKey,
                    IsSuccess = true,
                    Message = "Organization created successfully",
                    CreatedAt = created.CreatedAt,
                    CreatedByConnectedId = createdByConnectedId
                };

                // 캐시 무효화
                InvalidateOrganizationCache(created.Id, created.OrganizationKey);

                _logger.LogInformation(
                    "Organization created successfully: {OrganizationKey} by ConnectedId: {ConnectedId}",
                    created.OrganizationKey,
                    createdByConnectedId);

                return ServiceResult<CreateOrganizationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create organization: {OrganizationKey}", request.OrganizationKey);
                return ServiceResult<CreateOrganizationResponse>.Failure("Failed to create organization");
            }
        }

        /// <summary>
        /// 조직 정보 수정
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> UpdateAsync(
            Guid organizationId,
            UpdateOrganizationRequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                // 기존 조직 조회
                var existing = await _repository.GetByIdAsync(organizationId);
                if (existing == null)
                {
                    return ServiceResult<OrganizationDetailResponse>.Failure("Organization not found");
                }

                // 변경사항 적용 (Required 필드는 항상 업데이트)
                existing.Name = request.Name;
                existing.Type = request.Type;
                existing.HierarchyType = request.HierarchyType;
                existing.Region = request.Region;
                existing.PolicyInheritanceMode = request.PolicyInheritanceMode;
                existing.SortOrder = request.SortOrder;

                // Optional 필드 업데이트
                if (request.Description != null)
                    existing.Description = request.Description;

                if (request.LogoUrl != null)
                    existing.LogoUrl = request.LogoUrl;

                if (request.BrandColor != null)
                    existing.BrandColor = request.BrandColor;

                if (request.Website != null)
                    existing.Website = request.Website;

                if (request.Industry != null)
                    existing.Industry = request.Industry;

                if (request.EmployeeRange != null)
                    existing.EmployeeRange = request.EmployeeRange;

                if (request.EstablishedDate != null)
                    existing.EstablishedDate = request.EstablishedDate;

                if (request.Metadata != null)
                    existing.Metadata = request.Metadata;

                existing.UpdatedByConnectedId = updatedByConnectedId;
                existing.UpdatedAt = DateTime.UtcNow;

                // Repository를 통해 업데이트
                await _repository.UpdateAsync(existing);

                // 캐시 무효화
                InvalidateOrganizationCache(organizationId, existing.OrganizationKey);

                // 상세 정보 조회 후 반환
                var detailResult = await GetDetailAsync(organizationId);

                _logger.LogInformation(
                    "Organization updated successfully: {OrganizationId} by ConnectedId: {ConnectedId}",
                    organizationId,
                    updatedByConnectedId);

                return detailResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update organization: {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDetailResponse>.Failure("Failed to update organization");
            }
        }

        /// <summary>
        /// 조직 삭제
        /// </summary>
        public async Task<ServiceResult> DeleteAsync(
            Guid organizationId,
            Guid deletedByConnectedId,
            string? reason = null)
        {
            try
            {
                // 하위 조직 확인
                var childrenCount = await CountChildOrganizationsAsync(organizationId);
                if (childrenCount > 0)
                {
                    return ServiceResult.Failure(
                        $"Cannot delete organization with {childrenCount} child organizations");
                }

                // 조직 조회
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult.Failure("Organization not found");
                }

                // Repository를 통해 삭제
                await _repository.DeleteAsync(organization);

                // 캐시 무효화
                InvalidateOrganizationCache(organizationId, organization.OrganizationKey);

                _logger.LogInformation(
                    "Organization deleted: {OrganizationId} by ConnectedId: {ConnectedId}, Reason: {Reason}",
                    organizationId,
                    deletedByConnectedId,
                    reason ?? "Not specified");

                return ServiceResult.Success($"Organization deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete organization: {OrganizationId}", organizationId);
                return ServiceResult.Failure("Failed to delete organization");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 생성 요청 유효성 검사
        /// </summary>
        private async Task<ServiceResult> ValidateCreateRequestAsync(CreateOrganizationRequest request)
        {
            // 조직 키 중복 확인
            if (await _repository.IsOrganizationKeyExistsAsync(request.OrganizationKey))
            {
                return ServiceResult.Failure($"Organization key '{request.OrganizationKey}' already exists");
            }

            // 조직명 중복 확인
            if (await _repository.IsNameExistsAsync(request.Name))
            {
                return ServiceResult.Failure($"Organization name '{request.Name}' already exists");
            }

            // 부모 조직 확인
            if (request.ParentId.HasValue)
            {
                var parent = await _repository.GetByIdAsync(request.ParentId.Value);
                if (parent == null)
                {
                    return ServiceResult.Failure("Parent organization not found");
                }

                if (parent.Status != OrganizationStatus.Active)
                {
                    return ServiceResult.Failure("Parent organization is not active");
                }
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// 애플리케이션 수 계산
        /// </summary>
        private async Task<int> CountApplicationsAsync(Guid organizationId)
        {
            return await _context.PlatformApplications
                .CountAsync(a => a.OrganizationId == organizationId && !a.IsDeleted);
        }

        /// <summary>
        /// 활성 애플리케이션 수 계산
        /// </summary>
        private async Task<int> CountActiveApplicationsAsync(Guid organizationId)
        {
            return await _context.PlatformApplications
                .CountAsync(a => a.OrganizationId == organizationId &&
                               a.Status == ApplicationStatus.Active &&
                               !a.IsDeleted);
        }

        /// <summary>
        /// 전체 멤버 수 계산
        /// </summary>
        private async Task<int> CountTotalMembersAsync(Guid organizationId)
        {
            return await _context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == organizationId && !m.IsDeleted);
        }

        /// <summary>
        /// 활성 멤버 수 계산
        /// </summary>
        private async Task<int> CountActiveMembersAsync(Guid organizationId)
        {
            return await _context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == organizationId &&
                               m.Status == OrganizationMembershipStatus.Active &&
                               !m.IsDeleted);
        }

        /// <summary>
        /// 하위 조직 수 계산
        /// </summary>
        private async Task<int> CountChildOrganizationsAsync(Guid organizationId)
        {
            var children = await _repository.GetChildOrganizationsAsync(organizationId, false);
            return children?.Count() ?? 0;
        }

        /// <summary>
        /// 캐시 무효화
        /// </summary>
        private void InvalidateOrganizationCache(Guid organizationId, string organizationKey)
        {
            _cache.Remove($"{CACHE_KEY_PREFIX}{organizationId}");
            _cache.Remove($"{CACHE_KEY_BY_KEY}{organizationKey}");
        }

        /// <summary>
        /// Capability 코드를 Enum으로 매핑
        /// </summary>
        private OrganizationCapabilityEnum MapToCapabilityEnum(string code)
        {
            return code?.ToUpper() switch
            {
                "CUSTOMER" => OrganizationCapabilityEnum.Customer,
                "RESELLER" => OrganizationCapabilityEnum.Reseller,
                "PROVIDER" => OrganizationCapabilityEnum.Provider,
                "PLATFORM" => OrganizationCapabilityEnum.Platform,
                "PARTNER" => OrganizationCapabilityEnum.Partner,
                _ => OrganizationCapabilityEnum.Customer
            };
        }

        #endregion
    }
}