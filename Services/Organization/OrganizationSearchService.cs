using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Constants.Common.CommonConstants;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 검색 서비스 구현 - AuthHive v15
    /// </summary>
    public class OrganizationSearchService : IOrganizationSearchService
    {
        private readonly IOrganizationSearchRepository _searchRepository;
        private readonly IOrganizationCapabilityRepository _capabilityRepository;
        private readonly IOrganizationCapabilityAssignmentRepository _capabilityAssignmentRepository;
        private readonly IMapper _mapper;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationSearchService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_USER_ORGS = "org_search:user_orgs:{0}";
        private const string CACHE_KEY_CONNECTED_ORGS = "org_search:connected_orgs:{0}";

        public OrganizationSearchService(
            IOrganizationSearchRepository searchRepository,
            IOrganizationCapabilityRepository capabilityRepository,
            IOrganizationCapabilityAssignmentRepository capabilityAssignmentRepository,
            IMapper mapper,
            IMemoryCache cache,
            ILogger<OrganizationSearchService> logger)
        {
            _searchRepository = searchRepository ?? throw new ArgumentNullException(nameof(searchRepository));
            _capabilityRepository = capabilityRepository ?? throw new ArgumentNullException(nameof(capabilityRepository));
            _capabilityAssignmentRepository = capabilityAssignmentRepository ?? throw new ArgumentNullException(nameof(capabilityAssignmentRepository));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                var testQuery = await _searchRepository.GetCountByStatusAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationSearchService health check failed");
                return false;
            }
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing OrganizationSearchService");
            await Task.CompletedTask;
            _logger.LogInformation("OrganizationSearchService initialized successfully");
        }

        #endregion

        #region IOrganizationSearchService Implementation

        /// <summary>
        /// 조직 검색
        /// </summary>
        public async Task<ServiceResult<OrganizationListResponse>> SearchAsync(
            OrganizationSearchRequest request)
        {
            try
            {
                if (request == null)
                {
                    return ServiceResult<OrganizationListResponse>.Failure(
                        "Search request cannot be null", 
                        "INVALID_REQUEST");
                }

                // 기본값 설정
                request.PageNumber = Math.Max(1, request.PageNumber);
                request.PageSize = Math.Min(100, Math.Max(1, request.PageSize));

                // PrimaryCapability 변환
                OrganizationCapabilityEnum? primaryCapabilityEnum = null;
                if (request.PrimaryCapability != null)
                {
                    primaryCapabilityEnum = ConvertToCapabilityEnum(request.PrimaryCapability.Code);
                }

                // Repository 호출
                var (organizations, totalCount) = await _searchRepository.SearchAsync(
                    searchTerm: request.Keyword,
                    status: request.Status,
                    type: request.Type,
                    primaryCapability: primaryCapabilityEnum,
                    region: request.Region,
                    parentOrganizationId: request.ParentId,
                    includeDescendants: request.IncludeChildren,
                    createdFrom: request.CreatedFrom,
                    createdTo: request.CreatedTo,
                    sortBy: request.SortBy ?? "Name",
                    sortDescending: request.SortDescending,
                    pageNumber: request.PageNumber,
                    pageSize: request.PageSize);

                // HasCapability 필터 적용
                if (request.HasCapability != null)
                {
                    var filteredOrgs = new List<AuthHive.Core.Entities.Organization.Organization>();
                    foreach (var org in organizations)
                    {
                        var hasCapability = await _capabilityAssignmentRepository.HasCapabilityAsync(
                            org.Id, request.HasCapability.Code);
                        if (hasCapability)
                        {
                            filteredOrgs.Add(org);
                        }
                    }
                    organizations = filteredOrgs;
                    totalCount = filteredOrgs.Count;
                }

                // DTO 변환
                var organizationResponses = new List<OrganizationResponse>();
                foreach (var org in organizations)
                {
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id);
                    
                    organizationResponses.Add(new OrganizationResponse
                    {
                        Id = org.Id,
                        OrganizationKey = org.OrganizationKey,
                        Name = org.Name,
                        Description = org.Description,
                        PrimaryCapability = primaryCapability,
                        Status = org.Status,
                        Type = org.Type,
                        HierarchyType = org.HierarchyType,
                        Region = org.Region,
                        LogoUrl = org.LogoUrl,
                        BrandColor = org.BrandColor,
                        Website = org.Website,
                        ActivatedAt = org.ActivatedAt,
                        CreatedAt = org.CreatedAt
                    });
                }

                var response = new OrganizationListResponse
                {
                    Items = organizationResponses,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                return ServiceResult<OrganizationListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching organizations");
                return ServiceResult<OrganizationListResponse>.Failure(
                    "An error occurred while searching organizations",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 사용자가 속한 조직 목록 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationDto>>> GetUserOrganizationsAsync(
            Guid userId)
        {
            try
            {
                if (userId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                        "Invalid user ID",
                        "INVALID_USER_ID");
                }

                // 캐시 확인
                var cacheKey = string.Format(CACHE_KEY_USER_ORGS, userId);
                if (_cache.TryGetValue<List<OrganizationDto>>(cacheKey, out var cachedOrgs) && cachedOrgs != null)
                {
                    _logger.LogDebug("User organizations retrieved from cache for user: {UserId}", userId);
                    return ServiceResult<IEnumerable<OrganizationDto>>.Success(cachedOrgs);
                }

                // Repository 호출
                var organizations = await _searchRepository.GetUserOrganizationsAsync(
                    userId, 
                    activeOnly: true, 
                    includeInherited: false);

                // DTO 변환
                var organizationDtos = new List<OrganizationDto>();
                foreach (var org in organizations)
                {
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id);
                    
                    var dto = new OrganizationDto
                    {
                        Id = org.Id,
                        OrganizationKey = org.OrganizationKey,
                        Name = org.Name,
                        Description = org.Description,
                        PrimaryCapability = ConvertToCapabilityEnum(primaryCapability?.Code ?? "CUSTOMER"),
                        Status = org.Status,
                        Type = org.Type,
                        HierarchyType = org.HierarchyType,
                        Region = org.Region,
                        LogoUrl = org.LogoUrl,
                        BrandColor = org.BrandColor,
                        Website = org.Website,
                        EstablishedDate = org.EstablishedDate,
                        EmployeeRange = org.EmployeeRange,
                        Industry = org.Industry,
                        ActivatedAt = org.ActivatedAt,
                        SuspendedAt = org.SuspendedAt,
                        SuspensionReason = org.SuspensionReason,
                        Metadata = org.Metadata,
                        PolicyInheritanceMode = org.PolicyInheritanceMode,
                        OrganizationId = org.Id,
                        ParentId = org.ParentOrganizationId,
                        Path = org.Path,
                        Level = org.Level,
                        SortOrder = org.SortOrder,
                        CreatedAt = org.CreatedAt,
                        UpdatedAt = org.UpdatedAt
                    };
                    
                    // 추가 통계 정보
                    var capabilities = await _capabilityAssignmentRepository.GetCapabilitiesAsync(org.Id);
                    dto.AdditionalCapabilitiesCount = capabilities.Count() - 1; // Primary 제외
                    
                    organizationDtos.Add(dto);
                }

                // 캐시 저장
                _cache.Set(cacheKey, organizationDtos, TimeSpan.FromMinutes(10));

                return ServiceResult<IEnumerable<OrganizationDto>>.Success(
                    organizationDtos,
                    $"Found {organizationDtos.Count} organization(s) for user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user organizations for user: {UserId}", userId);
                return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                    "An error occurred while retrieving user organizations",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// ConnectedId가 접근 가능한 조직 목록 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationDto>>> GetAccessibleOrganizationsAsync(
            Guid connectedId)
        {
            try
            {
                if (connectedId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                        "Invalid connected ID",
                        "INVALID_CONNECTED_ID");
                }

                // 캐시 확인
                var cacheKey = string.Format(CACHE_KEY_CONNECTED_ORGS, connectedId);
                if (_cache.TryGetValue<List<OrganizationDto>>(cacheKey, out var cachedOrgs) && cachedOrgs != null)
                {
                    _logger.LogDebug("Accessible organizations retrieved from cache for ConnectedId: {ConnectedId}", connectedId);
                    return ServiceResult<IEnumerable<OrganizationDto>>.Success(cachedOrgs);
                }

                // Repository 호출
                var allowedStatuses = new[] { 
                    OrganizationMembershipStatus.Active, 
                    OrganizationMembershipStatus.Pending 
                };
                
                var organizations = await _searchRepository.GetAccessibleOrganizationsAsync(
                    connectedId,
                    allowedStatuses,
                    minimumRole: null);

                // DTO 변환
                var organizationDtos = new List<OrganizationDto>();
                foreach (var org in organizations)
                {
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id);
                    
                    var dto = new OrganizationDto
                    {
                        Id = org.Id,
                        OrganizationKey = org.OrganizationKey,
                        Name = org.Name,
                        Description = org.Description,
                        PrimaryCapability = ConvertToCapabilityEnum(primaryCapability?.Code ?? "CUSTOMER"),
                        Status = org.Status,
                        Type = org.Type,
                        HierarchyType = org.HierarchyType,
                        Region = org.Region,
                        LogoUrl = org.LogoUrl,
                        BrandColor = org.BrandColor,
                        Website = org.Website,
                        EstablishedDate = org.EstablishedDate,
                        EmployeeRange = org.EmployeeRange,
                        Industry = org.Industry,
                        ActivatedAt = org.ActivatedAt,
                        SuspendedAt = org.SuspendedAt,
                        SuspensionReason = org.SuspensionReason,
                        Metadata = org.Metadata,
                        PolicyInheritanceMode = org.PolicyInheritanceMode,
                        OrganizationId = org.Id,
                        ParentId = org.ParentOrganizationId,
                        Path = org.Path,
                        Level = org.Level,
                        SortOrder = org.SortOrder,
                        CreatedAt = org.CreatedAt,
                        UpdatedAt = org.UpdatedAt
                    };
                    
                    organizationDtos.Add(dto);
                }

                // 캐시 저장
                _cache.Set(cacheKey, organizationDtos, TimeSpan.FromMinutes(5));

                return ServiceResult<IEnumerable<OrganizationDto>>.Success(
                    organizationDtos,
                    $"Found {organizationDtos.Count} accessible organization(s)");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting accessible organizations for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                    "An error occurred while retrieving accessible organizations",
                    "SYSTEM_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 조직의 Primary Capability 조회
        /// </summary>
        private async Task<OrganizationCapability?> GetPrimaryCapabilityForOrganization(Guid organizationId)
        {
            var primaryAssignment = await _capabilityAssignmentRepository.GetPrimaryCapabilityAsync(organizationId);
            return primaryAssignment?.Capability;
        }

        /// <summary>
        /// Capability 코드를 Enum으로 변환
        /// </summary>
        private OrganizationCapabilityEnum ConvertToCapabilityEnum(string code)
        {
            return code?.ToUpper() switch
            {
                SystemCapabilities.Customer => OrganizationCapabilityEnum.Customer,
                SystemCapabilities.Reseller => OrganizationCapabilityEnum.Reseller,
                SystemCapabilities.Provider => OrganizationCapabilityEnum.Provider,
                SystemCapabilities.Platform => OrganizationCapabilityEnum.Platform,
                SystemCapabilities.Partner => OrganizationCapabilityEnum.Partner,
                _ => OrganizationCapabilityEnum.Customer
            };
        }

        #endregion
    }
}