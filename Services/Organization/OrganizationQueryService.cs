// 파일: AuthHive.Auth.Services.Organization/OrganizationQueryService.cs (최종 수정)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Audit; 
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Constants.Common.CommonConstants;
using AuthHive.Core.Interfaces.Audit;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// [v16 원칙 적용] 조직 조회 서비스 구현체 (CQRS Query Side)
    /// - IMemoryCache 제거, ICacheService 적용, CancellationToken 완벽 전달.
    /// - IAuditService 및 IPrincipalAccessor를 적용하여 감사 및 사용자 컨텍스트를 확보합니다.
    /// </summary>
    public class OrganizationQueryService : IOrganizationQueryService
    {
        private readonly IOrganizationQueryRepository _queryRepository;
        private readonly IOrganizationCapabilityAssignmentRepository _capabilityAssignmentRepository;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IMapper _mapper;
        private readonly ILogger<OrganizationQueryService> _logger;
        
        private readonly TimeSpan _userOrgsCacheExpiration = TimeSpan.FromMinutes(10);
        private readonly TimeSpan _connectedOrgsCacheExpiration = TimeSpan.FromMinutes(5);

        private const string CACHE_KEY_USER_ORGS = "OrgQuery:UserOrgs:{0}";
        private const string CACHE_KEY_CONNECTED_ORGS = "OrgQuery:ConnectedOrgs:{0}";

        public OrganizationQueryService(
            IOrganizationQueryRepository queryRepository, 
            IOrganizationCapabilityAssignmentRepository capabilityAssignmentRepository,
            IMapper mapper,
            ICacheService cacheService, 
            IAuditService auditService, 
            IPrincipalAccessor principalAccessor, 
            ILogger<OrganizationQueryService> logger)
        {
            _queryRepository = queryRepository ?? throw new ArgumentNullException(nameof(queryRepository));
            _capabilityAssignmentRepository = capabilityAssignmentRepository ?? throw new ArgumentNullException(nameof(capabilityAssignmentRepository));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _principalAccessor = principalAccessor ?? throw new ArgumentNullException(nameof(principalAccessor));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation (ASPIRE Ready)

        /// <summary>
        /// 서비스 상태 및 종속성(DB, Principal 접근)의 건강 상태를 확인합니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // .NET Aspire 환경을 위한 비동기 Principal 로딩 지원
            await _principalAccessor.GetPrincipalAsync(cancellationToken);
            try
            {
                // Repository를 통해 DB 연결 상태 확인
                await _queryRepository.CountAsync(cancellationToken: cancellationToken); 
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationQueryService health check failed");
                return false;
            }
        }
        
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationQueryService initialized successfully");
            return Task.CompletedTask;
        }

        #endregion

        #region IOrganizationQueryService Implementation

        /// <summary>
        /// 조직 검색 및 페이징된 목록 조회. 민감한 조회 작업이므로 감사 로그를 기록합니다.
        /// </summary>
        public async Task<ServiceResult<OrganizationListResponse>> SearchAsync(
            OrganizationSearchRequest request,
            CancellationToken cancellationToken = default)
        {
            // IPrincipalAccessor를 통해 요청 ConnectedId를 안전하게 확보합니다 (인증되지 않은 경우 Guid.Empty).
            Guid requesterConnectedId = _principalAccessor.ConnectedId ?? Guid.Empty; 
            
            try
            {
                if (request == null)
                {
                    return ServiceResult<OrganizationListResponse>.Failure(
                        "Search request cannot be null",
                        "INVALID_REQUEST");
                }
                
                // 안전장치 적용
                request.PageNumber = Math.Max(1, request.PageNumber);
                request.PageSize = Math.Min(1000, Math.Max(1, request.PageSize)); 

                // Repository 호출
                var pagedResult = await _queryRepository.SearchAsync(
                    searchTerm: request.Keyword,
                    status: request.Status,
                    type: request.Type,
                    pageNumber: request.PageNumber,
                    pageSize: request.PageSize,
                    cancellationToken: cancellationToken);
                
                // DTO 변환 및 Secondary Lookup
                var organizationResponses = new List<OrganizationResponse>();
                foreach (var org in pagedResult.Items)
                {
                    // Primary Capability 조회 시 CancellationToken 전달
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id, cancellationToken); 

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
                    TotalCount = pagedResult.TotalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                // 감사 로그 기록: 비용 최적화를 고려하여 성공적인 검색만 기록합니다.
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Read,
                    action: "ORG_SEARCH_SUCCESS",
                    connectedId: requesterConnectedId, 
                    success: true,
                    resourceType: "Organization",
                    resourceId: Guid.Empty.ToString(), 
                    metadata: new Dictionary<string, object> 
                    { 
                        { "SearchQuery", request.Keyword ?? "None" },
                        { "Status", request.Status?.ToString() ?? "All" }
                    },
                    cancellationToken: cancellationToken);
                
                return ServiceResult<OrganizationListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                // 실패 시 ConnectedId를 포함하여 에러 로그 기록
                Guid requesterConnectedIdForLog = _principalAccessor.ConnectedId ?? Guid.Empty;
                _logger.LogError(ex, "Error searching organizations by ConnectedId: {ConnectedId}", requesterConnectedIdForLog);
                
                return ServiceResult<OrganizationListResponse>.Failure(
                    "An error occurred while searching organizations",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 특정 User ID에 연결된 조직 목록을 조회합니다.
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationDto>>> GetUserOrganizationsAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (userId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                        "Invalid user ID",
                        "INVALID_USER_ID");
                }

                // ICacheService를 사용하여 캐시 확인 (Hybrid Cache)
                var cacheKey = string.Format(CACHE_KEY_USER_ORGS, userId);
                var cachedOrgs = await _cacheService.GetAsync<List<OrganizationDto>>(cacheKey, cancellationToken);

                if (cachedOrgs != null)
                {
                    _logger.LogDebug("User organizations retrieved from cache for user: {UserId}", userId);
                    return ServiceResult<IEnumerable<OrganizationDto>>.Success(cachedOrgs);
                }

                // Repository 호출
                var organizations = await _queryRepository.GetUserOrganizationsAsync(
                    userId,
                    activeOnly: true,
                    includeInherited: false,
                    cancellationToken: cancellationToken); 

                // DTO 변환 및 Secondary Lookup
                var organizationDtos = new List<OrganizationDto>();
                foreach (var org in organizations)
                {
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id, cancellationToken);
                    
                    // Secondary Lookup: Primary Capability를 제외한 Capability 수 계산
                    int additionalCapabilitiesCount = (await _capabilityAssignmentRepository.GetCapabilitiesAsync(org.Id, activeOnly: true, cancellationToken))?.Count() - 1 ?? 0;

                    var dto = new OrganizationDto
                    {
                        Id = org.Id,
                        OrganizationKey = org.OrganizationKey,
                        Name = org.Name,
                        Description = org.Description,
                        PrimaryCapability = ConvertToCapabilityEnum(primaryCapability?.Code ?? SystemCapabilities.Customer),
                        Status = org.Status,
                        Type = org.Type,
                        HierarchyType = org.HierarchyType,
                        // ✅ CS1061 해결: ParentOrganizationId 대신 ParentId를 사용합니다.
                        ParentId = org.ParentId, 
                        CreatedAt = org.CreatedAt,
                        UpdatedAt = org.UpdatedAt,
                        // Secondary Lookup 결과 할당
                        AdditionalCapabilitiesCount = additionalCapabilitiesCount 
                    };
                    organizationDtos.Add(dto);
                }

                // ICacheService를 사용하여 캐시 저장
                await _cacheService.SetAsync(cacheKey, organizationDtos, _userOrgsCacheExpiration, cancellationToken);

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
        /// ConnectedId가 접근 가능한 조직 목록을 조회합니다.
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationDto>>> GetAccessibleOrganizationsAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (connectedId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<OrganizationDto>>.Failure(
                        "Invalid connected ID",
                        "INVALID_CONNECTED_ID");
                }

                // ICacheService를 사용하여 캐시 확인
                var cacheKey = string.Format(CACHE_KEY_CONNECTED_ORGS, connectedId);
                var cachedOrgs = await _cacheService.GetAsync<List<OrganizationDto>>(cacheKey, cancellationToken);

                if (cachedOrgs != null)
                {
                    _logger.LogDebug("Accessible organizations retrieved from cache for ConnectedId: {ConnectedId}", connectedId);
                    return ServiceResult<IEnumerable<OrganizationDto>>.Success(cachedOrgs);
                }

                // Repository 호출
                var allowedStatuses = new[] {
                    OrganizationMembershipStatus.Active,
                    OrganizationMembershipStatus.Pending
                };

                var organizations = await _queryRepository.GetAccessibleOrganizationsAsync(
                    connectedId,
                    allowedStatuses,
                    cancellationToken: cancellationToken);

                // DTO 변환
                var organizationDtos = new List<OrganizationDto>();
                foreach (var org in organizations)
                {
                    var primaryCapability = await GetPrimaryCapabilityForOrganization(org.Id, cancellationToken);

                    var dto = new OrganizationDto
                    {
                        Id = org.Id,
                        OrganizationKey = org.OrganizationKey,
                        Name = org.Name,
                        Description = org.Description,
                        PrimaryCapability = ConvertToCapabilityEnum(primaryCapability?.Code ?? SystemCapabilities.Customer),
                        Status = org.Status,
                        Type = org.Type,
                        HierarchyType = org.HierarchyType,
                        // ✅ CS1061 해결: ParentOrganizationId 대신 ParentId를 사용합니다.
                        ParentId = org.ParentId,
                        CreatedAt = org.CreatedAt,
                        UpdatedAt = org.UpdatedAt,
                        AdditionalCapabilitiesCount = 0 
                    };

                    organizationDtos.Add(dto);
                }

                // ICacheService를 사용하여 캐시 저장
                await _cacheService.SetAsync(cacheKey, organizationDtos, _connectedOrgsCacheExpiration, cancellationToken);

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
        /// 조직의 Primary Capability 조회 (Repository 호출)
        /// </summary>
        private async Task<OrganizationCapability?> GetPrimaryCapabilityForOrganization(
            Guid organizationId, 
            CancellationToken cancellationToken)
        {
            var primaryAssignment = await _capabilityAssignmentRepository.GetPrimaryCapabilityAsync(organizationId, cancellationToken); 
            return primaryAssignment?.Capability;
        }

        /// <summary>
        /// Capability 코드를 Enum으로 안전하게 변환합니다.
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