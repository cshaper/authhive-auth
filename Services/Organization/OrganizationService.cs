using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using Microsoft.EntityFrameworkCore;
using AutoMapper;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Auth.Middleware;
using System.Net;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 기본 관리 서비스 - AuthHive v16 (Finalized)
    /// WHY: 조직 관리의 핵심 비즈니스 규칙을 적용하고, Repository와 책임을 분리합니다.
    /// </summary>
    public class OrganizationService : IOrganizationService
    {
        // 1. 필드 선언 (IMemoryCache 제거, ICacheService 및 핵심 서비스 추가)
        private readonly IOrganizationRepository _repository;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IOrganizationCapabilityRepository _capabilityRepository;
        private readonly IAuthorizationService _authorizationService;
        private readonly IConnectedIdService _connectedIdService;       // ✅ Owner ConnectedId 생성
        private readonly IRoleService _roleService;                     // ✅ Owner 역할 생성
        private readonly IPlanRestrictionService _planRestrictionService; // ✅ 조직 수 제한 검증
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus;
        private readonly AuthDbContext _context;
        private readonly IMapper _mapper;
        private readonly ICacheService _cacheService;
        private readonly ILogger<OrganizationService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_PREFIX = "org:";
        private const string CACHE_KEY_BY_KEY = "org:key:";
        private const int CACHE_DURATION_MINUTES = 10;

        public OrganizationService(
            IOrganizationRepository repository,
            IOrganizationHierarchyRepository hierarchyRepository,
            IOrganizationCapabilityRepository capabilityRepository,
            IAuthorizationService authorizationService,
            IConnectedIdService connectedIdService,
            IRoleService roleService,
            IPlanRestrictionService planRestrictionService,
            IUnitOfWork unitOfWork,
            IEventBus eventBus,
            AuthDbContext context,
            IMapper mapper,
            ICacheService cacheService,
            ILogger<OrganizationService> logger)
        {
            _repository = repository;
            _hierarchyRepository = hierarchyRepository;
            _capabilityRepository = capabilityRepository;
            _authorizationService = authorizationService;
            _connectedIdService = connectedIdService;
            _roleService = roleService;
            _planRestrictionService = planRestrictionService;
            _unitOfWork = unitOfWork;
            _eventBus = eventBus;
            _context = context;
            _mapper = mapper;
            _cacheService = cacheService;
            _logger = logger;
        }

        #region IService Implementation
        // OrganizationService.cs

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Pass the token to the underlying database connection check.
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Organization service health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            // The method body is already optimized for returning a completed task.
            _logger.LogInformation("OrganizationService initialized");
            return Task.CompletedTask;
        }


        #endregion

        #region IOrganizationService Implementation

        /// <summary>
        /// 조직 ID로 조회
        /// WHO: 인증된 사용자, 시스템 서비스
        /// WHEN: 조직 상세 정보 조회, 권한 검증 시
        /// WHERE: API 엔드포인트, 내부 서비스 호출
        /// WHAT: 조직 기본 정보 반환
        /// WHY: 조직 정보 표시 및 권한 검증 기반 데이터
        /// HOW: 캐시 확인 → Repository 조회 → DTO 매핑 → 캐싱
        /// </summary>
        public async Task<ServiceResult<OrganizationResponse>> GetByIdAsync(
                 Guid organizationId,
                 Guid currentUserConnectedId,
                 bool includeInactive = false,
                 CancellationToken cancellationToken = default)
        {
            var isAuthorized = await _authorizationService.CanAccessOrganizationAsync(
            organizationId, cancellationToken: cancellationToken);
    
            if (!isAuthorized)
            {
                // 권한이 없으면 AuthHiveForbiddenException을 발생시켜 Middleware가 처리하도록 합니다.
                throw new AuthHiveForbiddenException("You do not have permission to access this organization.");
            }
            try
            {
                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_PREFIX}{organizationId}";
                var cachedOrg = await _cacheService.GetAsync<OrganizationResponse>(cacheKey, cancellationToken);
                if (cachedOrg != null)
                {
                    if (!includeInactive && cachedOrg.Status.ToString() != OrganizationStatus.Active.ToString())
                    {
                        return ServiceResult<OrganizationResponse>.Failure("Organization is not active");
                    }
                    return ServiceResult<OrganizationResponse>.Success(cachedOrg);
                }

                // 2. Repository를 통해 조회 (Repository 패턴 준수)
                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);

                if (organization == null)
                {
                    // Throw the specific exception for "Not Found"
                    throw new AuthHiveNotFoundException($"Organization not found with ID: {organizationId}");
                }

                // 3. 상태 확인
                if (!includeInactive && organization.Status != OrganizationStatus.Active)
                {
                    return ServiceResult<OrganizationResponse>.Failure("Organization is not active");
                }

                var dto = _mapper.Map<OrganizationResponse>(organization);

                if (organization.Capabilities != null)
                {
                    // 4-1. 활성 상태인 Capability Assignment만 필터링합니다. (IsActive = true)
                    dto.ActiveCapabilities = organization.Capabilities
                        .Where(ca => ca.IsActive)
                        // 4-2. OrganizationCapabilityAssignment 엔티티를 DTO (OrganizationCapabilityInfo)로 매핑합니다.
                        .Select(ca =>
                        {
                            var info = _mapper.Map<OrganizationCapabilityInfo>(ca);
                            // Capability Code 매핑 (예: "PROVIDER" -> OrganizationCapabilityEnum.Provider)
                            info.Capability = MapToCapabilityEnum(ca.Capability?.Code);
                            return info;
                        })
                        .ToList();
                }
                // 5. [수정된 로직] 애플리케이션 목록 조회 및 DTO에 할당

                // 5-1. 목록 조회: 이름과 카테고리(Type)를 포함한 목록을 조회합니다.
                var applicationList = await GetApplicationBasicInfoListAsync(organizationId, cancellationToken);
                dto.ApplicationsList = applicationList;

                // 5-2. 개수 설정: 목록의 Count를 ApplicationsCount에 할당하여 일관성을 유지합니다.
                dto.ApplicationsCount = applicationList.Count;

                // 활성 멤버 수 계산 (Strict Pricing Enforcement의 기반 데이터)
                dto.ActiveMembersCount = await CountActiveMembersAsync(organizationId, cancellationToken);

                // 5. 캐시 저장 (ICacheService 사용)
                await _cacheService.SetAsync(
                    cacheKey,
                    dto,
                    TimeSpan.FromMinutes(CACHE_DURATION_MINUTES),
                    cancellationToken);

                return ServiceResult<OrganizationResponse>.Success(dto);

            }
            catch (AuthHiveException)
            {
                // Let our specific, known exceptions bubble up directly to the middleware.
                throw;
            }
            catch (Exception ex)
            {
                // Catch any other unexpected exception.
                _logger.LogError(ex, "An unexpected error occurred while getting organization by ID: {OrganizationId}", organizationId);

                // Rethrow to let the middleware handle it as a generic 500 Internal Server Error.
                throw;
            }
        }


        /// <summary>
        /// 조직 키로 조회
        /// WHO: 외부 API 클라이언트, SSO 프로세스
        /// HOW: 캐시 확인(ICacheService) → Repository 조회 → DTO 매핑(목록 포함) → 캐싱
        /// </summary>
        public async Task<ServiceResult<OrganizationResponse>> GetByKeyAsync(
            string organizationKey,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(organizationKey))
                {
                    return ServiceResult<OrganizationResponse>.Failure("Organization key is required");
                }

                // 1. 캐시 확인 (ICacheService 사용)
                var cacheKey = $"{CACHE_KEY_BY_KEY}{organizationKey}";
                // [수정] _cache.TryGetValue 대신 await _cacheService.GetAsync 사용
                var cachedOrg = await _cacheService.GetAsync<OrganizationResponse>(cacheKey, cancellationToken);

                if (cachedOrg != null)
                {
                    return ServiceResult<OrganizationResponse>.Success(cachedOrg);
                }

                // 2. Repository를 통해 조회
                var organization = await _repository.GetByOrganizationKeyAsync(organizationKey, cancellationToken); // ✅ Token 전달
                if (organization == null)
                {
                    return ServiceResult<OrganizationResponse>.Failure($"Organization not found: {organizationKey}");
                }

                // 3. DTO 매핑 및 통계 계산 (GetByIdAsync와 동일 로직)
                var dto = _mapper.Map<OrganizationResponse>(organization);

                // 3-1. 활성 Capability 목록 설정 (Active Capabilities)
                if (organization.Capabilities != null)
                {
                    dto.ActiveCapabilities = organization.Capabilities
                        .Where(ca => ca.IsActive)
                        .Select(ca =>
                        {
                            var info = _mapper.Map<OrganizationCapabilityInfo>(ca);
                            info.Capability = MapToCapabilityEnum(ca.Capability?.Code);
                            return info;
                        })
                        .ToList();
                }

                // 3-2. 애플리케이션 목록 설정 (이름과 카테고리 포함)
                var applicationList = await GetApplicationBasicInfoListAsync(organization.Id, cancellationToken); // ✅ Token 전달
                dto.ApplicationsList = applicationList;
                dto.ApplicationsCount = applicationList.Count;

                // 3-3. 활성 멤버 수 계산
                dto.ActiveMembersCount = await CountActiveMembersAsync(organization.Id, cancellationToken); // ✅ Token 전달

                // 4. 캐시 저장 (ICacheService 사용)
                // [수정] MemoryCacheEntryOptions와 _cache.Set 대신 ICacheService.SetAsync 사용
                await _cacheService.SetAsync(
                    cacheKey,
                    dto,
                    TimeSpan.FromMinutes(CACHE_DURATION_MINUTES),
                    cancellationToken);

                return ServiceResult<OrganizationResponse>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization by key: {OrganizationKey}", organizationKey);
                return ServiceResult<OrganizationResponse>.Failure("Failed to retrieve organization");
            }
        }

        /// <summary>
        /// 조직 상세 정보 조회 (관련 엔티티 포함)
        /// WHO: 조직 관리자, 대시보드 사용자
        /// WHEN: 조직 관리 페이지 접속, 상세 정보 필요 시
        /// WHERE: Admin Dashboard, 조직 설정 페이지
        /// WHAT: 조직 + 설정 + 도메인 + 멤버십 통계 등 전체 정보
        /// WHY: 단일 API 호출로 전체 정보 제공 (N+1 방지)
        /// HOW: Include/Join을 통한 관련 데이터 일괄 조회 → 통계 계산 → Response 구성
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> GetDetailAsync(Guid organizationId, CancellationToken cancellationToken = default)
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
                response.SortOrder = organization.SortOrder;//response.SortOrder는 조직의 계층 구조 내에서 같은 부모를 가진 형제 조직들(Siblings) 사이의 표시 순서를 결정하는 필드입니다
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
                    ApplicationCount = await CountApplicationsAsync(organizationId, cancellationToken),
                    ActiveApplicationCount = await CountActiveApplicationsAsync(organizationId, cancellationToken),
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
        /// WHO: 시스템 관리자, 리셀러, Self-Service 사용자
        /// WHEN: 신규 고객 온보딩, 조직 계층 구조 확장
        /// WHERE: 회원가입 플로우, Admin Console
        /// WHAT: 새로운 조직 + 기본 설정 + 초기 권한 생성
        /// WHY: 멀티테넌시 환경의 새로운 테넌트 생성
        /// HOW: 검증 → 엔티티 생성 → Capability 할당 → 저장 → 캐시 무효화
        /// </summary>
        // public async Task<ServiceResult<CreateOrganizationResponse>> CreateAsync(
        //    CreateOrganizationRequest request,
        //    Guid createdByConnectedId, CancellationToken cancellationToken = default)
        // {
        //     try
        //     {
        //         // 유효성 검사
        //         var validationResult = await ValidateCreateRequestAsync(request);
        //         if (!validationResult.IsSuccess)
        //         {
        //             return ServiceResult<CreateOrganizationResponse>.Failure(validationResult.ErrorMessage!);
        //         }

        //         // 엔티티 생성
        //         var organization = new Core.Entities.Organization.Organization
        //         {
        //             OrganizationKey = request.OrganizationKey,
        //             Name = request.Name,
        //             Description = request.Description,
        //             Type = request.Type,
        //             Status = OrganizationStatus.Active,
        //             ParentId = request.ParentId,
        //             Region = request.Region ?? "US",
        //             LogoUrl = request.LogoUrl,
        //             BrandColor = request.BrandColor,
        //             Website = request.Website,
        //             Industry = request.Industry,
        //             EmployeeRange = request.EmployeeRange,
        //             EstablishedDate = request.EstablishedDate,
        //             Metadata = request.Metadata,
        //             PolicyInheritanceMode = request.PolicyInheritanceMode ?? PolicyInheritanceMode.Inherit,
        //             ActivatedAt = DateTime.UtcNow,
        //             CreatedByConnectedId = createdByConnectedId
        //         };

        //         // PrimaryCapability 설정 - enum을 기반으로 Capability 엔티티 조회
        //         if (request.PrimaryCapability.HasValue)
        //         {
        //             var capabilityCode = request.PrimaryCapability.Value.ToString().ToUpper();
        //             var capability = await _capabilityRepository.GetByCodeAsync(capabilityCode);

        //             if (capability != null)
        //             {
        //                 organization.Capabilities = new List<OrganizationCapabilityAssignment>
        //                {
        //                    new OrganizationCapabilityAssignment
        //                    {
        //                        OrganizationId = organization.Id,
        //                        CapabilityId = capability.Id,
        //                        IsPrimary = true,
        //                        IsActive = true,
        //                        EnabledAt = DateTime.UtcNow,
        //                        AssignedAt = DateTime.UtcNow,
        //                        AssignedByConnectedId = createdByConnectedId
        //                    }
        //                };
        //             }
        //         }

        //         // Repository를 통해 저장
        //         var created = await _repository.AddAsync(organization);

        //         var response = new CreateOrganizationResponse
        //         {
        //             Id = created.Id,
        //             Name = created.Name,
        //             OrganizationId = created.OrganizationKey,
        //             IsSuccess = true,
        //             Message = "Organization created successfully",
        //             CreatedAt = created.CreatedAt,
        //             CreatedByConnectedId = createdByConnectedId
        //         };

        //         // 캐시 무효화
        //         await InvalidateOrgSelfCacheAsync(created.Id, created.OrganizationKey);

        //         _logger.LogInformation(
        //             "Organization created successfully: {OrganizationKey} by ConnectedId: {ConnectedId}",
        //             created.OrganizationKey,
        //             createdByConnectedId);

        //         return ServiceResult<CreateOrganizationResponse>.Success(response);
        //     }
        //     catch (Exception ex)
        //     {
        //         _logger.LogError(ex, "Failed to create organization: {OrganizationKey}", request.OrganizationKey);
        //         return ServiceResult<CreateOrganizationResponse>.Failure("Failed to create organization");
        //     }
        // }

        /// <summary>
        /// 조직 정보 수정
        /// WHO: 조직 소유자, 조직 관리자
        /// WHEN: 조직 정보 변경 (이름, 설정, 연락처 등)
        /// WHERE: 조직 설정 페이지
        /// WHAT: 조직 마스터 데이터 업데이트
        /// WHY: 조직 정보 최신화 유지
        /// HOW: 기존 조회 → 변경사항 적용 → 업데이트 → 캐시 무효화 → 상세 정보 반환
        /// </summary>
        public async Task<ServiceResult<OrganizationDetailResponse>> UpdateAsync(
            Guid organizationId,
            UpdateOrganizationRequest request,
            Guid updatedByConnectedId,
            CancellationToken cancellationToken = default)
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
                await InvalidateOrgSelfCacheAsync(organizationId, existing.OrganizationKey);

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
        /// 조직 삭제 (소프트 삭제)
        /// WHO: 시스템 관리자, 조직 소유자 (특별 권한)
        /// WHEN: 계약 종료, 정책 위반, 사용자 요청
        /// WHERE: Admin Console, 계정 삭제 플로우
        /// WHAT: 조직 및 관련 데이터 비활성화
        /// WHY: 데이터 보존 규정 준수, 복구 가능성 유지
        /// HOW: 하위 조직 체크 → 삭제 처리 → 캐시 무효화 → 감사 로그
        /// </summary>
        public async Task<ServiceResult> DeleteAsync(
            Guid organizationId,
            Guid deletedByConnectedId,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 하위 조직 확인
                var childrenCount = await CountChildOrganizationsAsync(organizationId);
                if (childrenCount > 0)
                {
                    throw new AuthHiveException(
                         "HAS_CHILDREN",
                         $"Cannot delete organization with {childrenCount} child organizations. Please remove children first.",
                         HttpStatusCode.Conflict);
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
                await InvalidateOrgSelfCacheAsync(organizationId, organization.OrganizationKey);

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
        /// WHO: CreateAsync 내부 프로세스
        /// WHEN: 조직 생성 요청 시
        /// WHERE: CreateAsync 메서드 내부
        /// WHAT: 중복 검사, 부모 조직 확인
        /// WHY: 데이터 무결성 보장
        /// HOW: 순차적 검증 (키 중복 → 이름 중복 → 부모 조직)
        /// </summary>
        private async Task<ServiceResult> ValidateCreateRequestAsync(CreateOrganizationRequest request)
        {
            // 조직 키 중복 확인
            if (await _repository.IsOrganizationKeyExistsAsync(request.OrganizationKey))
            {
                // A duplicate key is a "Conflict" (HTTP 409).
                throw new AuthHiveException(
                    "CONFLICT",
                    $"Organization key '{request.OrganizationKey}' already exists",
                    HttpStatusCode.Conflict);
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
                    throw new AuthHiveException(
                        "PARENT_NOT_FOUND",
                        "Parent organization not found",
                        HttpStatusCode.BadRequest);
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
        /// WHO: 통계 서비스
        /// WHY: 비동기 취소 가능성 및 리소스 해제를 보장
        /// HOW: AuthDbContext의 CountAsync에 CancellationToken 전달
        /// </summary>
        private async Task<int> CountApplicationsAsync(
            Guid organizationId,
            CancellationToken cancellationToken) // ✅ Token 추가
        {
            // AuthDbContext에 CancellationToken 전달하여 장시간 쿼리 방지
            return await _context.PlatformApplications
                .CountAsync(
                    a => a.OrganizationId == organizationId && !a.IsDeleted,
                    cancellationToken); // ✅ Token 전달
        }

        /// <summary>
        /// 활성 애플리케이션 수 계산
        /// WHO: 통계 서비스
        /// WHEN: 조직 상세 정보 조회 시
        /// WHERE: GetDetailAsync
        /// WHAT: 조직에 속한 활성 애플리케이션 수
        /// WHY: 실제 운영 중인 서비스 파악
        /// HOW: Status가 Active인 애플리케이션 개수 계산
        /// </summary>
        /// <summary>
        /// 활성 애플리케이션 수 계산
        /// WHO: 통계 서비스, 빌링 서비스
        /// WHY: 비동기 작업의 취소 가능성(Cancellability) 확보
        /// HOW: AuthDbContext의 CountAsync에 CancellationToken 전달
        /// </summary>
        private async Task<int> CountActiveApplicationsAsync(
            Guid organizationId,
            CancellationToken cancellationToken) // ✅ CancellationToken 추가
        {
            return await _context.PlatformApplications
                .CountAsync(a => a.OrganizationId == organizationId &&
                                    a.Status == ApplicationStatus.Active &&
                                    !a.IsDeleted,
                                    cancellationToken); // ✅ Token 전달
        }

        /// <summary>
        /// 전체 멤버 수 계산
        /// WHO: 통계 서비스
        /// WHEN: 조직 상세 정보 조회 시
        /// WHERE: GetDetailAsync
        /// WHAT: 조직에 속한 전체 멤버 수
        /// WHY: 조직 규모 파악
        /// HOW: OrganizationMembership 테이블 쿼리
        /// </summary>
        private async Task<int> CountTotalMembersAsync(Guid organizationId)
        {
            return await _context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == organizationId && !m.IsDeleted);
        }

        /// <summary>
        /// 활성 멤버 수 계산
        /// WHO: 통계 서비스, 빌링 서비스
        /// WHEN: 조직 상세 정보 조회, MAU 계산 시
        /// WHERE: GetDetailAsync, GetByIdAsync
        /// WHAT: 조직에 속한 활성 멤버 수
        /// WHY: 실제 사용자 규모 및 요금 계산
        /// HOW: Status가 Active인 멤버십 개수 계산
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
        /// WHO: 통계 서비스, 조직 삭제 검증
        /// WHEN: 조직 상세 정보 조회, 삭제 전 검증
        /// WHERE: GetDetailAsync, DeleteAsync
        /// WHAT: 직접 하위 조직 개수
        /// WHY: 조직 구조 파악 및 삭제 가능 여부 판단
        /// HOW: HierarchyRepository를 통한 자식 조직 조회
        /// </summary>
        private async Task<int> CountChildOrganizationsAsync(Guid organizationId)
        {
            var children = await _hierarchyRepository.GetChildrenAsync(organizationId, false);
            return children?.Count() ?? 0;
        }


        /// <summary>
        /// 조직 엔티티와 관련된 모든 캐시 항목을 비동기적으로 무효화합니다.
        /// WHO: 데이터 변경 프로세스 (Create, Update, Delete)
        /// WHY: ICacheService의 비동기 분산 캐싱 기능을 사용하며, 데이터 일관성을 보장합니다.
        /// HOW: ID 기반, Key 기반 캐시를 비동기로 제거하고 CancellationToken을 전달합니다.
        /// </summary>
        private async Task InvalidateOrgSelfCacheAsync(
            Guid organizationId,
            string organizationKey,
            CancellationToken cancellationToken = default)
        {
            // [수정] _cache 대신 _cacheService 사용
            if (_cacheService == null) return;

            // 1. ID 기반 캐시 무효화 (비동기)
            // 예: GetByIdAsync에서 사용하는 "org:GUID" 키 무효화
            await _cacheService.RemoveAsync(
                $"{CACHE_KEY_PREFIX}{organizationId}",
                cancellationToken);

            // 2. Key 기반 캐시 무효화 (비동기)
            // 예: GetByKeyAsync에서 사용하는 "org:key:slug" 키 무효화
            await _cacheService.RemoveAsync(
                $"{CACHE_KEY_BY_KEY}{organizationKey}",
                cancellationToken);
        }

        /// <summary>
        /// 조직이 소유한 활성 애플리케이션의 기본 정보 목록을 조회합니다.
        /// WHO: 조직 상세 정보 및 대시보드 조회
        /// </summary>
        /// <summary>
        /// 조직이 소유한 활성 애플리케이션의 기본 정보 목록을 조회합니다.
        /// DTO에 앱의 이름과 카테고리를 제공하여 비즈니스 가치를 높입니다.
        /// </summary>
        private async Task<List<ApplicationBasicInfo>> GetApplicationBasicInfoListAsync(
            Guid organizationId,
            CancellationToken cancellationToken)
        {
            // AuthDbContext의 DbSet<PlatformApplication>을 사용한다고 가정
            return await _context.PlatformApplications
                .AsNoTracking()
                .Where(a => a.OrganizationId == organizationId &&
                            !a.IsDeleted &&
                            a.Status == ApplicationStatus.Active)
                .Select(a => new ApplicationBasicInfo // ApplicationBasicInfo DTO에 맞춤
                {
                    ApplicationId = a.Id, // ✅ ApplicationId 대신 Id 필드 사용 (DTO 통일)
                    Name = a.Name,
                    ApplicationKey = a.ApplicationKey,
                    ApplicationType = a.ApplicationType.ToString(),
                    IsActive = (a.Status == ApplicationStatus.Active),
                    IconUrl = a.IconUrl, // ✅ 누락된 IconUrl 필드 추가
                })
                .ToListAsync(cancellationToken);
        }
        // AuthHive.Auth.Services.Organization/OrganizationService.cs - Private Helper Methods 섹션

        /// <summary>
        /// 조직이 소유한 애플리케이션의 상태 및 유형(Web/Api)별 통계를 조회합니다.
        /// WHY: 조직의 운영 상태와 기술 부하를 동시에 파악하기 위함입니다.
        /// </summary>
        private async Task<ApplicationStatistics> GetApplicationStatisticsAsync(
            Guid organizationId,
            CancellationToken cancellationToken)
        {
            // 1. 조직에 속한 삭제되지 않은 모든 앱을 조회합니다.
            var applications = await _context.PlatformApplications
                .AsNoTracking()
                .Where(a => a.OrganizationId == organizationId && !a.IsDeleted)
                .ToListAsync(cancellationToken);

            // 2. 통계 DTO를 구성합니다.
            var stats = new ApplicationStatistics
            {
                TotalCount = applications.Count,
                ActiveCount = applications.Count(a => a.Status == ApplicationStatus.Active),
                SuspendedCount = applications.Count(a => a.Status == ApplicationStatus.Suspended),

                // 3. 기술적 분류 (Web/Api) 계산
                // ApplicationType Enum (Web, Api 등)을 사용한다고 가정
                WebCount = applications.Count(a => a.ApplicationType.ToString().Equals("WEB", StringComparison.OrdinalIgnoreCase)),
                ApiCount = applications.Count(a => a.ApplicationType.ToString().Equals("API", StringComparison.OrdinalIgnoreCase)),

                // DraftCount 등 다른 상태도 필요하다면 여기서 추가 계산
            };

            return stats;
        }

        /// <summary>
        /// 활성 멤버 수 계산
        /// WHO: 통계 서비스, 빌링 서비스
        /// HOW: AuthDbContext에 CancellationToken 전달
        /// </summary>
        private async Task<int> CountActiveMembersAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            // AuthDbContext에 CancellationToken 전달
            return await _context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == organizationId &&
                                    m.Status == OrganizationMembershipStatus.Active &&
                                    !m.IsDeleted, cancellationToken); // ✅ Token 전달
        }
        /// <summary>
        /// Capability 코드를 Enum으로 매핑
        /// WHO: DTO 매핑 프로세스
        /// WHEN: 조직 상세 정보 조회 시
        /// WHERE: GetDetailAsync
        /// WHAT: 문자열 코드를 Enum으로 변환
        /// WHY: 타입 안전성 및 일관성
        /// HOW: Switch 표현식으로 매핑
        /// </summary>
        private OrganizationCapabilityEnum MapToCapabilityEnum(string? code)
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