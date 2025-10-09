using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Requests;
using AuthHive.Core.Models.PlatformApplication.Responses;
using AutoMapper; // AutoMapper를 사용하기 위해 필요
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.PlatformApplication.Views;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Models.User;


namespace AuthHive.Auth.Services.User
{
    public class UserApplicationAccessService : IUserApplicationAccessService
    {
        private const string CACHE_KEY_PREFIX = "user_app_access";
        private const string CACHE_KEY_MATRIX = $"{CACHE_KEY_PREFIX}:matrix";
        private const int DEFAULT_CACHE_MINUTES = 15;
        private readonly IUserApplicationAccessRepository _accessRepository;
        private readonly IPlatformApplicationAccessTemplateRepository _templateRepository;        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper; // 의존성 주입으로 받은 Mapper 인스턴스
        private readonly ILogger<UserApplicationAccessService> _logger;

        public UserApplicationAccessService(
            IUserApplicationAccessRepository accessRepository,
            IPlatformApplicationRepository applicationRepository,
            IPlatformApplicationAccessTemplateRepository templateRepository,
            IOrganizationRepository organizationRepository,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            IEmailService emailService,
            ICacheService cacheService,
            IMapper mapper,
            ILogger<UserApplicationAccessService> logger)
        {
            _accessRepository = accessRepository;
            _applicationRepository = applicationRepository;
            _organizationRepository = organizationRepository;
            _templateRepository = templateRepository;
            _auditService = auditService;
            _dateTimeProvider = dateTimeProvider;
            _cacheService = cacheService;
            _emailService = emailService;
            _mapper = mapper; // 주입받은 인스턴스를 필드에 할당
            _logger = logger;
        }

        #region IService Implementation
public Task InitializeAsync(CancellationToken cancellationToken = default)
{
    _logger.LogInformation("UserApplicationAccessService initialized.");
    return Task.CompletedTask;
}

public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
{
    try
    {
        await _accessRepository.ExistsAsync(Guid.Empty, Guid.Empty, cancellationToken);
        return true;
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "UserApplicationAccessService health check failed.");
        return false;
    }
}

        #endregion
        
        #region 접근 권한 CRUD

        public async Task<ServiceResult<UserApplicationAccessResponse>> GetAccessAsync(Guid connectedId, Guid applicationId)
        {
            var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(connectedId, applicationId);
            if (access == null)
            {
                return ServiceResult<UserApplicationAccessResponse>.NotFound("Access rights not found.");
            }
            // CS0120 오류 수정: 정적 Mapper.Map 대신 주입받은 _mapper 인스턴스 사용
            var response = _mapper.Map<UserApplicationAccessResponse>(access);
            return ServiceResult<UserApplicationAccessResponse>.Success(response);
        }

        public async Task<ServiceResult<UserApplicationAccessResponse>> CreateAccessAsync(CreateUserApplicationAccessRequest request, Guid grantedByConnectedId)
        {
            try
            {
                var granterAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(grantedByConnectedId, request.ApplicationId);
                if (!CanGrantAccess(granterAccess, request.AccessLevel))
                {
                    return ServiceResult<UserApplicationAccessResponse>.Forbidden("Insufficient permissions.");
                }

                if (await _accessRepository.ExistsAsync(request.ConnectedId, request.ApplicationId))
                {
                    return ServiceResult<UserApplicationAccessResponse>.Failure("Access already exists.", "DUPLICATE_ACCESS");
                }

                var application = await _applicationRepository.GetByIdAsync(request.ApplicationId);
                if (application == null)
                {
                    return ServiceResult<UserApplicationAccessResponse>.NotFound("Application not found.");
                }

                var access = _mapper.Map<UserPlatformApplicationAccess>(request);
                access.Id = Guid.NewGuid();
                access.OrganizationId = application.OrganizationId;
                access.GrantedAt = _dateTimeProvider.UtcNow;
                access.GrantedByConnectedId = grantedByConnectedId;
                access.CreatedByConnectedId = grantedByConnectedId;
                access.CreatedAt = _dateTimeProvider.UtcNow;
                access.IsActive = true;

                var newAccess = await _accessRepository.AddAsync(access);

                await _auditService.LogActionAsync(AuditActionType.Create, "ACCESS_GRANTED", grantedByConnectedId, resourceId: newAccess.Id.ToString());

                return ServiceResult<UserApplicationAccessResponse>.Success(_mapper.Map<UserApplicationAccessResponse>(newAccess));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create access for {ConnectedId}", request.ConnectedId);
                return ServiceResult<UserApplicationAccessResponse>.Failure("Failed to create access.", "CREATE_ACCESS_ERROR");
            }
        }

        public async Task<ServiceResult<UserApplicationAccessResponse>> UpdateAccessAsync(Guid accessId, UpdateUserApplicationAccessRequest request, Guid updatedByConnectedId)
        {
             try
            {
                var access = await _accessRepository.GetByIdAsync(accessId);
                if (access == null)
                {
                    return ServiceResult<UserApplicationAccessResponse>.NotFound("Access not found");
                }

                var updaterAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(updatedByConnectedId, access.ApplicationId);
                if (!CanModifyAccess(updaterAccess, access))
                {
                    return ServiceResult<UserApplicationAccessResponse>.Forbidden("Insufficient permissions.");
                }
                
                _mapper.Map(request, access);
                access.UpdatedAt = _dateTimeProvider.UtcNow;
                access.UpdatedByConnectedId = updatedByConnectedId;

                await _accessRepository.UpdateAsync(access);
                return ServiceResult<UserApplicationAccessResponse>.Success(_mapper.Map<UserApplicationAccessResponse>(access));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update access {AccessId}", accessId);
                return ServiceResult<UserApplicationAccessResponse>.Failure("Failed to update access.", "UPDATE_ACCESS_ERROR");
            }
        }

        public async Task<ServiceResult> RevokeAccessAsync(Guid connectedId, Guid applicationId, Guid revokedByConnectedId, string? reason = null)
        {
            try
            {
                var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(connectedId, applicationId);
                if (access == null)
                {
                    return ServiceResult.NotFound("Access not found");
                }

                var revokerAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(revokedByConnectedId, applicationId);
                if (!CanRevokeAccess(revokerAccess, access))
                {
                    return ServiceResult.Failure("Insufficient permissions.");
                }

                await _accessRepository.DeleteAsync(access.Id, revokedByConnectedId);
                return ServiceResult.Success("Access revoked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke access for {ConnectedId} to {ApplicationId}", connectedId, applicationId);
                return ServiceResult.Failure("Failed to revoke access.", "REVOKE_ERROR");
            }
        }
        #endregion

        #region 템플릿 기반 권한 관리

        /// <inheritdoc />
        public async Task<ServiceResult<UserApplicationAccessResponse>> ApplyTemplateAsync(
            Guid connectedId,
            Guid applicationId,
            Guid templateId,
            Guid appliedByConnectedId)
        {
            try
            {
                // 1. 템플릿 조회
                var template = await _templateRepository.GetByIdAsync(templateId);
                if (template == null || !template.IsActive)
                {
                    return ServiceResult<UserApplicationAccessResponse>.NotFound(
                        "Template not found or inactive");
                }

                // 2. 권한 확인
                var applierAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    appliedByConnectedId, applicationId);

                if (!CanGrantAccess(applierAccess, template.Level))
                {
                    return ServiceResult<UserApplicationAccessResponse>.Forbidden(
                        "Insufficient permissions to apply this template");
                }

                // 3. 기존 접근 권한 조회 또는 생성
                var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    connectedId, applicationId);

                bool isNewAccess = access == null;
                if (isNewAccess)
                {
                    var application = await _applicationRepository.GetByIdAsync(applicationId);
                    if (application == null)
                    {
                        return ServiceResult<UserApplicationAccessResponse>.NotFound(
                            "Application not found");
                    }

                    access = new UserPlatformApplicationAccess
                    {
                        Id = Guid.NewGuid(),
                        ConnectedId = connectedId,
                        ApplicationId = applicationId,
                        OrganizationId = application.OrganizationId,
                        GrantedAt = _dateTimeProvider.UtcNow,
                        CreatedAt = _dateTimeProvider.UtcNow,
                        CreatedByConnectedId = appliedByConnectedId,
                        GrantedByConnectedId = appliedByConnectedId
                    };
                }

                // 4. 템플릿 적용
                access!.AccessTemplateId = templateId;
                access.AccessLevel = template.Level;
                access.RoleId = null; // 템플릿에 DefaultRoleId가 없으므로 null 처리
                access.Scopes = "[\"read\"]"; // 기본 스코프 설정
                access.AdditionalPermissions = template.PermissionPatterns;
                access.ExcludedPermissions = null; // 템플릿 적용 시 제외 권한 초기화
                access.IsActive = true;
                access.UpdatedAt = _dateTimeProvider.UtcNow;
                access.UpdatedByConnectedId = appliedByConnectedId;

                if (isNewAccess)
                {
                    await _accessRepository.AddAsync(access);
                }
                else
                {
                    await _accessRepository.UpdateAsync(access);
                }

                // 5. 캐시 무효화
                await InvalidateCacheAsync(connectedId, applicationId);

                // 6. 감사 로그
                await LogAuditAsync(
                    appliedByConnectedId,
                    "TEMPLATE_APPLIED",
                    $"Applied template {template.Name} to user {connectedId}",
                    applicationId,
                    access.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["TemplateId"] = templateId,
                        ["TemplateName"] = template.Name,
                        ["TargetConnectedId"] = connectedId
                    });

                var response = MapToResponse(access);
                return ServiceResult<UserApplicationAccessResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to apply template {TemplateId} to {ConnectedId}",
                    templateId, connectedId);
                return ServiceResult<UserApplicationAccessResponse>.Failure(
                    "Failed to apply template", "TEMPLATE_APPLICATION_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> AddAdditionalPermissionsAsync(
            Guid accessId,
            List<string> permissions,
            Guid addedByConnectedId)
        {
            try
            {
                var access = await _accessRepository.GetByIdAsync(accessId);
                if (access == null)
                {
                    return ServiceResult.NotFound("Access not found");
                }

                // 권한 확인
                var adderAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    addedByConnectedId, access.ApplicationId);

                if (!CanModifyAccess(adderAccess, access))
                {
                    return ServiceResult.Failure(
                        "Insufficient permissions to modify permissions", "FORBIDDEN");
                }

                // 기존 추가 권한과 병합
                var existingPermissions = DeserializeList(access.AdditionalPermissions);
                var mergedPermissions = existingPermissions
                    .Union(permissions)
                    .Distinct()
                    .ToList();

                access.AdditionalPermissions = SerializeList(mergedPermissions);
                access.UpdatedAt = _dateTimeProvider.UtcNow;
                access.UpdatedByConnectedId = addedByConnectedId;

                await _accessRepository.UpdateAsync(access);

                // 캐시 무효화
                await InvalidateCacheAsync(access.ConnectedId, access.ApplicationId);

                // 감사 로그
                await LogAuditAsync(
                    addedByConnectedId,
                    "PERMISSIONS_ADDED",
                    $"Added permissions to access {accessId}",
                    access.ApplicationId,
                    access.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["AddedPermissions"] = permissions
                    });

                return ServiceResult.Success("Permissions added successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to add permissions to access {AccessId}",
                    accessId);
                return ServiceResult.Failure(
                    "Failed to add permissions", "ADD_PERMISSIONS_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult> ExcludePermissionsAsync(
            Guid accessId,
            List<string> permissions,
            Guid excludedByConnectedId)
        {
            try
            {
                var access = await _accessRepository.GetByIdAsync(accessId);
                if (access == null)
                {
                    return ServiceResult.NotFound("Access not found");
                }

                // 권한 확인
                var excluderAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    excludedByConnectedId, access.ApplicationId);

                if (!CanModifyAccess(excluderAccess, access))
                {
                    return ServiceResult.Failure(
                        "Insufficient permissions to modify permissions", "FORBIDDEN");
                }

                // 기존 제외 권한과 병합
                var existingExclusions = DeserializeList(access.ExcludedPermissions);
                var mergedExclusions = existingExclusions
                    .Union(permissions)
                    .Distinct()
                    .ToList();

                access.ExcludedPermissions = SerializeList(mergedExclusions);
                access.UpdatedAt = _dateTimeProvider.UtcNow;
                access.UpdatedByConnectedId = excludedByConnectedId;

                await _accessRepository.UpdateAsync(access);

                // 캐시 무효화
                await InvalidateCacheAsync(access.ConnectedId, access.ApplicationId);

                // 감사 로그
                await LogAuditAsync(
                    excludedByConnectedId,
                    "PERMISSIONS_EXCLUDED",
                    $"Excluded permissions from access {accessId}",
                    access.ApplicationId,
                    access.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["ExcludedPermissions"] = permissions
                    });

                return ServiceResult.Success("Permissions excluded successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to exclude permissions from access {AccessId}",
                    accessId);
                return ServiceResult.Failure(
                    "Failed to exclude permissions", "EXCLUDE_PERMISSIONS_ERROR");
            }
        }

        #endregion

        #region 접근 권한 검색 및 조회

        /// <inheritdoc />
        public async Task<ServiceResult<IEnumerable<UserApplicationAccessResponse>>> GetUserAccessesAsync(
            Guid connectedId,
            bool includeInactive = false)
        {
            try
            {
                var accesses = await _accessRepository.GetByConnectedIdAsync(connectedId, !includeInactive);

                var responses = new List<UserApplicationAccessResponse>();
                foreach (var access in accesses)
                {
                    responses.Add(MapToResponse(access));
                }

                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user accesses for {ConnectedId}", connectedId);
                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Failure(
                    "Failed to retrieve user accesses", "GET_USER_ACCESSES_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<IEnumerable<UserApplicationAccessResponse>>> GetApplicationAccessesAsync(
            Guid applicationId,
            bool includeInactive = false)
        {
            try
            {
                var accesses = await _accessRepository.GetByApplicationIdAsync(applicationId, !includeInactive);

                var responses = new List<UserApplicationAccessResponse>();
                foreach (var access in accesses)
                {
                    responses.Add(MapToResponse(access));
                }

                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get application accesses for {ApplicationId}",
                    applicationId);
                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Failure(
                    "Failed to retrieve application accesses", "GET_APP_ACCESSES_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<PaginationResponse<UserApplicationAccessResponse>>> SearchAccessesAsync(
            UserApplicationAccessSearchRequest request)
        {
            try
            {
                // SearchUserApplicationAccessRequest에 매핑
                var searchRequest = new SearchUserApplicationAccessRequest
                {
                    OrganizationId = request.OrganizationId,
                    ApplicationId = request.ApplicationId,
                    ConnectedId = request.ConnectedId,
                    AccessLevel = request.AccessLevel,
                    TemplateId = request.AccessTemplateId,
                    RoleId = request.RoleId,
                    IsActive = request.IsActive,
                    IncludeExpired = request.IncludeExpired,
                    IncludeInherited = request.IncludeInherited,
                    SearchTerm = request.SearchTerm ?? string.Empty,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };

                // Repository를 통해 검색
                var pagedResult = await _accessRepository.SearchAsync(searchRequest);

                // 응답 매핑
                var responses = new List<UserApplicationAccessResponse>();
                foreach (var item in pagedResult.Items)
                {
                    responses.Add(MapToResponse(item));
                }

                var result = new PaginationResponse<UserApplicationAccessResponse>
                {
                    Items = responses,
                    TotalCount = pagedResult.TotalCount,
                    PageNumber = pagedResult.PageNumber,
                    PageSize = pagedResult.PageSize
                };

                return ServiceResult<PaginationResponse<UserApplicationAccessResponse>>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to search accesses");
                return ServiceResult<PaginationResponse<UserApplicationAccessResponse>>.Failure(
                    "Failed to search accesses", "SEARCH_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<UserApplicationAccessMatrixView>> GetAccessMatrixAsync(
            Guid organizationId)
        {
            try
            {
                // Check cache first
                var cacheKey = $"{CACHE_KEY_MATRIX}:{organizationId}";
                var cached = await _cacheService.GetAsync<UserApplicationAccessMatrixView>(cacheKey);
                if (cached != null)
                {
                    return ServiceResult<UserApplicationAccessMatrixView>.Success(cached);
                }

                // Build matrix
                var matrix = new UserApplicationAccessMatrixView
                {
                    OrganizationId = organizationId,
                    GeneratedAt = _dateTimeProvider.UtcNow
                };

                // Get all accesses for the organization
                var accesses = await _accessRepository.GetByOrganizationIdAsync(organizationId);

                // Get unique applications
                var applicationIds = accesses.Select(a => a.ApplicationId).Distinct();
                var applications = new List<ApplicationHeader>();

                foreach (var appId in applicationIds)
                {
                    var app = await _applicationRepository.GetByIdAsync(appId);
                    if (app != null)
                    {
                        var appAccesses = accesses.Where(a => a.ApplicationId == appId);
                        applications.Add(new ApplicationHeader
                        {
                            ApplicationId = app.Id,
                            ApplicationName = app.Name,
                            ApplicationCode = app.ApplicationKey ?? app.Name.Substring(0, Math.Min(3, app.Name.Length)).ToUpper(),
                            ApplicationIconUrl = app.IconUrl,
                            ApplicationType = app.ApplicationType.ToString(),
                            TotalUsersCount = appAccesses.Count(),
                            ActiveUsersCount = appAccesses.Count(a => a.IsActive)
                        });
                    }
                }
                matrix.Applications = applications;

                // Get unique users
                var connectedIds = accesses.Select(a => a.ConnectedId).Distinct();
                var userRows = new List<UserAccessRow>();

                foreach (var connectedId in connectedIds)
                {
                    var userAccesses = accesses.Where(a => a.ConnectedId == connectedId).ToList();
                    var firstAccess = userAccesses.First();

                    // Get user info (would need user repository in real implementation)
                    var userRow = new UserAccessRow
                    {
                        ConnectedId = connectedId,
                        UserId = firstAccess.ConnectedIdNavigation?.UserId ?? Guid.Empty,
                        UserName = firstAccess.ConnectedIdNavigation?.User?.DisplayName ?? "Unknown",
                        UserEmail = firstAccess.ConnectedIdNavigation?.User?.Email ?? "unknown@example.com",
                        IsActive = userAccesses.Any(a => a.IsActive),
                        TotalAccessibleApps = userAccesses.Count(a => a.IsActive),
                        HighestAccessLevel = userAccesses.Max(a => a.AccessLevel),
                        LastActivityAt = userAccesses.Max(a => a.UpdatedAt ?? a.CreatedAt)
                    };

                    // Build access cells
                    userRow.AccessCells = new List<AccessCell>();
                    foreach (var app in applications)
                    {
                        var access = userAccesses.FirstOrDefault(a => a.ApplicationId == app.ApplicationId);
                        if (access != null)
                        {
                            userRow.AccessCells.Add(new AccessCell
                            {
                                ApplicationId = app.ApplicationId,
                                AccessId = access.Id,
                                AccessLevel = access.AccessLevel,
                                RoleName = access.Role?.Name,
                                IsTemplateBased = access.AccessTemplateId.HasValue,
                                IsInherited = access.IsInherited,
                                IsActive = access.IsActive,
                                IsExpired = access.ExpiresAt.HasValue && access.ExpiresAt < _dateTimeProvider.UtcNow,
                                ExpiresAt = access.ExpiresAt,
                                TooltipText = $"{access.AccessLevel} - {(access.IsActive ? "Active" : "Inactive")}"
                            });
                        }
                        else
                        {
                            userRow.AccessCells.Add(new AccessCell
                            {
                                ApplicationId = app.ApplicationId,
                                AccessLevel = ApplicationAccessLevel.None,
                                IsActive = false,
                                TooltipText = "No access"
                            });
                        }
                    }

                    userRows.Add(userRow);
                }
                matrix.UserRows = userRows;

                // Calculate statistics
                matrix.Statistics = CalculateMatrixStatistics(accesses, applications, userRows);

                // Cache the result
                await _cacheService.SetAsync(cacheKey, matrix, TimeSpan.FromMinutes(30));

                return ServiceResult<UserApplicationAccessMatrixView>.Success(matrix);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate access matrix for organization {OrganizationId}", organizationId);
                return ServiceResult<UserApplicationAccessMatrixView>.Failure(
                    "Failed to generate access matrix", "MATRIX_ERROR");
            }
        }

        #endregion

        #region 권한 검증 및 확인

        /// <inheritdoc />
        public async Task<ServiceResult<bool>> ValidateAccessAsync(
            Guid connectedId,
            Guid applicationId,
            string? requiredScope = null)
        {
            try
            {
                // Cache check - bool을 string으로 변환하여 캐싱
                var cacheKey = $"{CACHE_KEY_PREFIX}:validate:{connectedId}:{applicationId}:{requiredScope ?? "any"}";
                var cachedString = await _cacheService.GetAsync<string>(cacheKey);
                if (!string.IsNullOrEmpty(cachedString))
                {
                    var cachedValue = bool.Parse(cachedString);
                    return ServiceResult<bool>.Success(cachedValue);
                }

                var hasAccess = await _accessRepository.HasActiveAccessAsync(connectedId, applicationId);

                if (!hasAccess)
                {
                    await _cacheService.SetAsync(cacheKey, "false", TimeSpan.FromMinutes(5));
                    return ServiceResult<bool>.Success(false);
                }

                // Check scope if required
                if (!string.IsNullOrEmpty(requiredScope))
                {
                    var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                        connectedId, applicationId);

                    if (access != null)
                    {
                        var scopes = DeserializeList(access.Scopes);
                        hasAccess = scopes.Contains(requiredScope) || scopes.Contains("*");
                    }
                }

                await _cacheService.SetAsync(cacheKey, hasAccess.ToString(), TimeSpan.FromMinutes(DEFAULT_CACHE_MINUTES));
                return ServiceResult<bool>.Success(hasAccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to validate access for {ConnectedId} to {ApplicationId}",
                    connectedId, applicationId);
                return ServiceResult<bool>.Failure(
                    "Failed to validate access", "VALIDATION_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<bool>> HasPermissionAsync(
            Guid connectedId,
            Guid applicationId,
            string permission)
        {
            try
            {
                var hasPermission = await _accessRepository.HasPermissionAsync(
                    connectedId, applicationId, permission);

                return ServiceResult<bool>.Success(hasPermission);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to check permission {Permission} for {ConnectedId}",
                    permission, connectedId);
                return ServiceResult<bool>.Failure(
                    "Failed to check permission", "PERMISSION_CHECK_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<ApplicationAccessLevel>> GetAccessLevelAsync(
            Guid connectedId,
            Guid applicationId)
        {
            try
            {
                var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    connectedId, applicationId);

                if (access == null || !access.IsActive || access.IsDeleted)
                {
                    return ServiceResult<ApplicationAccessLevel>.Success(ApplicationAccessLevel.None);
                }

                return ServiceResult<ApplicationAccessLevel>.Success(access.AccessLevel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get access level for {ConnectedId} to {ApplicationId}",
                    connectedId, applicationId);
                return ServiceResult<ApplicationAccessLevel>.Failure(
                    "Failed to get access level", "ACCESS_LEVEL_ERROR");
            }
        }

        #endregion

        #region 권한 상속 및 계층 관리

        /// <inheritdoc />
        public async Task<ServiceResult<IEnumerable<UserApplicationAccessResponse>>> InheritAccessFromParentAsync(
            Guid childOrganizationId,
            Guid parentOrganizationId,
            Guid inheritedByConnectedId)
        {
            try
            {
                // Get parent organization's accesses
                var parentAccesses = await _accessRepository.GetByOrganizationIdAsync(parentOrganizationId);

                // Filter inheritable accesses (e.g., templates marked as inheritable)
                var inheritableAccesses = parentAccesses
                    .Where(a => a.AccessTemplateId.HasValue && a.IsActive)
                    .ToList();

                var inheritedAccesses = new List<UserPlatformApplicationAccess>();

                foreach (var parentAccess in inheritableAccesses)
                {
                    // Check if access already exists in child org
                    var existingAccess = await _accessRepository.ExistsAsync(
                        parentAccess.ConnectedId, parentAccess.ApplicationId);

                    if (!existingAccess)
                    {
                        var inheritedAccess = new UserPlatformApplicationAccess
                        {
                            Id = Guid.NewGuid(),
                            ConnectedId = parentAccess.ConnectedId,
                            ApplicationId = parentAccess.ApplicationId,
                            OrganizationId = childOrganizationId,
                            AccessLevel = parentAccess.AccessLevel,
                            AccessTemplateId = parentAccess.AccessTemplateId,
                            RoleId = parentAccess.RoleId,
                            Scopes = parentAccess.Scopes,
                            AdditionalPermissions = parentAccess.AdditionalPermissions,
                            ExcludedPermissions = parentAccess.ExcludedPermissions,
                            IsInherited = true,
                            InheritedFromId = parentAccess.Id,
                            GrantedAt = _dateTimeProvider.UtcNow,
                            IsActive = true,
                            CreatedAt = _dateTimeProvider.UtcNow,
                            CreatedByConnectedId = inheritedByConnectedId,
                            GrantedByConnectedId = inheritedByConnectedId
                        };

                        await _accessRepository.AddAsync(inheritedAccess);
                        inheritedAccesses.Add(inheritedAccess);
                    }
                }

                // Log audit
                await LogAuditAsync(
                    inheritedByConnectedId,
                    "ACCESS_INHERITED",
                    $"Inherited {inheritedAccesses.Count} accesses from parent organization",
                    null,
                    childOrganizationId,
                    new Dictionary<string, object>
                    {
                        ["ParentOrganizationId"] = parentOrganizationId,
                        ["InheritedCount"] = inheritedAccesses.Count
                    });

                var responses = new List<UserApplicationAccessResponse>();
                foreach (var access in inheritedAccesses)
                {
                    responses.Add(MapToResponse(access));
                }

                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to inherit access from parent {ParentOrgId} to child {ChildOrgId}",
                    parentOrganizationId, childOrganizationId);
                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Failure(
                    "Failed to inherit access", "INHERIT_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<IEnumerable<UserApplicationAccessResponse>>> GetInheritedAccessesAsync(
            Guid connectedId)
        {
            try
            {
                var accesses = await _accessRepository.GetInheritedAccessAsync(connectedId);

                var responses = new List<UserApplicationAccessResponse>();
                foreach (var access in accesses)
                {
                    responses.Add(MapToResponse(access));
                }

                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get inherited accesses for {ConnectedId}",
                    connectedId);
                return ServiceResult<IEnumerable<UserApplicationAccessResponse>>.Failure(
                    "Failed to get inherited accesses", "GET_INHERITED_ERROR");
            }
        }

        #endregion

        #region 권한 만료 및 갱신

        /// <inheritdoc />
        public async Task<ServiceResult<int>> CleanupExpiredAccessesAsync(DateTime? asOfDate = null)
        {
            try
            {
                var referenceDate = asOfDate ?? _dateTimeProvider.UtcNow;
                var expiredAccesses = await _accessRepository.GetExpiredAccessAsync(referenceDate);

                int cleanedCount = 0;
                foreach (var access in expiredAccesses)
                {
                    access.IsActive = false;
                    access.UpdatedAt = _dateTimeProvider.UtcNow;
                    await _accessRepository.UpdateAsync(access);

                    await InvalidateCacheAsync(access.ConnectedId, access.ApplicationId);
                    cleanedCount++;
                }

                _logger.LogInformation(
                    "Cleaned up {Count} expired accesses as of {Date}",
                    cleanedCount, referenceDate);

                return ServiceResult<int>.Success(cleanedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup expired accesses");
                return ServiceResult<int>.Failure(
                    "Failed to cleanup expired accesses", "CLEANUP_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<UserApplicationAccessResponse>> RenewAccessAsync(
            Guid accessId,
            DateTime newExpiryDate,
            Guid renewedByConnectedId)
        {
            try
            {
                var access = await _accessRepository.GetByIdAsync(accessId);
                if (access == null)
                {
                    return ServiceResult<UserApplicationAccessResponse>.NotFound("Access not found");
                }

                // Validate renewer permissions
                var renewerAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    renewedByConnectedId, access.ApplicationId);

                if (!CanModifyAccess(renewerAccess, access))
                {
                    return ServiceResult<UserApplicationAccessResponse>.Forbidden(
                        "Insufficient permissions to renew access");
                }

                var oldExpiryDate = access.ExpiresAt;
                access.ExpiresAt = newExpiryDate;
                access.IsActive = true; // Reactivate if it was expired
                access.UpdatedAt = _dateTimeProvider.UtcNow;
                access.UpdatedByConnectedId = renewedByConnectedId;

                await _accessRepository.UpdateAsync(access);
                await InvalidateCacheAsync(access.ConnectedId, access.ApplicationId);

                // Audit log
                await LogAuditAsync(
                    renewedByConnectedId,
                    "ACCESS_RENEWED",
                    $"Renewed access {accessId}",
                    access.ApplicationId,
                    access.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["OldExpiryDate"] = oldExpiryDate?.ToString() ?? "None",
                        ["NewExpiryDate"] = newExpiryDate.ToString()
                    });

                var response = MapToResponse(access);
                return ServiceResult<UserApplicationAccessResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to renew access {AccessId}", accessId);
                return ServiceResult<UserApplicationAccessResponse>.Failure(
                    "Failed to renew access", "RENEW_ERROR");
            }
        }

        #endregion

        #region 대량 작업

        /// <inheritdoc />
        public async Task<ServiceResult<BulkOperationResult>> BulkGrantAccessAsync(
            List<Guid> connectedIds,
            Guid applicationId,
            Guid? templateId,
            Guid grantedByConnectedId)
        {
            var result = new BulkOperationResult();
            var startTime = _dateTimeProvider.UtcNow;

            try
            {
                // Validate granter permissions
                var granterAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    grantedByConnectedId, applicationId);

                if (granterAccess == null || granterAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult<BulkOperationResult>.Forbidden(
                        "Insufficient permissions for bulk grant");
                }

                var application = await _applicationRepository.GetByIdAsync(applicationId);
                if (application == null)
                {
                    return ServiceResult<BulkOperationResult>.NotFound("Application not found");
                }

                PlatformApplicationAccessTemplate? template = null;
                if (templateId.HasValue)
                {
                    template = await _templateRepository.GetByIdAsync(templateId.Value);
                }

                var accessLevel = template?.Level ?? ApplicationAccessLevel.User;

                // Use repository bulk create
                var createdAccesses = await _accessRepository.CreateBulkAsync(
                    connectedIds,
                    applicationId,
                    accessLevel,
                    null, // RoleId - 템플릿에 DefaultRoleId가 없음
                    templateId,
                    grantedByConnectedId);

                result.SuccessCount = createdAccesses.Count();
                result.FailureCount = connectedIds.Count - result.SuccessCount;
                result.ElapsedTime = _dateTimeProvider.UtcNow - startTime;

                // Audit log
                await LogAuditAsync(
                    grantedByConnectedId,
                    "BULK_ACCESS_GRANTED",
                    $"Bulk granted access to {result.SuccessCount} users",
                    applicationId,
                    application.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["TotalRequested"] = connectedIds.Count,
                        ["SuccessCount"] = result.SuccessCount,
                        ["FailureCount"] = result.FailureCount,
                        ["TemplateId"] = templateId?.ToString() ?? "None"
                    });

                return ServiceResult<BulkOperationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to perform bulk grant");
                return ServiceResult<BulkOperationResult>.Failure(
                    "Failed to perform bulk grant", "BULK_GRANT_ERROR");
            }
        }

        /// <inheritdoc />
        public async Task<ServiceResult<BulkOperationResult>> BulkRevokeAccessAsync(
            List<Guid> connectedIds,
            Guid applicationId,
            Guid revokedByConnectedId,
            string? reason = null)
        {
            var result = new BulkOperationResult();
            var startTime = _dateTimeProvider.UtcNow;

            try
            {
                // Validate revoker permissions
                var revokerAccess = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                    revokedByConnectedId, applicationId);

                if (revokerAccess == null || revokerAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult<BulkOperationResult>.Forbidden(
                        "Insufficient permissions for bulk revoke");
                }

                // Get access IDs for the connected IDs
                var accesses = new List<UserPlatformApplicationAccess>();
                foreach (var connectedId in connectedIds)
                {
                    var access = await _accessRepository.GetByConnectedIdAndApplicationAsync(
                        connectedId, applicationId);
                    if (access != null)
                    {
                        accesses.Add(access);
                    }
                }

                var accessIds = accesses.Select(a => a.Id).ToList();

                // Bulk delete
                var deletedCount = await _accessRepository.DeleteBulkAsync(
                    accessIds, revokedByConnectedId);

                result.SuccessCount = deletedCount;
                result.FailureCount = connectedIds.Count - deletedCount;
                result.ElapsedTime = _dateTimeProvider.UtcNow - startTime;

                // Invalidate cache for each
                foreach (var connectedId in connectedIds)
                {
                    await InvalidateCacheAsync(connectedId, applicationId);
                }

                // Audit log
                await LogAuditAsync(
                    revokedByConnectedId,
                    "BULK_ACCESS_REVOKED",
                    $"Bulk revoked access for {result.SuccessCount} users",
                    applicationId,
                    revokerAccess.OrganizationId,
                    new Dictionary<string, object>
                    {
                        ["TotalRequested"] = connectedIds.Count,
                        ["SuccessCount"] = result.SuccessCount,
                        ["FailureCount"] = result.FailureCount,
                        ["Reason"] = reason ?? "No reason provided"
                    });

                return ServiceResult<BulkOperationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to perform bulk revoke");
                return ServiceResult<BulkOperationResult>.Failure(
                    "Failed to perform bulk revoke", "BULK_REVOKE_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        private UserApplicationAccessResponse MapToResponse(
            UserPlatformApplicationAccess access,
            UserAccessIncludeOptions? options = null)
        {
            var response = new UserApplicationAccessResponse
            {
                Id = access.Id,
                OrganizationId = access.OrganizationId,
                ConnectedId = access.ConnectedId,
                ApplicationId = access.ApplicationId,
                AccessLevel = access.AccessLevel,
                AccessTemplateId = access.AccessTemplateId,
                RoleId = access.RoleId,
                Scopes = DeserializeList(access.Scopes),
                AdditionalPermissions = DeserializeList(access.AdditionalPermissions),
                ExcludedPermissions = DeserializeList(access.ExcludedPermissions),
                IsActive = access.IsActive,
                IsValid = access.IsActive && !access.IsDeleted,
                IsExpired = access.ExpiresAt.HasValue && access.ExpiresAt < _dateTimeProvider.UtcNow,
                GrantedAt = access.GrantedAt,
                ExpiresAt = access.ExpiresAt,
                LastAccessedAt = access.LastAccessedAt,
                GrantReason = access.GrantReason,
                IsInherited = access.IsInherited,
                CreatedAt = access.CreatedAt,
                UpdatedAt = access.UpdatedAt
            };

            // Include related data if requested
            if (options?.IncludeApplication == true && access.PlatformApplication != null)
            {
                response.ApplicationName = access.PlatformApplication.Name;
            }

            if (options?.IncludeRole == true && access.Role != null)
            {
                response.RoleName = access.Role.Name;
            }

            if (options?.IncludeTemplate == true && access.AccessTemplate != null)
            {
                response.TemplateName = access.AccessTemplate.Name;
            }

            return response;
        }

        private bool CanGrantAccess(
            UserPlatformApplicationAccess? granterAccess,
            ApplicationAccessLevel targetLevel)
        {
            if (granterAccess == null) return false;

            return granterAccess.AccessLevel switch
            {
                ApplicationAccessLevel.Owner => true,
                ApplicationAccessLevel.Admin => targetLevel <= ApplicationAccessLevel.User,
                _ => false
            };
        }

        private bool CanModifyAccess(
            UserPlatformApplicationAccess? modifierAccess,
            UserPlatformApplicationAccess targetAccess)
        {
            if (modifierAccess == null) return false;

            // Owner can modify anyone
            if (modifierAccess.AccessLevel == ApplicationAccessLevel.Owner) return true;

            // Admin can modify non-admin/owner users
            if (modifierAccess.AccessLevel == ApplicationAccessLevel.Admin)
            {
                return targetAccess.AccessLevel < ApplicationAccessLevel.Admin;
            }

            return false;
        }

        private bool CanRevokeAccess(
            UserPlatformApplicationAccess? revokerAccess,
            UserPlatformApplicationAccess targetAccess)
        {
            return CanModifyAccess(revokerAccess, targetAccess);
        }

        private string GetCacheKey(Guid connectedId, Guid applicationId)
        {
            return $"{CACHE_KEY_PREFIX}:{connectedId}:{applicationId}";
        }

        private async Task InvalidateCacheAsync(Guid connectedId, Guid applicationId)
        {
            var pattern = $"{CACHE_KEY_PREFIX}:*{connectedId}*{applicationId}*";
            await _cacheService.RemoveByPatternAsync(pattern);
        }

        private List<string> ParsePermissions(string? permissionPatterns)
        {
            if (string.IsNullOrEmpty(permissionPatterns))
                return new List<string>();

            return System.Text.Json.JsonSerializer.Deserialize<List<string>>(permissionPatterns)
                ?? new List<string>();
        }

        private bool MatchesPermissionPattern(string permission, string pattern)
        {
            // Simple wildcard matching
            if (pattern.EndsWith("*"))
            {
                var prefix = pattern.Substring(0, pattern.Length - 1);
                return permission.StartsWith(prefix);
            }
            return permission == pattern;
        }

        private MatrixStatistics CalculateMatrixStatistics(
            IEnumerable<UserPlatformApplicationAccess> accesses,
            List<ApplicationHeader> applications,
            List<UserAccessRow> userRows)
        {
            var now = _dateTimeProvider.UtcNow;
            var stats = new MatrixStatistics
            {
                TotalUsers = userRows.Count,
                ActiveUsers = userRows.Count(u => u.IsActive),
                InactiveUsers = userRows.Count(u => !u.IsActive),
                TotalApplications = applications.Count,
                TotalAccessGrants = accesses.Count(),
                ActiveAccessGrants = accesses.Count(a => a.IsActive),
                ExpiredAccessGrants = accesses.Count(a => a.ExpiresAt.HasValue && a.ExpiresAt < now),
                ExpiringAccessGrants = accesses.Count(a =>
                    a.ExpiresAt.HasValue &&
                    a.ExpiresAt > now &&
                    a.ExpiresAt < now.AddDays(7)),
                InheritedAccessGrants = accesses.Count(a => a.IsInherited),
                TemplateBasedAccessGrants = accesses.Count(a => a.AccessTemplateId.HasValue)
            };

            // Access level distribution
            stats.AccessLevelDistribution = accesses
                .GroupBy(a => a.AccessLevel)
                .ToDictionary(g => g.Key, g => g.Count());

            // Average calculations
            stats.AverageAppsPerUser = userRows.Any()
                ? userRows.Average(u => u.TotalAccessibleApps)
                : 0;

            stats.AverageUsersPerApp = applications.Any()
                ? applications.Average(a => a.ActiveUsersCount)
                : 0;

            // Top accessed applications
            stats.TopAccessedApplications = applications
                .OrderByDescending(a => a.ActiveUsersCount)
                .Take(5)
                .Select((a, index) => new ApplicationUsageRank
                {
                    Rank = index + 1,
                    ApplicationId = a.ApplicationId,
                    ApplicationName = a.ApplicationName,
                    UserCount = a.ActiveUsersCount,
                    Percentage = stats.TotalUsers > 0
                        ? (a.ActiveUsersCount * 100.0) / stats.TotalUsers
                        : 0
                })
                .ToList();

            // Least accessed applications
            stats.LeastAccessedApplications = applications
                .OrderBy(a => a.ActiveUsersCount)
                .Take(5)
                .Select((a, index) => new ApplicationUsageRank
                {
                    Rank = index + 1,
                    ApplicationId = a.ApplicationId,
                    ApplicationName = a.ApplicationName,
                    UserCount = a.ActiveUsersCount,
                    Percentage = stats.TotalUsers > 0
                        ? (a.ActiveUsersCount * 100.0) / stats.TotalUsers
                        : 0
                })
                .ToList();

            return stats;
        }

        private async Task LogAuditAsync(
            Guid performedByConnectedId,
            string action,
            string description,
            Guid? applicationId,
            Guid? organizationId,
            Dictionary<string, object>? metadata = null)
        {
            try
            {
                // Description을 metadata에 포함
                var auditMetadata = metadata != null
                    ? new Dictionary<string, object>(metadata)
                    : new Dictionary<string, object>();

                auditMetadata["Description"] = description;

                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = performedByConnectedId,
                    TargetOrganizationId = organizationId,
                    ApplicationId = applicationId,
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = DetermineActionType(action),
                    Action = action,
                    ResourceType = "UserApplicationAccess",
                    ResourceId = applicationId?.ToString(),
                    Success = true,
                    Metadata = System.Text.Json.JsonSerializer.Serialize(auditMetadata),
                    Severity = AuditEventSeverity.Info,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = performedByConnectedId
                };

                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for action {Action}", action);
            }
        }

        private AuditActionType DetermineActionType(string action)
        {
            return action switch
            {
                "ACCESS_GRANTED" => AuditActionType.Create,
                "ACCESS_UPDATED" => AuditActionType.Update,
                "ACCESS_REVOKED" => AuditActionType.Delete,
                "ACCESS_RENEWED" => AuditActionType.Update,
                "TEMPLATE_APPLIED" => AuditActionType.Update,
                "PERMISSIONS_ADDED" => AuditActionType.Update,
                "PERMISSIONS_EXCLUDED" => AuditActionType.Update,
                "BULK_ACCESS_GRANTED" => AuditActionType.Create,
                "BULK_ACCESS_REVOKED" => AuditActionType.Delete,
                "ACCESS_INHERITED" => AuditActionType.Create,
                _ => AuditActionType.Read
            };
        }
        private void SendAccessGrantedNotification(
            Guid connectedId,
            Guid applicationId,
            string applicationName)
        {
            try
            {
                // 실제 구현에서는 이메일/푸시 알림 발송
                // 여기서는 로깅만 수행
                _logger.LogInformation(
                    "Access granted notification sent to {ConnectedId} for {ApplicationName} (ID: {ApplicationId})",
                    connectedId, applicationName, applicationId);

                // TODO: 실제 알림 서비스 호출
                // await _emailService.SendAccessGrantedEmailAsync(connectedId, applicationId, applicationName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send access granted notification");
                // 알림 실패는 전체 트랜잭션을 실패시키지 않음
            }
        }


        private void SendAccessRevokedNotification(
            Guid connectedId,
            Guid applicationId,
            string? reason)
        {
            try
            {
                // Implementation would send email/push notification
                _logger.LogInformation(
                    "Access revoked notification sent to {ConnectedId} for {ApplicationId}",
                    connectedId, applicationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send access revoked notification");
            }
        }

        // JSON serialization helpers for JSONB fields
        private string SerializeList(List<string>? list)
        {
            if (list == null || !list.Any())
                return "[]";

            return System.Text.Json.JsonSerializer.Serialize(list);
        }

        private List<string> DeserializeList(string? json)
        {
            if (string.IsNullOrEmpty(json) || json == "[]")
                return new List<string>();

            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<List<string>>(json)
                    ?? new List<string>();
            }
            catch
            {
                // If it's not JSON, try splitting by comma (backward compatibility)
                return json.Split(',').Select(s => s.Trim()).ToList();
            }
        }

        #endregion
    }
}