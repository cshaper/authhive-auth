using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
using System.Text.Json;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Models.Auth.Authentication;
using UserEntity = AuthHive.Core.Entities.User.User;
using static AuthHive.Core.Enums.Core.UserEnums;
using Microsoft.EntityFrameworkCore;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 SSO 서비스 구현체 - AuthHive v15.5
    /// WHO: 조직 관리자, 보안 팀, 시스템 스케줄러
    /// WHEN: SSO 설정 생성/수정/삭제, 인증 시도, 정기 검증 시
    /// WHERE: Admin Dashboard, 로그인 플로우, 백그라운드 작업
    /// WHAT: SSO 설정의 전체 생명주기 관리 및 비즈니스 로직 처리
    /// WHY: 엔터프라이즈 SSO 통합으로 보안 강화 및 사용자 편의성 향상
    /// HOW: Repository 패턴 + 캐싱 전략 + 이벤트 기반 알림
    /// </summary>
    public class OrganizationSSOService : IOrganizationSSOService
    {
        private readonly IOrganizationSSORepository _ssoRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationSSOService> _logger;
        private readonly IConnectedIdService _connectedIdService;
        private readonly AuthDbContext _context;
        public OrganizationSSOService(
            IOrganizationSSORepository ssoRepository,
            IOrganizationRepository organizationRepository,
            IUnitOfWork unitOfWork,
            IMemoryCache cache,
            ILogger<OrganizationSSOService> logger,
            IConnectedIdService connectedIdService,
            AuthDbContext context)
        {
            _ssoRepository = ssoRepository;
            _organizationRepository = organizationRepository;
            _unitOfWork = unitOfWork;
            _cache = cache;
            _logger = logger;
            _connectedIdService = connectedIdService;
            _context = context;
        }

        #region IService Implementation
        // OrganizationSSOService.cs

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            try
            {

                await _ssoRepository.CountAsync(null, cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                // Log the exception for diagnostics (added ex argument)
                _logger.LogError(ex, "OrganizationSSOService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) 
        {
            _logger.LogInformation("OrganizationSSOService 초기화 시작");
            _logger.LogInformation("OrganizationSSOService 초기화 완료");
            // Direct return avoids the unnecessary async state machine overhead.
            return Task.CompletedTask;
        }

        #endregion

        #region Core SSO Management

        public async Task<ServiceResult<OrganizationSSOResponse>> ConfigureSSOAsync(
            Guid organizationId,
            CreateOrganizationSSORequest request,
            Guid configuredByConnectedId)
        {
            try
            {
                _logger.LogInformation(
                    "SSO 설정 시작 - Organization: {OrganizationId}, ConfiguredBy: {ConnectedId}",
                    organizationId, configuredByConnectedId);

                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure("Organization not found");
                }

                if (organization.Status != OrganizationStatus.Active)
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure("Organization is not active");
                }

                var existingSSOs = await _ssoRepository.GetActiveByOrganizationAsync(organizationId);
                if (existingSSOs.Any(s => s.ProviderName == request.ProviderName &&
                                         s.DisplayName == request.DisplayName))
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure("SSO configuration already exists");
                }

                var sso = new OrganizationSSO
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    SSOType = request.SSOType,
                    ProviderName = request.ProviderName,
                    Configuration = request.Configuration,
                    DisplayName = request.DisplayName,
                    IsActive = request.ActivateImmediately,
                    IsDefault = request.IsDefault,
                    Priority = request.Priority,
                    AutoCreateUsers = request.AutoCreateUsers,
                    DefaultRoleId = request.DefaultRoleId,
                    IconUrl = request.IconUrl,
                    AttributeMapping = request.AttributeMapping,
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = configuredByConnectedId
                };

                await _ssoRepository.AddAsync(sso);
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(organizationId);

                var response = MapToResponse(sso);

                _logger.LogInformation(
                    "SSO 설정 완료 - SSO ID: {SSOId}, Organization: {OrganizationId}",
                    sso.Id, organizationId);

                return ServiceResult<OrganizationSSOResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "SSO 설정 중 오류 발생 - Organization: {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationSSOResponse>.Failure($"Failed to configure SSO: {ex.Message}");
            }
        }
        public async Task<ServiceResult<AuthenticationOutcome>> ProcessSsoResponseAsync(Guid organizationId, string samlResponse, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 조직의 SSO 설정을 가져옵니다.
                var ssoConfigs = await _ssoRepository.GetActiveByOrganizationAsync(organizationId);
                var ssoConfig = ssoConfigs.FirstOrDefault(s => s.IsDefault); // 기본 설정을 사용하거나, 적절한 설정을 찾습니다.

                if (ssoConfig == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("No active SSO configuration found for the organization.", "SSO_NOT_CONFIGURED");
                }

                // --- ❗ 중요 ❗ ---
                // TODO: 여기에 SAML 라이브러리(예: ITfoxtec.Identity.Saml2, Sustainsys.Saml2)를 사용하여
                //       SAML 응답을 검증하고 사용자 속성(Attribute)을 추출하는 로직을 구현해야 합니다.
                //       아래는 검증이 성공했다고 가정한 시뮬레이션 코드입니다.

                // --- SAML 검증 및 속성 추출 (시뮬레이션) ---
                var samlValidationResult = new
                {
                    IsValid = true, // SAML 응답이 유효한가?
                    Email = "user.from.sso@example.com", // NameID 또는 Email 속성
                    FirstName = "Sso",
                    LastName = "User",
                    ExternalId = "sso-user-12345" // 공급자 측의 사용자 고유 ID
                };
                // --- 시뮬레이션 끝 ---

                if (!samlValidationResult.IsValid || string.IsNullOrEmpty(samlValidationResult.Email))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid SAML response or missing user identifier.", "INVALID_SAML_RESPONSE");
                }

                var userEmail = samlValidationResult.Email;
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
                bool isNewUser = false;

                // 3. 사용자가 없으면 자동 생성 옵션에 따라 새로 만듭니다.
                if (user == null)
                {
                    if (!ssoConfig.AutoCreateUsers)
                    {
                        return ServiceResult<AuthenticationOutcome>.Failure($"User with email {userEmail} does not exist and auto-creation is disabled.", "USER_NOT_FOUND");
                    }

                    user = new UserEntity
                    {
                        Email = userEmail,
                        DisplayName = $"{samlValidationResult.FirstName} {samlValidationResult.LastName}".Trim(),
                        Status = UserStatus.Active,
                        EmailVerified = true // SSO를 통해 왔으므로 이메일은 검증된 것으로 간주
                    };
                    _context.Users.Add(user);
                    await _unitOfWork.SaveChangesAsync();
                    isNewUser = true;
                }

                // 4. ConnectedId를 찾거나 생성합니다.
                var connectedIdResult = await _connectedIdService.GetOrCreateAsync(user.Id, organizationId, cancellationToken);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to get or create a connection for the user to the organization.", "CONNECTED_ID_ERROR");
                }

                // 5. 최종 인증 결과를 반환합니다.
                var outcome = new AuthenticationOutcome
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedIdResult.Data.Id,
                    IsNewUser = isNewUser,
                    Provider = ssoConfig.ProviderName.ToString(),
                    ExternalId = samlValidationResult.ExternalId,
                    AuthenticationMethod = "SSO"
                };

                return ServiceResult<AuthenticationOutcome>.Success(outcome);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while processing SSO response for organization {OrganizationId}", organizationId);
                return ServiceResult<AuthenticationOutcome>.Failure("An unexpected error occurred during SSO processing.", "SSO_PROCESSING_ERROR");
            }
        }
        public async Task<ServiceResult<OrganizationSSOListResponse>> GetSSOConfigurationsAsync(
            Guid organizationId)
        {
            try
            {
                var cacheKey = $"OrgSSO:List:{organizationId}";

                if (_cache.TryGetValue(cacheKey, out OrganizationSSOListResponse? cached))
                {
                    _logger.LogDebug("SSO 목록 캐시 히트: {OrganizationId}", organizationId);
                    return ServiceResult<OrganizationSSOListResponse>.Success(cached!);
                }

                var ssos = await _ssoRepository.GetActiveByOrganizationAsync(organizationId);

                var response = new OrganizationSSOListResponse
                {
                    Items = ssos.Select(MapToResponse).ToList(),
                    TotalCount = ssos.Count()
                };

                _cache.Set(cacheKey, response, TimeSpan.FromMinutes(5));

                return ServiceResult<OrganizationSSOListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "SSO 목록 조회 중 오류 - Organization: {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationSSOListResponse>.Failure("Failed to retrieve SSO configurations");
            }
        }

        public async Task<ServiceResult<OrganizationSSODetailResponse>> GetSSODetailAsync(
            Guid ssoId,
            bool includeSensitive = false)
        {
            try
            {
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult<OrganizationSSODetailResponse>.Failure("SSO configuration not found");
                }

                var response = new OrganizationSSODetailResponse
                {
                    Id = sso.Id,
                    OrganizationId = sso.OrganizationId,
                    SSOType = sso.SSOType,
                    ProviderName = sso.ProviderName,
                    DisplayName = sso.DisplayName ?? string.Empty,
                    Configuration = includeSensitive ? sso.Configuration : MaskSensitiveMetadata(sso.Configuration),
                    AttributeMapping = sso.AttributeMapping,
                    IsActive = sso.IsActive,
                    IsDefault = sso.IsDefault,
                    AutoCreateUsers = sso.AutoCreateUsers,
                    DefaultRoleId = sso.DefaultRoleId,
                    IconUrl = sso.IconUrl,
                    Priority = sso.Priority,
                    LastTestedAt = sso.LastTestedAt,
                    CreatedAt = sso.CreatedAt,
                    UpdatedAt = sso.UpdatedAt
                };

                // AllowedDomains를 Configuration JSON에서 추출
                if (!string.IsNullOrEmpty(sso.Configuration))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(sso.Configuration);
                        if (doc.RootElement.TryGetProperty("allowedDomains", out var domainsElement))
                        {
                            response.AllowedDomains = domainsElement.EnumerateArray()
                                .Select(e => e.GetString() ?? string.Empty)
                                .Where(d => !string.IsNullOrEmpty(d))
                                .ToList();
                        }
                    }
                    catch { }
                }

                return ServiceResult<OrganizationSSODetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 상세 조회 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult<OrganizationSSODetailResponse>.Failure("Failed to retrieve SSO details");
            }
        }

        public async Task<ServiceResult<OrganizationSSOResponse>> UpdateSSOAsync(
            Guid ssoId,
            CreateOrganizationSSORequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                _logger.LogInformation(
                    "SSO 업데이트 시작 - SSO ID: {SSOId}, UpdatedBy: {ConnectedId}",
                    ssoId, updatedByConnectedId);

                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure("SSO configuration not found");
                }

                sso.SSOType = request.SSOType;
                sso.ProviderName = request.ProviderName;
                sso.DisplayName = request.DisplayName;
                sso.Configuration = request.Configuration;
                sso.AttributeMapping = request.AttributeMapping;
                sso.Priority = request.Priority;
                sso.IconUrl = request.IconUrl;
                sso.AutoCreateUsers = request.AutoCreateUsers;
                sso.DefaultRoleId = request.DefaultRoleId;
                sso.UpdatedAt = DateTime.UtcNow;
                sso.UpdatedByConnectedId = updatedByConnectedId;

                if (request.ActivateImmediately != sso.IsActive)
                {
                    sso.IsActive = request.ActivateImmediately;
                }

                await _ssoRepository.UpdateAsync(sso);
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(sso.OrganizationId);

                var response = MapToResponse(sso);

                _logger.LogInformation("SSO 업데이트 완료 - SSO ID: {SSOId}", ssoId);

                return ServiceResult<OrganizationSSOResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 업데이트 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult<OrganizationSSOResponse>.Failure("Failed to update SSO");
            }
        }

        public async Task<ServiceResult> DeleteSSOAsync(
            Guid ssoId,
            Guid deletedByConnectedId,
            string reason)
        {
            try
            {
                _logger.LogInformation(
                    "SSO 삭제 시작 - SSO ID: {SSOId}, DeletedBy: {ConnectedId}, Reason: {Reason}",
                    ssoId, deletedByConnectedId, reason);

                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult.Failure("SSO configuration not found");
                }

                if (sso.IsDefault)
                {
                    return ServiceResult.Failure("Cannot delete default SSO configuration");
                }

                sso.IsDeleted = true;
                sso.IsActive = false;
                sso.DeletedAt = DateTime.UtcNow;
                sso.DeletedByConnectedId = deletedByConnectedId;

                await _ssoRepository.UpdateAsync(sso);
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(sso.OrganizationId);

                _logger.LogInformation(
                    "SSO 삭제 완료 - SSO ID: {SSOId}, Organization: {OrganizationId}",
                    ssoId, sso.OrganizationId);

                return ServiceResult.Success("SSO configuration deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 삭제 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult.Failure("Failed to delete SSO");
            }
        }

        #endregion

        #region SSO Status Management

        public async Task<ServiceResult> ActivateSSOAsync(
            Guid ssoId,
            Guid activatedByConnectedId)
        {
            try
            {
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult.Failure("SSO configuration not found");
                }

                if (sso.IsActive)
                {
                    return ServiceResult.Success("SSO is already active");
                }

                sso.IsActive = true;
                sso.UpdatedAt = DateTime.UtcNow;
                sso.UpdatedByConnectedId = activatedByConnectedId;

                await _ssoRepository.UpdateAsync(sso);
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(sso.OrganizationId);

                _logger.LogInformation(
                    "SSO 활성화 - SSO ID: {SSOId}, ActivatedBy: {ConnectedId}",
                    ssoId, activatedByConnectedId);

                return ServiceResult.Success("SSO activated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 활성화 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult.Failure("Failed to activate SSO");
            }
        }

        public async Task<ServiceResult> DeactivateSSOAsync(
            Guid ssoId,
            Guid deactivatedByConnectedId,
            string reason)
        {
            try
            {
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult.Failure("SSO configuration not found");
                }

                if (sso.IsDefault && sso.IsActive)
                {
                    // Replace the GetCountByOrganizationAsync call with this:
                    var activeSSOs = await _ssoRepository.GetActiveByOrganizationAsync(sso.OrganizationId);
                    var activeCount = activeSSOs.Count();

                    if (activeCount <= 1)
                    {
                        return ServiceResult.Failure("Cannot deactivate the only active SSO");
                    }
                }

                sso.IsActive = false;
                sso.UpdatedAt = DateTime.UtcNow;
                sso.UpdatedByConnectedId = deactivatedByConnectedId;

                await _ssoRepository.UpdateAsync(sso);
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(sso.OrganizationId);

                _logger.LogInformation(
                    "SSO 비활성화 - SSO ID: {SSOId}, DeactivatedBy: {ConnectedId}, Reason: {Reason}",
                    ssoId, deactivatedByConnectedId, reason);

                return ServiceResult.Success("SSO deactivated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 비활성화 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult.Failure("Failed to deactivate SSO");
            }
        }
        public async Task<ServiceResult> SetAsDefaultAsync(
            Guid ssoId,
            Guid setByConnectedId)
        {
            try
            {
                // Get the SSO to be set as default
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult.Failure("SSO configuration not found");
                }

                // Get all SSOs for the organization
                var organizationSSOs = await _ssoRepository.GetActiveByOrganizationAsync(sso.OrganizationId);

                // Set all other SSOs as non-default
                foreach (var otherSSO in organizationSSOs)
                {
                    if (otherSSO.IsDefault && otherSSO.Id != ssoId)
                    {
                        otherSSO.IsDefault = false;
                        otherSSO.UpdatedAt = DateTime.UtcNow;
                        otherSSO.UpdatedByConnectedId = setByConnectedId;
                        await _ssoRepository.UpdateAsync(otherSSO);
                    }
                }

                // Set the target SSO as default
                sso.IsDefault = true;
                sso.UpdatedAt = DateTime.UtcNow;
                sso.UpdatedByConnectedId = setByConnectedId;
                await _ssoRepository.UpdateAsync(sso);

                // Save all changes
                await _unitOfWork.SaveChangesAsync();
                await InvalidateSSOCacheAsync(sso.OrganizationId);

                _logger.LogInformation(
                    "SSO 기본값 설정 - SSO ID: {SSOId}, SetBy: {ConnectedId}",
                    ssoId, setByConnectedId);

                return ServiceResult.Success("SSO set as default successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 기본값 설정 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult.Failure("Failed to set SSO as default");
            }
        }
        #endregion

        #region SSO Testing and Validation

        public async Task<ServiceResult<SSOTestResult>> TestSSOConnectionAsync(
            Guid ssoId,
            Guid? testedByConnectedId = null)
        {
            try
            {
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult<SSOTestResult>.Failure("SSO configuration not found");
                }

                var startTime = DateTime.UtcNow;
                var testResult = new SSOTestResult
                {
                    TestedAt = startTime
                };

                try
                {
                    await Task.Delay(100); // 시뮬레이션

                    testResult.Success = true;
                    testResult.ResponseTime = DateTime.UtcNow - startTime;
                    testResult.Details["Provider"] = sso.ProviderName.ToString();
                    testResult.Details["Status"] = "Connected";

                    if (testedByConnectedId.HasValue)
                    {
                        // Replace UpdateTestStatusAsync with direct entity update
                        sso.LastTestedAt = DateTime.UtcNow;
                        sso.UpdatedAt = DateTime.UtcNow;
                        sso.UpdatedByConnectedId = testedByConnectedId.Value;

                        await _ssoRepository.UpdateAsync(sso);
                        await _unitOfWork.SaveChangesAsync();
                    }

                    _logger.LogInformation(
                        "SSO 테스트 성공 - SSO ID: {SSOId}, ResponseTime: {ResponseTime}ms",
                        ssoId, testResult.ResponseTime.TotalMilliseconds);
                }
                catch (Exception testEx)
                {
                    testResult.Success = false;
                    testResult.ErrorMessage = testEx.Message;
                    testResult.ResponseTime = DateTime.UtcNow - startTime;

                    _logger.LogWarning(
                        "SSO 테스트 실패 - SSO ID: {SSOId}, Error: {Error}",
                        ssoId, testEx.Message);
                }

                return ServiceResult<SSOTestResult>.Success(testResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 테스트 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult<SSOTestResult>.Failure("Failed to test SSO connection");
            }
        }
        public Task<ServiceResult<SSOValidationResult>> ValidateSSOConfigurationAsync(
            OrganizationSSODto ssoDto)
        {
            var result = new SSOValidationResult
            {
                IsValid = true,
                Errors = new List<string>(),
                Warnings = new List<string>()
            };

            try
            {
                if (ssoDto.Id == Guid.Empty)
                {
                    result.Errors.Add("SSO ID is required");
                    result.IsValid = false;
                }

                if (string.IsNullOrWhiteSpace(ssoDto.DisplayName))
                {
                    result.Errors.Add("Display name is required");
                    result.IsValid = false;
                }

                if (!string.IsNullOrWhiteSpace(ssoDto.Configuration))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(ssoDto.Configuration);
                    }
                    catch
                    {
                        result.Errors.Add("Invalid configuration JSON");
                        result.IsValid = false;
                    }
                }

                return Task.FromResult(ServiceResult<SSOValidationResult>.Success(result));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SSO 설정 검증 중 오류");
                result.IsValid = false;
                result.Errors.Add($"Validation failed: {ex.Message}");
                return Task.FromResult(ServiceResult<SSOValidationResult>.Success(result));
            }
        }

        public async Task<ServiceResult<OrganizationSSOInfo>> GetSSOByDomainAsync(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain))
                {
                    return ServiceResult<OrganizationSSOInfo>.Failure("Domain is required");
                }

                var matchedSSO = await _ssoRepository.GetByDomainAsync(domain);

                if (matchedSSO == null)
                {
                    return ServiceResult<OrganizationSSOInfo>.Failure($"No SSO configuration found for domain: {domain}");
                }

                var info = new OrganizationSSOInfo
                {
                    Id = matchedSSO.Id,
                    OrganizationId = matchedSSO.OrganizationId,
                    ProviderName = matchedSSO.ProviderName.ToString(),
                    DisplayName = matchedSSO.DisplayName ?? string.Empty,
                    IsActive = matchedSSO.IsActive
                };

                return ServiceResult<OrganizationSSOInfo>.Success(info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "도메인 기반 SSO 조회 중 오류 - Domain: {Domain}", domain);
                return ServiceResult<OrganizationSSOInfo>.Failure("Failed to find SSO by domain");
            }
        }

        #endregion

        #region SSO Certificate Management

        public async Task<ServiceResult<SslCertificateStatus>> CheckCertificateStatusAsync(Guid ssoId)
        {
            try
            {
                var sso = await _ssoRepository.GetByIdAsync(ssoId);
                if (sso == null)
                {
                    return ServiceResult<SslCertificateStatus>.Failure("SSO configuration not found");
                }

                var status = new SslCertificateStatus
                {
                    IsEnabled = true,
                    IsValid = true,
                    Status = "Active",
                    ExpiresAt = DateTime.UtcNow.AddDays(90),
                    Subject = "CN=sso.example.com",
                    Issuer = "CN=Example CA",
                    LastCheckedAt = DateTime.UtcNow
                };

                if (status.DaysRemaining < 30)
                {
                    _logger.LogWarning(
                        "인증서 만료 임박 - SSO ID: {SSOId}, Days: {Days}",
                        ssoId, status.DaysRemaining);
                }

                return ServiceResult<SslCertificateStatus>.Success(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "인증서 상태 확인 중 오류 - SSO ID: {SSOId}", ssoId);
                return ServiceResult<SslCertificateStatus>.Failure("Failed to check certificate status");
            }
        }

        public async Task<ServiceResult<List<SslCertificateStatus>>> GetExpiringCertificatesAsync(
            Guid organizationId,
            int daysBeforeExpiry = 30)
        {
            try
            {
                var expiringCerts = new List<SslCertificateStatus>();
                var ssos = await _ssoRepository.GetActiveByOrganizationAsync(organizationId);

                foreach (var sso in ssos)
                {
                    var certCheck = await CheckCertificateStatusAsync(sso.Id);
                    if (certCheck.IsSuccess &&
                        certCheck.Data != null &&
                        certCheck.Data.DaysRemaining <= daysBeforeExpiry)
                    {
                        expiringCerts.Add(certCheck.Data);
                    }
                }

                if (expiringCerts.Any())
                {
                    _logger.LogWarning(
                        "만료 예정 인증서 발견 - Organization: {OrganizationId}, Count: {Count}",
                        organizationId, expiringCerts.Count);
                }

                return ServiceResult<List<SslCertificateStatus>>.Success(expiringCerts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "만료 예정 인증서 확인 중 오류 - Organization: {OrganizationId}",
                    organizationId);
                return ServiceResult<List<SslCertificateStatus>>.Failure("Failed to check expiring certificates");
            }
        }

        #endregion

        #region SSO Statistics

        public async Task<ServiceResult<SSOUsageStatistics>> GetUsageStatisticsAsync(
            Guid ssoId,
            DateTime startDate,
            DateTime endDate)
        {
            try
            {
                var cacheKey = $"SSOStats:{ssoId}:{startDate:yyyyMMdd}:{endDate:yyyyMMdd}";

                if (_cache.TryGetValue(cacheKey, out SSOUsageStatistics? cached))
                {
                    return ServiceResult<SSOUsageStatistics>.Success(cached!);
                }

                var statistics = await _ssoRepository.GetUsageStatisticsAsync(ssoId, startDate, endDate);

                _cache.Set(cacheKey, statistics, TimeSpan.FromHours(1));

                return ServiceResult<SSOUsageStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "SSO 통계 조회 중 오류 - SSO ID: {SSOId}",
                    ssoId);
                return ServiceResult<SSOUsageStatistics>.Failure("Failed to get usage statistics");
            }
        }

        #endregion

        #region Private Helper Methods

        private OrganizationSSOResponse MapToResponse(OrganizationSSO sso)
        {
            var response = new OrganizationSSOResponse
            {
                Id = sso.Id,
                OrganizationId = sso.OrganizationId,
                SSOType = sso.SSOType,
                ProviderName = sso.ProviderName,
                DisplayName = sso.DisplayName ?? string.Empty,
                Configuration = sso.Configuration,
                AttributeMapping = sso.AttributeMapping,
                IsActive = sso.IsActive,
                IsDefault = sso.IsDefault,
                AutoCreateUsers = sso.AutoCreateUsers,
                DefaultRoleId = sso.DefaultRoleId,
                IconUrl = sso.IconUrl,
                Priority = sso.Priority,
                LastTestedAt = sso.LastTestedAt,
                CreatedAt = sso.CreatedAt,
                UpdatedAt = sso.UpdatedAt
            };

            // Configuration에서 AllowedDomains 추출
            if (!string.IsNullOrEmpty(sso.Configuration))
            {
                try
                {
                    using var doc = JsonDocument.Parse(sso.Configuration);
                    if (doc.RootElement.TryGetProperty("allowedDomains", out var domainsElement))
                    {
                        response.AllowedDomains = domainsElement.EnumerateArray()
                            .Select(e => e.GetString() ?? string.Empty)
                            .Where(d => !string.IsNullOrEmpty(d))
                            .ToList();
                    }
                }
                catch { }
            }

            return response;
        }

        private async Task InvalidateSSOCacheAsync(Guid organizationId)
        {
            _cache.Remove($"OrgSSO:List:{organizationId}");
            _cache.Remove($"OrgSSO:Default:{organizationId}");
            await _ssoRepository.InvalidateCacheAsync(organizationId);
        }

        private string MaskSensitiveMetadata(string metadata)
        {
            if (string.IsNullOrEmpty(metadata))
                return string.Empty;

            try
            {
                using var doc = JsonDocument.Parse(metadata);
                var masked = new Dictionary<string, object>();

                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Name.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Contains("key", StringComparison.OrdinalIgnoreCase))
                    {
                        masked[prop.Name] = "***MASKED***";
                    }
                    else
                    {
                        masked[prop.Name] = prop.Value.ToString();
                    }
                }

                return JsonSerializer.Serialize(masked);
            }
            catch
            {
                return "***MASKED***";
            }
        }

        private bool IsValidDomain(string domain)
        {
            return !string.IsNullOrWhiteSpace(domain) &&
                   domain.Contains('.') &&
                   !domain.StartsWith('.') &&
                   !domain.EndsWith('.');
        }

        #endregion
    }
}