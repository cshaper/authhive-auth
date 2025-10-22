using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Entities.Organization; // Organization 엔티티 (필요시)
using AuthHive.Core.Interfaces.Auth.Repository; // ISSOConfigurationRepository
using AuthHive.Core.Interfaces.Organization.Repository; // IOrganizationRepository
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common; // ServiceResult, ServiceErrorReason
using AuthHive.Core.Models.Organization; // OrganizationSSODto
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Auth;
// ✨ SSOUsageStatistics 네임스페이스 확인
using AuthHive.Core.Models.Auth.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit;
// using AuthHive.Auth.Data.Context; // 직접 DbContext 사용 지양
using AuthHive.Core.Interfaces.User; // IUserRepository 가정
using AuthHive.Core.Models.Auth.Authentication;
using UserEntity = AuthHive.Core.Entities.User.User;
using static AuthHive.Core.Enums.Core.UserEnums;
using Microsoft.EntityFrameworkCore; // ToListAsync, EntityState 등 최소 사용
using AuthHive.Core.Constants;
using AuthHive.Core.Models.Audit; // AuditLogDto
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Models;
using System.Text.Json.Serialization;
using AuthHive.Auth.Extensions; // SamlConfiguration 엔티티

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 SSO 서비스 구현체 - AuthHive v16
    /// </summary>
    public class OrganizationSSOService : IOrganizationSSOService
    {
        private readonly ISSOConfigurationRepository _ssoConfigRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ICacheService _cacheService;
        private readonly ILogger<OrganizationSSOService> _logger;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IAuditService _auditService;
        private readonly IPrincipalAccessor _principalAccessor;
        // TODO: IAuthorizationService, IPlanRestrictionService, IRateLimiterService 등 주입 필요

        public OrganizationSSOService(
            ISSOConfigurationRepository ssoConfigRepository,
            IOrganizationRepository organizationRepository,
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ICacheService cacheService,
            ILogger<OrganizationSSOService> logger,
            IConnectedIdService connectedIdService,
            IDateTimeProvider dateTimeProvider,
            IAuditService auditService,
            IPrincipalAccessor principalAccessor)
        {
            _ssoConfigRepository = ssoConfigRepository ?? throw new ArgumentNullException(nameof(ssoConfigRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _principalAccessor = principalAccessor ?? throw new ArgumentNullException(nameof(principalAccessor));
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _ssoConfigRepository.CountAsync(cancellationToken: cancellationToken);
                // 다른 주요 의존성(예: CacheService) 상태 확인 추가 고려
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationSSOService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationSSOService initializing...");
            // TODO: 필요한 초기화 로직 (예: 캐시 워밍업)
            _logger.LogInformation("OrganizationSSOService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Core SSO Management

        public async Task<ServiceResult<OrganizationSSOResponse>> ConfigureSSOAsync(
            Guid organizationId, CreateOrganizationSSORequest request, Guid configuredByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증: configuredByConnectedId가 organizationId의 SSO를 설정할 권한이 있는가?
            // TODO: 요금제 검증: 해당 조직 요금제가 새 SSO 설정을 허용하는가? (개수 제한 등)

            try
            {
                _logger.LogInformation("Attempting to configure SSO for Organization {OrganizationId} by {ConfiguredBy}", organizationId, configuredByConnectedId);

                var organization = await _organizationRepository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null || organization.IsDeleted)
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure($"Organization '{organizationId}' not found or deleted.", errorCode: ServiceErrorReason.NotFound);
                }
                if (organization.Status != OrganizationStatus.Active)
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure($"Organization '{organizationId}' is not active.", errorCode: ServiceErrorReason.Forbidden);
                }

                // 동일 Provider + DisplayName 중복 확인
                var existingSSOs = await _ssoConfigRepository.FindAsync(s => s.OrganizationId == organizationId && s.Provider == request.ProviderName.ToString() && s.DisplayName == request.DisplayName, cancellationToken);
                if (existingSSOs.Any())
                {
                    return ServiceResult<OrganizationSSOResponse>.Failure($"SSO configuration with name '{request.DisplayName}' for provider '{request.ProviderName}' already exists.", errorCode: ServiceErrorReason.Conflict);
                }

                var now = _dateTimeProvider.UtcNow;
                // ✅ [수정] new(organizationId) public 생성자를 먼저 호출합니다.
                var ssoEntity = new SamlConfiguration(organizationId); // 엔티티 생성

                // ✅ [수정] 속성은 객체 생성 후에 개별적으로 할당합니다.
                ssoEntity.Protocol = request.SSOType.ToString();
                ssoEntity.Provider = request.ProviderName.ToString();
                ssoEntity.DisplayName = request.DisplayName;
                ssoEntity.IsEnabled = request.ActivateImmediately;
                ssoEntity.IsDefault = false; // 기본값 설정은 별도 메서드 사용 권장
                ssoEntity.Priority = request.Priority;
                ssoEntity.EnableAutoProvisioning = request.AutoCreateUsers;
                ssoEntity.DefaultRoleId = request.DefaultRoleId;
                ssoEntity.IconUrl = request.IconUrl;
                ssoEntity.AttributeMapping = request.AttributeMapping ?? "{}"; // Null 대신 기본값
                ssoEntity.AllowedDomains = request.AllowedDomains != null ? JsonSerializer.Serialize(request.AllowedDomains) : "[]";
                ssoEntity.GroupMapping = request.GroupMapping ?? "{}"; // Null 대신 기본값

                // ✅ [참고] Id, OrganizationId, CreatedAt은 
                // 부모 엔티티와 SamlConfiguration 생성자에서 자동으로 설정됩니다.
                // 따라서 CreatedByConnectedId만 설정해주면 됩니다.
                // ssoEntity.CreatedAt = now; // (자동 설정됨)
                ssoEntity.CreatedByConnectedId = configuredByConnectedId;
                ParseAndApplyConfiguration(request.Configuration, ssoEntity); // JSON 설정 파싱 및 적용

                // 요청에서 기본값으로 설정하려 할 경우
                if (request.IsDefault)
                {
                    await UnsetDefaultSSOAsync(organizationId, configuredByConnectedId, cancellationToken); // 기존 기본값 해제
                    ssoEntity.IsDefault = true;
                    ssoEntity.IsEnabled = true; // 기본값은 항상 활성화
                }

                // TODO: 생성 전 설정 유효성 검증 (ValidateSSOConfigurationAsync 호출)

                await _ssoConfigRepository.AddAsync(ssoEntity, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken); // DB 저장

                // 감사 로그 기록
                await _auditService.LogActionAsync(
         actionType: AuditActionType.Create, // ✨ AuditActionType enum 값 사용 (정의 필요)
         action: AuditEvent.SSOConfigured.ToString(), // ✨ AuditEvent enum 값 사용
         connectedId: configuredByConnectedId, // ✨ 필수 파라미터 전달
         success: true,
         resourceType: nameof(SamlConfiguration),
         resourceId: ssoEntity.Id.ToString(),
         metadata: new Dictionary<string, object> { // ✨ 메타데이터 전달 (선택적)
            { "OrganizationId", organizationId },
            { "DisplayName", ssoEntity.DisplayName ?? "N/A" },
            { "Provider", ssoEntity.Provider }
         },
         cancellationToken: cancellationToken);

                // 관련 캐시 무효화
                await InvalidateSSOCacheAsync(organizationId, cancellationToken);

                var response = MapToResponse(ssoEntity); // 엔티티 -> 응답 DTO 변환
                _logger.LogInformation("Successfully configured SSO {SsoId} for Organization {OrganizationId}", ssoEntity.Id, organizationId);
                return ServiceResult<OrganizationSSOResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error configuring SSO for Organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationSSOResponse>.Failure($"An error occurred while configuring SSO: {ex.Message}", errorCode: ServiceErrorReason.InternalError);
            }
        }

        public async Task<ServiceResult<OrganizationSSOListResponse>> GetSSOConfigurationsAsync(
            Guid organizationId, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증: 현재 사용자가 이 조직의 설정을 볼 수 있는가?
            try
            {
                var cacheKey = $"OrgSSO:List:{organizationId}";
                var cached = await _cacheService.GetAsync<OrganizationSSOListResponse>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    _logger.LogDebug("SSO list cache hit for Organization {OrganizationId}", organizationId);
                    return ServiceResult<OrganizationSSOListResponse>.Success(cached);
                }

                _logger.LogDebug("SSO list cache miss for Organization {OrganizationId}", organizationId);
                // 리포지토리 사용 (IsDeleted=false 는 BaseRepository가 처리)
                var ssoEntities = await _ssoConfigRepository.FindAsync(s => s.OrganizationId == organizationId, cancellationToken);

                var responseItems = ssoEntities
                                    .OrderBy(s => s.Priority)
                                    .ThenBy(s => s.DisplayName)
                                    .Select(MapToResponse) // DTO 변환
                                    .ToList();

                var response = new OrganizationSSOListResponse
                {
                    Items = responseItems,
                    TotalCount = responseItems.Count
                };

                // 캐시에 저장 (ICacheService 사용)
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(5), cancellationToken);

                return ServiceResult<OrganizationSSOListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting SSO configurations for Organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationSSOListResponse>.Failure("Failed to retrieve SSO configurations", errorCode: ServiceErrorReason.InternalError);
            }
        }

        public async Task<ServiceResult<OrganizationSSODetailResponse>> GetSSODetailAsync(
           Guid ssoId, bool includeSensitive = false, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증: 현재 사용자가 이 SSO 설정을 조회할 권한이 있는가? (includeSensitive 시 더 높은 권한 필요?)
            try
            {
                var ssoEntity = await _ssoConfigRepository.GetByIdAsync(ssoId, cancellationToken); // 캐시 우선 조회
                if (ssoEntity == null)
                {
                    return ServiceResult<OrganizationSSODetailResponse>.Failure("SSO configuration not found", errorCode: ServiceErrorReason.NotFound);
                }

                // TODO: 권한 검증 2: 조회된 ssoEntity.OrganizationId가 현재 사용자 컨텍스트와 일치하는가?
                if (!await IsUserAuthorizedForOrgAsync(ssoEntity.OrganizationId, cancellationToken))
                {
                    _logger.LogWarning("Unauthorized attempt to access SSO config {SsoId} from different organization context by {AccessorId}.", ssoId, _principalAccessor.ConnectedId);
                    return ServiceResult<OrganizationSSODetailResponse>.Failure("Access forbidden.", errorCode: ServiceErrorReason.Forbidden);
                }

                var response = MapToDetailResponse(ssoEntity, includeSensitive); // DTO 변환

                // TODO: 필요시 통계 정보(Statistics) 비동기 조회 후 응답에 추가
                // response.Statistics = await GetUsageStatisticsInternalAsync(ssoId, ...);

                return ServiceResult<OrganizationSSODetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting SSO detail for SSO ID {SsoId}", ssoId);
                return ServiceResult<OrganizationSSODetailResponse>.Failure("Failed to retrieve SSO details", errorCode: ServiceErrorReason.InternalError);
            }
        }


        public async Task<ServiceResult<OrganizationSSOResponse>> UpdateSSOAsync(
            Guid ssoId, CreateOrganizationSSORequest request, Guid updatedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            await _unitOfWork.BeginTransactionAsync(cancellationToken); // 기본값 변경 가능성 있으므로 트랜잭션
            try
            {
                _logger.LogInformation("Attempting to update SSO {SsoId} by {UpdatedBy}", ssoId, updatedByConnectedId);

                // 추적 엔티티 가져오기 (Find 사용)
                var ssoEntity = await _ssoConfigRepository.FindAsync(s => s.Id == ssoId, cancellationToken).ContinueWith(t => t.Result.FirstOrDefault(), cancellationToken);
                if (ssoEntity == null)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<OrganizationSSOResponse>.Failure("SSO configuration not found", errorCode: ServiceErrorReason.NotFound);
                }

                // TODO: 권한 검증 2 (조직 일치 확인)
                if (!await IsUserAuthorizedForOrgAsync(ssoEntity.OrganizationId, cancellationToken))
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<OrganizationSSOResponse>.Failure("Unauthorized access.", errorCode: ServiceErrorReason.Forbidden);
                }

                var originalDtoForAudit = MapToResponse(ssoEntity); // 변경 전 DTO (감사용)
                var changesDetected = UpdateSsoEntityFromRequest(ssoEntity, request); // 엔티티 업데이트
                var currentIsDefault = ssoEntity.IsDefault; // 업데이트 적용 전 IsDefault 상태
                var now = _dateTimeProvider.UtcNow;

                // 기본값 설정 로직
                if (request.IsDefault && !currentIsDefault)
                {
                    await UnsetDefaultSSOAsync(ssoEntity.OrganizationId, updatedByConnectedId, cancellationToken, ssoId); // 기존 기본값 해제
                    ssoEntity.IsDefault = true;
                    ssoEntity.IsEnabled = true; // 기본값은 항상 활성화
                    changesDetected = true;
                }
                else if (!request.IsDefault && currentIsDefault)
                {
                    // 기본값을 해제하는 것은 다른 기본값이 설정될 때만 가능
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<OrganizationSSOResponse>.Failure("Cannot unset the default SSO directly. Set another SSO as default instead.", errorCode: ServiceErrorReason.BadRequest);
                }

                // 변경사항이 있을 경우에만 업데이트 처리
                if (changesDetected)
                {
                    ssoEntity.UpdatedAt = now;
                    ssoEntity.UpdatedByConnectedId = updatedByConnectedId;

                    // TODO: 업데이트 전 설정 유효성 검증 (ValidateSSOConfigurationAsync 호출)

                    // UpdateAsync는 상태 변경 + 캐시 무효화 트리거 (ID 기반)
                    await _ssoConfigRepository.UpdateAsync(ssoEntity, cancellationToken);
                    // SaveChangesAsync는 트랜잭션 커밋 전에 호출
                    await _unitOfWork.SaveChangesAsync(cancellationToken);
                    var auditDetails = $"SSO configuration '{ssoEntity.DisplayName}' updated.";
                    var metadata = new Dictionary<string, object>
        {
            { "OrganizationId", ssoEntity.OrganizationId },
            { "Provider", ssoEntity.Provider },
            // 변경 전/후 값을 메타데이터나 별도 필드(OldValue/NewValue - DTO 지원 시)로 기록 고려
            { "ChangesDetected", true } // 예시 메타데이터
        };
                    var updatedDtoForAudit = MapToResponse(ssoEntity); // 변경 후 DTO (감사용)
                    await _auditService.LogActionAsync(
              actionType: AuditActionType.Update,     // ✨ AuditActionType 사용
              action: AuditEvent.SSOUpdated.ToString(), // ✨ AuditEvent 사용
              connectedId: updatedByConnectedId,       // ✨ 필수 파라미터
              success: true,
              resourceType: nameof(SamlConfiguration),
              resourceId: ssoEntity.Id.ToString(),
              errorMessage: null, // 성공 시 null
              metadata: metadata, // ✨ 메타데이터 전달
                                  // oldValueJson: oldValueJson, // IAuditService에 해당 파라미터가 있다면 전달
                                  // newValueJson: newValueJson, // IAuditService에 해당 파라미터가 있다면 전달
              cancellationToken: cancellationToken);

                    // 추가적인 캐시 무효화 (조직 목록 등)
                    await InvalidateSSOCacheAsync(ssoEntity.OrganizationId, cancellationToken);
                }

                await _unitOfWork.CommitTransactionAsync(cancellationToken); // 트랜잭션 커밋

                var response = MapToResponse(ssoEntity);
                _logger.LogInformation("Successfully updated SSO {SsoId}", ssoId);
                return ServiceResult<OrganizationSSOResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating SSO {SsoId}", ssoId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken); // 오류 시 롤백
                return ServiceResult<OrganizationSSOResponse>.Failure($"Failed to update SSO: {ex.Message}", errorCode: ServiceErrorReason.InternalError);
            }
        }
        public async Task<ServiceResult> DeleteSSOAsync(
                Guid ssoId, Guid deletedByConnectedId, string reason,
                CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            try
            {
                _logger.LogWarning("Attempting to delete SSO {SsoId} by {DeletedBy}. Reason: {Reason}", ssoId, deletedByConnectedId, reason);

                var ssoEntity = await _ssoConfigRepository.FindAsync(s => s.Id == ssoId, cancellationToken).ContinueWith(t => t.Result.FirstOrDefault(), cancellationToken); // 추적
                if (ssoEntity == null)
                {
                    return ServiceResult.Failure("SSO configuration not found", errorCode: ServiceErrorReason.NotFound);
                }

                // TODO: 권한 검증 2
                if (!await IsUserAuthorizedForOrgAsync(ssoEntity.OrganizationId, cancellationToken))
                {
                    return ServiceResult.Failure("Unauthorized access.", errorCode: ServiceErrorReason.Forbidden);
                }

                if (ssoEntity.IsDefault)
                {
                    return ServiceResult.Failure("Cannot delete the default SSO configuration.", errorCode: ServiceErrorReason.BadRequest);
                }

                // SoftDeleteAsync 사용
                await _ssoConfigRepository.SoftDeleteAsync(ssoEntity.Id, cancellationToken);
                // TODO: SoftDeleteAsync가 DeletedBy를 설정하는지 확인

                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                var auditDetails = $"Deleted SSO '{ssoEntity.DisplayName ?? ssoEntity.Id.ToString()}'. Reason: {reason}";
                var metadata = new Dictionary<string, object>
            {
                { "OrganizationId", ssoEntity.OrganizationId },
                { "Provider", ssoEntity.Provider },
                { "Reason", reason }
            };

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,      // ✨ AuditActionType 사용
                    action: AuditEvent.SSODeleted.ToString(), // ✨ AuditEvent 사용
                    connectedId: deletedByConnectedId,       // ✨ 필수 파라미터
                    success: true,                           // 삭제 작업 자체는 성공
                    resourceType: nameof(SamlConfiguration),
                    resourceId: ssoEntity.Id.ToString(),
                    errorMessage: null,
                    metadata: metadata,                      // ✨ 메타데이터 전달
                    cancellationToken: cancellationToken);
                // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆

                await InvalidateSSOCacheAsync(ssoEntity.OrganizationId, cancellationToken);

                _logger.LogInformation("Successfully soft-deleted SSO {SsoId} for Organization {OrganizationId}", ssoId, ssoEntity.OrganizationId);
                return ServiceResult.Success("SSO configuration deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting SSO {SsoId}", ssoId);
                // TODO: 감사 로그 실패 기록 고려
                // await _auditService.LogActionAsync(AuditActionType.Delete, AuditEvent.SSODeleted.ToString(), deletedByConnectedId, false, ex.Message, nameof(SamlConfiguration), ssoId.ToString(), ..., cancellationToken);
                return ServiceResult.Failure($"Failed to delete SSO: {ex.Message}", errorCode: ServiceErrorReason.InternalError);
            }
        }

        #endregion

        #region SSO Status Management
        public async Task<ServiceResult> ActivateSSOAsync(
                Guid ssoId, Guid activatedByConnectedId, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            try
            {
                var ssoEntity = await _ssoConfigRepository.FindAsync(s => s.Id == ssoId, cancellationToken).ContinueWith(t => t.Result.FirstOrDefault(), cancellationToken); // 추적
                if (ssoEntity == null) return ServiceResult.Failure("SSO configuration not found", ServiceErrorReason.NotFound);
                // TODO: 권한 검증 2

                if (ssoEntity.IsEnabled) return ServiceResult.Success("SSO is already active");

                ssoEntity.IsEnabled = true;
                ssoEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                ssoEntity.UpdatedByConnectedId = activatedByConnectedId;

                await _ssoConfigRepository.UpdateAsync(ssoEntity, cancellationToken); // 캐시 무효화 포함
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                var auditDetails = $"Activated SSO configuration '{ssoEntity.DisplayName ?? ssoId.ToString()}'.";
                var metadata = new Dictionary<string, object>
            {
                { "OrganizationId", ssoEntity.OrganizationId },
                { "Provider", ssoEntity.Provider }
            };

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,          // ✨ 상태 변경이므로 Update 사용 (또는 Activate 전용 타입)
                    action: AuditEvent.SSOActivated.ToString(), // ✨ AuditEvent 사용
                    connectedId: activatedByConnectedId,           // ✨ 필수 파라미터
                    success: true,
                    resourceType: nameof(SamlConfiguration),
                    resourceId: ssoEntity.Id.ToString(),
                    errorMessage: null,
                    metadata: metadata,                          // ✨ 메타데이터 전달
                    cancellationToken: cancellationToken);
                // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆

                await InvalidateSSOCacheAsync(ssoEntity.OrganizationId, cancellationToken);

                _logger.LogInformation("SSO {SsoId} activated by {ActivatedBy}", ssoId, activatedByConnectedId);
                return ServiceResult.Success("SSO activated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error activating SSO {SsoId}", ssoId);
                // TODO: 실패 감사 로그 기록 고려
                return ServiceResult.Failure($"Failed to activate SSO: {ex.Message}", ServiceErrorReason.InternalError);
            }
        }

        public async Task<ServiceResult> DeactivateSSOAsync(
                Guid ssoId, Guid deactivatedByConnectedId, string reason, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            try
            {
                var ssoEntity = await _ssoConfigRepository.FindAsync(s => s.Id == ssoId, cancellationToken).ContinueWith(t => t.Result.FirstOrDefault(), cancellationToken); // 추적
                if (ssoEntity == null) return ServiceResult.Failure("SSO configuration not found", ServiceErrorReason.NotFound);
                // TODO: 권한 검증 2

                if (!ssoEntity.IsEnabled) return ServiceResult.Success("SSO is already inactive");

                if (ssoEntity.IsDefault)
                {
                    var activeCount = await _ssoConfigRepository.CountAsync(s => s.OrganizationId == ssoEntity.OrganizationId && s.IsEnabled && s.Id != ssoId, cancellationToken);
                    if (activeCount < 1)
                    {
                        return ServiceResult.Failure("Cannot deactivate the only active default SSO.", ServiceErrorReason.BadRequest);
                    }
                }

                ssoEntity.IsEnabled = false;
                ssoEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                ssoEntity.UpdatedByConnectedId = deactivatedByConnectedId;

                await _ssoConfigRepository.UpdateAsync(ssoEntity, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                var auditDetails = $"Deactivated SSO '{ssoEntity.DisplayName ?? ssoId.ToString()}'. Reason: {reason}";
                var metadata = new Dictionary<string, object>
             {
                 { "OrganizationId", ssoEntity.OrganizationId },
                 { "Provider", ssoEntity.Provider },
                 { "Reason", reason }
             };

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,           // ✨ 상태 변경이므로 Update
                    action: AuditEvent.SSODeactivated.ToString(), // ✨ AuditEvent 사용
                    connectedId: deactivatedByConnectedId,        // ✨ 필수 파라미터
                    success: true,
                    resourceType: nameof(SamlConfiguration),
                    resourceId: ssoEntity.Id.ToString(),
                    errorMessage: null,
                    metadata: metadata,                           // ✨ 메타데이터 전달
                    cancellationToken: cancellationToken);
                // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆

                await InvalidateSSOCacheAsync(ssoEntity.OrganizationId, cancellationToken);

                _logger.LogWarning("SSO {SsoId} deactivated by {DeactivatedBy}. Reason: {Reason}", ssoId, deactivatedByConnectedId, reason);
                return ServiceResult.Success("SSO deactivated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deactivating SSO {SsoId}", ssoId);
                // TODO: 실패 감사 로그 기록 고려
                return ServiceResult.Failure($"Failed to deactivate SSO: {ex.Message}", ServiceErrorReason.InternalError);
            }
        }
        public async Task<ServiceResult> SetAsDefaultAsync(
                Guid ssoId, Guid setByConnectedId, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var ssoToSet = await _ssoConfigRepository.FindAsync(s => s.Id == ssoId, cancellationToken).ContinueWith(t => t.Result.FirstOrDefault(), cancellationToken); // 추적
                if (ssoToSet == null)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult.Failure("SSO configuration not found", ServiceErrorReason.NotFound);
                }
                // TODO: 권한 검증 2

                if (!ssoToSet.IsEnabled)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult.Failure("Cannot set an inactive SSO as default.", ServiceErrorReason.BadRequest);
                }
                if (ssoToSet.IsDefault)
                {
                    await _unitOfWork.CommitTransactionAsync(cancellationToken);
                    return ServiceResult.Success("SSO is already the default");
                }

                var organizationId = ssoToSet.OrganizationId;
                var now = _dateTimeProvider.UtcNow;

                // 기존 기본 SSO 해제 (헬퍼 사용)
                var unsetCount = await UnsetDefaultSSOAsync(organizationId, setByConnectedId, cancellationToken);

                // 새 기본 SSO 설정
                ssoToSet.IsDefault = true;
                ssoToSet.UpdatedAt = now;
                ssoToSet.UpdatedByConnectedId = setByConnectedId;

                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                var auditDetails = $"Set SSO '{ssoToSet.DisplayName ?? ssoId.ToString()}' as default.";
                var metadata = new Dictionary<string, object>
            {
                { "OrganizationId", organizationId },
                { "Provider", ssoToSet.Provider },
                { "UnsetCount", unsetCount } // 해제된 이전 기본값 개수 (선택적)
            };

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,             // ✨ 상태 변경이므로 Update
                    action: AuditEvent.SSODefaultChanged.ToString(),// ✨ AuditEvent 사용
                    connectedId: setByConnectedId,                  // ✨ 필수 파라미터
                    success: true,
                    resourceType: nameof(SamlConfiguration),
                    resourceId: ssoToSet.Id.ToString(),
                    errorMessage: null,
                    metadata: metadata,                              // ✨ 메타데이터 전달
                    cancellationToken: cancellationToken);
                // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆

                // Optionally log unset action too if required

                await InvalidateSSOCacheAsync(organizationId, cancellationToken);

                _logger.LogInformation("SSO {SsoId} set as default for Organization {OrganizationId} by {SetBy}", ssoId, organizationId, setByConnectedId);
                return ServiceResult.Success("SSO set as default successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting SSO {SsoId} as default", ssoId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                // TODO: 실패 감사 로그 기록 고려
                return ServiceResult.Failure($"Failed to set SSO as default: {ex.Message}", ServiceErrorReason.InternalError);
            }
        }


        #endregion

        #region SSO Validation and Testing
        public async Task<ServiceResult<SSOTestResult>> TestSSOConnectionAsync(
                     Guid ssoId, Guid? testedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            // TODO: 실제 SSO 프로토콜 테스트 로직 (외부 라이브러리/헬퍼 사용)
            SamlConfiguration? ssoEntity = null; // 감사 로그를 위해 try 블록 외부에서도 접근 가능하도록
            try
            {
                ssoEntity = await _ssoConfigRepository.GetByIdAsync(ssoId, cancellationToken);
                if (ssoEntity == null) return ServiceResult<SSOTestResult>.Failure("SSO configuration not found", ServiceErrorReason.NotFound);
                // TODO: 권한 검증

                var startTime = _dateTimeProvider.UtcNow;
                var testResult = new SSOTestResult { TestedAt = startTime };
                bool testSucceeded = false; // 테스트 결과

                try
                {
                    // --- 실제 테스트 로직 ---
                    _logger.LogInformation("Simulating SSO connection test for {SsoId}...", ssoId);
                    await Task.Delay(150, cancellationToken); // Simulate I/O
                    testSucceeded = true; // Assume success for simulation
                                          // --- 테스트 로직 끝 ---

                    testResult.Success = testSucceeded;
                    testResult.ResponseTime = _dateTimeProvider.UtcNow - startTime;
                    testResult.Details["Provider"] = ssoEntity.Provider;
                    testResult.Details["Status"] = testSucceeded ? "Connection successful (simulated)" : "Connection failed (simulated)";
                    _logger.LogInformation("SSO connection test for {SsoId}: Success={Success}", ssoId, testSucceeded);
                }
                catch (Exception testEx)
                {
                    testResult.Success = false;
                    testResult.ErrorMessage = testEx.Message;
                    testResult.ResponseTime = _dateTimeProvider.UtcNow - startTime;
                    _logger.LogWarning(testEx, "SSO connection test failed for {SsoId}", ssoId);
                }

                // DB에 테스트 결과 업데이트 (테스터가 명시된 경우)
                if (testedByConnectedId.HasValue)
                {
                    // UpdateAsync를 사용하기 위해 추적된 엔티티를 다시 로드하거나 상태를 변경
                    // 여기서는 상태 변경 방식을 사용 (DB 조회 최소화)
                    ssoEntity.LastTestedAt = testResult.TestedAt;
                    // TODO: 엔티티에 LastTestSuccess, LastTestError 필드 추가 및 업데이트
                    ssoEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                    ssoEntity.UpdatedByConnectedId = testedByConnectedId;
                    await _unitOfWork.SaveChangesAsync(cancellationToken); // SaveChanges 호출
                    await InvalidateSSOCacheAsync(ssoEntity.OrganizationId, cancellationToken); // 캐시 무효화
                }

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                var auditDetails = $"Tested SSO connection for '{ssoEntity.DisplayName ?? ssoId.ToString()}'. Success: {testResult.Success}";
                var metadata = new Dictionary<string, object>
                 {
                     { "OrganizationId", ssoEntity.OrganizationId },
                     { "Provider", ssoEntity.Provider },
                     { "TestSuccess", testResult.Success },
                     { "ResponseTimeMs", testResult.ResponseTime.TotalMilliseconds }
                 };
                if (!testResult.Success)
                {
                    metadata.Add("ErrorMessage", testResult.ErrorMessage ?? "N/A");
                }

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Execute, // ✨ 실행/테스트 관련 타입
                    action: AuditEvent.SSOTested.ToString(), // ✨ AuditEvent 사용
                    connectedId: testedByConnectedId ?? _principalAccessor.ConnectedId ?? Guid.Empty, // ✨ 테스터 ID 또는 현재 사용자 ID (null일 경우 시스템 ID 등)
                    success: testResult.Success, // ✨ 테스트 결과 반영
                    resourceType: nameof(SamlConfiguration),
                    resourceId: ssoEntity.Id.ToString(),
                    errorMessage: testResult.Success ? null : testResult.ErrorMessage, // ✨ 실패 시 메시지 전달
                    metadata: metadata, // ✨ 메타데이터 전달
                    cancellationToken: cancellationToken);
                // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆

                return ServiceResult<SSOTestResult>.Success(testResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing SSO connection for {SsoId}", ssoId);
                // TODO: 실패 감사 로그 기록 고려
                if (ssoEntity != null) // 엔티티 정보가 있으면 로그에 포함
                {
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Execute,
                        action: AuditEvent.SSOTested.ToString(),
                        connectedId: testedByConnectedId ?? _principalAccessor.ConnectedId ?? Guid.Empty,
                        success: false, // 실패
                        resourceType: nameof(SamlConfiguration),
                        resourceId: ssoEntity.Id.ToString(),
                        errorMessage: $"Failed to test SSO connection: {ex.Message}", // 실패 메시지
                        metadata: new Dictionary<string, object> { { "OrganizationId", ssoEntity.OrganizationId } },
                        cancellationToken: cancellationToken);
                }
                return ServiceResult<SSOTestResult>.Failure($"Failed to test SSO connection: {ex.Message}", ServiceErrorReason.InternalError);
            }
        }
        public Task<ServiceResult<SSOValidationResult>> ValidateSSOConfigurationAsync(
                OrganizationSSODto sso, CancellationToken cancellationToken = default)
        {
            var result = new SSOValidationResult { IsValid = true, Errors = new List<string>(), Warnings = new List<string>() };

            try
            {
                if (sso.OrganizationId == Guid.Empty) result.Errors.Add("OrganizationId is required.");
                if (string.IsNullOrWhiteSpace(sso.DisplayName)) result.Errors.Add("Display name is required.");
                if (string.IsNullOrWhiteSpace(sso.Configuration)) result.Errors.Add("Configuration JSON is required.");
                else
                {
                    try { JsonDocument.Parse(sso.Configuration); }
                    catch (JsonException ex)
                    {
                        result.Errors.Add($"Invalid configuration JSON format: {ex.Message}");
                    }
                    // TODO: JSON 내부 필수 필드 검사 (EntityId, SsoUrl 등 프로토콜에 따라)
                }

                if (!string.IsNullOrWhiteSpace(sso.AllowedDomains)) // Null이나 공백이 아닐 때만 검사
                {
                    try
                    {
                        // JSON 문자열을 List<string>으로 파싱
                        var domains = JsonSerializer.Deserialize<List<string>>(sso.AllowedDomains);
                        if (domains != null && domains.Any(d => !IsValidDomain(d ?? string.Empty))) // 파싱된 리스트에 대해 검사
                        {
                            result.Errors.Add("One or more allowed domains are invalid.");
                        }
                    }
                    catch (JsonException ex)
                    {
                        result.Errors.Add($"Invalid format for AllowedDomains JSON: {ex.Message}");
                    }
                }

                // TODO: 인증서 유효성 검사 (Configuration 내 certificate 필드 파싱)

                result.IsValid = !result.Errors.Any();
                _logger.LogInformation("Validation result for SSO config (Org: {OrgId}): IsValid={IsValid}", sso.OrganizationId, result.IsValid);
                return Task.FromResult(ServiceResult<SSOValidationResult>.Success(result));
            }
            catch (Exception ex) // 예기치 않은 오류 처리
            {
                _logger.LogError(ex, "Error during SSO configuration validation for Org {OrgId}", sso.OrganizationId);
                result.IsValid = false;
                result.Errors.Add($"An unexpected error occurred during validation: {ex.Message}");
                // 실패 결과를 반환해야 함
                return Task.FromResult(new ServiceResult<SSOValidationResult>
                {
                    IsSuccess = true, // Validation 자체는 성공했으나 결과가 Invalid일 수 있음
                    Data = result // IsValid = false 인 result 반환
                                  // 또는 ServiceResult<SSOValidationResult>.Failure 사용 고려
                });
            }
        }

        public async Task<ServiceResult<OrganizationSSOInfo>> GetSSOByDomainAsync(string domain, CancellationToken cancellationToken = default)
        {
            // TODO: Rate Limiting? (공개 엔드포인트에서 사용될 수 있음)
            try
            {
                if (string.IsNullOrWhiteSpace(domain) || !IsValidDomain(domain))
                {
                    return ServiceResult<OrganizationSSOInfo>.Failure("Invalid domain format.", ServiceErrorReason.BadRequest);
                }

                // 리포지토리 메서드 사용 (캐싱 처리 포함)
                var matchedConfigDto = await _ssoConfigRepository.GetByDomainAsync(domain, cancellationToken);

                if (matchedConfigDto == null)
                {
                    // 실패 결과를 짧게 캐싱하여 반복적인 DB 조회 방지 고려
                    return ServiceResult<OrganizationSSOInfo>.Failure($"No active SSO configuration found for domain: {domain}", ServiceErrorReason.NotFound);
                }

                var info = new OrganizationSSOInfo
                {
                    Id = matchedConfigDto.Id,
                    OrganizationId = matchedConfigDto.OrganizationId,
                    ProviderName = matchedConfigDto.Provider.ToString(),
                    DisplayName = matchedConfigDto.DisplayName ?? string.Empty,
                    IsActive = matchedConfigDto.IsEnabled // DTO 필드 확인
                };

                return ServiceResult<OrganizationSSOInfo>.Success(info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error finding SSO by domain {Domain}", domain);
                return ServiceResult<OrganizationSSOInfo>.Failure("Failed to find SSO by domain", ServiceErrorReason.InternalError);
            }
        }


        #endregion

        #region SSO Certificate Management

        public async Task<ServiceResult<SslCertificateStatus>> CheckCertificateStatusAsync(Guid ssoId, CancellationToken cancellationToken = default)
        {
            // TODO: 실제 인증서 파싱 및 유효성 검증 로직 (System.Security.Cryptography.X509Certificates 사용)
            // Configuration JSON 또는 Certificate 필드에서 인증서 문자열 가져오기
            _logger.LogWarning("CheckCertificateStatusAsync is using simulated data for {SsoId}.", ssoId);
            var sso = await _ssoConfigRepository.GetByIdAsync(ssoId, cancellationToken);
            if (sso == null) return ServiceResult<SslCertificateStatus>.Failure("SSO not found", ServiceErrorReason.NotFound);

            // 인증서 문자열 가져오기 (예시)
            // string certString = sso.Certificate; // 또는 JSON에서 추출
            // if (string.IsNullOrWhiteSpace(certString)) return ServiceResult<SslCertificateStatus>.Failure("Certificate not found in configuration.");

            // 실제 파싱 및 검증 로직 ...
            var expires = _dateTimeProvider.UtcNow.AddDays(90); // Simulated expiry
            var isValid = true; // Simulated validation
            var statusText = "Valid (Simulated)";

            return ServiceResult<SslCertificateStatus>.Success(new SslCertificateStatus
            {
                SsoId = ssoId, // SsoId는 할당 가능
                IsValid = isValid,
                Status = statusText,
                ExpiresAt = expires,
                // DaysRemaining은 자동으로 계산되므로 할당하지 않음!
                LastCheckedAt = _dateTimeProvider.UtcNow
                // Issuer, Subject 등은 실제 파싱 결과로 채움
            });
        }

        // OrganizationSSOService.cs

        // OrganizationSSOService.cs

        public async Task<ServiceResult<List<SslCertificateStatus>>> GetExpiringCertificatesAsync(
             Guid organizationId, int daysBeforeExpiry = 30, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            _logger.LogInformation("Checking for expiring SSO certificates in Org {OrganizationId} within {Days} days.", organizationId, daysBeforeExpiry);
            var expiringCerts = new List<SslCertificateStatus>();
            try
            {
                var activeSSOs = await _ssoConfigRepository.FindAsync(s => s.OrganizationId == organizationId && s.IsEnabled, cancellationToken);

                foreach (var sso in activeSSOs)
                {
                    var certCheckResult = await CheckCertificateStatusAsync(sso.Id, cancellationToken); // 인증서 상태 확인

                    // 👇👇👇 수정: DaysRemaining 값 확인만 수행 (할당 제거) 및 SsoId 할당 👇👇👇
                    if (certCheckResult.IsSuccess &&
                        certCheckResult.Data != null &&
                        certCheckResult.Data.DaysRemaining.HasValue && // Null 체크 추가
                        certCheckResult.Data.DaysRemaining.Value <= daysBeforeExpiry) // 남은 일수 확인
                    {
                        certCheckResult.Data.SsoId = sso.Id; // ✨ SsoId 할당

                        expiringCerts.Add(certCheckResult.Data);
                        _logger.LogWarning("Expiring certificate found for SSO {SsoId} (Org: {OrganizationId}), expires in {Days} days.", sso.Id, organizationId, certCheckResult.Data.DaysRemaining.Value);
                        // TODO: 알림 이벤트 발행 (IEventBus 사용)
                    }
                    // 👆👆👆 수정 끝 👆👆👆
                }
                return ServiceResult<List<SslCertificateStatus>>.Success(expiringCerts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking expiring certificates for Org {OrganizationId}", organizationId);
                return ServiceResult<List<SslCertificateStatus>>.Failure("Failed to check expiring certificates", ServiceErrorReason.InternalError);
            }
        }

        #endregion

        #region SSO Statistics

        public async Task<ServiceResult<SSOUsageStatistics>> GetUsageStatisticsAsync(
             Guid ssoId, DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default)
        {
            // TODO: 권한 검증
            try
            {
                var sso = await _ssoConfigRepository.GetByIdAsync(ssoId, cancellationToken);
                if (sso == null) return ServiceResult<SSOUsageStatistics>.Failure("SSO configuration not found", ServiceErrorReason.NotFound);
                // TODO: 권한 검증 2 (조직 일치)
                if (!await IsUserAuthorizedForOrgAsync(sso.OrganizationId, cancellationToken))
                {
                    return ServiceResult<SSOUsageStatistics>.Failure("Unauthorized access.", ServiceErrorReason.Forbidden);
                }


                var cacheKey = $"SSOStats:{ssoId}:{startDate:yyyyMMdd}:{endDate:yyyyMMdd}";
                var cached = await _cacheService.GetAsync<SSOUsageStatistics>(cacheKey, cancellationToken);
                if (cached != null) return ServiceResult<SSOUsageStatistics>.Success(cached);

                // 리포지토리 호출 (organizationId 사용)
                // TODO: SSOUsageStatistics를 계산하기 위한 더 적합한 리포지토리 메서드 필요 가능성
                //       (예: 특정 SSO 설정(Provider/EntityId)을 사용한 AuthenticationAttemptLog 조회)
                var statistics = await _ssoConfigRepository.GetUsageStatisticsAsync(sso.OrganizationId, startDate, endDate, cancellationToken);

                await _cacheService.SetAsync(cacheKey, statistics, TimeSpan.FromHours(1), cancellationToken);
                return ServiceResult<SSOUsageStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting usage statistics for SSO {SsoId}", ssoId);
                return ServiceResult<SSOUsageStatistics>.Failure($"Failed to get usage statistics: {ex.Message}", ServiceErrorReason.InternalError);
            }
        }


        #endregion

        #region SSO Response Processing
        public async Task<ServiceResult<AuthenticationOutcome>> ProcessSsoResponseAsync(
                Guid organizationId, string ssoResponse, CancellationToken cancellationToken = default)
        {
            // ... (초기 변수 설정) ...
            var currentTimestamp = _dateTimeProvider.UtcNow;
            string userEmail = "[unknown]";
            Guid? userId = null;
            Guid? connectedId = null;
            // ✨ 감사 로그를 위해 현재 요청자의 ConnectedId 가져오기 (없으면 null)
            Guid? requesterConnectedId = _principalAccessor.ConnectedId;

            using var logScope = _logger.BeginScope("Processing SSO Response for Org {OrganizationId}", organizationId);
            try
            {
                var ssoConfigResult = await GetActiveOrDefaultSsoConfigAsync(organizationId, cancellationToken);
                if (!ssoConfigResult.IsSuccess || ssoConfigResult.Data == null)
                {
                    // ✨ 실패 감사 로그 (connectedId는 아직 알 수 없으므로 요청자 ID 사용)
                    await _auditService.LogActionAsync(
                        AuditActionType.Authentication, // 또는 적절한 타입
                        AuditEvent.SSOLoginFailed.ToString(),
                        requesterConnectedId ?? Guid.Empty, // ✨ 요청자 ID 사용 (없으면 Empty)
                        false, // 실패
                        ssoConfigResult.ErrorMessage ?? "No active default SSO config.",
                        "SSO Process", // resourceType
                        organizationId.ToString(), // resourceId
                        new Dictionary<string, object> { { "ReasonCode", ssoConfigResult.ErrorCode ?? "SSO_NOT_ENABLED" } },
                        cancellationToken);
                    return ServiceResult<AuthenticationOutcome>.Failure(ssoConfigResult.ErrorMessage ?? "No active default SSO configuration found for the organization.", ssoConfigResult.ErrorCode ?? "SSO_NOT_ENABLED");
                }
                var ssoConfig = ssoConfigResult.Data; // SSOConfiguration DTO

                // --- ❗ 실제 SAML/OIDC 라이브러리 연동 ---
                var validationResult = SimulateSsoValidation(ssoResponse); // 시뮬레이션
                                                                           // --- 연동 로직 끝 ---

                userEmail = validationResult.Email ?? "[missing]";

                if (!validationResult.IsValid || string.IsNullOrEmpty(validationResult.Email))
                {
                    // 👇👇👇 감사 로그 호출 수정 👇👇👇
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Authentication,
                        action: AuditEvent.SSOLoginFailed.ToString(),
                        connectedId: requesterConnectedId ?? Guid.Empty, // ✨ 요청자 ID
                        success: false, // 실패
                        errorMessage: "Invalid SSO response or missing user identifier.",
                        resourceType: "SSO Process",
                        resourceId: organizationId.ToString(),
                        metadata: new Dictionary<string, object> { { "Provider", ssoConfig.Provider.ToString() } },
                        cancellationToken: cancellationToken);
                    // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid SSO response or missing user identifier.", "INVALID_SSO_RESPONSE");
                }

                var externalId = validationResult.ExternalId;

                // 사용자 조회 또는 JIT 프로비저닝
                var userResult = await FindOrCreateUserFromSsoAsync(userEmail, validationResult, ssoConfig, cancellationToken);
                if (!userResult.IsSuccess || userResult.Data == null)
                {
                    // 감사 로그는 FindOrCreateUserFromSsoAsync 내부에서 처리 (필요시 connectedId 전달)
                    return ServiceResult<AuthenticationOutcome>.Failure(userResult.ErrorMessage ?? "User processing failed.", userResult.ErrorCode);
                }
                var user = userResult.Data;
                userId = user.Id; // 로그용

                // ConnectedId 확인/생성
                var connectedIdResult = await _connectedIdService.GetOrCreateAsync(user.Id, organizationId, cancellationToken);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == null)
                {
                    // 👇👇👇 감사 로그 호출 수정 👇👇👇
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Authentication,
                        action: AuditEvent.SSOLoginFailed.ToString(),
                        connectedId: requesterConnectedId ?? user.CreatedByConnectedId ?? Guid.Empty, // ✨ 요청자 또는 생성자 ID
                        success: false, // 실패
                        errorMessage: "Failed to get/create ConnectedId.",
                        resourceType: "ConnectedId",
                        resourceId: user.Id.ToString(), // 사용자 ID 기준
                        metadata: new Dictionary<string, object> { { "OrganizationId", organizationId } },
                        cancellationToken: cancellationToken);
                    // 👆👆👆 감사 로그 호출 수정 끝 👆👆👆
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to link user to the organization.", "CONNECTED_ID_ERROR");
                }
                connectedId = connectedIdResult.Data.Id; // 로그용

                // TODO: 역할/그룹 매핑 로직

                // 최종 인증 결과 생성
                var outcome = new AuthenticationOutcome
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedId.Value, // 이제 non-nullable
                    IsNewUser = userResult.Message == "UserCreated",
                    Provider = ssoConfig.Provider.ToString(),
                    ExternalId = externalId,
                    AuthenticationMethod = ssoConfig.Protocol.ToString()
                };

                // 👇👇👇 감사 로그 호출 수정 👇👇👇
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Authentication,
                    action: AuditEvent.SSOLoginSuccess.ToString(),
                    connectedId: connectedId.Value, // ✨ SSO로 로그인한 사용자의 ConnectedId
                    success: true,
                    resourceType: "Session", // 또는 "Authentication"
                    resourceId: user.Id.ToString(), // 사용자 ID 기준
                    metadata: new Dictionary<string, object> {
                    { "OrganizationId", organizationId },
                    { "Provider", ssoConfig.Provider.ToString() },
                    { "IsNewUser", outcome.IsNewUser }
                    },
                    cancellationToken: cancellationToken);

                return ServiceResult<AuthenticationOutcome>.Success(outcome);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SSO response for Organization {OrganizationId}. User: {UserEmail}", organizationId, userEmail);
                // 실패 감사 로그 호출 수정
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Authentication,
                    action: AuditEvent.SSOLoginFailed.ToString(),
                    connectedId: connectedId ?? requesterConnectedId ?? Guid.Empty, // ✨ 가능한 ID 사용
                    success: false, // 실패
                    errorMessage: $"Internal error during SSO processing: {ex.Message}",
                    resourceType: "SSO Process",
                    resourceId: organizationId.ToString(),
                    metadata: new Dictionary<string, object> {
                    { "UserEmailAttempted", userEmail },
                    { "UserIdAttempted", userId?.ToString() ?? "N/A" }
                    },
                    cancellationToken: cancellationToken);
                // 👆👆👆 실패 감사 로그 호출 수정 끝 👆👆👆
                return ServiceResult<AuthenticationOutcome>.Failure($"An unexpected error occurred: {ex.Message}", "SSO_PROCESSING_ERROR");
            }
        }

        // FindOrCreateUserFromSsoAsync 헬퍼 메서드도 connectedId를 받을 수 있도록 수정 (감사용)
        // OrganizationSSOService.cs
        private async Task<ServiceResult<UserEntity>> FindOrCreateUserFromSsoAsync(string email, dynamic validationResult, SSOConfiguration ssoConfig, CancellationToken cancellationToken)
        {
            // 1. 사용자 조회
            var user = await _userRepository.FindByEmailAsync(email, includeDeleted: false, cancellationToken: cancellationToken);
            bool isNewUser = user == null;
            Guid? requesterConnectedId = _principalAccessor.ConnectedId; // 감사 로그용

            if (isNewUser) // 2. user가 null인 경우 (신규 사용자)
            {
                if (!ssoConfig.EnableJitProvisioning)
                {
                    // JIT 비활성화 시 실패 감사 로그 및 반환
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Authentication,
                        action: AuditEvent.SSOLoginFailed.ToString(),
                        connectedId: requesterConnectedId ?? Guid.Empty,
                        success: false,
                        errorMessage: $"User {email} not found, JIT disabled.",
                        resourceType: "User",
                        resourceId: email,
                        metadata: new Dictionary<string, object> { { "OrganizationId", ssoConfig.OrganizationId } },
                        cancellationToken: cancellationToken);
                    return ServiceResult<UserEntity>.Failure($"User '{email}' not found and JIT provisioning is disabled.", errorCode: "USER_NOT_FOUND_JIT_DISABLED");
                }

                // 새 사용자 생성 로직...
                user = new UserEntity
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    DisplayName = $"{validationResult.FirstName} {validationResult.LastName}".Trim(), // 예시 매핑
                    Status = UserStatus.Active,
                    EmailVerified = true,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = requesterConnectedId
                    // TODO: 기본 역할 할당 로직
                };

                await _userRepository.AddAsync(user, cancellationToken);
                // SaveChanges는 ProcessSsoResponseAsync에서 처리

                // 사용자 생성 감사 로그
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: AuditEvent.UserCreated.ToString(),
                    connectedId: requesterConnectedId ?? Guid.Empty,
                    success: true,
                    resourceType: nameof(UserEntity),
                    resourceId: user.Id.ToString(),
                    metadata: new Dictionary<string, object> { { "OrganizationId", ssoConfig.OrganizationId }, { "Source", "JIT Provisioning" } },
                    cancellationToken: cancellationToken);

                // 새로 생성된 user 객체를 반환
                return ServiceResult<UserEntity>.Success(user, "UserCreated");
            }
            else // 3. 기존 사용자를 찾은 경우 (user != null 이 보장됨)
            {
                if (user!.Status != UserStatus.Active)
                {
                    // 비활성 사용자 감사 로그
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Authentication,
                        action: AuditEvent.SSOLoginFailed.ToString(),
                        connectedId: requesterConnectedId ?? Guid.Empty,
                        success: false,
                        errorMessage: $"User {email} is not active.",
                        resourceType: nameof(UserEntity),
                        resourceId: user.Id.ToString(), // user가 null이 아님
                        metadata: new Dictionary<string, object> {
                        { "OrganizationId", ssoConfig.OrganizationId },
                        { "UserStatus", user.Status.ToString() } // user가 null이 아님
                        },
                        cancellationToken: cancellationToken);
                    return ServiceResult<UserEntity>.Failure($"User account '{email}' is not active.", errorCode: "USER_INACTIVE");
                }
                else
                {
                    // TODO: 기존 사용자 프로필 업데이트 (JIT Update)
                    _logger.LogDebug("Existing active user {UserId} found for email {Email}", user.Id, email); // user가 null이 아님
                                                                                                               // 기존 사용자 user 객체 반환
                    return ServiceResult<UserEntity>.Success(user);
                }
            }
        }

        #endregion


        #region Private Helper Methods

        // SSO 엔티티(SamlConfiguration) -> 응답 DTO(OrganizationSSOResponse) 매핑
        private OrganizationSSOResponse MapToResponse(SamlConfiguration entity)
        {
            var response = new OrganizationSSOResponse { /* ... 이전 답변과 동일 ... */ };
            response.IsActive = entity.IsEnabled; // 필드명 매핑
            response.AutoCreateUsers = entity.EnableAutoProvisioning; // 필드명 매핑
            // TODO: CreatedByName, UpdatedByName 조회 (IConnectedIdService 또는 IUserRepository 사용)
            return response;
        }

        // SSO 엔티티(SamlConfiguration) -> 상세 응답 DTO(OrganizationSSODetailResponse) 매핑
        private OrganizationSSODetailResponse MapToDetailResponse(SamlConfiguration entity, bool includeSensitive)
        {
            var detail = new OrganizationSSODetailResponse { /* ... 이전 답변과 동일 ... */ };
            detail.Configuration = includeSensitive ? (entity.ConfigurationDetails ?? string.Empty) : MaskSensitiveMetadata(entity.ConfigurationDetails);
            detail.IsActive = entity.IsEnabled;
            detail.AutoCreateUsers = entity.EnableAutoProvisioning;
            // JSON 필드 파싱
            if (!string.IsNullOrEmpty(entity.AllowedDomains)) { try { detail.AllowedDomains = JsonSerializer.Deserialize<List<string>>(entity.AllowedDomains); } catch { detail.AllowedDomains = new List<string> { "Error parsing domains" }; } }
            detail.GroupMapping = entity.GroupMapping; // 문자열 그대로 또는 파싱

            // TODO: Statistics 정보 추가 (별도 비동기 호출 필요)
            // detail.Statistics = await GetUsageStatisticsAsync(...) // Detail 메서드 내에서는 동기적으로 처리하거나 분리

            return detail;
        }

        // Create Request -> SSO 엔티티(SamlConfiguration) 업데이트 적용
        private bool UpdateSsoEntityFromRequest(SamlConfiguration entity, CreateOrganizationSSORequest request)
        {
            bool changed = false;
            changed |= SetValueIfChanged(v => entity.Protocol = v, entity.Protocol, request.SSOType.ToString());
            changed |= SetValueIfChanged(v => entity.Provider = v, entity.Provider, request.ProviderName.ToString());
            changed |= SetValueIfChanged(v => entity.DisplayName = v, entity.DisplayName, request.DisplayName);

            if (entity.ConfigurationDetails != request.Configuration)
            {
                ParseAndApplyConfiguration(request.Configuration, entity); // 파싱 및 개별 필드 + 원본 JSON 저장
                changed = true;
            }

            changed |= SetValueIfChanged(v => entity.AttributeMapping = v, entity.AttributeMapping, request.AttributeMapping ?? "{}");
            changed |= SetValueIfChanged(v => entity.Priority = v, entity.Priority, request.Priority);
            changed |= SetValueIfChanged(v => entity.IconUrl = v, entity.IconUrl, request.IconUrl);
            changed |= SetValueIfChanged(v => entity.EnableAutoProvisioning = v, entity.EnableAutoProvisioning, request.AutoCreateUsers);
            changed |= SetValueIfChanged(v => entity.DefaultRoleId = v, entity.DefaultRoleId, request.DefaultRoleId);

            var newAllowedDomains = request.AllowedDomains != null ? JsonSerializer.Serialize(request.AllowedDomains) : "[]";
            changed |= SetValueIfChanged(v => entity.AllowedDomains = v, entity.AllowedDomains, newAllowedDomains);

            changed |= SetValueIfChanged(v => entity.GroupMapping = v, entity.GroupMapping, request.GroupMapping ?? "{}");
            changed |= SetValueIfChanged(v => entity.IsEnabled = v, entity.IsEnabled, request.ActivateImmediately);
            // IsDefault는 SetAsDefaultAsync 또는 Configure/Update 내 별도 로직에서 처리

            return changed;
        }

        // 값 변경 시 속성 설정 헬퍼
        private bool SetValueIfChanged<T>(Action<T> setter, T currentValue, T newValue)
        {
            if (!EqualityComparer<T>.Default.Equals(currentValue, newValue))
            {
                setter(newValue);
                return true;
            }
            return false;
        }

        // Configuration JSON 파싱하여 엔티티 필드 설정
        private void ParseAndApplyConfiguration(string? configJson, SamlConfiguration entity)
        {
            entity.ConfigurationDetails = configJson ?? "{}"; // 원본 JSON 저장
            if (string.IsNullOrWhiteSpace(configJson)) return;
            try
            {
                using var doc = JsonDocument.Parse(configJson);
                var root = doc.RootElement;
                // TryGetValue 확장 메서드 사용하면 더 간결
                entity.EntityId = root.TryGetStringProperty("entityId") ?? entity.EntityId ?? string.Empty;
                entity.SsoUrl = root.TryGetStringProperty("ssoUrl") ?? entity.SsoUrl ?? string.Empty;
                entity.SloUrl = root.TryGetStringProperty("sloUrl") ?? entity.SloUrl ?? string.Empty;
                entity.Certificate = root.TryGetStringProperty("certificate") ?? entity.Certificate ?? string.Empty;
                entity.MetadataUrl = root.TryGetStringProperty("metadataUrl") ?? entity.MetadataUrl ?? string.Empty;
                // 필요한 다른 필드들 파싱...
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to parse SSO configuration JSON for entity {EntityId}. Storing raw JSON.", entity.Id);
            }
        }

        // 캐시 무효화
        // OrganizationSSOService.cs

        #region Private Helper Methods

        // 캐시 무효화 (ICacheService 사용)
        private async Task InvalidateSSOCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // 서비스에서 사용하는 캐시 키 형식을 직접 정의
            var listCacheKey = $"OrgSSO:List:{organizationId}";
            var defaultCacheKey = $"OrgSSO:Default:{organizationId}";

            _logger.LogDebug("Invalidating SSO cache keys for Organization {OrganizationId}", organizationId);

            var tasks = new List<Task>
        {
            _cacheService.RemoveAsync(listCacheKey, cancellationToken),
            _cacheService.RemoveAsync(defaultCacheKey, cancellationToken)
            // 개별 SSO 설정 캐시 (GetByIdAsync) 는 BaseRepository 에서 처리 (ID 기반 키 사용 가정)
        };

            // 도메인/EntityId 기반 캐시 무효화 (설정 조회 후 특정 키 삭제)
            try
            {
                // 리포지토리의 GetConfigurationAsync 호출 (캐싱 비활성화 또는 짧게 설정된 메서드 권장)
                var configDto = await _ssoConfigRepository.GetConfigurationAsync(organizationId, cancellationToken); // DTO 조회

                if (configDto != null)
                {
                    // AllowedDomains 키 삭제
                    if (configDto.AllowedDomains != null)
                    {
                        foreach (var domain in configDto.AllowedDomains.Where(d => !string.IsNullOrWhiteSpace(d)))
                        {
                            // 👇👇👇 리포지토리 메서드 호출 대신 직접 키 생성 👇👇👇
                            var domainCacheKey = $"SSO:Domain:{domain}"; // GetByDomainAsync에서 사용하는 캐시 키와 동일하게!
                            tasks.Add(_cacheService.RemoveAsync(domainCacheKey, cancellationToken));
                        }
                    }
                    // EntityId 키 삭제
                    if (!string.IsNullOrEmpty(configDto.EntityId))
                    {
                        // 👇👇👇 리포지토리 메서드 호출 대신 직접 키 생성 👇👇👇
                        var entityIdCacheKey = $"SSO:EntityId:{configDto.EntityId}"; // GetByEntityIdAsync에서 사용하는 캐시 키와 동일하게!
                        tasks.Add(_cacheService.RemoveAsync(entityIdCacheKey, cancellationToken));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during additional SSO cache invalidation for Org {OrganizationId}. Main operation succeeded.", organizationId);
            }

            await Task.WhenAll(tasks);
        }
        #endregion
        // 기존 기본 SSO 해제
        private async Task<int> UnsetDefaultSSOAsync(Guid organizationId, Guid changedByConnectedId, CancellationToken cancellationToken, Guid? excludeSsoId = null)
        {
            var currentDefaults = await _ssoConfigRepository.FindAsync(s => s.OrganizationId == organizationId && s.IsDefault && s.Id != excludeSsoId, cancellationToken); // 추적
            if (!currentDefaults.Any()) return 0;

            var now = _dateTimeProvider.UtcNow;
            int count = 0;
            foreach (var oldDefault in currentDefaults)
            {
                oldDefault.IsDefault = false;
                oldDefault.UpdatedAt = now;
                oldDefault.UpdatedByConnectedId = changedByConnectedId;
                count++;
            }
            _logger.LogInformation("Unset {Count} previous default SSO(s) for Organization {OrganizationId}", count, organizationId);
            // SaveChanges는 호출부에서 처리
            return count;
        }

        // 민감 정보 마스킹
        private string MaskSensitiveMetadata(string? metadata) { /* ... 이전 구현 ... */ return metadata ?? "{}"; }
        /// <summary>
        /// 감사 로그 DTO 생성 헬퍼 (엔티티 정보 포함) - AuditLogDto v15 호환
        /// </summary>
        /// <param name="actionEvent">감사 이벤트 타입 (Enum)</param>
        /// <param name="entity">관련된 엔티티 (여기서는 SamlConfiguration)</param>
        /// <param name="performedBy">작업 수행자 ConnectedId</param>
        /// <param name="details">상세 설명 (메타데이터에 포함될 수 있음)</param>
        /// <param name="oldValue">변경 전 값 (선택적, 메타데이터에 포함됨)</param>
        /// <param name="newValue">변경 후 값 (선택적, 메타데이터에 포함됨)</param>
        /// <returns>생성된 AuditLogDto 객체</returns>
        private AuditLogDto CreateAuditLog(
                AuditEvent actionEvent,         // 감사 이벤트 타입 (Enum)
                SamlConfiguration entity, // 관련된 엔티티
                Guid? performedBy,        // 작업 수행자 ConnectedId
                string details,           // 상세 설명
                object? oldValue = null,  // 변경 전 값 (선택적)
                object? newValue = null)  // 변경 후 값 (선택적)
        {
            var metadataDict = new Dictionary<string, object?>
        {
            { "Details", details } // 상세 설명을 메타데이터에 포함
        };

            if (oldValue != null)
            {
                // oldValue를 직렬화하거나 필요한 속성만 추출하여 추가
                metadataDict.Add("OldValue", oldValue); // 예시: 객체 그대로 추가 (JSON 직렬화는 LogActionAsync에서 처리 가정)
            }
            if (newValue != null)
            {
                metadataDict.Add("NewValue", newValue); // 예시: 객체 그대로 추가
            }

            return new AuditLogDto
            {
                // Id = Guid.NewGuid(), // ID는 DB에서 생성될 수 있음
                PerformedByConnectedId = performedBy,
                OrganizationId = entity?.OrganizationId, // 엔티티에서 조직 ID 가져오기
                                                         // ApplicationId = ..., // 필요시 설정

                ActionType = GetActionTypeFromAuditEvent(actionEvent), // ✨ ActionType 설정
                Action = actionEvent.ToString(), // ✨ Action 설정 (Enum 이름)

                ResourceType = nameof(SamlConfiguration), // ✨ ResourceType 설정
                ResourceId = entity?.Id.ToString(),       // ✨ ResourceId 설정

                // IpAddress = ..., // IHttpContextAccessor 등으로 가져오기
                // UserAgent = ..., // IHttpContextAccessor 등으로 가져오기
                // RequestId = ..., // IHttpContextAccessor 등으로 가져오기

                Success = true, // 기본적으로 성공으로 설정 (호출부에서 필요시 변경)
                                // ErrorCode = ..., // 실패 시 설정
                                // ErrorMessage = ..., // 실패 시 설정

                // ✨ Metadata 설정 (Dictionary를 JSON 문자열로 변환)
                Metadata = JsonSerializer.Serialize(metadataDict, new JsonSerializerOptions { WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }),

                // DurationMs = ..., // 필요시 설정
                Severity = GetSeverityFromAuditEvent(actionEvent), // ✨ Severity 설정

                CreatedAt = _dateTimeProvider.UtcNow // ✨ CreatedAt (Timestamp 대신)
                                                     // CreatedByConnectedId = performedBy, // PerformedByConnectedId와 동일하게 설정 가능
                                                     // UpdatedAt/UpdatedBy 등은 감사 로그 자체에는 보통 불필요
            };
        }
        // AuditEvent enum 값을 AuditActionType enum 값으로 변환하는 예시 헬퍼
        private AuditActionType GetActionTypeFromAuditEvent(AuditEvent action)
        {
            // AuditEvent 값에 따라 적절한 AuditActionType 반환
            return action switch
            {
                AuditEvent.SSOConfigured => AuditActionType.Create,
                AuditEvent.SSOUpdated => AuditActionType.Update,
                AuditEvent.SSODeleted => AuditActionType.Delete,
                AuditEvent.SSOActivated => AuditActionType.Update, // 또는 별도 타입
                AuditEvent.SSODeactivated => AuditActionType.Update, // 또는 별도 타입
                AuditEvent.SSODefaultChanged => AuditActionType.Update,
                AuditEvent.SSOTested => AuditActionType.Execute, // 또는 Read/Info
                AuditEvent.SSOLoginSuccess => AuditActionType.Authentication,
                AuditEvent.SSOLoginFailed => AuditActionType.Authentication,
                // ... 다른 AuditEvent 매핑 ...
                _ => AuditActionType.Others, // 기본값
            };
        }

        private AuditEventSeverity GetSeverityFromAuditEvent(AuditEvent action)
        {
            // AuditEvent 값에 따라 적절한 AuditEventSeverity 반환
            return action switch
            {
                AuditEvent.SSOLoginFailed => AuditEventSeverity.Warning,
                AuditEvent.SSODeleted => AuditEventSeverity.Warning,
                AuditEvent.SSODeactivated => AuditEventSeverity.Warning,
                AuditEvent.SSOLoginSuccess => AuditEventSeverity.Info,
                AuditEvent.SSOTested => AuditEventSeverity.Info,
                // ... 다른 AuditEvent 매핑 ...
                _ => AuditEventSeverity.Info,
            };
        }
        // 감사 로그 DTO 헬퍼 (엔티티 없이)
        private AuditLogDto CreateAuditLog(AuditEvent action, Guid organizationId, UserEntity? user, Guid? connectedId, string details)
        {
            return new AuditLogDto { /* ... 이전 구현 ... */ };
        }
        private AuditLogDto CreateAuditLog(AuditEvent action, Guid organizationId, Guid? userId, Guid? connectedId, string details)
        {
            return new AuditLogDto { /* ... 이전 구현 ... */ };
        }

        // 권한 확인 헬퍼 (임시 - IAuthorizationService로 대체 필요)
        private Task<bool> IsUserAuthorizedForOrgAsync(Guid targetOrganizationId, CancellationToken cancellationToken)
        {
            // TODO: IAuthorizationService 구현 및 호출 (이후 async/await 필요)
            var currentOrgId = _principalAccessor.OrganizationId; // 현재 요청 컨텍스트
            if (!currentOrgId.HasValue)
            {
                _logger.LogWarning("Cannot verify organization authorization: Current organization context is missing.");
                return Task.FromResult(false); // 컨텍스트 없으면 실패 처리
            }

            var isAuthorized = currentOrgId.Value == targetOrganizationId; // 가장 기본적인 검사

            if (!isAuthorized)
            {
                _logger.LogWarning("Authorization failed: User context OrgId {CurrentOrgId} does not match target OrgId {TargetOrgId}", currentOrgId.Value, targetOrganizationId);
            }

            return Task.FromResult(isAuthorized); // bool 값을 Task<bool>로 감싸서 반환
        }

        // ProcessSsoResponseAsync 내부 헬퍼: 활성 기본 SSO 설정 조회
        private async Task<ServiceResult<SSOConfiguration>> GetActiveOrDefaultSsoConfigAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            var defaultCacheKey = $"OrgSSO:Default:{organizationId}";
            var cached = await _cacheService.GetAsync<SSOConfiguration>(defaultCacheKey, cancellationToken);
            if (cached != null)
            {
                _logger.LogDebug("Default SSO cache hit for Org {OrganizationId}", organizationId);
                return ServiceResult<SSOConfiguration>.Success(cached);
            }

            _logger.LogDebug("Default SSO cache miss for Org {OrganizationId}", organizationId);

            // 1. DB에서 활성화된 기본 설정 엔티티 조회
            var defaultEntity = await _ssoConfigRepository.FirstOrDefaultAsync(s => s.OrganizationId == organizationId && s.IsEnabled && s.IsDefault, cancellationToken);

            SamlConfiguration? entityToUse = defaultEntity; // 사용할 엔티티

            // 2. 기본 설정 없으면, 활성화된 설정 중 하나라도 있는지 확인 (우선순위 고려)
            if (entityToUse == null)
            {
                _logger.LogWarning("No default SSO configured for Org {OrganizationId}. Searching for any enabled SSO.", organizationId);
                //수정: OrderBy() 추가 후 FirstOrDefaultAsync 호출 
                entityToUse = await _ssoConfigRepository.Query() // IQueryable<SamlConfiguration> 가져오기
                    .Where(s => s.OrganizationId == organizationId && s.IsEnabled) // 활성화된 것 필터링
                    .OrderBy(s => s.Priority) // 우선순위로 정렬 (낮은 값이 먼저)
                    .FirstOrDefaultAsync(cancellationToken); // 정렬된 결과 중 첫 번째 것 가져오기 (orderBy 파라미터 없음)


                if (entityToUse != null)
                {
                    _logger.LogWarning("Using first enabled SSO {SsoId} as fallback for Org {OrganizationId}.", entityToUse.Id, organizationId);
                }
            }

            // 3. 사용할 엔티티를 찾았으면 DTO로 변환
            if (entityToUse != null)
            {
                // 👇👇👇 엔티티 -> DTO 변환 로직 (리포지토리의 MapToDto 로직 참고) 👇👇👇
                var configDto = new SSOConfiguration
                {
                    Id = entityToUse.Id,
                    OrganizationId = entityToUse.OrganizationId,
                    Protocol = Enum.TryParse<SSOProtocol>(entityToUse.Protocol, true, out var proto) ? proto : default,
                    Provider = Enum.TryParse<SSOProvider>(entityToUse.Provider, true, out var prov) ? prov : default,
                    DisplayName = entityToUse.DisplayName,
                    EntityId = entityToUse.EntityId,
                    SsoUrl = entityToUse.SsoUrl,
                    SloUrl = entityToUse.SloUrl,
                    Certificate = entityToUse.Certificate, // 민감 정보 포함 (필요시 마스킹)
                    MetadataUrl = entityToUse.MetadataUrl,
                    // Metadata = entityToUse.Metadata, // 필요시 포함
                    AcsUrl = entityToUse.AcsUrl,
                    AttributeMapping = entityToUse.AttributeMapping.DeserializeJson<Dictionary<string, string>>(_logger) ?? new Dictionary<string, string>(),
                    AllowedDomains = entityToUse.AllowedDomains.DeserializeJson<List<string>>(_logger) ?? new List<string>(),
                    AdditionalSettings = entityToUse.AdditionalSettings.DeserializeJson<Dictionary<string, object>>(_logger) ?? new Dictionary<string, object>(),
                    EnableAutoProvisioning = entityToUse.EnableAutoProvisioning,
                    EnableJitProvisioning = entityToUse.EnableJitProvisioning,
                    IsEnabled = entityToUse.IsEnabled,
                    IsDefault = entityToUse.IsDefault,
                    DefaultRoleId = entityToUse.DefaultRoleId,
                    LastSyncAt = entityToUse.LastSyncAt,
                    LastTestedAt = entityToUse.LastTestedAt,
                    CreatedByConnectedId = entityToUse.CreatedByConnectedId,
                    UpdatedByConnectedId = entityToUse.UpdatedByConnectedId,
                    CreatedAt = entityToUse.CreatedAt,
                    UpdatedAt = entityToUse.UpdatedAt
                    // IconUrl, Priority 등 필요한 다른 필드 추가
                };
                // 👆👆👆 DTO 변환 끝 👆👆👆

                // 찾은 설정이 '기본' 설정이었다면 캐시에 저장
                if (entityToUse.IsDefault)
                {
                    await _cacheService.SetAsync(defaultCacheKey, configDto, TimeSpan.FromMinutes(15), cancellationToken);
                }

                return ServiceResult<SSOConfiguration>.Success(configDto);
            }

            // 활성화된 설정이 아무것도 없으면 실패 반환
            return ServiceResult<SSOConfiguration>.Failure("No active SSO configuration found for the organization.", errorCode: ServiceErrorReason.NotFound);
        }
        // ProcessSsoResponseAsync 내부 헬퍼: SSO 응답 시뮬레이션
        private (bool IsValid, string? Email, string? ExternalId, Dictionary<string, string> Attributes, string? FirstName, string? LastName) SimulateSsoValidation(string ssoResponse)
        {
            _logger.LogWarning("Simulating SSO response validation.");
            // 실제 라이브러리는 ssoResponse(SAML/OIDC 토큰)를 검증하고 속성을 추출
            return (IsValid: true,
                    Email: $"sso-sim-{Guid.NewGuid().ToString().Substring(0, 8)}@example.com",
                    ExternalId: $"sim-ext-{Guid.NewGuid()}",
                    Attributes: new Dictionary<string, string> { { "groups", "[\"Developers\", \"Admins\"]" } }, // 그룹 예시
                    FirstName: "Simulated",
                    LastName: "User");
        }

        /// <summary>
        /// 도메인 이름 형식 유효성 검사 (간단 버전)
        /// </summary>
        private bool IsValidDomain(string domain)
        {
            return !string.IsNullOrWhiteSpace(domain) && domain.Contains(".");
        }


        #endregion
    }

    // JsonElement 확장 메서드 (헬퍼 클래스 또는 Extensions 폴더에 위치 권장)
    internal static class JsonElementExtensions
    {
        public static string? TryGetStringProperty(this JsonElement element, string propertyName)
        {
            return element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String
                   ? prop.GetString() : null;
        }
    }
}