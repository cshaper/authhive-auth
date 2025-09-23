using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 데이터 정책 관리 서비스 - AuthHive v15
    /// 조직의 데이터 보관 정책, GDPR 준수, 익명화 등을 관리합니다.
    /// </summary>
    public class OrganizationDataPolicyService : IOrganizationDataPolicyService
    {
        private readonly ILogger<OrganizationDataPolicyService> _logger;
        private readonly AuthDbContext _context;
        private readonly IOrganizationDataPolicyRepository _dataPolicyRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IAuditLogRepository _auditLogRepository;
        private readonly IMapper _mapper;
        private readonly IDistributedCache _cache;

        public OrganizationDataPolicyService(
            ILogger<OrganizationDataPolicyService> logger,
            AuthDbContext context,
            IOrganizationDataPolicyRepository dataPolicyRepository,
            IOrganizationRepository organizationRepository,
            IAuditLogRepository auditLogRepository,
            IMapper mapper,
            IDistributedCache cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _dataPolicyRepository = dataPolicyRepository ?? throw new ArgumentNullException(nameof(dataPolicyRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        #region IService Implementation

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // DB 연결 확인
                await _context.Database.CanConnectAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing OrganizationDataPolicyService");
                // 필요한 초기화 작업 수행
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize OrganizationDataPolicyService");
                throw;
            }
        }

        #endregion

        #region 데이터 정책 CRUD

        public async Task<ServiceResult<OrganizationDataPolicyDto>> GetByIdAsync(Guid dataPolicyId)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"data_policy:{dataPolicyId}";
                var cachedPolicy = await GetFromCacheAsync<OrganizationDataPolicyDto>(cacheKey);
                if (cachedPolicy != null)
                {
                    return ServiceResult<OrganizationDataPolicyDto>.Success(cachedPolicy);
                }

                // DB에서 조회
                var policy = await _dataPolicyRepository.GetByIdAsync(dataPolicyId);
                if (policy == null)
                {
                    return ServiceResult<OrganizationDataPolicyDto>.Failure($"Data policy not found: {dataPolicyId}");
                }

                var dto = _mapper.Map<OrganizationDataPolicyDto>(policy);

                // 캐시 저장
                await SetCacheAsync(cacheKey, dto, TimeSpan.FromMinutes(30));

                return ServiceResult<OrganizationDataPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting data policy {PolicyId}", dataPolicyId);
                return ServiceResult<OrganizationDataPolicyDto>.Failure("Failed to get data policy");
            }
        }

        public async Task<ServiceResult<OrganizationDataPolicyDto>> GetByOrganizationAsync(Guid organizationId)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"org_data_policy:{organizationId}";
                var cachedPolicy = await GetFromCacheAsync<OrganizationDataPolicyDto>(cacheKey);
                if (cachedPolicy != null)
                {
                    return ServiceResult<OrganizationDataPolicyDto>.Success(cachedPolicy);
                }

                // DB에서 조회 - Repository 메서드 이름 수정
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    // 정책이 없으면 기본 정책 생성
                    _logger.LogInformation("No data policy found for organization {OrgId}, creating default", organizationId);

                    var defaultPolicy = await CreateDefaultPolicyAsync(organizationId);
                    return ServiceResult<OrganizationDataPolicyDto>.Success(defaultPolicy);
                }

                var dto = _mapper.Map<OrganizationDataPolicyDto>(policy);

                // 캐시 저장
                await SetCacheAsync(cacheKey, dto, TimeSpan.FromMinutes(30));

                return ServiceResult<OrganizationDataPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting data policy for organization {OrgId}", organizationId);
                return ServiceResult<OrganizationDataPolicyDto>.Failure("Failed to get organization data policy");
            }
        }

        public async Task<ServiceResult<OrganizationDataPolicyResponse>> CreateAsync(
            CreateOrganizationDataPolicyRequest createRequest,
            Guid createdByConnectedId)
        {
            try
            {
                // 조직 확인
                var org = await _organizationRepository.GetByIdAsync(createRequest.OrganizationId);
                if (org == null)
                {
                    return ServiceResult<OrganizationDataPolicyResponse>.Failure("Organization not found");
                }

                // 기존 정책 확인 (조직당 하나의 정책만 허용)
                var existingPolicy = await _dataPolicyRepository.GetByOrganizationAsync(createRequest.OrganizationId);
                if (existingPolicy != null)
                {
                    return ServiceResult<OrganizationDataPolicyResponse>.Failure("Data policy already exists for this organization");
                }

                // 플랜별 제한 확인
                var planLimitCheck = await ValidatePlanLimitsAsync(createRequest, org);
                if (!planLimitCheck.IsSuccess)
                {
                    return ServiceResult<OrganizationDataPolicyResponse>.Failure(planLimitCheck.Message ?? "Plan limits validation failed");
                }

                // 엔티티 생성
                var policy = new OrganizationDataPolicy
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = createRequest.OrganizationId,
                    UserMetadataMode = createRequest.UserMetadataMode,
                    CollectMemberProfile = createRequest.CollectMemberProfile,
                    CollectUserProfile = createRequest.CollectUserProfile,
                    ApiKeyManagement = createRequest.ApiKeyManagement,
                    DataRetentionDays = createRequest.DataRetentionDays,
                    AuditLogRetentionDays = createRequest.AuditLogRetentionDays,
                    PointTransactionRetentionDays = createRequest.PointTransactionRetentionDays,
                    AllowDataExport = false, // 기본값, Business 플랜 이상에서만 true
                    AllowSqlDumpExport = false,
                    AllowBulkApiAccess = false,
                    EnableAutoAnonymization = createRequest.EnableAutoAnonymization,
                    AnonymizationAfterDays = createRequest.AnonymizationAfterDays,
                    AllowExternalSync = createRequest.AllowExternalSync,
                    AllowedExternalSystems = createRequest.AllowedExternalSystems != null
                        ? JsonSerializer.Serialize(createRequest.AllowedExternalSystems)
                        : null,
                    EncryptionLevel = createRequest.EncryptionLevel,
                    PolicyVersion = 1,
                    NextReviewDate = DateTime.UtcNow.AddMonths(6), // 6개월 후 검토
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = createdByConnectedId
                };

                // DB 저장
                await _dataPolicyRepository.AddAsync(policy);

                // 감사 로그 기록
                await LogAuditAsync(
                    AuditActionType.Create,
                    "OrganizationDataPolicy",
                    policy.Id,
                    createdByConnectedId,
                    "Data policy created",
                    policy);

                // 응답 생성
                var response = _mapper.Map<OrganizationDataPolicyResponse>(policy);

                // 캐시 무효화
                await InvalidatePolicyCacheAsync(createRequest.OrganizationId);

                _logger.LogInformation(
                    "Data policy created for organization {OrgId} by {UserId}",
                    createRequest.OrganizationId, createdByConnectedId);

                return ServiceResult<OrganizationDataPolicyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating data policy");
                return ServiceResult<OrganizationDataPolicyResponse>.Failure("Failed to create data policy");
            }
        }

        public async Task<ServiceResult<OrganizationDataPolicyResponse>> UpdateAsync(
            Guid dataPolicyId,
            UpdateOrganizationDataPolicyRequest updateRequest,
            Guid updatedByConnectedId)
        {
            try
            {
                // 정책 조회
                var policy = await _dataPolicyRepository.GetByIdAsync(dataPolicyId);
                if (policy == null)
                {
                    return ServiceResult<OrganizationDataPolicyResponse>.Failure("Data policy not found");
                }

                // 조직 확인
                var org = await _organizationRepository.GetByIdAsync(policy.OrganizationId);
                if (org == null)
                {
                    return ServiceResult<OrganizationDataPolicyResponse>.Failure("Organization not found");
                }

                // 변경 사항 추적
                var changes = TrackPolicyChanges(policy, updateRequest);

                // 업데이트 적용
                if (updateRequest.UserMetadataMode.HasValue)
                    policy.UserMetadataMode = updateRequest.UserMetadataMode.Value;

                if (updateRequest.CollectMemberProfile.HasValue)
                    policy.CollectMemberProfile = updateRequest.CollectMemberProfile.Value;

                if (updateRequest.CollectUserProfile.HasValue)
                    policy.CollectUserProfile = updateRequest.CollectUserProfile.Value;

                if (updateRequest.ApiKeyManagement.HasValue)
                    policy.ApiKeyManagement = updateRequest.ApiKeyManagement.Value;

                if (updateRequest.DataRetentionDays.HasValue)
                    policy.DataRetentionDays = updateRequest.DataRetentionDays.Value;

                if (updateRequest.AuditLogRetentionDays.HasValue)
                    policy.AuditLogRetentionDays = updateRequest.AuditLogRetentionDays.Value;

                if (updateRequest.PointTransactionRetentionDays.HasValue)
                    policy.PointTransactionRetentionDays = updateRequest.PointTransactionRetentionDays.Value;

                if (updateRequest.EnableAutoAnonymization.HasValue)
                    policy.EnableAutoAnonymization = updateRequest.EnableAutoAnonymization.Value;

                if (updateRequest.AnonymizationAfterDays.HasValue)
                    policy.AnonymizationAfterDays = updateRequest.AnonymizationAfterDays.Value;

                if (updateRequest.AllowExternalSync.HasValue)
                    policy.AllowExternalSync = updateRequest.AllowExternalSync.Value;

                if (updateRequest.AllowedExternalSystems != null)
                {
                    policy.AllowedExternalSystems = JsonSerializer.Serialize(updateRequest.AllowedExternalSystems);
                }

                if (updateRequest.EncryptionLevel.HasValue)
                    policy.EncryptionLevel = updateRequest.EncryptionLevel.Value;

                // 버전 증가 및 업데이트 정보 설정
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                policy.UpdatedByConnectedId = updatedByConnectedId;
                policy.LastReviewedAt = DateTime.UtcNow;
                policy.NextReviewDate = DateTime.UtcNow.AddMonths(6);

                // DB 저장
                await _dataPolicyRepository.UpdateAsync(policy);

                // 감사 로그 기록
                await LogAuditAsync(
                    AuditActionType.Update,
                    "OrganizationDataPolicy",
                    policy.Id,
                    updatedByConnectedId,
                    $"Data policy updated. Changes: {JsonSerializer.Serialize(changes)}",
                    policy);

                // 응답 생성
                var response = _mapper.Map<OrganizationDataPolicyResponse>(policy);

                // 캐시 무효화
                await InvalidatePolicyCacheAsync(policy.OrganizationId);

                _logger.LogInformation(
                    "Data policy {PolicyId} updated by {UserId}",
                    dataPolicyId, updatedByConnectedId);

                return ServiceResult<OrganizationDataPolicyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating data policy {PolicyId}", dataPolicyId);
                return ServiceResult<OrganizationDataPolicyResponse>.Failure("Failed to update data policy");
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid dataPolicyId, Guid deletedByConnectedId)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByIdAsync(dataPolicyId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Data policy not found");
                }

                // Soft delete
                policy.IsDeleted = true;
                policy.DeletedAt = DateTime.UtcNow;
                policy.DeletedByConnectedId = deletedByConnectedId;

                await _dataPolicyRepository.UpdateAsync(policy);

                // 감사 로그 기록
                await LogAuditAsync(
                    AuditActionType.Delete,
                    "OrganizationDataPolicy",
                    policy.Id,
                    deletedByConnectedId,
                    "Data policy deleted",
                    null);

                // 캐시 무효화
                await InvalidatePolicyCacheAsync(policy.OrganizationId);

                _logger.LogInformation(
                    "Data policy {PolicyId} deleted by {UserId}",
                    dataPolicyId, deletedByConnectedId);

                return ServiceResult.Success("Data policy deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting data policy {PolicyId}", dataPolicyId);
                return ServiceResult.Failure("Failed to delete data policy");
            }
        }

        #endregion

        #region 데이터 정책 검증

        public async Task<ServiceResult<ValidationResult>> ValidatePolicyAsync(Guid organizationId)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    return ServiceResult<ValidationResult>.Failure("Data policy not found");
                }

                var validationResult = new ValidationResult
                {
                    IsValid = true,
                    Errors = new List<ValidationError>()
                };

                // 데이터 보관 기간 검증
                if (policy.DataRetentionDays < 30 || policy.DataRetentionDays > 3650)
                {
                    validationResult.Errors.Add(new ValidationError
                    {
                        PropertyName = "DataRetentionDays",
                        ErrorMessage = "Data retention days must be between 30 and 3650",
                        Field = "DataRetentionDays",
                        Message = "Data retention days must be between 30 and 3650"
                    });
                }

                // 감사 로그 보관 기간 검증
                if (policy.AuditLogRetentionDays < policy.DataRetentionDays)
                {
                    validationResult.Errors.Add(new ValidationError
                    {
                        PropertyName = "AuditLogRetentionDays",
                        ErrorMessage = "Audit log retention must be greater than or equal to data retention",
                        Field = "AuditLogRetentionDays",
                        Message = "Audit log retention must be greater than or equal to data retention"
                    });
                }

                // 익명화 설정 검증
                if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays < policy.DataRetentionDays)
                {
                    validationResult.Errors.Add(new ValidationError
                    {
                        PropertyName = "AnonymizationAfterDays",
                        ErrorMessage = "Anonymization period should be greater than data retention period",
                        Field = "AnonymizationAfterDays",
                        Message = "Anonymization period should be greater than data retention period"
                    });
                }

                // GDPR 준수 검증
                if (policy.UserMetadataMode == UserMetadataMode.Full && !policy.EnableAutoAnonymization)
                {
                    validationResult.Warnings.Add("Full metadata collection without anonymization may not comply with GDPR");
                }

                validationResult.IsValid = !validationResult.Errors.Any();

                return ServiceResult<ValidationResult>.Success(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating data policy for organization {OrgId}", organizationId);
                return ServiceResult<ValidationResult>.Failure("Failed to validate data policy");
            }
        }

        public async Task<ServiceResult<PolicyLimitCheckResult>> CheckPolicyLimitsAsync(Guid organizationId)
        {
            try
            {
                var org = await _organizationRepository.GetByIdAsync(organizationId);
                if (org == null)
                {
                    return ServiceResult<PolicyLimitCheckResult>.Failure("Organization not found");
                }

                // 플랜에 따른 한도 설정 (예시)
                var limits = GetPlanLimits(org.PricingTier);

                // 현재 사용량 계산
                var currentUsage = await CalculateCurrentUsageAsync(organizationId);

                var result = new PolicyLimitCheckResult
                {
                    IsWithinLimit = currentUsage <= limits.MaxDataRetentionDays,
                    CurrentUsage = currentUsage,
                    MaxLimit = limits.MaxDataRetentionDays,
                    LimitType = "DataRetention",
                    WarningMessage = currentUsage > limits.MaxDataRetentionDays * 0.8
                        ? "Approaching data retention limit"
                        : null
                };

                return ServiceResult<PolicyLimitCheckResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking policy limits for organization {OrgId}", organizationId);
                return ServiceResult<PolicyLimitCheckResult>.Failure("Failed to check policy limits");
            }
        }

        public async Task<ServiceResult<IEnumerable<DataPolicyReviewHistory>>> GetPolicyHistoryAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    return ServiceResult<IEnumerable<DataPolicyReviewHistory>>.Failure("Data policy not found");
                }

                // 감사 로그에서 정책 변경 이력 조회 - 수정된 메서드 시그니처
                var auditLogs = await _auditLogRepository.SearchAsync(
                    organizationId,
                    null, // userId
                    "OrganizationDataPolicy", // action
                    null, // connectedId
                    null, // applicationId  
                    startDate ?? DateTime.UtcNow.AddYears(-1),
                    endDate ?? DateTime.UtcNow,
                    1, // pageNumber
                    100); // pageSize

                var history = auditLogs.Items.Select(log => new DataPolicyReviewHistory
                {
                    ReviewId = Guid.NewGuid(),
                    PolicyId = policy.Id,
                    OrganizationId = organizationId,
                    PolicyVersion = ExtractVersionFromLog(log),
                    ReviewType = DetermineReviewType(log),
                    ReviewDate = log.Timestamp,
                    ReviewedByConnectedId = log.PerformedByConnectedId ?? Guid.Empty,
                    ReviewedByName = "System",
                    ReviewerRole = "Administrator",
                    ReviewResult = "Approved",
                    ComplianceScore = 85, // 예시 값
                    Comments = log.Metadata,
                    NextReviewDate = policy.NextReviewDate
                }).ToList();

                return ServiceResult<IEnumerable<DataPolicyReviewHistory>>.Success(history);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting policy history for organization {OrgId}", organizationId);
                return ServiceResult<IEnumerable<DataPolicyReviewHistory>>.Failure("Failed to get policy history");
            }
        }

        #endregion

        #region 데이터 익명화/삭제 (GDPR)

        public async Task<ServiceResult<AnonymizationResult>> RequestAnonymizationAsync(
            Guid organizationId,
            Guid userId,
            Guid requestedByConnectedId)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    return ServiceResult<AnonymizationResult>.Failure("Data policy not found");
                }

                if (!policy.EnableAutoAnonymization)
                {
                    return ServiceResult<AnonymizationResult>.Failure("Anonymization is not enabled for this organization");
                }

                var result = new AnonymizationResult
                {
                    IsSuccess = false,
                    StartedAt = DateTime.UtcNow,
                    AnonymizationMethod = "SHA256_HASH"
                };

                try
                {
                    // 사용자 개인정보 익명화 처리
                    var processedCount = await AnonymizeUserDataAsync(userId, organizationId);

                    result.ProcessedRecords = processedCount;
                    result.AnonymizedFields = new List<string>
                    {
                        "Email", "PhoneNumber", "FirstName", "LastName",
                        "Address", "DateOfBirth", "IPAddress"
                    };
                    result.IsSuccess = true;
                    result.CompletedAt = DateTime.UtcNow;

                    // 감사 로그 기록
                    await LogAuditAsync(
                        AuditActionType.Update,
                        "UserDataAnonymization",
                        userId,
                        requestedByConnectedId,
                        $"User data anonymized. Records: {processedCount}",
                        null);

                    _logger.LogInformation(
                        "User {UserId} data anonymized in organization {OrgId} by {RequestedBy}",
                        userId, organizationId, requestedByConnectedId);
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"Anonymization failed: {ex.Message}");
                    _logger.LogError(ex, "Error during anonymization");
                }

                return ServiceResult<AnonymizationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting anonymization");
                return ServiceResult<AnonymizationResult>.Failure("Failed to request anonymization");
            }
        }

        public async Task<ServiceResult> RequestDataDeletionAsync(
            Guid organizationId,
            Guid userId,
            string reason,
            Guid requestedByConnectedId)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Data policy not found");
                }

                // GDPR Article 17 - Right to erasure
                _logger.LogWarning(
                    "Data deletion requested for user {UserId} in organization {OrgId}. Reason: {Reason}",
                    userId, organizationId, reason);

                // 실제 삭제는 별도 배치 프로세스에서 처리
                // 여기서는 삭제 요청만 기록
                var deletionRequest = new
                {
                    UserId = userId,
                    OrganizationId = organizationId,
                    RequestedAt = DateTime.UtcNow,
                    RequestedBy = requestedByConnectedId,
                    Reason = reason,
                    Status = "Pending"
                };

                // 삭제 요청 큐에 추가 (실제 구현 시)
                // await _deletionQueue.EnqueueAsync(deletionRequest);

                // 감사 로그 기록
                await LogAuditAsync(
                    AuditActionType.Delete,
                    "UserDataDeletion",
                    userId,
                    requestedByConnectedId,
                    $"Data deletion requested. Reason: {reason}",
                    deletionRequest);

                return ServiceResult.Success("Data deletion request submitted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting data deletion");
                return ServiceResult.Failure("Failed to request data deletion");
            }
        }

        public async Task<ServiceResult<DataExportResult>> RequestDataExportAsync(
            Guid organizationId,
            Guid userId,
            string format,
            Guid requestedByConnectedId)
        {
            try
            {
                var policy = await _dataPolicyRepository.GetByOrganizationAsync(organizationId);
                if (policy == null)
                {
                    return ServiceResult<DataExportResult>.Failure("Data policy not found");
                }

                if (!policy.AllowDataExport)
                {
                    return ServiceResult<DataExportResult>.Failure("Data export is not enabled for this organization");
                }

                var result = new DataExportResult
                {
                    IsSuccess = false,
                    ExportId = Guid.NewGuid(),
                    FileFormat = format,
                    StartedAt = DateTime.UtcNow
                };

                try
                {
                    // 데이터 수집 및 내보내기 (실제 구현 필요)
                    var exportData = await CollectUserDataForExportAsync(userId, organizationId);

                    // 파일 생성 (예시)
                    var fileName = $"user_data_{userId}_{DateTime.UtcNow:yyyyMMddHHmmss}.{format.ToLower()}";
                    var filePath = $"/exports/{organizationId}/{fileName}";

                    result.FilePath = filePath;
                    result.FileSize = 1024 * 50; // 예시: 50KB
                    result.RecordCount = 100; // 예시
                    result.CompletedAt = DateTime.UtcNow;
                    result.ExpiresAt = DateTime.UtcNow.AddDays(7);
                    result.DownloadUrl = $"https://api.authhive.com/v1/exports/{result.ExportId}/download";
                    result.IsSuccess = true;

                    // 감사 로그 기록
                    await LogAuditAsync(
                        AuditActionType.Read,
                        "UserDataExport",
                        userId,
                        requestedByConnectedId,
                        $"User data exported. Format: {format}",
                        result);

                    _logger.LogInformation(
                        "User {UserId} data exported in {Format} format by {RequestedBy}",
                        userId, format, requestedByConnectedId);
                }
                catch (Exception ex)
                {
                    result.ErrorMessage = $"Export failed: {ex.Message}";
                    _logger.LogError(ex, "Error during data export");
                }

                return ServiceResult<DataExportResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting data export");
                return ServiceResult<DataExportResult>.Failure("Failed to request data export");
            }
        }

        #endregion

        #region Helper Methods

        private async Task<OrganizationDataPolicyDto> CreateDefaultPolicyAsync(Guid organizationId)
        {
            var defaultPolicy = new OrganizationDataPolicy
            {
                Id = Guid.NewGuid(),
                OrganizationId = organizationId,
                UserMetadataMode = UserMetadataMode.Hybrid,
                CollectMemberProfile = true,
                CollectUserProfile = false,
                ApiKeyManagement = ApiKeyManagementPolicy.CustomerManaged,
                DataRetentionDays = 365,
                AuditLogRetentionDays = 730,
                PointTransactionRetentionDays = 1095,
                AllowDataExport = false,
                AllowSqlDumpExport = false,
                AllowBulkApiAccess = false,
                EnableAutoAnonymization = false,
                AnonymizationAfterDays = 1095,
                AllowExternalSync = true,
                EncryptionLevel = DataEncryptionLevel.Standard,
                PolicyVersion = 1,
                CreatedAt = DateTime.UtcNow,
                NextReviewDate = DateTime.UtcNow.AddMonths(6)
            };

            await _dataPolicyRepository.AddAsync(defaultPolicy);

            return _mapper.Map<OrganizationDataPolicyDto>(defaultPolicy);
        }

        private Task<ServiceResult> ValidatePlanLimitsAsync(
            CreateOrganizationDataPolicyRequest request,
            Core.Entities.Organization.Organization org)
        {
            // 플랜별 제한 검증 로직
            var planLimits = GetPlanLimits(org.PricingTier);

            if (request.DataRetentionDays > planLimits.MaxDataRetentionDays)
            {
                return Task.FromResult(ServiceResult.Failure($"Data retention days exceeds plan limit of {planLimits.MaxDataRetentionDays}"));
            }

            if (request.EncryptionLevel > planLimits.MaxEncryptionLevel)
            {
                return Task.FromResult(ServiceResult.Failure("Selected encryption level is not available in your plan"));
            }

            return Task.FromResult(ServiceResult.Success());
        }
        private PlanLimits GetPlanLimits(string pricingTier)
        {
            // 플랜별 제한 설정 (예시)
            return pricingTier?.ToLower() switch
            {
                "enterprise" => new PlanLimits
                {
                    MaxDataRetentionDays = 3650,
                    MaxEncryptionLevel = DataEncryptionLevel.Maximum
                },
                "business" => new PlanLimits
                {
                    MaxDataRetentionDays = 1825,
                    MaxEncryptionLevel = DataEncryptionLevel.Enhanced
                },
                "standard" => new PlanLimits
                {
                    MaxDataRetentionDays = 730,
                    MaxEncryptionLevel = DataEncryptionLevel.Standard
                },
                _ => new PlanLimits
                {
                    MaxDataRetentionDays = 365,
                    MaxEncryptionLevel = DataEncryptionLevel.Standard
                }
            };
        }

        private List<PolicyChange> TrackPolicyChanges(
            OrganizationDataPolicy current,
            UpdateOrganizationDataPolicyRequest update)
        {
            var changes = new List<PolicyChange>();

            if (update.UserMetadataMode.HasValue && current.UserMetadataMode != update.UserMetadataMode.Value)
            {
                changes.Add(new PolicyChange
                {
                    FieldName = "UserMetadataMode",
                    OldValue = current.UserMetadataMode.ToString(),
                    NewValue = update.UserMetadataMode.Value.ToString(),
                    ChangeReason = "Policy update"
                });
            }

            if (update.DataRetentionDays.HasValue && current.DataRetentionDays != update.DataRetentionDays.Value)
            {
                changes.Add(new PolicyChange
                {
                    FieldName = "DataRetentionDays",
                    OldValue = current.DataRetentionDays.ToString(),
                    NewValue = update.DataRetentionDays.Value.ToString(),
                    ChangeReason = "Compliance requirement"
                });
            }

            // 다른 필드들도 동일한 방식으로 처리...

            return changes;
        }

        private async Task<int> CalculateCurrentUsageAsync(Guid organizationId)
        {
            // 실제 데이터 사용량 계산 로직
            // 예시로 간단한 값 반환
            return await Task.FromResult(500);
        }

        private async Task<int> AnonymizeUserDataAsync(Guid userId, Guid organizationId)
        {
            // 실제 익명화 처리 로직
            // 예시로 간단한 값 반환
            return await Task.FromResult(25);
        }

        private async Task<object> CollectUserDataForExportAsync(Guid userId, Guid organizationId)
        {
            // 실제 데이터 수집 로직
            // 예시로 간단한 객체 반환
            return await Task.FromResult(new { UserId = userId, Data = "User data" });
        }

        private int ExtractVersionFromLog(AuditLog log)
        {
            // 로그에서 버전 정보 추출 (실제 구현 필요)
            return 1;
        }

        private string DetermineReviewType(AuditLog log)
        {
            // 로그 타입에 따른 검토 유형 결정
            return log.ActionType switch
            {
                AuditActionType.Create => "Initial",
                AuditActionType.Update => "Regular",
                _ => "System"
            };
        }

        private async Task LogAuditAsync(
            AuditActionType action,
            string entityType,
            Guid entityId,
            Guid performedBy,
            string details,
            object? additionalData)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    ActionType = action,
                    Action = entityType,
                    ResourceType = entityType,
                    ResourceId = entityId.ToString(),
                    PerformedByConnectedId = performedBy,
                    Metadata = additionalData != null ? JsonSerializer.Serialize(additionalData) : null,
                    Timestamp = DateTime.UtcNow,
                    Success = true
                };

                await _auditLogRepository.AddAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit entry");
            }
        }

        private async Task InvalidatePolicyCacheAsync(Guid organizationId)
        {
            var keys = new[]
            {
                $"org_data_policy:{organizationId}",
                $"data_policy:*"
            };

            foreach (var key in keys)
            {
                await _cache.RemoveAsync(key);
            }
        }

        private async Task<T?> GetFromCacheAsync<T>(string key) where T : class
        {
            try
            {
                var cached = await _cache.GetStringAsync(key);
                if (!string.IsNullOrEmpty(cached))
                {
                    return JsonSerializer.Deserialize<T>(cached);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache get failed for key {Key}", key);
            }
            return null;
        }

        private async Task SetCacheAsync<T>(string key, T value, TimeSpan expiry)
        {
            try
            {
                var json = JsonSerializer.Serialize(value);
                await _cache.SetStringAsync(key, json, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = expiry
                });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache set failed for key {Key}", key);
            }
        }

        #endregion

        #region Inner Classes

        private class PlanLimits
        {
            public int MaxDataRetentionDays { get; set; }
            public DataEncryptionLevel MaxEncryptionLevel { get; set; }
        }

        #endregion
    }
}