// ApplicationApiKeyService.cs - 전체 수정된 코드
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Service;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Common;
using AuthHive.Core.Models.PlatformApplication.Requests;
using AuthHive.Core.Models.PlatformApplication.Responses;
using Newtonsoft.Json;

namespace AuthHive.Auth.Services.PlatformApplication
{
    public class ApplicationApiKeyService : IApplicationApiKeyService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<ApplicationApiKeyService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IApplicationAccessService _accessService;
        private readonly IEncryptionService _encryptionService;
        private readonly IConfiguration _configuration;

        private readonly string _apiKeyPrefix;
        private const int API_KEY_LENGTH = 32;
        private const int MAX_KEYS_PER_APPLICATION = 10;
        private const int KEY_PREFIX_LENGTH = 15;
        private const int KEY_LAST_FOUR_LENGTH = 4;

        public ApplicationApiKeyService(
            AuthDbContext context,
            ILogger<ApplicationApiKeyService> logger,
            IDateTimeProvider dateTimeProvider,
            IApplicationAccessService accessService,
            IEncryptionService encryptionService,
            IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
            _accessService = accessService;
            _encryptionService = encryptionService;
            _configuration = configuration;

            var environment = configuration["Environment"] ?? "Development";
            _apiKeyPrefix = environment switch
            {
                "Production" => "ahk_live_",
                "Staging" => "ahk_stg_",
                "Testing" => "ahk_test_",
                _ => "ahk_dev_"
            };
        }

        #region 조회 Operations

        public async Task<ServiceResult<ApplicationApiKeyResponse>> GetByIdAsync(Guid id)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApplicationApiKeyResponse>.Failure("API key not found");
                }

                var response = MapToResponse(apiKey);
                return ServiceResult<ApplicationApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API key by ID: {Id}", id);
                return ServiceResult<ApplicationApiKeyResponse>.Failure("Failed to retrieve API key");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyDetailResponse>> GetDetailByIdAsync(Guid id)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("API key not found");
                }

                var response = MapToDetailResponse(apiKey);
                return ServiceResult<ApplicationApiKeyDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API key detail by ID: {Id}", id);
                return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("Failed to retrieve API key details");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyResponse>> GetByKeyValueAsync(string keyValue)
        {
            try
            {
                if (string.IsNullOrEmpty(keyValue) || keyValue.Length < KEY_PREFIX_LENGTH)
                {
                    return ServiceResult<ApplicationApiKeyResponse>.Failure("Invalid API key format");
                }

                var keyPrefix = keyValue.Substring(0, KEY_PREFIX_LENGTH);
                var keyHash = ComputeHash(keyValue);

                var apiKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k =>
                        k.KeyPrefix == keyPrefix &&
                        k.KeyHash == keyHash &&
                        !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApplicationApiKeyResponse>.Failure("API key not found");
                }

                var response = MapToResponse(apiKey);
                return ServiceResult<ApplicationApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API key by value");
                return ServiceResult<ApplicationApiKeyResponse>.Failure("Failed to retrieve API key");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyListResponse>> GetByApplicationAsync(
            Guid applicationId,
            PaginationRequest pagination)
        {
            try
            {
                var query = _context.PlatformApplicationApiKeys
                    .Where(k => k.ApplicationId == applicationId && !k.IsDeleted);

                var totalCount = await query.CountAsync();

                var items = await query
                    .OrderByDescending(k => k.CreatedAt)
                    .Skip(pagination.Skip)
                    .Take(pagination.Take)
                    .ToListAsync();

                var response = new ApplicationApiKeyListResponse
                {
                    Items = items.Select(MapToResponse).ToList(),
                    TotalCount = totalCount,
                    PageNumber = pagination.PageNumber,
                    PageSize = pagination.PageSize
                };

                return ServiceResult<ApplicationApiKeyListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API keys for application: {ApplicationId}", applicationId);
                return ServiceResult<ApplicationApiKeyListResponse>.Failure("Failed to retrieve API keys");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyListResponse>> GetByOrganizationAsync(
            Guid organizationId,
            PaginationRequest pagination)
        {
            try
            {
                var query = _context.PlatformApplicationApiKeys
                    .Where(k => k.OrganizationId == organizationId && !k.IsDeleted);

                var totalCount = await query.CountAsync();

                var items = await query
                    .OrderByDescending(k => k.CreatedAt)
                    .Skip(pagination.Skip)
                    .Take(pagination.Take)
                    .ToListAsync();

                var response = new ApplicationApiKeyListResponse
                {
                    Items = items.Select(MapToResponse).ToList(),
                    TotalCount = totalCount,
                    PageNumber = pagination.PageNumber,
                    PageSize = pagination.PageSize
                };

                return ServiceResult<ApplicationApiKeyListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API keys for organization: {OrganizationId}", organizationId);
                return ServiceResult<ApplicationApiKeyListResponse>.Failure("Failed to retrieve API keys");
            }
        }

        #endregion

        #region CUD Operations

        public async Task<ServiceResult<ApplicationApiKeyDetailResponse>> CreateAsync(
            Guid applicationId,
            CreateApplicationApiKeyRequest request,
            Guid createdByConnectedId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var application = await _context.PlatformApplications
                    .Include(a => a.ApiKeys)
                    .FirstOrDefaultAsync(a => a.Id == applicationId && !a.IsDeleted);

                if (application == null)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("Application not found");
                }

                // ✨ 1. [오류 수정] CS1061 해결: 권한 확인 로직 변경
                // 'HasSufficientAccessLevel' 대신 'CheckPermissionAsync'를 사용합니다.
                // 권한 이름은 'apikey:create'와 같이 비즈니스 행위에 기반한 이름으로 가정합니다.
                var permissionResult = await _accessService.CheckPermissionAsync(
                    createdByConnectedId, applicationId, "apikey:create");

                if (!permissionResult.IsValid)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure(
                        permissionResult.Reason ?? "Insufficient permissions to create API key");
                }

                var activeKeyCount = application.ApiKeys?.Count(k => k.IsActive && !k.RevokedAt.HasValue) ?? 0;
                if (activeKeyCount >= MAX_KEYS_PER_APPLICATION)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure(
                        $"Maximum number of API keys ({MAX_KEYS_PER_APPLICATION}) reached");
                }

                var (apiKey, keyHash) = GenerateApiKey();
                var keyPrefix = apiKey.Substring(0, KEY_PREFIX_LENGTH);
                var keyLastFour = apiKey.Substring(apiKey.Length - KEY_LAST_FOUR_LENGTH);

                int rateLimitPerMinute = request.RateLimitPolicy switch
                {
                    ApiKeyRateLimitPolicy.VeryLow => 10,
                    ApiKeyRateLimitPolicy.Low => 30,
                    ApiKeyRateLimitPolicy.Normal => 60,
                    ApiKeyRateLimitPolicy.High => 120,
                    ApiKeyRateLimitPolicy.VeryHigh => 300,
                    ApiKeyRateLimitPolicy.Custom => request.CustomRateLimitPerMinute ?? 60,
                    _ => 60
                };

                var apiKeyEntity = new PlatformApplicationApiKey
                {
                    ApplicationId = applicationId,
                    OrganizationId = application.OrganizationId,
                    KeyName = request.Name,
                    KeyHash = keyHash,
                    KeyPrefix = keyPrefix,
                    KeyLastFour = keyLastFour,
                    KeyManagementType = ApiKeyManagementType.CustomerManaged,
                    KeySource = request.Source,
                    PermissionLevel = request.PermissionLevel,
                    AccessLevel = MapPermissionLevelToAccessLevel(request.PermissionLevel),
                    AllowedScopes = JsonConvert.SerializeObject(request.AllowedScopes),
                    AllowedIPs = request.IpRestrictionPolicy != IpRestrictionPolicy.None
                        ? JsonConvert.SerializeObject(request.AllowedIpAddresses)
                        : null,
                    RateLimitPerMinute = rateLimitPerMinute,
                    IssuedAt = _dateTimeProvider.UtcNow,
                    ExpiresAt = request.ExpiresAt,
                    IsActive = true,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = createdByConnectedId,
                    AdditionalSettings = JsonConvert.SerializeObject(new
                    {
                        Environment = request.Environment.ToString(),
                        IpRestrictionPolicy = request.IpRestrictionPolicy.ToString(),
                        RateLimitPolicy = request.RateLimitPolicy.ToString(),
                        DailyQuota = request.DailyQuota,
                        Metadata = request.Metadata
                    })
                };

                _context.PlatformApplicationApiKeys.Add(apiKeyEntity);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation(
                    "API Key created: {KeyId} for Application {ApplicationId} by {CreatedBy}",
                    apiKeyEntity.Id, applicationId, createdByConnectedId);

                var response = MapToDetailResponse(apiKeyEntity);
                response.FullKeyValue = apiKey;

                return ServiceResult<ApplicationApiKeyDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to create API key for application {ApplicationId}", applicationId);
                return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("Failed to create API key");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyResponse>> UpdateAsync(
            Guid id,
            UpdateApplicationApiKeyRequest request,
            Guid updatedByConnectedId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApplicationApiKeyResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(updatedByConnectedId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<ApplicationApiKeyResponse>.Failure("Insufficient permissions");
                }
                
                // ... (이하 업데이트 로직은 변경 없음)
                if (!string.IsNullOrEmpty(request.Name))
                {
                    apiKey.KeyName = request.Name;
                }
                if (request.Status.HasValue)
                {
                    apiKey.IsActive = request.Status.Value == ApiKeyStatus.Active;
                    if (request.Status.Value == ApiKeyStatus.Expired) apiKey.ExpiresAt = _dateTimeProvider.UtcNow.AddMinutes(-1);
                    else if (request.Status.Value == ApiKeyStatus.Deleted)
                    {
                        apiKey.IsDeleted = true;
                        apiKey.DeletedAt = _dateTimeProvider.UtcNow;
                    }
                }
                if (request.PermissionLevel.HasValue)
                {
                    apiKey.PermissionLevel = request.PermissionLevel.Value;
                    apiKey.AccessLevel = MapPermissionLevelToAccessLevel(request.PermissionLevel.Value);
                }
                if (request.AllowedScopes != null)
                {
                    apiKey.AllowedScopes = JsonConvert.SerializeObject(request.AllowedScopes);
                }
                if (request.IpRestrictionPolicy.HasValue)
                {
                    var settings = GetAdditionalSettings(apiKey);
                    settings["IpRestrictionPolicy"] = request.IpRestrictionPolicy.Value.ToString();
                    apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);
                    if (request.AllowedIpAddresses != null)
                    {
                        apiKey.AllowedIPs = request.IpRestrictionPolicy.Value != IpRestrictionPolicy.None
                            ? JsonConvert.SerializeObject(request.AllowedIpAddresses)
                            : null;
                    }
                }
                if (request.RateLimitPolicy.HasValue)
                {
                    apiKey.RateLimitPerMinute = request.RateLimitPolicy.Value switch
                    {
                        ApiKeyRateLimitPolicy.VeryLow => 10,
                        ApiKeyRateLimitPolicy.Low => 30,
                        ApiKeyRateLimitPolicy.Normal => 60,
                        ApiKeyRateLimitPolicy.High => 120,
                        ApiKeyRateLimitPolicy.VeryHigh => 300,
                        ApiKeyRateLimitPolicy.Custom => request.CustomRateLimitPerMinute ?? apiKey.RateLimitPerMinute,
                        _ => 60
                    };
                    var settings = GetAdditionalSettings(apiKey);
                    settings["RateLimitPolicy"] = request.RateLimitPolicy.Value.ToString();
                    apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);
                }
                if (request.DailyQuota.HasValue)
                {
                    var settings = GetAdditionalSettings(apiKey);
                    settings["DailyQuota"] = request.DailyQuota.Value;
                    apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);
                }
                if (request.ExpiresAt.HasValue)
                {
                    apiKey.ExpiresAt = request.ExpiresAt;
                }
                if (!string.IsNullOrEmpty(request.Metadata))
                {
                    var settings = GetAdditionalSettings(apiKey);
                    settings["Metadata"] = request.Metadata;
                    apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);
                }

                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = updatedByConnectedId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("API Key updated: {KeyId} by {UpdatedBy}", id, updatedByConnectedId);

                var response = MapToResponse(apiKey);
                return ServiceResult<ApplicationApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to update API key {KeyId}", id);
                return ServiceResult<ApplicationApiKeyResponse>.Failure("Failed to update API key");
            }
        }
        
        // ... (이하 다른 CUD 메서드는 변경 없음)
        public async Task<ServiceResult<bool>> DeleteAsync(Guid id, Guid deletedByConnectedId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<bool>.Success(true);
                }

                var hasPermission = await ValidateUserCanManageApiKey(deletedByConnectedId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions");
                }

                apiKey.IsDeleted = true;
                apiKey.DeletedAt = _dateTimeProvider.UtcNow;
                apiKey.DeletedByConnectedId = deletedByConnectedId;
                apiKey.IsActive = false;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                _logger.LogWarning("API Key deleted: {KeyId} by {DeletedBy}", id, deletedByConnectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete API key {KeyId}", id);
                return ServiceResult<bool>.Failure("Failed to delete API key");
            }
        }

        public async Task<ServiceResult<ApplicationApiKeyDetailResponse>> RegenerateAsync(
            Guid id,
            Guid regeneratedByConnectedId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var oldKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (oldKey == null)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(regeneratedByConnectedId, oldKey);
                if (!hasPermission)
                {
                    return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("Insufficient permissions");
                }

                var (newApiKey, newKeyHash) = GenerateApiKey();
                var newKeyPrefix = newApiKey.Substring(0, KEY_PREFIX_LENGTH);
                var newKeyLastFour = newApiKey.Substring(newApiKey.Length - KEY_LAST_FOUR_LENGTH);

                oldKey.KeyHash = newKeyHash;
                oldKey.KeyPrefix = newKeyPrefix;
                oldKey.KeyLastFour = newKeyLastFour;
                oldKey.IssuedAt = _dateTimeProvider.UtcNow;
                oldKey.UpdatedAt = _dateTimeProvider.UtcNow;
                oldKey.UpdatedByConnectedId = regeneratedByConnectedId;

                _context.PlatformApplicationApiKeys.Update(oldKey);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("API Key regenerated: {KeyId} by {RegeneratedBy}", id, regeneratedByConnectedId);

                var response = MapToDetailResponse(oldKey);
                response.FullKeyValue = newApiKey;

                return ServiceResult<ApplicationApiKeyDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to regenerate API key {KeyId}", id);
                return ServiceResult<ApplicationApiKeyDetailResponse>.Failure("Failed to regenerate API key");
            }
        }

        public async Task<ServiceResult<bool>> ActivateAsync(Guid id, Guid activatedByConnectedId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<bool>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(activatedByConnectedId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions");
                }

                apiKey.IsActive = true;
                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = activatedByConnectedId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                _logger.LogInformation("API Key activated: {KeyId} by {ActivatedBy}", id, activatedByConnectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to activate API key {KeyId}", id);
                return ServiceResult<bool>.Failure("Failed to activate API key");
            }
        }

        public async Task<ServiceResult<bool>> DeactivateAsync(
            Guid id,
            string reason,
            Guid deactivatedByConnectedId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<bool>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(deactivatedByConnectedId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions");
                }

                apiKey.IsActive = false;
                apiKey.RevocationReason = reason;
                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = deactivatedByConnectedId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                _logger.LogWarning("API Key deactivated: {KeyId} by {DeactivatedBy}, Reason: {Reason}",
                    id, deactivatedByConnectedId, reason);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to deactivate API key {KeyId}", id);
                return ServiceResult<bool>.Failure("Failed to deactivate API key");
            }
        }

        public async Task<ServiceResult<bool>> SuspendAsync(
            Guid id,
            string reason,
            DateTime? until,
            Guid suspendedByConnectedId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<bool>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(suspendedByConnectedId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions");
                }

                apiKey.IsActive = false;
                apiKey.RevocationReason = $"Suspended: {reason}";
                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = suspendedByConnectedId;

                var settings = GetAdditionalSettings(apiKey);
                settings["SuspendedUntil"] = until?.ToString("O") ?? string.Empty;
                settings["SuspensionReason"] = reason;
                apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                _logger.LogWarning("API Key suspended: {KeyId} until {Until} by {SuspendedBy}, Reason: {Reason}",
                    id, until, suspendedByConnectedId, reason);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to suspend API key {KeyId}", id);
                return ServiceResult<bool>.Failure("Failed to suspend API key");
            }
        }

        #endregion
        
        // ... (이하 다른 모든 영역의 코드는 변경 없음)
        #region Validation & Authentication Operations
        public async Task<ServiceResult<ApiKeyValidationResult>> ValidateAsync(string keyValue)
        {
            try
            {
                if (string.IsNullOrEmpty(keyValue) || keyValue.Length < KEY_PREFIX_LENGTH)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = "Invalid API key format" });
                }

                var keyPrefix = keyValue.Substring(0, KEY_PREFIX_LENGTH);
                var keyHash = ComputeHash(keyValue);

                var apiKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k => k.KeyPrefix == keyPrefix && k.KeyHash == keyHash && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = "API key not found" });
                }
                if (!apiKey.IsActive)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = "API key is inactive" });
                }
                if (apiKey.RevokedAt.HasValue)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has been revoked" });
                }

                var settings = GetAdditionalSettings(apiKey);
                if (settings.ContainsKey("SuspendedUntil"))
                {
                    if (DateTime.TryParse(settings["SuspendedUntil"]?.ToString(), out var suspendedUntil))
                    {
                        if (suspendedUntil > _dateTimeProvider.UtcNow)
                        {
                            return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = $"API key is suspended until {suspendedUntil}" });
                        }
                    }
                }
                if (apiKey.ExpiresAt.HasValue && apiKey.ExpiresAt.Value < _dateTimeProvider.UtcNow)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has expired" });
                }

                var scopes = JsonConvert.DeserializeObject<List<string>>(apiKey.AllowedScopes ?? "[]") ?? new List<string>();
                return ServiceResult<ApiKeyValidationResult>.Success(new ApiKeyValidationResult { IsValid = true, ApplicationId = apiKey.ApplicationId, OrganizationId = apiKey.OrganizationId, Scopes = scopes });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate API key");
                return ServiceResult<ApiKeyValidationResult>.Failure("Failed to validate API key");
            }
        }

        public async Task<ServiceResult<ApiKeyAuthenticationResult>> AuthenticateAsync(
            string keyValue,
            string? ipAddress = null)
        {
            try
            {
                var validationResult = await ValidateAsync(keyValue);
                if (!validationResult.IsSuccess || validationResult.Data == null || !validationResult.Data.IsValid)
                {
                    return ServiceResult<ApiKeyAuthenticationResult>.Success(new ApiKeyAuthenticationResult { IsAuthenticated = false, FailureReason = validationResult.ErrorMessage ?? validationResult.Data?.FailureReason ?? "Validation failed" });
                }

                if (!string.IsNullOrEmpty(ipAddress))
                {
                    var keyPrefix = keyValue.Substring(0, KEY_PREFIX_LENGTH);
                    var apiKey = await GetApiKeyByPrefixAndHashAsync(keyPrefix, ComputeHash(keyValue));
                    if (apiKey != null && !IsIpAllowed(apiKey, ipAddress))
                    {
                        return ServiceResult<ApiKeyAuthenticationResult>.Success(new ApiKeyAuthenticationResult { IsAuthenticated = false, FailureReason = "IP address not allowed" });
                    }
                    if (apiKey != null)
                    {
                        await RecordUsageInternalAsync(apiKey.Id, ipAddress);
                    }
                }

                var keyPrefixForId = keyValue.Substring(0, KEY_PREFIX_LENGTH);
                var actualApiKey = await GetApiKeyByPrefixAndHashAsync(keyPrefixForId, ComputeHash(keyValue));

                return ServiceResult<ApiKeyAuthenticationResult>.Success(new ApiKeyAuthenticationResult
                {
                    IsAuthenticated = true,
                    ApiKeyId = actualApiKey?.Id ?? Guid.Empty,
                    ApplicationId = validationResult.Data.ApplicationId!.Value,
                    OrganizationId = validationResult.Data.OrganizationId!.Value,
                    Claims = new Dictionary<string, object> { ["scopes"] = validationResult.Data.Scopes }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to authenticate with API key");
                return ServiceResult<ApiKeyAuthenticationResult>.Failure("Authentication failed");
            }
        }
        
        public async Task<ServiceResult<bool>> CheckPermissionAsync(
            string keyValue,
            string scope,
            string? resource = null)
        {
            try
            {
                var validationResult = await ValidateAsync(keyValue);
                if (!validationResult.IsSuccess || validationResult.Data == null || !validationResult.Data.IsValid)
                {
                    return ServiceResult<bool>.Success(false);
                }

                if (validationResult.Data.Scopes.Contains("*") || validationResult.Data.Scopes.Contains(scope))
                {
                    return ServiceResult<bool>.Success(true);
                }

                foreach (var allowedScope in validationResult.Data.Scopes)
                {
                    if (allowedScope.EndsWith("*"))
                    {
                        var prefix = allowedScope.TrimEnd('*');
                        if (scope.StartsWith(prefix))
                        {
                            return ServiceResult<bool>.Success(true);
                        }
                    }
                }

                return ServiceResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check permission for scope: {Scope}", scope);
                return ServiceResult<bool>.Failure("Failed to check permission");
            }
        }
        #endregion

        #region Usage Operations
        public async Task<ServiceResult<bool>> RecordUsageAsync(Guid id, ApiKeyUsageRecord usage)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys.FirstOrDefaultAsync(k => k.Id == id);
                if (apiKey == null)
                {
                    return ServiceResult<bool>.Failure("API key not found");
                }

                apiKey.LastUsedAt = usage.Timestamp;
                apiKey.UseCount++;
                if (!string.IsNullOrEmpty(usage.IpAddress))
                {
                    apiKey.LastUsedFromIP = usage.IpAddress;
                }

                var settings = GetAdditionalSettings(apiKey);
                var currentDailyUsage = settings.ContainsKey("CurrentDailyUsage") ? Convert.ToInt64(settings["CurrentDailyUsage"]) : 0;
                settings["CurrentDailyUsage"] = currentDailyUsage + 1;
                settings["LastUsageDate"] = _dateTimeProvider.UtcNow.Date.ToString("O");
                apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record API key usage for {KeyId}", id);
                return ServiceResult<bool>.Success(false);
            }
        }
        
        public async Task<ServiceResult<bool>> ResetDailyUsageAsync(Guid id)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys.FirstOrDefaultAsync(k => k.Id == id);
                if (apiKey == null)
                {
                    return ServiceResult<bool>.Failure("API key not found");
                }

                var settings = GetAdditionalSettings(apiKey);
                settings["DailyUsageResetAt"] = _dateTimeProvider.UtcNow;
                settings["CurrentDailyUsage"] = 0;
                apiKey.AdditionalSettings = JsonConvert.SerializeObject(settings);
                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();
                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset daily usage for API key {KeyId}", id);
                return ServiceResult<bool>.Failure("Failed to reset daily usage");
            }
        }
        
        public async Task<ServiceResult<ApiKeyUsageStatistics>> GetUsageStatisticsAsync(
            Guid id,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys.FirstOrDefaultAsync(k => k.Id == id);
                if (apiKey == null)
                {
                    return ServiceResult<ApiKeyUsageStatistics>.Failure("API key not found");
                }
                var statistics = new ApiKeyUsageStatistics
                {
                    ApiKeyId = id,
                    TotalUsage = (int)apiKey.UseCount,
                    LastUsedAt = apiKey.LastUsedAt,
                    DailyUsage = new Dictionary<DateTime, int>(),
                    TopEndpoints = new List<EndpointUsage>(),
                    TopIpAddresses = new List<string>(),
                    AverageResponseTime = 0
                };
                return ServiceResult<ApiKeyUsageStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get usage statistics for API key {KeyId}", id);
                return ServiceResult<ApiKeyUsageStatistics>.Failure("Failed to get usage statistics");
            }
        }
        #endregion

        #region Helper Methods
        private (string apiKey, string keyHash) GenerateApiKey()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            var apiKey = $"{_apiKeyPrefix}{Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=')}";
            var keyHash = ComputeHash(apiKey);
            return (apiKey, keyHash);
        }

        private string ComputeHash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashBytes);
            }
        }

        private ApplicationAccessLevel MapPermissionLevelToAccessLevel(ApiKeyPermissionLevel permissionLevel)
        {
            return permissionLevel switch
            {
                ApiKeyPermissionLevel.System => ApplicationAccessLevel.Owner,
                ApiKeyPermissionLevel.Admin => ApplicationAccessLevel.Admin,
                ApiKeyPermissionLevel.ReadWrite => ApplicationAccessLevel.User,
                ApiKeyPermissionLevel.ReadOnly => ApplicationAccessLevel.Viewer,
                ApiKeyPermissionLevel.Test => ApplicationAccessLevel.Viewer,
                _ => ApplicationAccessLevel.Viewer
            };
        }

        private ApiKeyStatus GetApiKeyStatus(PlatformApplicationApiKey apiKey)
        {
            if (apiKey.IsDeleted) return ApiKeyStatus.Deleted;
            if (apiKey.ExpiresAt.HasValue && apiKey.ExpiresAt.Value <= _dateTimeProvider.UtcNow) return ApiKeyStatus.Expired;
            if (!apiKey.IsActive) return ApiKeyStatus.Inactive;
            var settings = GetAdditionalSettings(apiKey);
            if (settings.ContainsKey("SuspendedUntil"))
            {
                if (DateTime.TryParse(settings["SuspendedUntil"]?.ToString(), out var suspendedUntil))
                {
                    if (suspendedUntil > _dateTimeProvider.UtcNow) return ApiKeyStatus.Suspended;
                }
            }
            return ApiKeyStatus.Active;
        }

        private async Task<bool> ValidateUserCanManageApiKey(Guid userId, PlatformApplicationApiKey apiKey)
        {
            if (apiKey.CreatedByConnectedId == userId)
            {
                return true;
            }

            // ✨ 2. [오류 수정] CS1061 해결: 권한 확인 로직 변경
            // 'Admin' 레벨을 확인하는 대신 'apikey:manage'와 같은 구체적인 권한을 확인합니다.
            var permissionResult = await _accessService.CheckPermissionAsync(userId, apiKey.ApplicationId, "apikey:manage");
            return permissionResult.IsValid;
        }

        private bool IsIpAllowed(PlatformApplicationApiKey apiKey, string ipAddress)
        {
            if (string.IsNullOrEmpty(apiKey.AllowedIPs)) return true;
            var allowedIPs = JsonConvert.DeserializeObject<List<string>>(apiKey.AllowedIPs);
            if (allowedIPs == null || allowedIPs.Contains("*")) return true;
            return allowedIPs.Contains(ipAddress);
        }
        
        private bool IsDomainAllowed(PlatformApplicationApiKey apiKey, string domain)
        {
            if (string.IsNullOrEmpty(apiKey.AllowedDomains)) return true;
            var allowedDomains = JsonConvert.DeserializeObject<List<string>>(apiKey.AllowedDomains);
            if (allowedDomains == null || allowedDomains.Contains("*")) return true;
            return allowedDomains.Any(d => domain.EndsWith(d, StringComparison.OrdinalIgnoreCase));
        }
        
        private async Task<PlatformApplicationApiKey?> GetApiKeyByPrefixAndHashAsync(string keyPrefix, string keyHash)
        {
            return await _context.PlatformApplicationApiKeys
                .FirstOrDefaultAsync(k => k.KeyPrefix == keyPrefix && k.KeyHash == keyHash && !k.IsDeleted);
        }
        
        private async Task RecordUsageInternalAsync(Guid apiKeyId, string? ipAddress)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys.FirstOrDefaultAsync(k => k.Id == apiKeyId);
                if (apiKey != null)
                {
                    apiKey.LastUsedAt = _dateTimeProvider.UtcNow;
                    apiKey.UseCount++;
                    if (!string.IsNullOrEmpty(ipAddress))
                    {
                        apiKey.LastUsedFromIP = ipAddress;
                    }
                    _context.PlatformApplicationApiKeys.Update(apiKey);
                    await _context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record internal API key usage");
            }
        }
        
        private Dictionary<string, object> GetAdditionalSettings(PlatformApplicationApiKey apiKey)
        {
            if (string.IsNullOrEmpty(apiKey.AdditionalSettings)) return new Dictionary<string, object>();
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(apiKey.AdditionalSettings) ?? new Dictionary<string, object>();
        }
        
        private ApiKeyEnvironment GetEnvironmentFromSettings(PlatformApplicationApiKey apiKey)
        {
            var settings = GetAdditionalSettings(apiKey);
            if (settings.ContainsKey("Environment") && Enum.TryParse<ApiKeyEnvironment>(settings["Environment"]?.ToString(), out var env))
            {
                return env;
            }
            return ApiKeyEnvironment.Production;
        }
        
        private ApplicationApiKeyResponse MapToResponse(PlatformApplicationApiKey apiKey)
        {
            return new ApplicationApiKeyResponse
            {
                Id = apiKey.Id, ApplicationId = apiKey.ApplicationId, Name = apiKey.KeyName,
                MaskedKeyValue = $"{apiKey.KeyPrefix}****{apiKey.KeyLastFour}", Status = GetApiKeyStatus(apiKey),
                PermissionLevel = apiKey.PermissionLevel, Source = apiKey.KeySource, Environment = GetEnvironmentFromSettings(apiKey),
                CreatedAt = apiKey.CreatedAt, ExpiresAt = apiKey.ExpiresAt, LastUsedAt = apiKey.LastUsedAt
            };
        }
        
        private ApplicationApiKeyDetailResponse MapToDetailResponse(PlatformApplicationApiKey apiKey)
        {
            var settings = GetAdditionalSettings(apiKey);
            var scopes = JsonConvert.DeserializeObject<List<ApiKeyScope>>(apiKey.AllowedScopes ?? "[]") ?? new List<ApiKeyScope>();
            var ipAddresses = JsonConvert.DeserializeObject<List<string>>(apiKey.AllowedIPs ?? "[]") ?? new List<string>();
            return new ApplicationApiKeyDetailResponse
            {
                Id = apiKey.Id, ApplicationId = apiKey.ApplicationId, Name = apiKey.KeyName,
                MaskedKeyValue = $"{apiKey.KeyPrefix}****{apiKey.KeyLastFour}", Status = GetApiKeyStatus(apiKey),
                PermissionLevel = apiKey.PermissionLevel, Source = apiKey.KeySource, Environment = GetEnvironmentFromSettings(apiKey),
                CreatedAt = apiKey.CreatedAt, ExpiresAt = apiKey.ExpiresAt, LastUsedAt = apiKey.LastUsedAt,
                AllowedScopes = scopes,
                IpRestrictionPolicy = Enum.TryParse<IpRestrictionPolicy>(settings.GetValueOrDefault("IpRestrictionPolicy")?.ToString() ?? "None", out var ipPolicy) ? ipPolicy : IpRestrictionPolicy.None,
                AllowedIpAddresses = ipAddresses,
                RateLimitPolicy = Enum.TryParse<ApiKeyRateLimitPolicy>(settings.GetValueOrDefault("RateLimitPolicy")?.ToString() ?? "Normal", out var ratePolicy) ? ratePolicy : ApiKeyRateLimitPolicy.Normal,
                CustomRateLimitPerMinute = apiKey.RateLimitPerMinute,
                DailyQuota = settings.ContainsKey("DailyQuota") ? Convert.ToInt64(settings["DailyQuota"]) : null,
                CurrentDailyUsage = settings.ContainsKey("CurrentDailyUsage") ? Convert.ToInt64(settings["CurrentDailyUsage"]) : 0,
                HashingAlgorithm = HashingAlgorithm.SHA256,
                Metadata = settings.GetValueOrDefault("Metadata")?.ToString(),
                UpdatedAt = apiKey.UpdatedAt,
                CreatedByConnectedId = apiKey.CreatedByConnectedId,
                UpdatedByConnectedId = apiKey.UpdatedByConnectedId
            };
        }
        #endregion
    }
}