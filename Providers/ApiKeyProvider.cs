using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Common;
using AuthHive.Core.Models.PlatformApplication.Requests;
using AuthHive.Core.Models.PlatformApplication.Responses;
using Newtonsoft.Json;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Models.Common.RateLimiting;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// API Key 인증 제공자 구현 - AuthHive v15
    /// </summary>
    public class ApiKeyProvider : IApiKeyProvider
    {
        private readonly AuthDbContext _context;
        private readonly IMemoryCache _cache;
        private readonly ILogger<ApiKeyProvider> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ISecurityAnalyzer _securityAnalyzer;
        private readonly IGeolocationService _geolocationService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEncryptionService _encryptionService;

        private const string CACHE_KEY_PREFIX = "apikey:";
        private const int CACHE_DURATION_MINUTES = 5;
        private const int API_KEY_LENGTH = 32;
        private const int MAX_KEYS_PER_APPLICATION = 10;

        private readonly string _apiKeyPrefix;
        private readonly ApplicationEnvironment _environment;

        public ApiKeyProvider(
            AuthDbContext context,
            IMemoryCache cache,
            ILogger<ApiKeyProvider> logger,
            IConfiguration configuration,
            IHttpContextAccessor httpContextAccessor,
            ISecurityAnalyzer securityAnalyzer,
            IGeolocationService geolocationService,
            IDateTimeProvider dateTimeProvider,
            IEncryptionService encryptionService)
        {
            _context = context;
            _cache = cache;
            _logger = logger;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
            _securityAnalyzer = securityAnalyzer;
            _geolocationService = geolocationService;
            _dateTimeProvider = dateTimeProvider;
            _encryptionService = encryptionService;

            var envString = _configuration["Environment"] ?? "Development";
            _environment = Enum.Parse<ApplicationEnvironment>(envString);
            _apiKeyPrefix = _environment switch
            {
                ApplicationEnvironment.Production => "ahk_live_",
                ApplicationEnvironment.Staging => "ahk_stg_",
                ApplicationEnvironment.Testing => "ahk_test_",
                _ => "ahk_dev_"
            };
        }

        #region API Key Generation

        public async Task<ServiceResult<CreateApiKeyResponse>> GenerateApiKeyAsync(
            CreateApiKeyRequest request,
            Guid currentUserId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var application = await _context.PlatformApplications
                    .Include(a => a.Organization)
                    .FirstOrDefaultAsync(a => a.Id == request.ApplicationId && !a.IsDeleted);

                if (application == null)
                {
                    return ServiceResult<CreateApiKeyResponse>.Failure("Application not found");
                }

                if (application.Status != ApplicationStatus.Active)
                {
                    return ServiceResult<CreateApiKeyResponse>.Failure("Application is not active");
                }

                var userAccess = await ValidateUserApplicationAccess(
                    currentUserId,
                    request.ApplicationId,
                    ApplicationAccessLevel.Admin);

                if (!userAccess.HasAccess)
                {
                    return ServiceResult<CreateApiKeyResponse>.Failure(userAccess.Reason ?? "Insufficient permissions");
                }

                var allowedScopes = FilterScopesByUserAccess(request.Scopes, userAccess.UserAccess!);

                var existingKeysCount = await _context.PlatformApplicationApiKeys
                    .CountAsync(k => k.ApplicationId == request.ApplicationId &&
                                   k.IsActive &&
                                   k.RevokedAt == null);

                if (existingKeysCount >= MAX_KEYS_PER_APPLICATION)
                {
                    return ServiceResult<CreateApiKeyResponse>.Failure(
                        $"Maximum number of API keys ({MAX_KEYS_PER_APPLICATION}) reached");
                }

                var (fullKey, hashedKey, lastFour) = GenerateSecureApiKey();
                var keyPrefix = ExtractKeyPrefix(fullKey);

                var accessControl = request.AccessControl ??
                    await GetDefaultAccessControl(application.OrganizationId, application.Id);

                var apiKeyEntity = new PlatformApplicationApiKey
                {
                    ApplicationId = request.ApplicationId,
                    OrganizationId = application.OrganizationId,
                    KeyName = request.Name,
                    KeyHash = hashedKey,
                    KeyPrefix = keyPrefix,
                    KeyLastFour = lastFour,
                    KeyManagementType = ApiKeyManagementType.CustomerManaged,
                    AccessLevel = ParseAccessLevel(request.PermissionLevel),
                    AllowedScopes = JsonConvert.SerializeObject(allowedScopes),
                    ExcludedScopes = JsonConvert.SerializeObject(new List<string>()),
                    AllowedIPs = JsonConvert.SerializeObject(accessControl?.AllowedIPs ?? new List<string> { "*" }),
                    AllowedDomains = JsonConvert.SerializeObject(accessControl?.AllowedDomains ?? new List<string> { "*" }),
                    AllowedOrigins = JsonConvert.SerializeObject(accessControl?.AllowedOrigins ?? new List<string>()),
                    RateLimitPerMinute = request.RateLimitPerMinute ?? 60,
                    IsActive = true,
                    ExpiresAt = request.ExpiresAt,
                    IssuedAt = _dateTimeProvider.UtcNow,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = currentUserId,
                    UseCount = 0,
                    AdditionalSettings = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        { "Environment", _environment.ToString() },
                        { "Version", "1.0" },
                        { "Description", request.Description ?? "" },
                        { "Metadata", request.Metadata ?? new Dictionary<string, string>() }
                    })
                };

                _context.PlatformApplicationApiKeys.Add(apiKeyEntity);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                var response = new CreateApiKeyResponse
                {
                    Success = true,
                    FullApiKey = fullKey,
                    ApiKey = new ApiKeyInfo
                    {
                        Id = apiKeyEntity.Id,
                        Key = $"{keyPrefix}****{lastFour}",
                        KeyPrefix = keyPrefix,
                        Name = apiKeyEntity.KeyName,
                        ApplicationId = apiKeyEntity.ApplicationId,
                        OrganizationId = apiKeyEntity.OrganizationId,
                        Scopes = allowedScopes,
                        CreatedAt = apiKeyEntity.CreatedAt,
                        CreatedByConnectedId = currentUserId,
                        ExpiresAt = apiKeyEntity.ExpiresAt,
                        IsActive = true,
                        RateLimitPerMinute = apiKeyEntity.RateLimitPerMinute,
                        PermissionLevel = apiKeyEntity.AccessLevel.ToString(),
                        KeyManagementType = apiKeyEntity.KeyManagementType.ToString(),
                        AccessControl = accessControl
                    },
                    Message = "API key created successfully. Please save the full key as it won't be shown again."
                };

                _logger.LogInformation(
                    "API Key created: {KeyId} for Application {ApplicationId} by User {UserId}",
                    apiKeyEntity.Id, request.ApplicationId, currentUserId);

                return ServiceResult<CreateApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to generate API key for application {ApplicationId}",
                    request.ApplicationId);
                return ServiceResult<CreateApiKeyResponse>.Failure("Failed to generate API key");
            }
        }

        #endregion

        #region API Key Validation

        public async Task<ServiceResult<ApiKeyValidationResult>> ValidateApiKeyAsync(
            string apiKey,
            string? clientIp = null,
            string? userAgent = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(
                        new ApiKeyValidationResult
                        {
                            IsValid = false,
                            FailureReason = "API key is required"
                        });
                }

                var cacheKey = $"{CACHE_KEY_PREFIX}{apiKey}";
                if (_cache.TryGetValue<ApiKeyValidationResult>(cacheKey, out var cachedResult) && cachedResult != null)
                {
                    return ServiceResult<ApiKeyValidationResult>.Success(cachedResult);
                }

                var keyPrefix = ExtractKeyPrefix(apiKey);
                var keyHash = ComputeHash(apiKey);

                var apiKeyEntity = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                        .Include(a => a.Organization)
                    .Include(k => k.CreatedByConnectedIdNavigation)
                    .FirstOrDefaultAsync(k =>
                        k.KeyPrefix == keyPrefix &&
                        k.KeyHash == keyHash);

                if (apiKeyEntity == null)
                {
                    var notFoundResult = new ApiKeyValidationResult
                    {
                        IsValid = false,
                        FailureReason = "Invalid API key"
                    };
                    CacheValidationResult(cacheKey, notFoundResult, 1);
                    return ServiceResult<ApiKeyValidationResult>.Success(notFoundResult);
                }

                var basicValidation = ValidateBasicRequirements(apiKeyEntity);
                if (!basicValidation.IsValid)
                {
                    CacheValidationResult(cacheKey, basicValidation, 1);
                    return ServiceResult<ApiKeyValidationResult>.Success(basicValidation);
                }

                if (!string.IsNullOrEmpty(apiKeyEntity.AllowedIPs))
                {
                    clientIp ??= GetClientIpAddress();
                    userAgent ??= GetUserAgent();

                    var securityValidation = await ValidateAdvancedSecurity(
                        apiKeyEntity, clientIp, userAgent);

                    if (!securityValidation.IsValid)
                    {
                        CacheValidationResult(cacheKey, securityValidation, 1);
                        await LogSecurityEvent(apiKeyEntity, securityValidation.FailureReason, clientIp);
                        return ServiceResult<ApiKeyValidationResult>.Success(securityValidation);
                    }
                }

                var rateLimitResult = await CheckRateLimit(apiKeyEntity);
                if (!rateLimitResult.IsWithinLimit)
                {
                    var rateLimitExceeded = new ApiKeyValidationResult
                    {
                        IsValid = false,
                        FailureReason = "Rate limit exceeded"
                    };
                    return ServiceResult<ApiKeyValidationResult>.Success(rateLimitExceeded);
                }

                var validResult = new ApiKeyValidationResult
                {
                    IsValid = true,
                    ApiKeyId = apiKeyEntity.Id,
                    ApplicationId = apiKeyEntity.ApplicationId,
                    OrganizationId = apiKeyEntity.OrganizationId,
                    Scopes = DeserializeScopes(apiKeyEntity.AllowedScopes),
                    PermissionLevel = apiKeyEntity.AccessLevel.ToString(),
                    RateLimitPerMinute = apiKeyEntity.RateLimitPerMinute,
                    RemainingRequests = rateLimitResult.RemainingRequests,
                    RateLimitResetAt = rateLimitResult.ResetAt,
                    Metadata = new ValidationMetadata
                    {
                        ValidatedAt = _dateTimeProvider.UtcNow,
                        ClientIp = clientIp,
                        UserAgent = userAgent,
                        RiskScore = rateLimitResult.RiskScore
                    }
                };

                _ = UpdateLastUsedAsync(apiKeyEntity.Id, clientIp);
                CacheValidationResult(cacheKey, validResult, CACHE_DURATION_MINUTES);

                return ServiceResult<ApiKeyValidationResult>.Success(validResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate API key");
                return ServiceResult<ApiKeyValidationResult>.Success(
                    new ApiKeyValidationResult
                    {
                        IsValid = false,
                        FailureReason = "Validation error occurred"
                    });
            }
        }

        #endregion

        #region API Key Management

        public async Task<ServiceResult<RegenerateApiKeyResponse>> RegenerateApiKeyAsync(
            RegenerateApiKeyRequest request,
            Guid currentUserId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var existingKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k => k.Id == request.Id);

                if (existingKey == null)
                {
                    return ServiceResult<RegenerateApiKeyResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(currentUserId, existingKey);
                if (!hasPermission)
                {
                    return ServiceResult<RegenerateApiKeyResponse>.Failure("Insufficient permissions");
                }

                var (fullKey, hashedKey, lastFour) = GenerateSecureApiKey();
                var keyPrefix = ExtractKeyPrefix(fullKey);

                var newApiKey = new PlatformApplicationApiKey
                {
                    ApplicationId = existingKey.ApplicationId,
                    OrganizationId = existingKey.OrganizationId,
                    KeyName = $"{existingKey.KeyName} (Regenerated)",
                    KeyHash = hashedKey,
                    KeyPrefix = keyPrefix,
                    KeyLastFour = lastFour,
                    KeyManagementType = existingKey.KeyManagementType,
                    AccessLevel = existingKey.AccessLevel,
                    AllowedScopes = existingKey.AllowedScopes,
                    ExcludedScopes = existingKey.ExcludedScopes,
                    AllowedIPs = existingKey.AllowedIPs,
                    AllowedDomains = existingKey.AllowedDomains,
                    AllowedOrigins = existingKey.AllowedOrigins,
                    RateLimitPerMinute = existingKey.RateLimitPerMinute,
                    IsActive = true,
                    ExpiresAt = existingKey.ExpiresAt,
                    IssuedAt = _dateTimeProvider.UtcNow,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = currentUserId,
                    UseCount = 0,
                    AdditionalSettings = existingKey.AdditionalSettings
                };

                _context.PlatformApplicationApiKeys.Add(newApiKey);

                DateTime? oldKeyExpiresAt = null;
                if (request.ImmediateRevoke)
                {
                    existingKey.IsActive = false;
                    existingKey.RevokedAt = _dateTimeProvider.UtcNow;
                    existingKey.RevocationReason = request.Reason;
                    existingKey.RevokedBy = currentUserId;
                }
                else if (request.GracePeriodMinutes.HasValue && request.GracePeriodMinutes.Value > 0)
                {
                    oldKeyExpiresAt = _dateTimeProvider.UtcNow.AddMinutes(request.GracePeriodMinutes.Value);
                    existingKey.ExpiresAt = oldKeyExpiresAt;
                }

                existingKey.UpdatedAt = _dateTimeProvider.UtcNow;
                existingKey.UpdatedByConnectedId = currentUserId;

                _context.PlatformApplicationApiKeys.Update(existingKey);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                InvalidateApiKeyCache(existingKey.KeyPrefix);

                var response = new RegenerateApiKeyResponse
                {
                    Success = true,
                    NewFullApiKey = fullKey,
                    NewApiKey = new ApiKeyInfo
                    {
                        Id = newApiKey.Id,
                        Key = $"{keyPrefix}****{lastFour}",
                        KeyPrefix = keyPrefix,
                        Name = newApiKey.KeyName,
                        ApplicationId = newApiKey.ApplicationId,
                        OrganizationId = newApiKey.OrganizationId,
                        Scopes = DeserializeScopes(newApiKey.AllowedScopes),
                        CreatedAt = newApiKey.CreatedAt,
                        CreatedByConnectedId = currentUserId,
                        ExpiresAt = newApiKey.ExpiresAt,
                        IsActive = true,
                        RateLimitPerMinute = newApiKey.RateLimitPerMinute,
                        PermissionLevel = newApiKey.AccessLevel.ToString()
                    },
                    OldApiKeyId = existingKey.Id,
                    OldKeyExpiresAt = oldKeyExpiresAt,
                    Message = "API key regenerated successfully. Please save the new key."
                };

                _logger.LogInformation(
                    "API Key regenerated: Old {OldKeyId}, New {NewKeyId} by User {UserId}",
                    existingKey.Id, newApiKey.Id, currentUserId);

                return ServiceResult<RegenerateApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to regenerate API key {ApiKeyId}", request.Id);
                return ServiceResult<RegenerateApiKeyResponse>.Failure("Failed to regenerate API key");
            }
        }

        public async Task<ServiceResult<RevokeApiKeyResponse>> RevokeApiKeyAsync(
            RevokeApiKeyRequest request,
            Guid currentUserId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == request.Id);

                if (apiKey == null)
                {
                    return ServiceResult<RevokeApiKeyResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(currentUserId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<RevokeApiKeyResponse>.Failure("Insufficient permissions");
                }

                if (apiKey.RevokedAt.HasValue)
                {
                    return ServiceResult<RevokeApiKeyResponse>.Success(new RevokeApiKeyResponse
                    {
                        Success = true,
                        ApiKeyId = apiKey.Id,
                        RevokedAt = apiKey.RevokedAt.Value,
                        Reason = apiKey.RevocationReason ?? "",
                        RevokedBy = apiKey.RevokedBy ?? currentUserId,
                        Message = $"API key was already revoked on {apiKey.RevokedAt:yyyy-MM-dd}"
                    });
                }

                apiKey.IsActive = false;
                apiKey.RevokedAt = _dateTimeProvider.UtcNow;
                apiKey.RevocationReason = request.Reason;
                apiKey.RevokedBy = currentUserId;
                apiKey.DeletedAt = _dateTimeProvider.UtcNow;
                apiKey.DeletedByConnectedId = currentUserId;
                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = currentUserId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                InvalidateApiKeyCache(apiKey.KeyPrefix);

                var response = new RevokeApiKeyResponse
                {
                    Success = true,
                    ApiKeyId = apiKey.Id,
                    RevokedAt = apiKey.RevokedAt.Value,
                    Reason = request.Reason,
                    RevokedBy = currentUserId,
                    Message = "API key revoked successfully"
                };

                _logger.LogWarning(
                    "API Key revoked: {ApiKeyId}, Reason: {Reason}, RevokedBy: {UserId}",
                    apiKey.Id, request.Reason, currentUserId);

                return ServiceResult<RevokeApiKeyResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke API key {ApiKeyId}", request.Id);
                return ServiceResult<RevokeApiKeyResponse>.Failure("Failed to revoke API key");
            }
        }

        #endregion

        #region Query Methods

        public async Task<ServiceResult<ApiKeyDetailResponse>> GetApiKeyDetailsAsync(
            Guid apiKeyId,
            Guid currentUserId)
        {
            try
            {
                var apiKeyData = await _context.PlatformApplicationApiKeys
                    .Where(k => k.Id == apiKeyId && !k.IsDeleted)
                    .Select(k => new
                    {
                        ApiKey = k,
                        ApplicationId = k.PlatformApplication != null ? k.PlatformApplication.Id : Guid.Empty,
                        ApplicationName = k.PlatformApplication != null ? k.PlatformApplication.Name : "Unknown",
                        ApplicationKey = k.PlatformApplication != null ? k.PlatformApplication.ApplicationKey : "",
                        ApplicationStatus = k.PlatformApplication != null ? k.PlatformApplication.Status : ApplicationStatus.Inactive,
                        ApplicationEnvironment = k.PlatformApplication != null ? k.PlatformApplication.Environment : ApplicationEnvironment.Development,
                        CreatorConnectedId = k.CreatedByConnectedId,
                        CreatorDisplayName = k.CreatedByConnectedIdNavigation != null
                            ? k.CreatedByConnectedIdNavigation.DisplayName
                            : null,
                        CreatorProfileImage = k.CreatedByConnectedIdNavigation != null
                            && k.CreatedByConnectedIdNavigation.User != null
                            && k.CreatedByConnectedIdNavigation.User.UserProfile != null
                            ? k.CreatedByConnectedIdNavigation.User.UserProfile.ProfileImageUrl
                            : null
                    })
                    .FirstOrDefaultAsync();

                if (apiKeyData == null)
                {
                    return ServiceResult<ApiKeyDetailResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanViewApiKey(currentUserId, apiKeyData.ApiKey);
                if (!hasPermission)
                {
                    return ServiceResult<ApiKeyDetailResponse>.Failure("Insufficient permissions");
                }

                var usageStats = await GetApiKeyUsageStatistics(apiKeyData.ApiKey.Id);
                var recentActivities = await GetApiKeyRecentActivities(apiKeyData.ApiKey.Id);

                var response = new ApiKeyDetailResponse
                {
                    ApiKey = MapToApiKeyInfo(apiKeyData.ApiKey),
                    UsageStatistics = usageStats,
                    RecentActivities = recentActivities,
                    AccessControl = string.IsNullOrEmpty(apiKeyData.ApiKey.AllowedIPs)
                        ? null
                        : new ApiKeyAccessControl
                        {
                            AllowedIPs = DeserializeScopes(apiKeyData.ApiKey.AllowedIPs),
                            AllowedDomains = DeserializeScopes(apiKeyData.ApiKey.AllowedDomains),
                            AllowedOrigins = DeserializeScopes(apiKeyData.ApiKey.AllowedOrigins),
                            RateLimitPerMinute = apiKeyData.ApiKey.RateLimitPerMinute
                        },
                    Creator = apiKeyData.CreatorConnectedId != null
                        ? new CreatorInfo
                        {
                            ConnectedId = apiKeyData.CreatorConnectedId.Value,
                            Name = apiKeyData.CreatorDisplayName ?? $"User_{apiKeyData.CreatorConnectedId.Value.ToString().Substring(0, 8)}",
                            Email = "",
                            ProfileImageUrl = apiKeyData.CreatorProfileImage
                        }
                        : null,
                    Application = new ApplicationBasicInfo
                    {
                        Id = apiKeyData.ApplicationId,
                        Name = apiKeyData.ApplicationName,
                        ApplicationKey = apiKeyData.ApplicationKey,
                        Status = apiKeyData.ApplicationStatus.ToString(),
                        Environment = apiKeyData.ApplicationEnvironment.ToString()
                    }
                };

                return ServiceResult<ApiKeyDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API key details {ApiKeyId}", apiKeyId);
                return ServiceResult<ApiKeyDetailResponse>.Failure("Failed to retrieve API key details");
            }
        }

        public async Task<ServiceResult<ApiKeyDetailResponse>> UpdateApiKeyAsync(
            UpdateApiKeyRequest request,
            Guid currentUserId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .FirstOrDefaultAsync(k => k.Id == request.Id && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult<ApiKeyDetailResponse>.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(currentUserId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult<ApiKeyDetailResponse>.Failure("Insufficient permissions");
                }

                if (!string.IsNullOrEmpty(request.Name))
                {
                    apiKey.KeyName = request.Name;
                }

                if (request.ExpiresAt.HasValue)
                {
                    apiKey.ExpiresAt = request.ExpiresAt;
                }

                if (request.RateLimitPerMinute.HasValue)
                {
                    apiKey.RateLimitPerMinute = request.RateLimitPerMinute.Value;
                }

                if (request.IsActive.HasValue)
                {
                    apiKey.IsActive = request.IsActive.Value;
                }

                if (request.Scopes != null && request.Scopes.Any())
                {
                    apiKey.AllowedScopes = JsonConvert.SerializeObject(request.Scopes);
                }

                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = currentUserId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                InvalidateApiKeyCache(apiKey.KeyPrefix);

                return await GetApiKeyDetailsAsync(apiKey.Id, currentUserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update API key {ApiKeyId}", request.Id);
                return ServiceResult<ApiKeyDetailResponse>.Failure("Failed to update API key");
            }
        }

        public async Task<ServiceResult<ApiKeyListResponse>> GetApiKeysAsync(
            SearchApiKeysRequest request,
            Guid currentUserId)
        {
            try
            {
                var query = _context.PlatformApplicationApiKeys
                    .Include(k => k.PlatformApplication)
                    .Where(k => !k.IsDeleted);

                if (request.ApplicationId.HasValue)
                {
                    query = query.Where(k => k.ApplicationId == request.ApplicationId.Value);
                }

                if (request.OrganizationId.HasValue)
                {
                    query = query.Where(k => k.OrganizationId == request.OrganizationId.Value);
                }

                if (request.IsActive.HasValue)
                {
                    query = query.Where(k => k.IsActive == request.IsActive.Value);
                }

                if (!string.IsNullOrEmpty(request.Keyword))
                {
                    query = query.Where(k => k.KeyName.Contains(request.Keyword));
                }

                var accessibleApplicationIds = await _context.UserPlatformApplicationAccess
                    .Where(u => u.ConnectedId == currentUserId && u.IsActive && !u.IsDeleted)
                    .Select(u => u.ApplicationId)
                    .ToListAsync();

                query = query.Where(k => accessibleApplicationIds.Contains(k.ApplicationId));

                var totalCount = await query.CountAsync();

                var items = await query
                    .OrderByDescending(k => k.CreatedAt)
                    .Skip((request.PageNumber - 1) * request.PageSize)
                    .Take(request.PageSize)
                    .Select(k => new ApiKeyInfo
                    {
                        Id = k.Id,
                        Key = $"{k.KeyPrefix}****{k.KeyLastFour}",
                        KeyPrefix = k.KeyPrefix,
                        Name = k.KeyName,
                        ApplicationId = k.ApplicationId,
                        OrganizationId = k.OrganizationId,
                        CreatedAt = k.CreatedAt,
                        ExpiresAt = k.ExpiresAt,
                        LastUsedAt = k.LastUsedAt,
                        IsActive = k.IsActive && !k.RevokedAt.HasValue,
                        RateLimitPerMinute = k.RateLimitPerMinute,
                        PermissionLevel = k.AccessLevel.ToString(),
                        Scopes = DeserializeScopes(k.AllowedScopes),
                        CreatedByConnectedId = k.CreatedByConnectedId ?? Guid.Empty
                    })
                    .ToListAsync();

                var response = new ApiKeyListResponse
                {
                    Items = items,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize,
                    TotalPages = (int)Math.Ceiling(totalCount / (double)request.PageSize)
                };

                return ServiceResult<ApiKeyListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get API keys");
                return ServiceResult<ApiKeyListResponse>.Failure("Failed to retrieve API keys");
            }
        }

        public async Task<ServiceResult> UpdateApiKeyAccessControlAsync(
            Guid apiKeyId,
            ApiKeyAccessControl accessControl,
            Guid currentUserId)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys
                    .FirstOrDefaultAsync(k => k.Id == apiKeyId && !k.IsDeleted);

                if (apiKey == null)
                {
                    return ServiceResult.Failure("API key not found");
                }

                var hasPermission = await ValidateUserCanManageApiKey(currentUserId, apiKey);
                if (!hasPermission)
                {
                    return ServiceResult.Failure("Insufficient permissions");
                }

                apiKey.AllowedIPs = JsonConvert.SerializeObject(accessControl.AllowedIPs ?? new List<string> { "*" });
                apiKey.AllowedDomains = JsonConvert.SerializeObject(accessControl.AllowedDomains ?? new List<string> { "*" });
                apiKey.AllowedOrigins = JsonConvert.SerializeObject(accessControl.AllowedOrigins ?? new List<string>());
                apiKey.RateLimitPerMinute = accessControl.RateLimitPerMinute;

                apiKey.UpdatedAt = _dateTimeProvider.UtcNow;
                apiKey.UpdatedByConnectedId = currentUserId;

                _context.PlatformApplicationApiKeys.Update(apiKey);
                await _context.SaveChangesAsync();

                InvalidateApiKeyCache(apiKey.KeyPrefix);

                _logger.LogInformation(
                    "API Key access control updated: {ApiKeyId} by {UpdatedBy}",
                    apiKeyId, currentUserId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update API key access control {ApiKeyId}", apiKeyId);
                return ServiceResult.Failure("Failed to update access control");
            }
        }

        public async Task<ServiceResult> SetApplicationDefaultAccessControlAsync(
            Guid applicationId,
            ApiKeyAccessControl accessControl,
            Guid currentUserId)
        {
            try
            {
                var application = await _context.PlatformApplications
                    .FirstOrDefaultAsync(a => a.Id == applicationId && !a.IsDeleted);

                if (application == null)
                {
                    return ServiceResult.Failure("Application not found");
                }

                var userAccess = await ValidateUserApplicationAccess(currentUserId, applicationId, ApplicationAccessLevel.Admin);
                if (!userAccess.HasAccess)
                {
                    return ServiceResult.Failure(userAccess.Reason ?? "Insufficient permissions");
                }

                var settings = string.IsNullOrEmpty(application.AdditionalSettings)
                    ? new Dictionary<string, object>()
                    : JsonConvert.DeserializeObject<Dictionary<string, object>>(application.AdditionalSettings) ?? new Dictionary<string, object>();

                settings["DefaultAccessControl"] = accessControl;
                application.AdditionalSettings = JsonConvert.SerializeObject(settings);
                application.UpdatedAt = _dateTimeProvider.UtcNow;

                _context.PlatformApplications.Update(application);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Application default access control updated: {ApplicationId} by {UpdatedBy}",
                    applicationId, currentUserId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set application default access control {ApplicationId}", applicationId);
                return ServiceResult.Failure("Failed to set default access control");
            }
        }

        public async Task<ServiceResult> SetOrganizationDefaultAccessControlAsync(
            Guid organizationId,
            ApiKeyAccessControl accessControl,
            Guid currentUserId)
        {
            try
            {
                var organization = await _context.Organizations
                    .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

                if (organization == null)
                {
                    return ServiceResult.Failure("Organization not found");
                }

                var membershipCheck = await _context.OrganizationMemberships
                    .FirstOrDefaultAsync(m =>
                        m.ConnectedId == currentUserId &&
                        m.OrganizationId == organizationId &&
                        m.IsDeleted == false);

                if (membershipCheck == null || membershipCheck.MemberRole < OrganizationMemberRole.Admin)
                {
                    return ServiceResult.Failure("Insufficient organization permissions");
                }

                var orgSettings = await _context.OrganizationSettings
                    .FirstOrDefaultAsync(s => s.OrganizationId == organizationId && s.Category == "General" && s.SettingKey == "DefaultApiKeyAccessControl");

                if (orgSettings == null)
                {
                    orgSettings = new OrganizationSettings
                    {
                        OrganizationId = organizationId,
                        Category = "General",
                        SettingKey = "DefaultApiKeyAccessControl",
                        DataType = "JSON",
                        IsUserConfigurable = true,
                        IsActive = true,
                        CreatedAt = _dateTimeProvider.UtcNow
                    };
                    _context.OrganizationSettings.Add(orgSettings);
                }

                orgSettings.SettingValue = JsonConvert.SerializeObject(accessControl);
                orgSettings.LastModifiedAt = _dateTimeProvider.UtcNow;
                orgSettings.LastModifiedByConnectedId = currentUserId;
                orgSettings.UpdatedAt = _dateTimeProvider.UtcNow;

                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Organization default access control updated: {OrganizationId} by {UpdatedBy}",
                    organizationId, currentUserId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set organization default access control {OrganizationId}", organizationId);
                return ServiceResult.Failure("Failed to set default access control");
            }
        }

        #endregion

        #region Private Helper Methods

        private ApplicationAccessLevel ParseAccessLevel(string permissionLevel)
        {
            return permissionLevel?.ToLower() switch
            {
                "owner" => ApplicationAccessLevel.Owner,
                "admin" => ApplicationAccessLevel.Admin,
                "user" => ApplicationAccessLevel.User,
                "viewer" => ApplicationAccessLevel.Viewer,
                "readonly" => ApplicationAccessLevel.Viewer,
                _ => ApplicationAccessLevel.User
            };
        }

        private string GetClientIpAddress()
        {
            var context = _httpContextAccessor.HttpContext;
            if (context == null) return "0.0.0.0";

            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
                return forwardedFor.Split(',')[0].Trim();

            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
                return realIp;

            return context.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
        }

        private string GetUserAgent()
        {
            return _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].FirstOrDefault() ?? "Unknown";
        }

        private (string fullKey, string hashedKey, string lastFour) GenerateSecureApiKey()
        {
            var randomBytes = new byte[API_KEY_LENGTH];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            var keyWithoutPrefix = Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');

            var fullKey = $"{_apiKeyPrefix}{keyWithoutPrefix}";
            var hashedKey = ComputeHash(fullKey);
            var lastFour = fullKey.Length >= 4 ? fullKey.Substring(fullKey.Length - 4) : fullKey;

            return (fullKey, hashedKey, lastFour);
        }

        private string ComputeHash(string input)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        private string ExtractKeyPrefix(string apiKey)
        {
            return apiKey.Length >= 15 ? apiKey.Substring(0, 15) : string.Empty;
        }

        private void CacheValidationResult(string key, ApiKeyValidationResult result, int minutes)
        {
            _cache.Set(key, result, TimeSpan.FromMinutes(minutes));
        }

        private void InvalidateApiKeyCache(string keyPrefix)
        {
            _logger.LogDebug("Cache invalidated for key prefix: {KeyPrefix}", keyPrefix);
        }

        private async Task UpdateLastUsedAsync(Guid apiKeyId, string? clientIp = null)
        {
            try
            {
                var apiKey = await _context.PlatformApplicationApiKeys.FindAsync(apiKeyId);
                if (apiKey != null)
                {
                    apiKey.LastUsedAt = _dateTimeProvider.UtcNow;
                    apiKey.UseCount++;
                    if (!string.IsNullOrEmpty(clientIp))
                        apiKey.LastUsedFromIP = clientIp;

                    await _context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update last used time for API key {ApiKeyId}", apiKeyId);
            }
        }

        private List<string> DeserializeScopes(string? scopes)
        {
            if (string.IsNullOrEmpty(scopes))
                return new List<string>();

            try
            {
                return JsonConvert.DeserializeObject<List<string>>(scopes) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }

        private ApiKeyInfo MapToApiKeyInfo(PlatformApplicationApiKey entity)
        {
            return new ApiKeyInfo
            {
                Id = entity.Id,
                Key = $"{entity.KeyPrefix}****{entity.KeyLastFour}",
                KeyPrefix = entity.KeyPrefix,
                Name = entity.KeyName,
                ApplicationId = entity.ApplicationId,
                OrganizationId = entity.OrganizationId,
                Scopes = DeserializeScopes(entity.AllowedScopes),
                CreatedAt = entity.CreatedAt,
                CreatedByConnectedId = entity.CreatedByConnectedId ?? Guid.Empty,
                ExpiresAt = entity.ExpiresAt,
                LastUsedAt = entity.LastUsedAt,
                IsActive = entity.IsActive && !entity.RevokedAt.HasValue,
                RevokedAt = entity.RevokedAt,
                RevokedReason = entity.RevocationReason,
                RevokedBy = entity.RevokedBy,
                TotalRequestCount = entity.UseCount,
                RateLimitPerMinute = entity.RateLimitPerMinute,
                PermissionLevel = entity.AccessLevel.ToString(),
                KeyManagementType = entity.KeyManagementType.ToString()
            };
        }

        private ApiKeyValidationResult ValidateBasicRequirements(PlatformApplicationApiKey apiKey)
        {
            if (!apiKey.IsActive)
                return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key is inactive" };

            if (apiKey.RevokedAt.HasValue)
                return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has been revoked" };

            if (apiKey.ExpiresAt.HasValue && apiKey.ExpiresAt.Value < _dateTimeProvider.UtcNow)
                return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has expired" };

            if (apiKey.IsDeleted)
                return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has been deleted" };

            return new ApiKeyValidationResult { IsValid = true };
        }

        private Task<ApiKeyValidationResult> ValidateAdvancedSecurity(
            PlatformApplicationApiKey apiKey, string clientIp, string userAgent)
        {
            if (!string.IsNullOrEmpty(apiKey.AllowedIPs))
            {
                var allowedIPs = JsonConvert.DeserializeObject<List<string>>(apiKey.AllowedIPs) ?? new List<string>();
                if (!allowedIPs.Contains("*") && !allowedIPs.Contains(clientIp))
                {
                    return Task.FromResult(new ApiKeyValidationResult
                    {
                        IsValid = false,
                        FailureReason = $"IP address {clientIp} is not allowed"
                    });
                }
            }

            var riskScore = 0;
            if (IsHighRiskIp(clientIp))
            {
                riskScore = 80;
            }

            if (riskScore > 70)
            {
                return Task.FromResult(new ApiKeyValidationResult
                {
                    IsValid = false,
                    FailureReason = "High risk score detected"
                });
            }

            return Task.FromResult(new ApiKeyValidationResult { IsValid = true });
        }

        private bool IsHighRiskIp(string clientIp)
        {
            var highRiskIpRanges = new[] { "192.168.0.", "10.0.0." };
            return highRiskIpRanges.Any(range => clientIp.StartsWith(range));
        }

        private Task<RateLimitResult> CheckRateLimit(PlatformApplicationApiKey apiKey)
        {
            var cacheKey = $"rate_limit_{apiKey.Id}";
            var limit = apiKey.RateLimitPerMinute;
            // ResetAt은 공통적으로 사용되므로 미리 정의합니다.
            var resetTime = _dateTimeProvider.UtcNow.AddMinutes(1);

            // 1. 캐시에 요청 횟수(currentCount)가 있는지 확인합니다.
            if (_cache.TryGetValue<int>(cacheKey, out var currentCount))
            {
                // 2. [실패] 요청 횟수가 한도에 도달했거나 초과한 경우
                if (currentCount >= limit)
                {
                    // Exceeded 팩토리 메서드를 사용하여 실패 결과를 반환합니다.
                    // 이 메서드가 IsSuccess=false, RemainingRequests=0 등을 모두 설정합니다.
                    return Task.FromResult(RateLimitResult.Exceeded(currentCount, limit, resetTime));
                }

                // 3. [성공] 아직 한도 이내인 경우
                // 캐시의 카운트를 1 증가시킵니다.
                _cache.Set(cacheKey, currentCount + 1, TimeSpan.FromMinutes(1));

                // Success 팩토리 메서드를 사용하여 성공 결과를 반환합니다.
                // CurrentRate에 현재 요청을 포함한 'currentCount + 1'을 전달합니다.
                return Task.FromResult(RateLimitResult.Success(currentCount + 1, limit, resetTime));
            }

            // 4. [첫 요청 성공] 캐시에 값이 없는 경우 (첫 번째 요청)
            // 캐시에 첫 요청 횟수인 1을 저장합니다.
            _cache.Set(cacheKey, 1, TimeSpan.FromMinutes(1));

            // Success 팩토리 메서드를 사용하여 첫 성공 결과를 반환합니다.
            // CurrentRate는 1입니다.
            return Task.FromResult(RateLimitResult.Success(1, limit, resetTime));
        }

        private async Task LogSecurityEvent(PlatformApplicationApiKey apiKey, string? reason, string? clientIp)
        {
            _logger.LogWarning("Security event for API Key {ApiKeyId}: {Reason} from IP {ClientIp}",
                apiKey.Id, reason, clientIp);

            await Task.CompletedTask;
        }

        private async Task<(bool HasAccess, string? Reason, UserPlatformApplicationAccess? UserAccess)>
            ValidateUserApplicationAccess(Guid userId, Guid applicationId, ApplicationAccessLevel requiredLevel)
        {
            var userAccess = await _context.UserPlatformApplicationAccess
                .FirstOrDefaultAsync(u =>
                    u.ConnectedId == userId &&
                    u.ApplicationId == applicationId &&
                    u.IsActive &&
                    !u.IsDeleted);

            if (userAccess == null)
                return (false, "User has no access to this application", null);

            if (userAccess.AccessLevel < requiredLevel)
                return (false, $"User access level {userAccess.AccessLevel} is insufficient", userAccess);

            return (true, null, userAccess);
        }

        private List<string> FilterScopesByUserAccess(List<string> requestedScopes,
            UserPlatformApplicationAccess userAccess)
        {
            if (userAccess.AccessLevel == ApplicationAccessLevel.Owner)
                return requestedScopes;

            var userScopes = DeserializeScopes(userAccess.Scopes);
            return requestedScopes.Where(s => userScopes.Contains(s)).ToList();
        }

        private Task<ApiKeyAccessControl> GetDefaultAccessControl(Guid organizationId, Guid applicationId)
        {
            return Task.FromResult(new ApiKeyAccessControl
            {
                AllowedIPs = new List<string> { "*" },
                AllowedDomains = new List<string> { "*" },
                AllowedOrigins = new List<string>(),
                RateLimitPerMinute = 60
            });
        }

        private async Task<bool> ValidateUserCanManageApiKey(Guid userId, PlatformApplicationApiKey apiKey)
        {
            if (apiKey.CreatedByConnectedId == userId)
                return true;

            var userAccess = await ValidateUserApplicationAccess(userId, apiKey.ApplicationId, ApplicationAccessLevel.Admin);
            return userAccess.HasAccess;
        }

        private async Task<bool> ValidateUserCanViewApiKey(Guid userId, PlatformApplicationApiKey apiKey)
        {
            if (apiKey.CreatedByConnectedId == userId)
                return true;

            var userAccess = await ValidateUserApplicationAccess(userId, apiKey.ApplicationId, ApplicationAccessLevel.User);
            return userAccess.HasAccess;
        }
        private async Task<ApiKeyUsageStatistics?> GetApiKeyUsageStatistics(Guid apiKeyId)
        {
            var apiKey = await _context.PlatformApplicationApiKeys.FindAsync(apiKeyId);
            if (apiKey == null)
                return null;

            // ApiKeyUsageStatistics 타입으로 반환 (InternalApiKeyUsageStatistics가 아님)
            return new ApiKeyUsageStatistics
            {
                ApiKeyId = apiKeyId,
                TotalUsage = apiKey.UseCount,
                LastUsedAt = apiKey.LastUsedAt,
                DailyUsage = new Dictionary<DateTime, int>(),  // TODO: 실제 일별 사용량 구현
                TopEndpoints = new List<EndpointUsage>(),       // TODO: 실제 엔드포인트 통계 구현
                TopIpAddresses = new List<string>               // TODO: 실제 IP 통계 구현
        {
            apiKey.LastUsedFromIP ?? "Unknown"
        },
                AverageResponseTime = 0  // TODO: 실제 응답 시간 구현
            };
        }

        private Task<List<ApiKeyRecentActivity>> GetApiKeyRecentActivities(Guid apiKeyId)
        {
            return Task.FromResult(new List<ApiKeyRecentActivity>());
        }

        #endregion

    }
}