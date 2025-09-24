using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Proxy.Validator;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Interfaces.Infra.Cache;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Entities.PlatformApplications;

namespace AuthHive.Auth.Services.Authorization
{
    public class PermissionValidationService : IPermissionValidationService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IUserApplicationAccessRepository _accessRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IRoleService _roleService;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IOrganizationRouteValidator _orgValidator;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<PermissionValidationService> _logger;

        // Helper class for TTL cache data
        private class TtlCacheData
        {
            public int? Minutes { get; set; }
        }

        public PermissionValidationService(
            IUnitOfWork unitOfWork,
            IUserApplicationAccessRepository accessRepository,
            IOrganizationRepository organizationRepository,
            IRoleService roleService,
            ICacheService cacheService,
            IAuditService auditService,
            IOrganizationRouteValidator orgValidator,
            IDateTimeProvider dateTimeProvider,
            ILogger<PermissionValidationService> logger)
        {
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _accessRepository = accessRepository ?? throw new ArgumentNullException(nameof(accessRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _roleService = roleService ?? throw new ArgumentNullException(nameof(roleService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _orgValidator = orgValidator ?? throw new ArgumentNullException(nameof(orgValidator));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                var tasks = new List<Task<bool>>
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            await _roleService.GetPermissionsAsync(Guid.Empty, false);
                            return true;
                        }
                        catch { return false; }
                    }),
                    _cacheService.IsHealthyAsync(),
                    _auditService.IsHealthyAsync()
                };

                var results = await Task.WhenAll(tasks);
                return results.All(r => r);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PermissionValidationService health check failed");
                return false;
            }
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("PermissionValidationService initialized at {Time}",
                _dateTimeProvider.UtcNow);

            await WarmUpCacheAsync();
        }

        public async Task<ServiceResult<bool>> HasAllPermissionsAsync(PermissionValidationRequest request)
        {
            var validationResult = await ValidatePermissionsAsync(request);

            if (!validationResult.IsSuccess || validationResult.Data == null)
            {
                return ServiceResult<bool>.Failure(validationResult.ErrorMessage ?? "Validation failed");
            }

            return ServiceResult<bool>.Success(validationResult.Data.IsAllowed);
        }

        public async Task<ServiceResult<PermissionValidationResponse>> ValidatePermissionsAsync(
            PermissionValidationRequest request)
        {
            var stopwatch = Stopwatch.StartNew();
            var response = new PermissionValidationResponse
            {
                RequestId = request.RequestId ?? Guid.NewGuid().ToString(),
                CacheStatus = PermissionCacheStatus.Miss,
                ValidatedScopes = new List<ValidatedScope>(),
                AppliedRoles = new List<AppliedRole>()
            };

            try
            {
                var cacheKey = GenerateOrganizationScopedCacheKey(request);
                var cachedResponse = await _cacheService.GetAsync<PermissionValidationResponse>(cacheKey);

                if (cachedResponse != null)
                {
                    cachedResponse.CacheStatus = PermissionCacheStatus.Hit;
                    cachedResponse.ValidationDurationMs = stopwatch.ElapsedMilliseconds;

                    _logger.LogDebug("Permission cache hit for {ConnectedId} in org {OrgId}",
                        request.ConnectedId, request.OrganizationId);

                    return ServiceResult<PermissionValidationResponse>.Success(cachedResponse);
                }

                var orgValidation = await _orgValidator.ValidateOrganizationAccessAsync(
                    request.ConnectedId,
                    request.OrganizationId);

                if (!orgValidation.IsValid)
                {
                    await LogSecurityEventAsync(
                        AuditActionType.Blocked,
                        request.ConnectedId,
                        request.OrganizationId,
                        "Cross-tenant access attempt",
                        request);

                    response.IsAllowed = false;
                    response.ValidationResult = PermissionValidationResult.OrganizationScopeExceeded;
                    response.DenialReason = "Organization access denied";

                    FinalizeResponse(stopwatch, response);
                    return ServiceResult<PermissionValidationResponse>.Success(response);
                }

                var organization = await _organizationRepository.GetByIdAsync(request.OrganizationId);
                if (organization == null)
                {
                    response.IsAllowed = false;
                    response.ValidationResult = PermissionValidationResult.OrganizationScopeExceeded;
                    response.DenialReason = "Organization not found";

                    FinalizeResponse(stopwatch, response);
                    return ServiceResult<PermissionValidationResponse>.Success(response);
                }

                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    var accessInfo = await _accessRepository
                        .GetByConnectedIdApplicationAndOrganizationAsync(
                            request.ConnectedId,
                            request.ApplicationId ?? Guid.Empty,
                            request.OrganizationId);

                    if (accessInfo == null || !accessInfo.IsActive)
                    {
                        response.IsAllowed = false;
                        response.ValidationResult = PermissionValidationResult.ApplicationAccessDenied;
                        response.DenialReason = "User has no active access to the application in this organization";

                        await LogPermissionDenialAsync(request, response.DenialReason);
                        await _unitOfWork.SaveChangesAsync();
                        await _unitOfWork.CommitTransactionAsync();

                        FinalizeResponse(stopwatch, response);
                        return ServiceResult<PermissionValidationResponse>.Success(response);
                    }

                    var rolePermissions = new List<string>();
                    if (accessInfo.RoleId.HasValue)
                    {
                        var rolePermsResult = await GetRolePermissionsWithCacheAsync(
                            accessInfo.RoleId.Value,
                            request.OrganizationId,
                            request.IncludeInheritedPermissions);

                        if (rolePermsResult.IsSuccess && rolePermsResult.Data != null)
                        {
                            rolePermissions = rolePermsResult.Data.Select(p => p.Scope).ToList();
                            response.AppliedRoles.Add(new AppliedRole
                            {
                                RoleId = accessInfo.RoleId.Value,
                                RoleName = accessInfo.Role?.Name ?? "N/A"
                            });
                        }
                    }

                    var excludedPermissions = SafeDeserializePermissions(
                        accessInfo.ExcludedPermissions,
                        nameof(accessInfo.ExcludedPermissions),
                        accessInfo.Id);

                    var additionalPermissions = SafeDeserializePermissions(
                        accessInfo.AdditionalPermissions,
                        nameof(accessInfo.AdditionalPermissions),
                        accessInfo.Id);

                    var dynamicPermissions = ExtractDynamicPermissionsFromContext(request.RequestContext);

                    var planRestrictions = await GetPlanRestrictionsAsync(
                        organization.PricingTier,
                        request.OrganizationId);

                    foreach (var scope in request.Scopes)
                    {
                        if (IsScopeRestrictedByPlan(scope, planRestrictions))
                        {
                            response.ValidatedScopes.Add(new ValidatedScope
                            {
                                RequestedScope = scope,
                                IsAllowed = false,
                                PermissionSource = "PlanRestriction"
                            });
                            continue;
                        }

                        var waterfallResult = await ApplyPermissionWaterfallAsync(
                            scope,
                            accessInfo,
                            excludedPermissions,
                            additionalPermissions,
                            rolePermissions,
                            dynamicPermissions,
                            request.OrganizationId,
                            request.RequestContext);

                        response.ValidatedScopes.Add(new ValidatedScope
                        {
                            RequestedScope = scope,
                            IsAllowed = waterfallResult.Result == PermissionValidationResult.Granted,
                            PermissionSource = waterfallResult.Source
                        });
                    }

                    var firstDenial = response.ValidatedScopes.FirstOrDefault(s => !s.IsAllowed);
                    if (firstDenial != null)
                    {
                        response.IsAllowed = false;
                        response.ValidationResult = firstDenial.PermissionSource switch
                        {
                            "ExcludedPermissions" => PermissionValidationResult.PolicyViolation,
                            "PlanRestriction" => PermissionValidationResult.PlanLimitExceeded,
                            _ => PermissionValidationResult.NoPermission
                        };
                        response.DenialReason = $"Permission denied for scope: {firstDenial.RequestedScope} (Source: {firstDenial.PermissionSource})";

                        await LogPermissionDenialAsync(request, response.DenialReason);
                    }
                    else
                    {
                        response.IsAllowed = true;
                        response.ValidationResult = PermissionValidationResult.Granted;

                        await LogPermissionGrantAsync(request);
                    }

                    await _unitOfWork.SaveChangesAsync();
                    await _unitOfWork.CommitTransactionAsync();

                    var cacheTtl = await GetOrganizationCacheTTLAsync(request.OrganizationId);
                    await _cacheService.SetAsync(cacheKey, response, cacheTtl);
                }
                catch (Exception ex)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    _logger.LogError(ex, "Transaction failed during permission validation");
                    throw;
                }

                FinalizeResponse(stopwatch, response);
                return ServiceResult<PermissionValidationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Permission validation failed for ConnectedId {ConnectedId} in Org {OrgId}",
                    request.ConnectedId, request.OrganizationId);

                response.IsAllowed = false;
                response.ValidationResult = PermissionValidationResult.SystemError;
                response.DenialReason = "An unexpected error occurred during validation";
                response.CacheStatus = PermissionCacheStatus.Error;

                FinalizeResponse(stopwatch, response);
                return ServiceResult<PermissionValidationResponse>.FailureWithData(
                    "An unexpected error occurred", response);
            }
        }

        private async Task<(PermissionValidationResult Result, string Source)> ApplyPermissionWaterfallAsync(
            string requiredScope,
            UserPlatformApplicationAccess accessInfo,
            List<string> excludedPermissions,
            List<string> additionalPermissions,
            List<string> rolePermissions,
            List<string> dynamicPermissions,
            Guid organizationId,
            Dictionary<string, object>? requestContext)
        {
            if (excludedPermissions.Any(scope => ScopeMatches(requiredScope, scope)))
            {
                return (PermissionValidationResult.PolicyViolation, "ExcludedPermissions");
            }

            if (additionalPermissions.Any(scope => ScopeMatches(requiredScope, scope)))
            {
                return (PermissionValidationResult.Granted, "AdditionalPermissions");
            }

            if (dynamicPermissions.Any(scope => ScopeMatches(requiredScope, scope)))
            {
                return (PermissionValidationResult.Granted, "DynamicContext");
            }

            var orgCustomPermission = await EvaluateOrganizationCustomRulesAsync(
                requiredScope,
                organizationId,
                requestContext);

            if (orgCustomPermission)
            {
                return (PermissionValidationResult.Granted, "OrganizationCustomRule");
            }

            if (accessInfo.RoleId.HasValue)
            {
                if (rolePermissions.Any(scope => ScopeMatches(requiredScope, scope)))
                {
                    return (PermissionValidationResult.Granted, "Role");
                }
                else
                {
                    return (PermissionValidationResult.NoPermission, "Role (Denied)");
                }
            }

            if (accessInfo.AccessLevel == ApplicationAccessLevel.Admin ||
                accessInfo.AccessLevel == ApplicationAccessLevel.Owner)
            {
                return (PermissionValidationResult.Granted, "AccessLevel");
            }

            return (PermissionValidationResult.NoPermission, "None");
        }

        private bool ScopeMatches(string requiredScope, string userScope)
        {
            if (string.IsNullOrWhiteSpace(requiredScope) || string.IsNullOrWhiteSpace(userScope))
            {
                return false;
            }

            if (userScope == "*")
            {
                return true;
            }

            var requiredParts = requiredScope.Split(':');
            var userParts = userScope.Split(':');

            for (int i = 0; i < userParts.Length; i++)
            {
                if (userParts[i] == "*")
                {
                    return true;
                }

                if (i >= requiredParts.Length)
                {
                    return false;
                }

                if (!string.Equals(requiredParts[i], userParts[i], StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return requiredParts.Length == userParts.Length;
        }

        private List<string> SafeDeserializePermissions(string? jsonPermissions, string propertyName, Guid accessInfoId)
        {
            if (string.IsNullOrWhiteSpace(jsonPermissions))
            {
                return new List<string>();
            }

            try
            {
                return JsonSerializer.Deserialize<List<string>>(jsonPermissions) ?? new List<string>();
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to deserialize {PropertyName} for Access ID {AccessId}",
                    propertyName, accessInfoId);
                return new List<string>();
            }
        }

        private List<string> ExtractDynamicPermissionsFromContext(Dictionary<string, object>? requestContext)
        {
            if (requestContext == null)
            {
                return new List<string>();
            }

            var permissions = new List<string>();

            foreach (var kvp in requestContext)
            {
                var key = kvp.Key.ToLowerInvariant();

                if (key.Contains("permission") || key.Contains("scope") ||
                    key.Contains("access") || key.Contains("role"))
                {
                    permissions.AddRange(ParsePermissionValue(kvp.Value));
                }

                if (key.StartsWith("custom_") || key.StartsWith("x_"))
                {
                    var customPerms = ParsePermissionValue(kvp.Value);
                    if (customPerms.Any())
                    {
                        _logger.LogDebug("Found custom permissions in field {Field}: {Permissions}",
                            key, string.Join(", ", customPerms));
                        permissions.AddRange(customPerms);
                    }
                }
            }

            return permissions.Distinct().ToList();
        }

        private List<string> ParsePermissionValue(object value)
        {
            return value switch
            {
                List<string> list => list,
                string[] array => array.ToList(),
                string str when IsValidJson(str) => DeserializeJsonPermissions(str),
                string str when !string.IsNullOrWhiteSpace(str) => new List<string> { str },
                IEnumerable<object> enumerable => enumerable
                    .SelectMany(v => ParsePermissionValue(v))
                    .ToList(),
                _ => new List<string>()
            };
        }

        private bool IsValidJson(string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return false;

            str = str.Trim();
            return (str.StartsWith("{") && str.EndsWith("}")) ||
                   (str.StartsWith("[") && str.EndsWith("]"));
        }

        private List<string> DeserializeJsonPermissions(string json)
        {
            try
            {
                var array = JsonSerializer.Deserialize<List<string>>(json);
                if (array != null)
                    return array;

                var obj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                if (obj != null && obj.ContainsKey("permissions"))
                {
                    return JsonSerializer.Deserialize<List<string>>(obj["permissions"].GetRawText())
                           ?? new List<string>();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to deserialize JSON permissions: {Json}", json);
            }

            return new List<string>();
        }

        private async Task<bool> EvaluateOrganizationCustomRulesAsync(
            string requiredScope,
            Guid organizationId,
            Dictionary<string, object>? requestContext)
        {
            var cacheKey = $"org_custom_rules:{organizationId}";
            var customRules = await _cacheService.GetAsync<Dictionary<string, List<string>>>(cacheKey);

            if (customRules == null || requestContext == null)
            {
                return false;
            }

            foreach (var contextKey in requestContext.Keys)
            {
                if (customRules.ContainsKey(contextKey))
                {
                    var contextValue = requestContext[contextKey]?.ToString();
                    if (!string.IsNullOrEmpty(contextValue))
                    {
                        var allowedScopes = customRules[contextKey];
                        if (allowedScopes.Any(scope => ScopeMatches(requiredScope, scope)))
                        {
                            _logger.LogDebug("Custom rule matched for org {OrgId}: {Key}={Value} grants {Scope}",
                                organizationId, contextKey, contextValue, requiredScope);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private async Task<HashSet<string>> GetPlanRestrictionsAsync(string pricingTier, Guid organizationId)
        {
            var cacheKey = $"plan_restrictions:{pricingTier}:{organizationId}";
            var cached = await _cacheService.GetAsync<HashSet<string>>(cacheKey);

            if (cached != null)
            {
                return cached;
            }

            var restrictions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            switch (pricingTier?.ToLower())
            {
                case "free":
                    restrictions.Add("bulk:*");
                    restrictions.Add("export:*");
                    restrictions.Add("api:unlimited");
                    restrictions.Add("analytics:advanced");
                    restrictions.Add("integration:premium");
                    break;

                case "standard":
                    restrictions.Add("api:unlimited");
                    restrictions.Add("analytics:advanced");
                    restrictions.Add("integration:premium");
                    break;

                case "business":
                    restrictions.Add("integration:premium");
                    break;

                case "enterprise":
                    break;

                default:
                    restrictions.Add("bulk:*");
                    restrictions.Add("export:*");
                    restrictions.Add("api:*");
                    break;
            }

            await _cacheService.SetAsync(cacheKey, restrictions, TimeSpan.FromHours(1));
            return restrictions;
        }

        private bool IsScopeRestrictedByPlan(string scope, HashSet<string> planRestrictions)
        {
            return planRestrictions.Any(restriction => ScopeMatches(scope, restriction));
        }

        private async Task<ServiceResult<IEnumerable<PermissionDto>>> GetRolePermissionsWithCacheAsync(
            Guid roleId,
            Guid organizationId,
            bool includeInherited)
        {
            var cacheKey = $"role_perms:{organizationId}:{roleId}:{includeInherited}";
            var cached = await _cacheService.GetAsync<IEnumerable<PermissionDto>>(cacheKey);

            if (cached != null)
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Success(cached);
            }

            var result = await _roleService.GetPermissionsAsync(roleId, includeInherited);

            if (result.IsSuccess && result.Data != null)
            {
                await _cacheService.SetAsync(cacheKey, result.Data, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        private string GenerateOrganizationScopedCacheKey(PermissionValidationRequest request)
        {
            var keyBuilder = new StringBuilder();
            keyBuilder.Append($"perm:v3:{request.OrganizationId}");
            keyBuilder.Append($":{request.ConnectedId}");
            keyBuilder.Append($":{request.ApplicationId ?? Guid.Empty}");

            var scopeHash = string.Join(":", request.Scopes.OrderBy(s => s));
            keyBuilder.Append($":{GetStableHashCode(scopeHash)}");

            if (request.RequestContext != null && request.RequestContext.Any())
            {
                var contextJson = JsonSerializer.Serialize(request.RequestContext.OrderBy(kvp => kvp.Key));
                keyBuilder.Append($":{GetStableHashCode(contextJson)}");
            }
            else
            {
                keyBuilder.Append(":no-context");
            }

            return keyBuilder.ToString();
        }

        private string GetStableHashCode(string text)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
            return Convert.ToBase64String(hashBytes).Substring(0, 8);
        }

        private async Task<TimeSpan> GetOrganizationCacheTTLAsync(Guid organizationId)
        {
            var cacheKey = $"org_cache_ttl:{organizationId}";
            var ttlData = await _cacheService.GetAsync<TtlCacheData>(cacheKey);
            var ttlMinutes = ttlData?.Minutes;

            if (ttlMinutes.HasValue)
            {
                return TimeSpan.FromMinutes(ttlMinutes.Value);
            }

            var org = await _organizationRepository.GetByIdAsync(organizationId);
            return org?.PricingTier?.ToLower() switch
            {
                "enterprise" => TimeSpan.FromMinutes(30),
                "business" => TimeSpan.FromMinutes(15),
                "standard" => TimeSpan.FromMinutes(10),
                _ => TimeSpan.FromMinutes(5)
            };
        }

        private async Task WarmUpCacheAsync()
        {
            try
            {
                _logger.LogDebug("Warming up permission cache...");

                // 애플리케이션 시작 시 모든 요금제 등급에 대한 제한 사항을 미리 캐시에 로드합니다.
                // 이렇게 하면 첫 권한 요청 시 DB 조회 없이 캐시에서 바로 데이터를 가져올 수 있습니다.
                var pricingTiers = new[] { "free", "standard", "business", "enterprise" };

                var warmUpTasks = pricingTiers.Select(tier =>
                            GetPlanRestrictionsAsync(tier, Guid.Empty) // Guid.Empty는 조직 특정 제한이 아닌, 기본 템플릿을 의미합니다.
                        );

                // 모든 요금제의 캐싱 작업이 완료될 때까지 비동기적으로 기다립니다.
                await Task.WhenAll(warmUpTasks);

                _logger.LogInformation("Permission cache warmed up successfully for {Count} pricing tiers.", pricingTiers.Length);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to warm up permission cache");
            }
        }

        private async Task LogSecurityEventAsync(
            AuditActionType actionType,
            Guid connectedId,
            Guid organizationId,
            string details,
            object? additionalData)
        {
            await _auditService.LogAsync(new AuditLog
            {
                Id = Guid.NewGuid(),
                ActionType = actionType,
                Action = "PermissionValidation",
                PerformedByConnectedId = connectedId,
                TargetOrganizationId = organizationId,
                Timestamp = _dateTimeProvider.UtcNow,
                Success = false,
                Metadata = additionalData != null ? JsonSerializer.Serialize(additionalData) : null,
                Severity = AuditEventSeverity.Warning
            });
        }

        private async Task LogPermissionDenialAsync(PermissionValidationRequest request, string reason)
        {
            await LogSecurityEventAsync(
                AuditActionType.Blocked,
                request.ConnectedId,
                request.OrganizationId,
                $"Permission denied: {reason}",
                new
                {
                    request.Scopes,
                    request.ApplicationId,
                    Reason = reason,
                    RequestContext = request.RequestContext
                });
        }

        private async Task LogPermissionGrantAsync(PermissionValidationRequest request)
        {
            await _auditService.LogAsync(new AuditLog
            {
                Id = Guid.NewGuid(),
                ActionType = AuditActionType.Read,
                Action = "PermissionValidation",
                PerformedByConnectedId = request.ConnectedId,
                TargetOrganizationId = request.OrganizationId,
                Timestamp = _dateTimeProvider.UtcNow,
                Success = true,
                Metadata = JsonSerializer.Serialize(new
                {
                    request.Scopes,
                    request.ApplicationId
                }),
                Severity = AuditEventSeverity.Info
            });
        }

        private void FinalizeResponse(Stopwatch stopwatch, PermissionValidationResponse response)
        {
            stopwatch.Stop();
            response.ValidationDurationMs = stopwatch.ElapsedMilliseconds;
        }
    }
}