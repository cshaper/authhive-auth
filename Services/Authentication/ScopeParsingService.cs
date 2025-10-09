using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Common;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Auth.Permissions.Cache;
using AuthHive.Core.Models.Auth.Permissions.Views;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 스코프 파싱 서비스 구현 - AuthHive v15
    /// Permission의 Scope 문자열을 파싱하고 분석하는 전용 서비스
    /// </summary>
    public class ScopeParsingService : IScopeParsingService
    {
        private readonly ICacheService _cacheService;
        private readonly IPermissionRepository _permissionRepository;
        private readonly ILogger<ScopeParsingService> _logger;

        // 스코프 패턴 정규식
        private static readonly Regex StandardScopePattern = new(@"^([a-zA-Z0-9_-]+:)*[a-zA-Z0-9_*-]+$", RegexOptions.Compiled);
        private static readonly Regex LegacyScopePattern = new(@"^([a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_*-]+$", RegexOptions.Compiled);
        private static readonly Regex ComponentPattern = new(@"^[a-zA-Z0-9_*-]+$", RegexOptions.Compiled);

        // 캐시 키 접두사
        private const string CacheKeyPrefix = "scope:parse:";
        private const string CacheStatPrefix = "scope:stats:";

        // 캐시 만료 시간
        private readonly TimeSpan _defaultCacheExpiration = TimeSpan.FromMinutes(30);
        private readonly TimeSpan _statsCacheExpiration = TimeSpan.FromHours(1);

        public ScopeParsingService(
            ICacheService cacheService,
            IPermissionRepository permissionRepository,
            ILogger<ScopeParsingService> logger)
        {
            _cacheService = cacheService;
            _permissionRepository = permissionRepository;
            _logger = logger;
        }

        #region IService Implementation

        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("ScopeParsingService initializing...");
                var commonScopes = new List<string>
                {
                    "user:read", "user:write", "user:*",
                    "organization:manage", "application:*"
                };
                await WarmupCacheAsync(commonScopes, cancellationToken);
                _logger.LogInformation("ScopeParsingService initialized successfully");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize ScopeParsingService");
                throw;
            }
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var testResult = await ValidateScopeAsync("test:read", cancellationToken);
                return testResult.IsSuccess;
            }
            catch (OperationCanceledException) { return false; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScopeParsingService health check failed");
                return false;
            }
        }

        #endregion

        #region Permission Scope 파싱

        public async Task<ServiceResult> PopulatePermissionScopeComponentsAsync(PermissionEntity permission, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(permission.Scope))
                {
                    return ServiceResult.Failure("Scope cannot be empty", "EMPTY_SCOPE");
                }

                var parseResult = await ParsePermissionScopeAsync(permission.Scope, cancellationToken);
                if (!parseResult.IsSuccess || parseResult.Data == null)
                {
                    return ServiceResult.Failure($"Failed to parse scope: {parseResult.ErrorMessage}", "PARSE_ERROR");
                }

                var components = parseResult.Data;

                permission.ScopeOrganization = components.Organization;
                permission.ScopeApplication = components.Application;
                permission.ScopeResource = components.Resource;
                permission.ScopeAction = components.Action;
                permission.HasWildcard = permission.Scope.Contains("*");
                permission.ScopeLevel = permission.Scope.Split(':').Length;
                permission.NormalizedScope = await NormalizeScopeInternalAsync(permission.Scope, cancellationToken);
                permission.ResourceType = components.Resource;
                permission.ActionType = components.Action;

                _logger.LogDebug($"Successfully populated scope components for permission: {permission.Scope}");
                return ServiceResult.Success("Scope components populated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error populating scope components for permission: {permission.Scope}");
                return ServiceResult.Failure("Failed to populate scope components", "POPULATE_ERROR");
            }
        }

        public Task<ServiceResult<ScopeComponents>> ParsePermissionScopeAsync(string permissionScope, CancellationToken cancellationToken = default)
        {
            try
            {
                var components = new ScopeComponents();

                if (string.IsNullOrWhiteSpace(permissionScope))
                {
                    components.IsValid = false;
                    components.ValidationErrors.Add("Scope cannot be empty");
                    return Task.FromResult(ServiceResult<ScopeComponents>.Success(components));
                }

                var parts = permissionScope.Split(':');

                if (parts.Length < 2)
                {
                    components.IsValid = false;
                    components.ValidationErrors.Add("Scope must contain at least resource and action");
                    return Task.FromResult(ServiceResult<ScopeComponents>.Success(components));
                }

                switch (parts.Length)
                {
                    case 2:
                        components.Resource = parts[0];
                        components.Action = parts[1];
                        break;
                    case 3:
                        if (IsOrganizationOrApplication(parts[0]))
                        {
                            components.Application = parts[0];
                            components.Resource = parts[1];
                            components.Action = parts[2];
                        }
                        else
                        {
                            components.Resource = $"{parts[0]}:{parts[1]}";
                            components.Action = parts[2];
                        }
                        break;
                    case 4:
                        components.Organization = parts[0];
                        components.Application = parts[1];
                        components.Resource = parts[2];
                        components.Action = parts[3];
                        break;
                    default:
                        components.Organization = parts[0];
                        components.Application = parts[1];
                        components.Resource = string.Join(":", parts.Skip(2).Take(parts.Length - 3));
                        components.Action = parts[^1];
                        break;
                }

                components.IsValid = ValidateComponents(components);
                return Task.FromResult(ServiceResult<ScopeComponents>.Success(components));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error parsing permission scope: {permissionScope}");
                return Task.FromResult(ServiceResult<ScopeComponents>.Failure("Failed to parse permission scope", "PARSE_ERROR"));
            }
        }

        public async Task<ServiceResult<List<ScopeComponents>>> ParseMultiplePermissionScopesAsync(List<string> permissionScopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var results = new List<ScopeComponents>();
                foreach (var scope in permissionScopes)
                {
                    var parseResult = await ParsePermissionScopeAsync(scope, cancellationToken);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        results.Add(parseResult.Data);
                    }
                    else
                    {
                        results.Add(new ScopeComponents
                        {
                            IsValid = false,
                            ValidationErrors = new List<string> { parseResult.ErrorMessage ?? "Parse failed" }
                        });
                    }
                }
                return ServiceResult<List<ScopeComponents>>.Success(results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing multiple permission scopes");
                return ServiceResult<List<ScopeComponents>>.Failure("Failed to parse multiple scopes", "BATCH_PARSE_ERROR");
            }
        }

        #endregion

        #region 런타임 스코프 파싱 및 분석

        public async Task<ServiceResult<ScopeParseResponse>> ParseScopeAsync(ScopeParseRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CacheKeyPrefix}{request.Scope}:{request.GetHashCode()}";
                var cachedResponse = await _cacheService.GetAsync<ScopeParseResponse>(cacheKey, cancellationToken);
                if (cachedResponse != null)
                {
                    _logger.LogDebug($"Cache hit for scope parsing: {request.Scope}");
                    return ServiceResult<ScopeParseResponse>.Success(cachedResponse);
                }

                var response = new ScopeParseResponse { OriginalScope = request.Scope, Success = true };
                var parts = request.Scope.Split(':');
                response.ParsedScope = new ParsedScope
                {
                    Components = parts.ToList(),
                    Depth = parts.Length,
                    DetectedStyle = DetectScopeStyle(request.Scope)
                };

                if (parts.Length >= 2)
                {
                    response.ParsedScope.ResourcePath = string.Join(":", parts.Take(parts.Length - 1));
                    response.ParsedScope.Action = parts[^1];
                }
                else
                {
                    response.ParsedScope.ResourcePath = request.Scope;
                    response.ParsedScope.Action = "*";
                }

                if (request.IncludeHierarchy) response.HierarchicalScopes = BuildHierarchy(parts);
                if (request.ResolveWildcards) response.WildcardResolution = await ResolveWildcardsAsync(request.Scope, cancellationToken);
                if (request.ValidateScope) response.Validation = await ValidateScopeInternalAsync(request.Scope, cancellationToken);

                await _cacheService.SetAsync(cacheKey, response, expiration: _defaultCacheExpiration, cancellationToken: cancellationToken);
                return ServiceResult<ScopeParseResponse>.Success(response);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning($"Scope parsing cancelled for: {request.Scope}");
                var canceledResponse = new ScopeParseResponse { Success = false, OriginalScope = request.Scope, ErrorMessage = "Scope parsing was cancelled.", ErrorCode = "CANCELLED" };
                return ServiceResult<ScopeParseResponse>.Success(canceledResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error parsing scope: {request.Scope}");
                var errorResponse = new ScopeParseResponse { Success = false, OriginalScope = request.Scope, ErrorMessage = ex.Message, ErrorCode = "PARSE_ERROR" };
                return ServiceResult<ScopeParseResponse>.Success(errorResponse);
            }
        }

        public Task<ServiceResult<bool>> ValidateScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(scope)) return Task.FromResult(ServiceResult<bool>.Success(false, "Scope cannot be empty"));
                if (!StandardScopePattern.IsMatch(scope) && !LegacyScopePattern.IsMatch(scope)) return Task.FromResult(ServiceResult<bool>.Success(false, "Invalid scope format"));

                var parts = scope.Contains(':') ? scope.Split(':') : scope.Split('.');
                foreach (var part in parts)
                {
                    if (!ComponentPattern.IsMatch(part)) return Task.FromResult(ServiceResult<bool>.Success(false, $"Invalid component: {part}"));
                }
                return Task.FromResult(ServiceResult<bool>.Success(true));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating scope: {scope}");
                return Task.FromResult(ServiceResult<bool>.Failure("Validation error", "VALIDATION_ERROR"));
            }
        }

        public async Task<ServiceResult<string>> NormalizeScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var normalized = await NormalizeScopeInternalAsync(scope, cancellationToken);
                return ServiceResult<string>.Success(normalized);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error normalizing scope: {scope}");
                return ServiceResult<string>.Failure("Normalization error", "NORMALIZE_ERROR");
            }
        }

        public Task<ServiceResult<ScopeHierarchy>> AnalyzeScopeHierarchyAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var parts = scope.Split(':');
                var hierarchy = new ScopeHierarchy
                {
                    Scopes = new List<string> { scope },
                    IsValid = true,
                    MaxDepthFound = parts.Length
                };

                var resource = parts[0];
                hierarchy.Tree = new Dictionary<string, List<string>> { [resource] = new List<string> { scope } };
                hierarchy.ScopesByDepth = new Dictionary<int, List<string>> { [parts.Length] = new List<string> { scope } };

                if (parts.Length > 1)
                {
                    var parentScope = string.Join(":", parts.Take(parts.Length - 1)) + ":*";
                    if (!hierarchy.Tree.ContainsKey(resource))
                    {
                        hierarchy.Tree[resource] = new List<string>();
                    }
                    hierarchy.Tree[resource].Add(parentScope);
                }

                if (!scope.EndsWith("*"))
                {
                    var childScopes = new List<string> { $"{scope}:*", $"{scope}:read", $"{scope}:write", $"{scope}:delete" };
                    hierarchy.Tree[resource].AddRange(childScopes);
                }

                return Task.FromResult(ServiceResult<ScopeHierarchy>.Success(hierarchy));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing scope hierarchy: {scope}");
                return Task.FromResult(ServiceResult<ScopeHierarchy>.Failure("Hierarchy analysis error", "HIERARCHY_ERROR"));
            }
        }

        #endregion

        #region 스코프 구성 요소 추출

        public async Task<ServiceResult<string?>> ExtractOrganizationFromScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var components = await DecomposeAsync(scope, cancellationToken);
                return ServiceResult<string?>.Success(components.IsSuccess && components.Data != null ? components.Data.Organization : null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting organization from scope: {scope}");
                return ServiceResult<string?>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        public async Task<ServiceResult<string?>> ExtractApplicationFromScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var components = await DecomposeAsync(scope, cancellationToken);
                return ServiceResult<string?>.Success(components.IsSuccess && components.Data != null ? components.Data.Application : null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting application from scope: {scope}");
                return ServiceResult<string?>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        public async Task<ServiceResult<string>> ExtractResourceFromScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var components = await DecomposeAsync(scope, cancellationToken);
                return ServiceResult<string>.Success(components.IsSuccess && components.Data != null ? components.Data.Resource : string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting resource from scope: {scope}");
                return ServiceResult<string>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        public async Task<ServiceResult<string>> ExtractActionFromScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var components = await DecomposeAsync(scope, cancellationToken);
                return ServiceResult<string>.Success(components.IsSuccess && components.Data != null ? components.Data.Action : string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting action from scope: {scope}");
                return ServiceResult<string>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        public async Task<ServiceResult<ScopeComponents>> DecomposeAsync(string scope, CancellationToken cancellationToken = default)
        {
            return await ParsePermissionScopeAsync(scope, cancellationToken);
        }

        #endregion

        #region 스코프 생성 및 변환

        public Task<ServiceResult<string>> BuildScopeAsync(string resource, string action, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(resource) || string.IsNullOrWhiteSpace(action))
                {
                    return Task.FromResult(ServiceResult<string>.Failure("Resource and action are required", "INVALID_PARAMS"));
                }
                var scope = $"{resource}:{action}";
                return Task.FromResult(ServiceResult<string>.Success(scope));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error building scope: {resource}:{action}");
                return Task.FromResult(ServiceResult<string>.Failure("Build error", "BUILD_ERROR"));
            }
        }

        public Task<ServiceResult<string>> BuildFullScopeAsync(string? organization, string? application, string resource, string action, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(resource) || string.IsNullOrWhiteSpace(action))
                {
                    return Task.FromResult(ServiceResult<string>.Failure("Resource and action are required", "INVALID_PARAMS"));
                }

                var parts = new List<string>();
                if (!string.IsNullOrWhiteSpace(organization)) parts.Add(organization);
                if (!string.IsNullOrWhiteSpace(application)) parts.Add(application);
                parts.Add(resource);
                parts.Add(action);

                var scope = string.Join(":", parts);
                return Task.FromResult(ServiceResult<string>.Success(scope));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error building full scope");
                return Task.FromResult(ServiceResult<string>.Failure("Build error", "BUILD_ERROR"));
            }
        }

        public Task<ServiceResult<string>> ConvertScopeFormatAsync(string scope, ScopeFormat targetFormat, CancellationToken cancellationToken = default)
        {
            try
            {
                string converted = scope;
                switch (targetFormat)
                {
                    case ScopeFormat.Standard:
                        converted = scope.Replace('.', ':').Replace('/', ':');
                        break;
                    case ScopeFormat.Legacy:
                        converted = scope.Replace(':', '.').Replace('/', '.');
                        break;
                    case ScopeFormat.Compact:
                        var compactParts = scope.Split(':');
                        if (compactParts.Length >= 2)
                        {
                            converted = $"{compactParts[0]}{compactParts[^1]}";
                        }
                        break;
                    case ScopeFormat.Hierarchical:
                        break;
                }
                return Task.FromResult(ServiceResult<string>.Success(converted));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error converting scope format: {scope}");
                return Task.FromResult(ServiceResult<string>.Failure("Conversion error", "CONVERT_ERROR"));
            }
        }

        #endregion

        #region 와일드카드 및 패턴 매칭

        public Task<ServiceResult<List<string>>> ExpandWildcardScopeAsync(string wildcardScope, CancellationToken cancellationToken = default)
        {
            try
            {
                var expanded = new List<string>();
                if (!wildcardScope.Contains("*"))
                {
                    expanded.Add(wildcardScope);
                    return Task.FromResult(ServiceResult<List<string>>.Success(expanded));
                }

                var standardActions = new[] { "read", "write", "delete", "update", "execute", "manage" };

                if (wildcardScope.EndsWith(":*"))
                {
                    var basePath = wildcardScope.Substring(0, wildcardScope.Length - 2);
                    foreach (var action in standardActions)
                    {
                        expanded.Add($"{basePath}:{action}");
                    }
                }
                else if (wildcardScope == "*")
                {
                    expanded.AddRange(new[] { "read", "write", "delete", "update", "execute" });
                }
                else
                {
                    var parts = wildcardScope.Split(':');
                    if (parts.Any(p => p == "*"))
                    {
                        expanded.Add(wildcardScope.Replace("*", "default"));
                        expanded.Add(wildcardScope.Replace("*", "primary"));
                        expanded.Add(wildcardScope.Replace("*", "secondary"));
                    }
                }
                return Task.FromResult(ServiceResult<List<string>>.Success(expanded));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error expanding wildcard scope: {wildcardScope}");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Expansion error", "EXPAND_ERROR"));
            }
        }

        public Task<ServiceResult<string>> CompressToWildcardAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!scopes.Any())
                {
                    return Task.FromResult(ServiceResult<string>.Failure("No scopes provided", "EMPTY_LIST"));
                }
                var commonPrefix = FindCommonPrefix(scopes);
                if (string.IsNullOrEmpty(commonPrefix))
                {
                    return Task.FromResult(ServiceResult<string>.Success("*"));
                }
                var resourceGroups = scopes.GroupBy(s =>
                {
                    var lastColon = s.LastIndexOf(':');
                    return Task.FromResult(lastColon > 0 ? s.Substring(0, lastColon) : s);
                });
                if (resourceGroups.Count() == 1)
                {
                    var resource = resourceGroups.First().Key;
                    return Task.FromResult(ServiceResult<string>.Success($"{resource}:*"));
                }
                return Task.FromResult(ServiceResult<string>.Success($"{commonPrefix}*"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compressing scopes to wildcard");
                return Task.FromResult(ServiceResult<string>.Failure("Compression error", "COMPRESS_ERROR"));
            }
        }

        public Task<ServiceResult<bool>> MatchesScopePatternAsync(string scope, string pattern, CancellationToken cancellationToken = default)
        {
            try
            {
                if (scope == pattern) return Task.FromResult(ServiceResult<bool>.Success(true));

                if (pattern.Contains("*"))
                {
                    var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                    var matches = Regex.IsMatch(scope, regexPattern);
                    return Task.FromResult(ServiceResult<bool>.Success(matches));
                }

                if (pattern.EndsWith(":*"))
                {
                    var basePattern = pattern.Substring(0, pattern.Length - 2);
                    if (scope.StartsWith(basePattern + ":"))
                    {
                        return Task.FromResult(ServiceResult<bool>.Success(true));
                    }
                }
                return Task.FromResult(ServiceResult<bool>.Success(false));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error matching scope pattern: {scope} against {pattern}");
                return Task.FromResult(ServiceResult<bool>.Failure("Pattern matching error", "MATCH_ERROR"));
            }
        }

        public Task<ServiceResult<List<string>>> MatchByRegexAsync(List<string> scopes, string regexPattern, CancellationToken cancellationToken = default)
        {
            try
            {
                var regex = new Regex(regexPattern, RegexOptions.Compiled);
                var matched = scopes.Where(s => regex.IsMatch(s)).ToList();
                return Task.FromResult(ServiceResult<List<string>>.Success(matched));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error matching scopes by regex: {regexPattern}");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Regex matching error", "REGEX_ERROR"));
            }
        }

        #endregion

        #region 스코프 비교 및 관계 분석

        public Task<ServiceResult<ScopeRelationType>> CompareScopesAsync(string scope1, string scope2, CancellationToken cancellationToken = default)
        {
            try
            {
                if (scope1 == scope2) return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Equal));

                var parts1 = scope1.Split(':');
                var parts2 = scope2.Split(':');

                if (IsParentChild(parts1, parts2)) return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.ParentChild));
                if (AreSiblings(parts1, parts2)) return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Sibling));
                if (IsAncestorDescendant(parts1, parts2)) return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.AncestorDescendant));

                return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Unrelated));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error comparing scopes: {scope1} and {scope2}");
                return Task.FromResult(ServiceResult<ScopeRelationType>.Failure("Comparison error", "COMPARE_ERROR"));
            }
        }

        public async Task<ServiceResult<bool>> ContainsScopeAsync(string containerScope, string targetScope, CancellationToken cancellationToken = default)
        {
            try
            {
                if (containerScope.Contains("*"))
                {
                    return await MatchesScopePatternAsync(targetScope, containerScope, cancellationToken);
                }
                if (targetScope.StartsWith(containerScope + ":"))
                {
                    return ServiceResult<bool>.Success(true);
                }
                return ServiceResult<bool>.Success(containerScope == targetScope);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking scope containment: {containerScope} contains {targetScope}");
                return ServiceResult<bool>.Failure("Containment check error", "CONTAIN_ERROR");
            }
        }

        public async Task<ServiceResult<List<ScopeConflict>>> DetectConflictsAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var conflicts = new List<ScopeConflict>();
                for (int i = 0; i < scopes.Count; i++)
                {
                    for (int j = i + 1; j < scopes.Count; j++)
                    {
                        var conflict = await DetectConflictBetween(scopes[i], scopes[j], cancellationToken);
                        if (conflict != null)
                        {
                            conflicts.Add(conflict);
                        }
                    }
                }
                return ServiceResult<List<ScopeConflict>>.Success(conflicts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting scope conflicts");
                return ServiceResult<List<ScopeConflict>>.Failure("Conflict detection error", "CONFLICT_ERROR");
            }
        }

        public Task<ServiceResult<List<string>>> PrioritizeScopesAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var prioritized = scopes
                    .OrderBy(s => s.Contains("*") ? 1 : 0)
                    .ThenBy(s => s.Split(':').Length)
                    .ThenBy(s => s)
                    .ToList();
                return Task.FromResult(ServiceResult<List<string>>.Success(prioritized));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error prioritizing scopes");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Prioritization error", "PRIORITY_ERROR"));
            }
        }

        #endregion

        #region 집합 연산

        public async Task<ServiceResult<List<string>>> MergeScopesAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var merged = new HashSet<string>();
                var toRemove = new HashSet<string>();
                foreach (var scope in scopes)
                {
                    bool isRedundant = false;
                    foreach (var existing in merged)
                    {
                        var containsResult = await ContainsScopeAsync(existing, scope, cancellationToken);
                        if (containsResult.IsSuccess && containsResult.Data)
                        {
                            isRedundant = true;
                            break;
                        }
                        containsResult = await ContainsScopeAsync(scope, existing, cancellationToken);
                        if (containsResult.IsSuccess && containsResult.Data)
                        {
                            toRemove.Add(existing);
                        }
                    }
                    if (!isRedundant)
                    {
                        merged.Add(scope);
                    }
                }
                foreach (var item in toRemove)
                {
                    merged.Remove(item);
                }
                return ServiceResult<List<string>>.Success(merged.ToList());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error merging scopes");
                return ServiceResult<List<string>>.Failure("Merge error", "MERGE_ERROR");
            }
        }

        public Task<ServiceResult<List<string>>> UnionScopesAsync(List<string> scopes1, List<string> scopes2, CancellationToken cancellationToken = default)
        {
            try
            {
                var union = scopes1.Union(scopes2).ToList();
                return Task.FromResult(ServiceResult<List<string>>.Success(union));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating scope union");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Union error", "UNION_ERROR"));
            }
        }

        public async Task<ServiceResult<List<string>>> CalculateMinimalScopeSetAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var mergedResult = await MergeScopesAsync(scopes, cancellationToken);
                if (!mergedResult.IsSuccess || mergedResult.Data == null)
                {
                    return mergedResult;
                }

                var minimal = new List<string>();
                var grouped = mergedResult.Data.GroupBy(s =>
                {
                    var lastColon = s.LastIndexOf(':');
                    return lastColon > 0 ? s.Substring(0, lastColon) : s;
                });

                foreach (var group in grouped)
                {
                    var items = group.ToList();
                    if (items.Count > 3)
                    {
                        minimal.Add($"{group.Key}:*");
                    }
                    else
                    {
                        minimal.AddRange(items);
                    }
                }
                return ServiceResult<List<string>>.Success(minimal);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating minimal scope set");
                return ServiceResult<List<string>>.Failure("Minimal set error", "MINIMAL_ERROR");
            }
        }

        #endregion

        #region 트리 구조 및 계층 분석

        public Task<ServiceResult<ScopeTree>> BuildScopeTreeAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var tree = new ScopeTree
                {
                    Root = new ScopeTreeNode { Value = "root", FullScope = "" }
                };

                foreach (var scope in scopes)
                {
                    var parts = scope.Split(':');
                    var currentNode = tree.Root;

                    for (int i = 0; i < parts.Length; i++)
                    {
                        var part = parts[i];
                        var fullPath = string.Join(":", parts.Take(i + 1));

                        var childNode = currentNode.Children.FirstOrDefault(c => c.Value == part);
                        if (childNode == null)
                        {
                            childNode = new ScopeTreeNode
                            {
                                Value = part,
                                FullScope = fullPath,
                                Depth = i + 1,
                                Parent = currentNode
                            };
                            currentNode.Children.Add(childNode);
                            tree.NodeMap[fullPath] = childNode;
                        }
                        currentNode = childNode;
                    }
                }

                tree.TotalNodes = CountNodes(tree.Root);
                tree.MaxDepth = CalculateMaxDepth(tree.Root);

                return Task.FromResult(ServiceResult<ScopeTree>.Success(tree));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error building scope tree");
                return Task.FromResult(ServiceResult<ScopeTree>.Failure("Tree build error", "TREE_ERROR"));
            }
        }

        public Task<ServiceResult<int>> CalculateScopeDepthAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var depth = scope.Split(':').Length;
                return Task.FromResult(ServiceResult<int>.Success(depth));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error calculating scope depth: {scope}");
                return Task.FromResult(ServiceResult<int>.Failure("Depth calculation error", "DEPTH_ERROR"));
            }
        }

        public Task<ServiceResult<string?>> GetParentScopeAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var lastColon = scope.LastIndexOf(':');
                if (lastColon <= 0)
                {
                    return Task.FromResult(ServiceResult<string?>.Success(null));
                }
                var parent = scope.Substring(0, lastColon) + ":*";
                return Task.FromResult(ServiceResult<string?>.Success(parent));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting parent scope: {scope}");
                return Task.FromResult(ServiceResult<string?>.Failure("Parent scope error", "PARENT_ERROR"));
            }
        }

        public Task<ServiceResult<List<string>>> GenerateChildScopesAsync(string parentScope, List<string> actions, CancellationToken cancellationToken = default)
        {
            try
            {
                var children = new List<string>();
                var basePath = parentScope.EndsWith(":*") ? parentScope.Substring(0, parentScope.Length - 2) : parentScope;

                foreach (var action in actions)
                {
                    children.Add($"{basePath}:{action}");
                }
                return Task.FromResult(ServiceResult<List<string>>.Success(children));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error generating child scopes: {parentScope}");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Child generation error", "CHILD_ERROR"));
            }
        }

        #endregion

        #region 검증 및 규칙
        public async Task<ServiceResult<bool>> ValidateOrganizationScopeRulesAsync(Guid organizationId, string scope, CancellationToken cancellationToken = default)
        {
            // TODO: 조직별 스코프 규칙 검증 로직 구현
            _logger.LogInformation("Validating organization-specific scope rules for {OrganizationId}", organizationId);
            // 기본 검증으로 대체합니다.
            return await ValidateScopeAsync(scope, cancellationToken);
        }

        public async Task<ServiceResult<bool>> ValidateApplicationScopeRulesAsync(Guid applicationId, string scope, CancellationToken cancellationToken = default)
        {
            // TODO: 애플리케이션별 스코프 규칙 검증 로직 구현
            _logger.LogInformation("Validating application-specific scope rules for {ApplicationId}", applicationId);
            // 기본 검증으로 대체합니다.
            return await ValidateScopeAsync(scope, cancellationToken);
        }
        public Task<ServiceResult<ScopeValidationResult>> ValidateNamingConventionAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = new ScopeValidationResult { IsValid = true };

                if (string.IsNullOrWhiteSpace(scope))
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope cannot be empty");
                    return Task.FromResult(ServiceResult<ScopeValidationResult>.Success(result));
                }
                if (scope.Length > 200)
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope exceeds maximum length of 200 characters");
                }
                if (!StandardScopePattern.IsMatch(scope))
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope does not match the required pattern");
                    result.Suggestions["format"] = "Use format: resource:action or org:app:resource:action";
                }

                var parts = scope.Split(':');
                foreach (var part in parts)
                {
                    if (part.Length == 0)
                    {
                        result.IsValid = false;
                        result.Errors.Add("Empty scope component found");
                    }
                    else if (!ComponentPattern.IsMatch(part))
                    {
                        result.IsValid = false;
                        result.Errors.Add($"Invalid component: {part}");
                        result.Warnings.Add($"Component '{part}' contains invalid characters");
                    }
                }

                if (parts.Length == 1)
                {
                    result.Warnings.Add("Single-part scope detected. Consider using resource:action format");
                }
                if (parts.Any(p => p.Length < 2))
                {
                    result.Warnings.Add("Very short scope components detected");
                }
                return Task.FromResult(ServiceResult<ScopeValidationResult>.Success(result));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating naming convention: {scope}");
                return Task.FromResult(ServiceResult<ScopeValidationResult>.Failure("Validation error", "VALIDATE_ERROR"));
            }
        }

        public async Task<ServiceResult<bool>> ValidatePermissionScopeConsistencyAsync(PermissionEntity permission, CancellationToken cancellationToken = default)
        {
            try
            {
                var parseResult = await ParsePermissionScopeAsync(permission.Scope, cancellationToken);
                if (!parseResult.IsSuccess || parseResult.Data == null)
                {
                    return ServiceResult<bool>.Success(false, "Failed to parse scope");
                }

                var components = parseResult.Data;
                bool isConsistent = true;
                var errors = new List<string>();

                if (permission.ScopeOrganization != components.Organization) { isConsistent = false; errors.Add($"Organization mismatch: {permission.ScopeOrganization} != {components.Organization}"); }
                if (permission.ScopeApplication != components.Application) { isConsistent = false; errors.Add($"Application mismatch: {permission.ScopeApplication} != {components.Application}"); }
                if (permission.ScopeResource != components.Resource) { isConsistent = false; errors.Add($"Resource mismatch: {permission.ScopeResource} != {components.Resource}"); }
                if (permission.ScopeAction != components.Action) { isConsistent = false; errors.Add($"Action mismatch: {permission.ScopeAction} != {components.Action}"); }

                if (!isConsistent)
                {
                    _logger.LogWarning($"Scope inconsistency detected for permission {permission.Id}: {string.Join(", ", errors)}");
                }

                return ServiceResult<bool>.Success(isConsistent, isConsistent ? null : string.Join("; ", errors));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating permission scope consistency: {permission.Id}");
                return ServiceResult<bool>.Failure("Consistency validation error", "CONSISTENCY_ERROR");
            }
        }

        #endregion

        #region 분석 및 최적화

        public Task<ServiceResult<ScopeUsageStatistics>> AnalyzeUsageAsync(List<string> scopes, DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var statistics = new ScopeUsageStatistics
                {
                    AnalyzedFrom = from ?? DateTime.UtcNow.AddMonths(-1),
                    AnalyzedTo = to ?? DateTime.UtcNow
                };

                foreach (var scope in scopes)
                {
                    statistics.UsageCount[scope] = statistics.UsageCount.GetValueOrDefault(scope, 0) + 1;
                }

                if (statistics.UsageCount.Any())
                {
                    statistics.MostUsedScope = statistics.UsageCount.OrderByDescending(kvp => kvp.Value).First().Key;
                    statistics.LeastUsedScope = statistics.UsageCount.OrderBy(kvp => kvp.Value).First().Key;
                    statistics.AverageUsage = statistics.UsageCount.Values.Average();
                }

                return Task.FromResult(ServiceResult<ScopeUsageStatistics>.Success(statistics));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing scope usage");
                return Task.FromResult(ServiceResult<ScopeUsageStatistics>.Failure("Usage analysis error", "USAGE_ERROR"));
            }
        }

        public async Task<ServiceResult<ScopeOptimizationSuggestions>> SuggestOptimizationsAsync(List<string> currentScopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var suggestions = new ScopeOptimizationSuggestions();

                var redundant = await FindRedundantScopesAsync(currentScopes, cancellationToken);
                if (redundant.IsSuccess && redundant.Data != null)
                {
                    suggestions.RedundantScopes = redundant.Data;
                }

                var resourceGroups = currentScopes.GroupBy(s =>
                {
                    var lastColon = s.LastIndexOf(':');
                    return lastColon > 0 ? s.Substring(0, lastColon) : s;
                });

                foreach (var group in resourceGroups.Where(g => g.Count() > 3))
                {
                    suggestions.SuggestedWildcards.Add($"{group.Key}:*");
                    suggestions.MergeRecommendations.Add(new ScopeMergeRecommendation
                    {
                        OriginalScopes = group.ToList(),
                        SuggestedScope = $"{group.Key}:*",
                        Reason = $"Can be simplified with wildcard (covers {group.Count()} scopes)"
                    });
                }

                suggestions.PotentialReduction = suggestions.RedundantScopes.Count + suggestions.MergeRecommendations.Sum(m => m.OriginalScopes.Count - 1);
                return ServiceResult<ScopeOptimizationSuggestions>.Success(suggestions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error suggesting scope optimizations");
                return ServiceResult<ScopeOptimizationSuggestions>.Failure("Optimization suggestion error", "OPTIMIZE_ERROR");
            }
        }

        public async Task<ServiceResult<List<string>>> FindRedundantScopesAsync(List<string> scopes, CancellationToken cancellationToken = default)
        {
            try
            {
                var redundant = new List<string>();
                for (int i = 0; i < scopes.Count; i++)
                {
                    for (int j = 0; j < scopes.Count; j++)
                    {
                        if (i == j) continue;
                        var containsResult = await ContainsScopeAsync(scopes[j], scopes[i], cancellationToken);
                        if (containsResult.IsSuccess && containsResult.Data && scopes[i] != scopes[j])
                        {
                            redundant.Add(scopes[i]);
                            break;
                        }
                    }
                }
                return ServiceResult<List<string>>.Success(redundant.Distinct().ToList());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error finding redundant scopes");
                return ServiceResult<List<string>>.Failure("Redundancy detection error", "REDUNDANT_ERROR");
            }
        }

        #endregion

        #region 캐싱 및 성능
        public Task<ServiceResult> ClearOrganizationScopeCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // TODO: 조직 ID를 포함하는 캐시 키를 찾아 삭제하는 로직 구현
            _logger.LogInformation("Clearing organization-specific scope cache for {OrganizationId}", organizationId);
            return Task.FromResult(ServiceResult.Success("Organization cache cleared"));
        }

        public Task<ServiceResult> OptimizeCacheAsync(CancellationToken cancellationToken = default)
        {
            // TODO: 오래되거나 사용 빈도가 낮은 캐시를 정리하는 로직 구현
            _logger.LogInformation("Cache optimization completed");
            return Task.FromResult(ServiceResult.Success("Cache optimized"));
        }

        public async Task<ServiceResult> CacheParsingResultAsync(string scope, ScopeParseResponse result, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CacheKeyPrefix}{scope}";
                await _cacheService.SetAsync(cacheKey, result, expiration: _defaultCacheExpiration, cancellationToken: cancellationToken);
                await UpdateCacheStatisticsAsync(scope, true, cancellationToken);
                return ServiceResult.Success("Cached successfully");
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning($"Caching parsing result cancelled for scope: {scope}");
                return ServiceResult.Failure("Cache operation cancelled", "CACHE_CANCELLED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error caching parsing result for scope: {scope}");
                return ServiceResult.Failure("Cache error", "CACHE_ERROR");
            }
        }

        public async Task<ServiceResult<ScopeParseResponse?>> GetCachedParsingResultAsync(string scope, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CacheKeyPrefix}{scope}";
                var cached = await _cacheService.GetAsync<ScopeParseResponse>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    await UpdateCacheStatisticsAsync(scope, true, cancellationToken);
                    return ServiceResult<ScopeParseResponse?>.Success(cached);
                }

                await UpdateCacheStatisticsAsync(scope, false, cancellationToken); // Corrected: should be 'false' for a cache miss
                return ServiceResult<ScopeParseResponse?>.Success(null);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning($"Getting cached parsing result cancelled for scope: {scope}");
                return ServiceResult<ScopeParseResponse?>.Success(null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting cached parsing result for scope: {scope}");
                return ServiceResult<ScopeParseResponse?>.Failure("Cache retrieval error", "CACHE_GET_ERROR");
            }
        }

        public Task<ServiceResult> ClearScopeParsingCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Scope parsing cache clear requested (Note: IMemoryCache doesn't support prefix-based clearing)");
                return Task.FromResult(ServiceResult.Success("Cache clear requested"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing scope parsing cache");
                return Task.FromResult(ServiceResult.Failure("Cache clear error", "CACHE_CLEAR_ERROR"));
            }
        }

        public async Task<ServiceResult<ScopeCacheStatistics>> GetCacheStatisticsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var stats = await _cacheService.GetAsync<ScopeCacheStatistics>(CacheStatPrefix, cancellationToken) ?? new ScopeCacheStatistics();
                return ServiceResult<ScopeCacheStatistics>.Success(stats);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Getting cache statistics cancelled.");
                return ServiceResult<ScopeCacheStatistics>.Success(new ScopeCacheStatistics());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting cache statistics");
                return ServiceResult<ScopeCacheStatistics>.Failure("Statistics retrieval error", "STATS_ERROR");
            }
        }

        public async Task<ServiceResult> WarmupCacheAsync(List<string> frequentScopes, CancellationToken cancellationToken = default)
        {
            try
            {
                int warmedUp = 0;
                foreach (var scope in frequentScopes)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var request = new ScopeParseRequest
                    {
                        Scope = scope,
                        IncludeHierarchy = true,
                        ValidateScope = true,
                        ResolveWildcards = scope.Contains("*")
                    };
                    var result = await ParseScopeAsync(request, cancellationToken);
                    if (result.IsSuccess)
                    {
                        warmedUp++;
                    }
                }
                _logger.LogInformation($"Cache warmed up with {warmedUp} scopes");
                return ServiceResult.Success($"Warmed up {warmedUp} scopes");
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Cache warm-up was cancelled.");
                return ServiceResult.Failure("Warmup cancelled", "WARMUP_CANCELLED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error warming up cache");
                return ServiceResult.Failure("Warmup error", "WARMUP_ERROR");
            }
        }

        #endregion

        #region Permission 연동

        public async Task<ServiceResult<ScopeMatrixView>> BuildPermissionScopeMatrixAsync(List<PermissionEntity> permissions, CancellationToken cancellationToken = default)
        {
            try
            {
                var matrix = new ScopeMatrixView { TotalPermissions = permissions.Count };
                var resourceSet = new HashSet<string>();
                var actionSet = new HashSet<string>();

                foreach (var permission in permissions)
                {
                    var parseResult = await ParsePermissionScopeAsync(permission.Scope, cancellationToken);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        var components = parseResult.Data;
                        resourceSet.Add(components.Resource);
                        actionSet.Add(components.Action);

                        if (!matrix.Matrix.ContainsKey(components.Resource))
                        {
                            matrix.Matrix[components.Resource] = new Dictionary<string, PermissionScopeInfo>();
                        }
                        matrix.Matrix[components.Resource][components.Action] = new PermissionScopeInfo
                        {
                            PermissionId = permission.Id,
                            Scope = permission.Scope,
                            Name = permission.Name,
                            IsActive = permission.IsActive,
                            HasWildcard = permission.HasWildcard
                        };
                    }
                }

                matrix.Resources = resourceSet.OrderBy(r => r).ToList();
                matrix.Actions = actionSet.OrderBy(a => a).ToList();

                return ServiceResult<ScopeMatrixView>.Success(matrix);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error building permission scope matrix");
                return ServiceResult<ScopeMatrixView>.Failure("Matrix build error", "MATRIX_ERROR");
            }
        }

        public async Task<ServiceResult> UpdatePermissionScopeComponentsAsync(PermissionEntity permission, string newScope, CancellationToken cancellationToken = default)
        {
            try
            {
                var validationResult = await ValidateScopeAsync(newScope, cancellationToken);
                if (!validationResult.IsSuccess || !validationResult.Data)
                {
                    return ServiceResult.Failure("Invalid new scope", "INVALID_SCOPE");
                }
                permission.Scope = newScope;
                return await PopulatePermissionScopeComponentsAsync(permission, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating permission scope components: {permission.Id}");
                return ServiceResult.Failure("Update error", "UPDATE_SCOPE_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationScopeAnalysis>> AnalyzeOrganizationScopesAsync(Guid organizationId, List<PermissionEntity> permissions, CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = new OrganizationScopeAnalysis { OrganizationId = organizationId };
                var resourceSet = new HashSet<string>();
                var actionSet = new HashSet<string>();

                foreach (var permission in permissions)
                {
                    var parseResult = await ParsePermissionScopeAsync(permission.Scope, cancellationToken);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        var components = parseResult.Data;
                        resourceSet.Add(components.Resource);
                        actionSet.Add(components.Action);

                        analysis.ResourceDistribution[components.Resource] = analysis.ResourceDistribution.GetValueOrDefault(components.Resource, 0) + 1;
                        analysis.ActionDistribution[components.Action] = analysis.ActionDistribution.GetValueOrDefault(components.Action, 0) + 1;

                        if (permission.Scope.Contains("*"))
                        {
                            analysis.WildcardScopes++;
                        }
                    }
                }

                analysis.TotalScopes = permissions.Count;
                analysis.UniqueResources = resourceSet.Count;
                analysis.UniqueActions = actionSet.Count;

                return ServiceResult<OrganizationScopeAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing organization scopes: {organizationId}");
                return ServiceResult<OrganizationScopeAnalysis>.Failure("Analysis error", "ANALYZE_ORG_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        private string DetectScopeStyle(string scope)
        {
            if (scope.Contains(':')) return "resource:action";
            if (scope.Contains('.')) return "legacy";
            if (scope.Split(':').Length > 3) return "hierarchical";
            return "custom";
        }

        private List<string> BuildHierarchy(string[] parts)
        {
            var hierarchy = new List<string>();
            for (int i = 1; i <= parts.Length; i++)
            {
                hierarchy.Add(string.Join(":", parts.Take(i)));
            }
            return hierarchy;
        }

        private async Task<WildcardResolution> ResolveWildcardsAsync(string scope, CancellationToken cancellationToken = default)
        {
            var resolution = new WildcardResolution { ContainsWildcard = scope.Contains("*") };
            if (resolution.ContainsWildcard)
            {
                var parts = scope.Split(':');
                resolution.WildcardPositions = new List<int>();
                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == "*") resolution.WildcardPositions.Add(i);
                }
                resolution.ImpactDescription = $"Wildcard at position(s): {string.Join(", ", resolution.WildcardPositions)}";

                var expandResult = await ExpandWildcardScopeAsync(scope, cancellationToken);
                if (expandResult.IsSuccess)
                {
                    resolution.MatchingPatterns = expandResult.Data;
                }
            }
            return resolution;
        }

        private Task<ScopeValidation> ValidateScopeInternalAsync(string scope, CancellationToken cancellationToken = default)
        {
            var validation = new ScopeValidation { IsValid = true, ValidationErrors = new List<string>() };
            validation.IsFormatValid = StandardScopePattern.IsMatch(scope);
            if (!validation.IsFormatValid)
            {
                validation.IsValid = false;
                validation.ValidationErrors.Add("Invalid scope format");
            }
            validation.ExistsInSystem = true; // Placeholder
            if (!validation.IsValid)
            {
                validation.SuggestedScopes = GenerateSuggestions(scope);
            }
            return Task.FromResult(validation);
        }

        private List<string> GenerateSuggestions(string scope)
        {
            var suggestions = new List<string>();
            if (!scope.Contains(':'))
            {
                suggestions.Add(scope.Replace('.', ':'));
                suggestions.Add(scope.Replace('-', ':'));
            }
            if (scope.Split(':').Length == 1)
            {
                suggestions.Add($"{scope}:read");
                suggestions.Add($"{scope}:write");
                suggestions.Add($"{scope}:*");
            }
            return suggestions;
        }

        private bool ValidateComponents(ScopeComponents components)
        {
            if (string.IsNullOrWhiteSpace(components.Resource) || string.IsNullOrWhiteSpace(components.Action))
            {
                components.ValidationErrors.Add("Resource and action are required");
                return false;
            }
            if (!ComponentPattern.IsMatch(components.Resource))
            {
                components.ValidationErrors.Add($"Invalid resource: {components.Resource}");
                return false;
            }
            if (!ComponentPattern.IsMatch(components.Action))
            {
                components.ValidationErrors.Add($"Invalid action: {components.Action}");
                return false;
            }
            return true;
        }

        private bool IsOrganizationOrApplication(string part)
        {
            return part.Length > 3 && !IsCommonAction(part) && !IsCommonResource(part);
        }

        private bool IsCommonAction(string part)
        {
            var commonActions = new[] { "read", "write", "delete", "update", "create", "manage", "execute", "view" };
            return commonActions.Contains(part.ToLower());
        }

        private bool IsCommonResource(string part)
        {
            var commonResources = new[] { "user", "users", "role", "roles", "permission", "permissions", "resource", "resources" };
            return commonResources.Contains(part.ToLower());
        }

        private string FindCommonPrefix(List<string> scopes)
        {
            if (!scopes.Any()) return string.Empty;
            var shortest = scopes.OrderBy(s => s.Length).First();
            for (int i = shortest.Length; i > 0; i--)
            {
                var prefix = shortest.Substring(0, i);
                if (scopes.All(s => s.StartsWith(prefix)))
                {
                    var lastColon = prefix.LastIndexOf(':');
                    if (lastColon > 0)
                    {
                        return prefix.Substring(0, lastColon + 1);
                    }
                    return prefix;
                }
            }
            return string.Empty;
        }

        private Task<string> NormalizeScopeInternalAsync(string scope, CancellationToken cancellationToken = default)
        {
            var normalized = scope.ToLower().Trim();
            normalized = Regex.Replace(normalized, ":+", ":");
            normalized = normalized.Trim(':');
            return Task.FromResult(normalized);
        }

        private bool IsParentChild(string[] parts1, string[] parts2)
        {
            if (Math.Abs(parts1.Length - parts2.Length) != 1) return false;
            var shorter = parts1.Length < parts2.Length ? parts1 : parts2;
            var longer = parts1.Length > parts2.Length ? parts1 : parts2;
            for (int i = 0; i < shorter.Length - 1; i++)
            {
                if (shorter[i] != longer[i]) return false;
            }
            return shorter[^1] == "*" || longer[^1] != "*";
        }

        private bool AreSiblings(string[] parts1, string[] parts2)
        {
            if (parts1.Length != parts2.Length || parts1.Length < 2) return false;
            for (int i = 0; i < parts1.Length - 1; i++)
            {
                if (parts1[i] != parts2[i]) return false;
            }
            return parts1[^1] != parts2[^1];
        }

        private bool IsAncestorDescendant(string[] parts1, string[] parts2)
        {
            var shorter = parts1.Length < parts2.Length ? parts1 : parts2;
            var longer = parts1.Length > parts2.Length ? parts1 : parts2;
            if (shorter.Length >= longer.Length) return false;
            for (int i = 0; i < shorter.Length - 1; i++)
            {
                if (shorter[i] != longer[i]) return false;
            }
            return shorter[^1] == "*";
        }

        private async Task<ScopeConflict?> DetectConflictBetween(string scope1, string scope2, CancellationToken cancellationToken = default)
        {
            if (scope1 == scope2)
            {
                return new ScopeConflict { Scope1 = scope1, Scope2 = scope2, Type = ScopeConflictType.Redundant, Description = "Duplicate scopes detected", Severity = ConflictSeverity.Medium, Resolution = "Remove one of the duplicate scopes" };
            }
            var contains1 = await ContainsScopeAsync(scope1, scope2, cancellationToken);
            if (contains1.IsSuccess && contains1.Data)
            {
                return new ScopeConflict { Scope1 = scope1, Scope2 = scope2, Type = ScopeConflictType.Overlap, Description = $"{scope1} contains {scope2}", Severity = ConflictSeverity.Low, Resolution = $"Consider removing {scope2} as it's covered by {scope1}" };
            }
            return null;
        }

        private async Task UpdateCacheStatisticsAsync(string scope, bool isHit, CancellationToken cancellationToken = default)
        {
            try
            {
                var stats = await _cacheService.GetAsync<ScopeCacheStatistics>(CacheStatPrefix, cancellationToken) ?? new ScopeCacheStatistics();
                if (isHit) stats.HitCount++; else stats.MissCount++;
                stats.TotalRequests++;
                stats.HitRate = (double)stats.HitCount / stats.TotalRequests;
                await _cacheService.SetAsync(CacheStatPrefix, stats, expiration: _statsCacheExpiration, cancellationToken: cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning($"UpdateCacheStatistics cancelled for scope: {scope}.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating cache statistics for scope: {scope}");
            }
        }

        private int CountNodes(ScopeTreeNode node)
        {
            return 1 + node.Children.Sum(child => CountNodes(child));
        }

        private int CalculateMaxDepth(ScopeTreeNode node)
        {
            if (!node.Children.Any())
                return node.Depth;
            return node.Children.Max(child => CalculateMaxDepth(child));
        }

        #endregion
    }
}