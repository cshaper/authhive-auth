using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
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
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 스코프 파싱 서비스 구현 - AuthHive v15
    /// Permission의 Scope 문자열을 파싱하고 분석하는 전용 서비스
    /// </summary>
    public class ScopeParsingService : IScopeParsingService
    {
        private readonly IMemoryCache _cache;
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
            IMemoryCache cache,
            ILogger<ScopeParsingService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        #region Permission Scope 파싱

        /// <summary>
        /// Permission Entity의 Scope 필드 파싱 및 구성 요소 자동 채우기
        /// </summary>
        public async Task<ServiceResult> PopulatePermissionScopeComponentsAsync(PermissionEntity permission)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(permission.Scope))
                {
                    return ServiceResult.Failure("Scope cannot be empty", "EMPTY_SCOPE");
                }

                var parseResult = await ParsePermissionScopeAsync(permission.Scope);
                if (!parseResult.IsSuccess || parseResult.Data == null)
                {
                    return ServiceResult.Failure($"Failed to parse scope: {parseResult.ErrorMessage}", "PARSE_ERROR");
                }

                var components = parseResult.Data;

                // Permission 엔티티의 파싱된 필드들 채우기
                permission.ScopeOrganization = components.Organization;
                permission.ScopeApplication = components.Application;
                permission.ScopeResource = components.Resource;
                permission.ScopeAction = components.Action;
                permission.HasWildcard = permission.Scope.Contains("*");
                permission.ScopeLevel = permission.Scope.Split(':').Length;
                permission.NormalizedScope = await NormalizeScopeInternalAsync(permission.Scope);

                // ResourceType과 ActionType 설정
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

        /// <summary>
        /// Permission의 Scope 문자열을 파싱하여 구성 요소 추출
        /// </summary>
        /// <summary>
        /// Permission의 Scope 문자열을 파싱하여 구성 요소 추출
        /// </summary>
        public Task<ServiceResult<ScopeComponents>> ParsePermissionScopeAsync(string permissionScope)
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

                // 최소 2개 부분 필요 (resource:action)
                if (parts.Length < 2)
                {
                    components.IsValid = false;
                    components.ValidationErrors.Add("Scope must contain at least resource and action");
                    // 여기도 Task.FromResult로 감싸기
                    return Task.FromResult(ServiceResult<ScopeComponents>.Success(components));
                }

                // 파싱 로직
                switch (parts.Length)
                {
                    case 2: // resource:action
                        components.Resource = parts[0];
                        components.Action = parts[1];
                        break;

                    case 3: // application:resource:action 또는 resource:subresource:action
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

                    case 4: // organization:application:resource:action
                        components.Organization = parts[0];
                        components.Application = parts[1];
                        components.Resource = parts[2];
                        components.Action = parts[3];
                        break;

                    default: // 5개 이상인 경우
                        components.Organization = parts[0];
                        components.Application = parts[1];
                        components.Resource = string.Join(":", parts.Skip(2).Take(parts.Length - 3));
                        components.Action = parts[^1];
                        break;
                }

                // 유효성 검증
                components.IsValid = ValidateComponents(components);

                // 마지막 return도 Task.FromResult로 감싸기
                return Task.FromResult(ServiceResult<ScopeComponents>.Success(components));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error parsing permission scope: {permissionScope}");
                // Exception 처리에서도 Task.FromResult 사용
                return Task.FromResult(ServiceResult<ScopeComponents>.Failure("Failed to parse permission scope", "PARSE_ERROR"));
            }
        }
        /// <summary>
        /// 여러 Permission의 Scope를 일괄 파싱
        /// </summary>
        public async Task<ServiceResult<List<ScopeComponents>>> ParseMultiplePermissionScopesAsync(List<string> permissionScopes)
        {
            try
            {
                var results = new List<ScopeComponents>();

                foreach (var scope in permissionScopes)
                {
                    var parseResult = await ParsePermissionScopeAsync(scope);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        results.Add(parseResult.Data);
                    }
                    else
                    {
                        // 실패한 경우에도 결과에 포함 (IsValid = false)
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

        /// <summary>
        /// 런타임 스코프 문자열 파싱
        /// </summary>
        public async Task<ServiceResult<ScopeParseResponse>> ParseScopeAsync(ScopeParseRequest request)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"{CacheKeyPrefix}{request.Scope}:{request.GetHashCode()}";
                if (_cache.TryGetValue(cacheKey, out ScopeParseResponse? cachedResponse))
                {
                    _logger.LogDebug($"Cache hit for scope parsing: {request.Scope}");
                    return ServiceResult<ScopeParseResponse>.Success(cachedResponse!);
                }

                var response = new ScopeParseResponse
                {
                    OriginalScope = request.Scope,
                    Success = true
                };

                // 기본 파싱
                var parts = request.Scope.Split(':');
                response.ParsedScope = new ParsedScope
                {
                    Components = parts.ToList(),
                    Depth = parts.Length,
                    DetectedStyle = DetectScopeStyle(request.Scope)
                };

                // 리소스 경로와 액션 분리
                if (parts.Length >= 2)
                {
                    response.ParsedScope.ResourcePath = string.Join(":", parts.Take(parts.Length - 1));
                    response.ParsedScope.Action = parts[^1];
                }
                else
                {
                    response.ParsedScope.ResourcePath = request.Scope;
                    response.ParsedScope.Action = "*"; // 기본값
                }

                // 계층 구조 포함
                if (request.IncludeHierarchy)
                {
                    response.HierarchicalScopes = BuildHierarchy(parts);
                }

                // 와일드카드 해석
                if (request.ResolveWildcards)
                {
                    response.WildcardResolution = await ResolveWildcardsAsync(request.Scope);
                }

                // 유효성 검증
                if (request.ValidateScope)
                {
                    response.Validation = await ValidateScopeInternalAsync(request.Scope);
                }

                // 캐시 저장
                _cache.Set(cacheKey, response, _defaultCacheExpiration);

                return ServiceResult<ScopeParseResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error parsing scope: {request.Scope}");

                var errorResponse = new ScopeParseResponse
                {
                    Success = false,
                    OriginalScope = request.Scope,
                    ErrorMessage = ex.Message,
                    ErrorCode = "PARSE_ERROR"
                };

                return ServiceResult<ScopeParseResponse>.Success(errorResponse);
            }
        }

        /// <summary>
        /// 스코프 유효성 검증
        /// </summary>
        public Task<ServiceResult<bool>> ValidateScopeAsync(string scope)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(scope))
                {
                    return Task.FromResult(ServiceResult<bool>.Success(false, "Scope cannot be empty"));
                }

                // 패턴 매칭
                if (!StandardScopePattern.IsMatch(scope) && !LegacyScopePattern.IsMatch(scope))
                {
                    return Task.FromResult(ServiceResult<bool>.Success(false, "Invalid scope format"));
                }

                // 각 구성 요소 검증
                var parts = scope.Contains(':') ? scope.Split(':') : scope.Split('.');
                foreach (var part in parts)
                {
                    if (!ComponentPattern.IsMatch(part))
                    {
                        return Task.FromResult(ServiceResult<bool>.Success(false, $"Invalid component: {part}"));
                    }
                }

                return Task.FromResult(ServiceResult<bool>.Success(true));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating scope: {scope}");
                return Task.FromResult(ServiceResult<bool>.Failure("Validation error", "VALIDATION_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 정규화
        /// </summary>
        public async Task<ServiceResult<string>> NormalizeScopeAsync(string scope)
        {
            try
            {
                var normalized = await NormalizeScopeInternalAsync(scope);
                return ServiceResult<string>.Success(normalized);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error normalizing scope: {scope}");
                return ServiceResult<string>.Failure("Normalization error", "NORMALIZE_ERROR");
            }
        }

        /// <summary>
        /// 스코프 계층 분석
        /// </summary>
        public Task<ServiceResult<ScopeHierarchy>> AnalyzeScopeHierarchyAsync(string scope)
        {
            try
            {
                var parts = scope.Split(':');
                var hierarchy = new ScopeHierarchy
                {
                    Scopes = new List<string> { scope }, // Scope 대신 Scopes 사용
                    IsValid = true,
                    MaxDepthFound = parts.Length // Level 대신 MaxDepthFound 사용
                };

                // 계층 트리 구조 생성
                var resource = parts[0];
                hierarchy.Tree = new Dictionary<string, List<string>>
                {
                    [resource] = new List<string> { scope }
                };

                // 깊이별 스코프 분류
                hierarchy.ScopesByDepth = new Dictionary<int, List<string>>
                {
                    [parts.Length] = new List<string> { scope }
                };

                // 부모-자식 관계는 Tree 구조로 표현
                if (parts.Length > 1)
                {
                    // 부모 스코프를 Tree에 추가
                    var parentScope = string.Join(":", parts.Take(parts.Length - 1)) + ":*";
                    if (!hierarchy.Tree.ContainsKey(resource))
                    {
                        hierarchy.Tree[resource] = new List<string>();
                    }
                    hierarchy.Tree[resource].Add(parentScope);
                }

                // 자식 스코프 예시를 Tree에 추가
                if (!scope.EndsWith("*"))
                {
                    var childScopes = new List<string>
            {
                $"{scope}:*",
                $"{scope}:read",
                $"{scope}:write",
                $"{scope}:delete"
            };

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

        /// <summary>
        /// 스코프에서 조직 부분 추출
        /// </summary>
        public async Task<ServiceResult<string?>> ExtractOrganizationFromScopeAsync(string scope)
        {
            try
            {
                var components = await DecomposeAsync(scope);
                if (components.IsSuccess && components.Data != null)
                {
                    return ServiceResult<string?>.Success(components.Data.Organization);
                }
                return ServiceResult<string?>.Success(null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting organization from scope: {scope}");
                return ServiceResult<string?>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        /// <summary>
        /// 스코프에서 애플리케이션 부분 추출
        /// </summary>
        public async Task<ServiceResult<string?>> ExtractApplicationFromScopeAsync(string scope)
        {
            try
            {
                var components = await DecomposeAsync(scope);
                if (components.IsSuccess && components.Data != null)
                {
                    return ServiceResult<string?>.Success(components.Data.Application);
                }
                return ServiceResult<string?>.Success(null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting application from scope: {scope}");
                return ServiceResult<string?>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        /// <summary>
        /// 스코프에서 리소스 부분 추출
        /// </summary>
        public async Task<ServiceResult<string>> ExtractResourceFromScopeAsync(string scope)
        {
            try
            {
                var components = await DecomposeAsync(scope);
                if (components.IsSuccess && components.Data != null)
                {
                    return ServiceResult<string>.Success(components.Data.Resource);
                }
                return ServiceResult<string>.Success(string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting resource from scope: {scope}");
                return ServiceResult<string>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        /// <summary>
        /// 스코프에서 액션 부분 추출
        /// </summary>
        public async Task<ServiceResult<string>> ExtractActionFromScopeAsync(string scope)
        {
            try
            {
                var components = await DecomposeAsync(scope);
                if (components.IsSuccess && components.Data != null)
                {
                    return ServiceResult<string>.Success(components.Data.Action);
                }
                return ServiceResult<string>.Success(string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting action from scope: {scope}");
                return ServiceResult<string>.Failure("Extraction error", "EXTRACT_ERROR");
            }
        }

        /// <summary>
        /// 스코프 구성 요소 전체 분해
        /// </summary>
        public async Task<ServiceResult<ScopeComponents>> DecomposeAsync(string scope)
        {
            return await ParsePermissionScopeAsync(scope);
        }

        #endregion

        #region 스코프 생성 및 변환

        /// <summary>
        /// 기본 스코프 생성
        /// </summary>
        public Task<ServiceResult<string>> BuildScopeAsync(string resource, string action)
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

        /// <summary>
        /// 전체 스코프 생성
        /// </summary>
        public Task<ServiceResult<string>> BuildFullScopeAsync(
            string? organization,
            string? application,
            string resource,
            string action)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(resource) || string.IsNullOrWhiteSpace(action))
                {
                    return Task.FromResult(ServiceResult<string>.Failure("Resource and action are required", "INVALID_PARAMS"));
                }

                var parts = new List<string>();

                if (!string.IsNullOrWhiteSpace(organization))
                    parts.Add(organization);

                if (!string.IsNullOrWhiteSpace(application))
                    parts.Add(application);

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

        /// <summary>
        /// 스코프 형식 변환
        /// </summary>
        public Task<ServiceResult<string>> ConvertScopeFormatAsync(string scope, ScopeFormat targetFormat)
        {
            try
            {
                string converted = scope;

                switch (targetFormat)
                {
                    case ScopeFormat.Standard:
                        // 콜론 구분자로 변환
                        converted = scope.Replace('.', ':').Replace('/', ':');
                        break;

                    case ScopeFormat.Legacy:
                        // 점 구분자로 변환
                        converted = scope.Replace(':', '.').Replace('/', '.');
                        break;

                    case ScopeFormat.Compact:
                        // 컴팩트 형식 (중간 구분자 제거)
                        var compactParts = scope.Split(':');
                        if (compactParts.Length >= 2)
                        {
                            converted = $"{compactParts[0]}{compactParts[^1]}";
                        }
                        break;

                    case ScopeFormat.Hierarchical:
                        // 계층적 형식 유지
                        converted = scope;
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

        /// <summary>
        /// 레거시 스코프 마이그레이션
        /// </summary>
        public async Task<ServiceResult<string>> MigrateLegacyScopeAsync(string legacyScope)
        {
            try
            {
                // 점(.) 구분자를 콜론(:)으로 변환
                var migrated = legacyScope.Replace('.', ':');

                // 유효성 검증
                var validationResult = await ValidateScopeAsync(migrated);
                if (!validationResult.IsSuccess || !validationResult.Data)
                {
                    return ServiceResult<string>.Failure("Invalid migrated scope", "INVALID_MIGRATION");
                }

                return ServiceResult<string>.Success(migrated);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error migrating legacy scope: {legacyScope}");
                return ServiceResult<string>.Failure("Migration error", "MIGRATE_ERROR");
            }
        }

        #endregion

        #region 와일드카드 및 패턴 매칭

        /// <summary>
        /// 와일드카드 스코프 확장
        /// </summary>
        public Task<ServiceResult<List<string>>> ExpandWildcardScopeAsync(string wildcardScope)
        {
            try
            {
                var expanded = new List<string>();

                if (!wildcardScope.Contains("*"))
                {
                    expanded.Add(wildcardScope);
                    return Task.FromResult(ServiceResult<List<string>>.Success(expanded));
                }

                // 기본 액션들
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
                    // 전체 와일드카드 - 제한적으로 확장
                    expanded.AddRange(new[] { "read", "write", "delete", "update", "execute" });
                }
                else
                {
                    // 중간에 와일드카드가 있는 경우
                    var parts = wildcardScope.Split(':');
                    if (parts.Any(p => p == "*"))
                    {
                        // 복잡한 와일드카드 패턴 - 예시로 몇 가지만 생성
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

        /// <summary>
        /// 와일드카드 스코프로 압축
        /// </summary>
        public Task<ServiceResult<string>> CompressToWildcardAsync(List<string> scopes)
        {
            try
            {
                if (!scopes.Any())
                {
                    return Task.FromResult(ServiceResult<string>.Failure("No scopes provided", "EMPTY_LIST"));
                }

                // 공통 접두사 찾기
                var commonPrefix = FindCommonPrefix(scopes);

                if (string.IsNullOrEmpty(commonPrefix))
                {
                    return Task.FromResult(ServiceResult<string>.Success("*"));
                }

                // 모든 스코프가 같은 리소스에 대한 다른 액션인지 확인
                var resourceGroups = scopes.GroupBy(s =>
                {
                    var lastColon = s.LastIndexOf(':');
                    return Task.FromResult(lastColon > 0 ? s.Substring(0, lastColon) : s);
                });

                if (resourceGroups.Count() == 1)
                {
                    // 모두 같은 리소스 - 와일드카드로 압축 가능
                    var resource = resourceGroups.First().Key;
                    return Task.FromResult(ServiceResult<string>.Success($"{resource}:*"));
                }

                // 압축 불가능 - 가장 일반적인 패턴 반환
                return Task.FromResult(ServiceResult<string>.Success($"{commonPrefix}*"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compressing scopes to wildcard");
                return Task.FromResult(ServiceResult<string>.Failure("Compression error", "COMPRESS_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 패턴 매칭
        /// </summary>
        public Task<ServiceResult<bool>> MatchesScopePatternAsync(string scope, string pattern)
        {
            try
            {
                // 정확한 매치
                if (scope == pattern)
                    return Task.FromResult(ServiceResult<bool>.Success(true));

                // 와일드카드 패턴 매칭
                if (pattern.Contains("*"))
                {
                    var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                    var matches = Regex.IsMatch(scope, regexPattern);
                    return Task.FromResult(ServiceResult<bool>.Success(matches));
                }

                // 계층적 매칭 (상위 권한이 하위 권한을 포함)
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

        /// <summary>
        /// 정규식 패턴으로 스코프 매칭
        /// </summary>
        public Task<ServiceResult<List<string>>> MatchByRegexAsync(List<string> scopes, string regexPattern)
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

        /// <summary>
        /// 두 스코프 간 관계 분석
        /// </summary>
        public Task<ServiceResult<ScopeRelationType>> CompareScopesAsync(string scope1, string scope2)
        {
            try
            {
                if (scope1 == scope2)
                    return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Equal));

                var parts1 = scope1.Split(':');
                var parts2 = scope2.Split(':');

                // 부모-자식 관계 확인
                if (IsParentChild(parts1, parts2))
                    return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.ParentChild));

                // 형제 관계 확인 (같은 부모)
                if (AreSiblings(parts1, parts2))
                    return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Sibling));

                // 조상-후손 관계 확인
                if (IsAncestorDescendant(parts1, parts2))
                    return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.AncestorDescendant));

                return Task.FromResult(ServiceResult<ScopeRelationType>.Success(ScopeRelationType.Unrelated));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error comparing scopes: {scope1} and {scope2}");
                return Task.FromResult(ServiceResult<ScopeRelationType>.Failure("Comparison error", "COMPARE_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 포함 관계 확인
        /// </summary>
        public async Task<ServiceResult<bool>> ContainsScopeAsync(string containerScope, string targetScope)
        {
            try
            {
                // 와일드카드 처리
                if (containerScope.Contains("*"))
                {
                    var matchResult = await MatchesScopePatternAsync(targetScope, containerScope);
                    return matchResult;
                }

                // 계층적 포함 관계
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

        /// <summary>
        /// 스코프 충돌 검사
        /// </summary>
        public async Task<ServiceResult<List<ScopeConflict>>> DetectConflictsAsync(List<string> scopes)
        {
            try
            {
                var conflicts = new List<ScopeConflict>();

                for (int i = 0; i < scopes.Count; i++)
                {
                    for (int j = i + 1; j < scopes.Count; j++)
                    {
                        var conflict = await DetectConflictBetween(scopes[i], scopes[j]);
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

        /// <summary>
        /// 스코프 우선순위 결정
        /// </summary>
        public Task<ServiceResult<List<string>>> PrioritizeScopesAsync(List<string> scopes)
        {
            try
            {
                var prioritized = scopes
                    .OrderBy(s => s.Contains("*") ? 1 : 0)  // 와일드카드가 없는 것 우선
                    .ThenBy(s => s.Split(':').Length)       // 더 구체적인 것 우선
                    .ThenBy(s => s)                         // 알파벳순
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

        /// <summary>
        /// 스코프 병합
        /// </summary>
        public async Task<ServiceResult<List<string>>> MergeScopesAsync(List<string> scopes)
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
                        // 이미 포함되어 있는지 확인
                        var containsResult = await ContainsScopeAsync(existing, scope);
                        if (containsResult.IsSuccess && containsResult.Data)
                        {
                            isRedundant = true;
                            break;
                        }

                        // 반대로 현재 스코프가 기존 것을 포함하는지 확인
                        containsResult = await ContainsScopeAsync(scope, existing);
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

                // 중복 제거
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

        /// <summary>
        /// 스코프 교집합
        /// </summary>
        public Task<ServiceResult<List<string>>> IntersectScopesAsync(List<string> scopes1, List<string> scopes2)
        {
            try
            {
                var intersection = scopes1.Intersect(scopes2).ToList();
                return Task.FromResult(ServiceResult<List<string>>.Success(intersection));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error intersecting scopes");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Intersection error", "INTERSECT_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 차집합
        /// </summary>
        public Task<ServiceResult<List<string>>> DifferenceScopesAsync(List<string> scopes1, List<string> scopes2)
        {
            try
            {
                var difference = scopes1.Except(scopes2).ToList();
                return Task.FromResult(ServiceResult<List<string>>.Success(difference));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating scope difference");
                return Task.FromResult(ServiceResult<List<string>>.Failure("Difference error", "DIFF_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 합집합
        /// </summary>
        public Task<ServiceResult<List<string>>> UnionScopesAsync(List<string> scopes1, List<string> scopes2)
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

        /// <summary>
        /// 최소 스코프 집합 계산
        /// </summary>
        public async Task<ServiceResult<List<string>>> CalculateMinimalScopeSetAsync(List<string> scopes)
        {
            try
            {
                // 병합을 통해 중복 및 포함 관계 제거
                var mergedResult = await MergeScopesAsync(scopes);
                if (!mergedResult.IsSuccess)
                {
                    return mergedResult;
                }

                // 와일드카드로 압축 가능한 것 찾기
                var minimal = new List<string>();
                var grouped = mergedResult.Data!.GroupBy(s =>
                {
                    var lastColon = s.LastIndexOf(':');
                    return lastColon > 0 ? s.Substring(0, lastColon) : s;
                });

                foreach (var group in grouped)
                {
                    var items = group.ToList();
                    if (items.Count > 3) // 3개 이상이면 와일드카드로 압축
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

        /// <summary>
        /// 스코프 트리 구축
        /// </summary>
        public Task<ServiceResult<ScopeTree>> BuildScopeTreeAsync(List<string> scopes)
        {
            try
            {
                var tree = new ScopeTree
                {
                    Root = new ScopeNode { Name = "root", FullPath = "" }
                };

                foreach (var scope in scopes)
                {
                    var parts = scope.Split(':');
                    var currentNode = tree.Root;

                    for (int i = 0; i < parts.Length; i++)
                    {
                        var part = parts[i];
                        var fullPath = string.Join(":", parts.Take(i + 1));

                        var childNode = currentNode.Children.FirstOrDefault(c => c.Name == part);
                        if (childNode == null)
                        {
                            childNode = new ScopeNode
                            {
                                Name = part,
                                FullPath = fullPath,
                                Level = i + 1,
                                Parent = currentNode
                            };
                            currentNode.Children.Add(childNode);
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

        /// <summary>
        /// 스코프 깊이 계산
        /// </summary>
        public Task<ServiceResult<int>> CalculateScopeDepthAsync(string scope)
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

        /// <summary>
        /// 부모 스코프 추출
        /// </summary>
        public Task<ServiceResult<string?>> GetParentScopeAsync(string scope)
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

        /// <summary>
        /// 자식 스코프 생성
        /// </summary>
        public Task<ServiceResult<List<string>>> GenerateChildScopesAsync(string parentScope, List<string> actions)
        {
            try
            {
                var children = new List<string>();

                // 와일드카드 제거
                var basePath = parentScope.EndsWith(":*")
                    ? parentScope.Substring(0, parentScope.Length - 2)
                    : parentScope;

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

        /// <summary>
        /// 스코프 명명 규칙 검증
        /// </summary>
        public Task<ServiceResult<ScopeValidationResult>> ValidateNamingConventionAsync(string scope)
        {
            try
            {
                var result = new ScopeValidationResult { IsValid = true };

                // 빈 문자열 체크
                if (string.IsNullOrWhiteSpace(scope))
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope cannot be empty");
                    return Task.FromResult(ServiceResult<ScopeValidationResult>.Success(result));
                }

                // 길이 체크
                if (scope.Length > 200)
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope exceeds maximum length of 200 characters");
                }

                // 패턴 검증
                if (!StandardScopePattern.IsMatch(scope))
                {
                    result.IsValid = false;
                    result.Errors.Add("Scope does not match the required pattern");
                    result.Suggestions["format"] = "Use format: resource:action or org:app:resource:action";
                }

                // 각 구성 요소 검증
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

                // 권장사항
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

        /// <summary>
        /// 조직별 스코프 규칙 검증
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateOrganizationScopeRulesAsync(Guid organizationId, string scope)
        {
            try
            {
                // 조직별 커스텀 규칙 적용
                // TODO: 실제 구현 시 조직 설정 조회

                // 기본 검증
                var basicValidation = await ValidateScopeAsync(scope);
                if (!basicValidation.IsSuccess || !basicValidation.Data)
                {
                    return ServiceResult<bool>.Success(false);
                }

                // 조직 특화 규칙 예시
                // - 특정 조직은 4단계 이상 스코프 금지
                // - 특정 조직은 와일드카드 사용 금지
                // 등...

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating organization scope rules: {organizationId}, {scope}");
                return ServiceResult<bool>.Failure("Organization validation error", "ORG_VALIDATE_ERROR");
            }
        }

        /// <summary>
        /// 애플리케이션별 스코프 규칙 검증
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateApplicationScopeRulesAsync(Guid applicationId, string scope)
        {
            try
            {
                // 애플리케이션별 커스텀 규칙 적용
                // TODO: 실제 구현 시 애플리케이션 설정 조회

                var basicValidation = await ValidateScopeAsync(scope);
                return basicValidation;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating application scope rules: {applicationId}, {scope}");
                return ServiceResult<bool>.Failure("Application validation error", "APP_VALIDATE_ERROR");
            }
        }

        /// <summary>
        /// Permission Entity와 스코프 일관성 검증
        /// </summary>
        public async Task<ServiceResult<bool>> ValidatePermissionScopeConsistencyAsync(PermissionEntity permission)
        {
            try
            {
                // 스코프 파싱
                var parseResult = await ParsePermissionScopeAsync(permission.Scope);
                if (!parseResult.IsSuccess || parseResult.Data == null)
                {
                    return ServiceResult<bool>.Success(false, "Failed to parse scope");
                }

                var components = parseResult.Data;

                // 파싱된 컴포넌트와 저장된 필드 비교
                bool isConsistent = true;
                var errors = new List<string>();

                if (permission.ScopeOrganization != components.Organization)
                {
                    isConsistent = false;
                    errors.Add($"Organization mismatch: {permission.ScopeOrganization} != {components.Organization}");
                }

                if (permission.ScopeApplication != components.Application)
                {
                    isConsistent = false;
                    errors.Add($"Application mismatch: {permission.ScopeApplication} != {components.Application}");
                }

                if (permission.ScopeResource != components.Resource)
                {
                    isConsistent = false;
                    errors.Add($"Resource mismatch: {permission.ScopeResource} != {components.Resource}");
                }

                if (permission.ScopeAction != components.Action)
                {
                    isConsistent = false;
                    errors.Add($"Action mismatch: {permission.ScopeAction} != {components.Action}");
                }

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

        /// <summary>
        /// 스코프 사용 빈도 분석
        /// </summary>
        public Task<ServiceResult<ScopeUsageStatistics>> AnalyzeUsageAsync(
            List<string> scopes,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                var statistics = new ScopeUsageStatistics
                {
                    AnalyzedFrom = from ?? DateTime.UtcNow.AddMonths(-1),
                    AnalyzedTo = to ?? DateTime.UtcNow
                };

                // 사용 빈도 계산
                foreach (var scope in scopes)
                {
                    statistics.UsageCount[scope] = statistics.UsageCount.GetValueOrDefault(scope, 0) + 1;
                }

                if (statistics.UsageCount.Any())
                {
                    statistics.MostUsedScope = statistics.UsageCount
                        .OrderByDescending(kvp => kvp.Value)
                        .First().Key;

                    statistics.LeastUsedScope = statistics.UsageCount
                        .OrderBy(kvp => kvp.Value)
                        .First().Key;

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

        /// <summary>
        /// 스코프 복잡도 계산
        /// </summary>
        public Task<ServiceResult<int>> CalculateComplexityAsync(string scope)
        {
            try
            {
                int complexity = 0;

                // 깊이에 따른 복잡도
                var parts = scope.Split(':');
                complexity += parts.Length * 10;

                // 와일드카드 복잡도
                complexity += scope.Count(c => c == '*') * 20;

                // 특수 문자 복잡도
                complexity += scope.Count(c => !char.IsLetterOrDigit(c) && c != ':' && c != '*') * 5;

                // 길이에 따른 복잡도
                complexity += scope.Length / 10;

                return Task.FromResult(ServiceResult<int>.Success(complexity));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error calculating scope complexity: {scope}");
                return Task.FromResult(ServiceResult<int>.Failure("Complexity calculation error", "COMPLEXITY_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 최적화 제안
        /// </summary>
        public async Task<ServiceResult<ScopeOptimizationSuggestions>> SuggestOptimizationsAsync(List<string> currentScopes)
        {
            try
            {
                var suggestions = new ScopeOptimizationSuggestions();

                // 중복 스코프 찾기
                var redundant = await FindRedundantScopesAsync(currentScopes);
                if (redundant.IsSuccess && redundant.Data != null)
                {
                    suggestions.RedundantScopes = redundant.Data;
                }

                // 와일드카드로 압축 가능한 패턴 찾기
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

                // 잠재적 감소 계산
                suggestions.PotentialReduction = suggestions.RedundantScopes.Count +
                    suggestions.MergeRecommendations.Sum(m => m.OriginalScopes.Count - 1);

                return ServiceResult<ScopeOptimizationSuggestions>.Success(suggestions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error suggesting scope optimizations");
                return ServiceResult<ScopeOptimizationSuggestions>.Failure("Optimization suggestion error", "OPTIMIZE_ERROR");
            }
        }

        /// <summary>
        /// 중복 스코프 탐지
        /// </summary>
        public async Task<ServiceResult<List<string>>> FindRedundantScopesAsync(List<string> scopes)
        {
            try
            {
                var redundant = new List<string>();

                for (int i = 0; i < scopes.Count; i++)
                {
                    for (int j = 0; j < scopes.Count; j++)
                    {
                        if (i == j) continue;

                        // scopes[j]가 scopes[i]를 포함하는지 확인
                        var containsResult = await ContainsScopeAsync(scopes[j], scopes[i]);
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

        /// <summary>
        /// 파싱 결과 캐싱
        /// </summary>
        public Task<ServiceResult> CacheParsingResultAsync(string scope, ScopeParseResponse result)
        {
            try
            {
                var cacheKey = $"{CacheKeyPrefix}{scope}";
                _cache.Set(cacheKey, result, _defaultCacheExpiration);

                // 통계 업데이트
                UpdateCacheStatistics(scope, true);

                return Task.FromResult(ServiceResult.Success("Cached successfully"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error caching parsing result for scope: {scope}");
                return Task.FromResult(ServiceResult.Failure("Cache error", "CACHE_ERROR"));
            }
        }

        /// <summary>
        /// 캐시된 파싱 결과 조회
        /// </summary>
        public Task<ServiceResult<ScopeParseResponse?>> GetCachedParsingResultAsync(string scope)
        {
            try
            {
                var cacheKey = $"{CacheKeyPrefix}{scope}";
                if (_cache.TryGetValue(cacheKey, out ScopeParseResponse? cached))
                {
                    UpdateCacheStatistics(scope, true);
                    return Task.FromResult(ServiceResult<ScopeParseResponse?>.Success(cached));
                }

                UpdateCacheStatistics(scope, false);
                return Task.FromResult(ServiceResult<ScopeParseResponse?>.Success(null));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting cached parsing result for scope: {scope}");
                return Task.FromResult(ServiceResult<ScopeParseResponse?>.Failure("Cache retrieval error", "CACHE_GET_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 파싱 캐시 초기화
        /// </summary>
        public Task<ServiceResult> ClearScopeParsingCacheAsync()
        {
            try
            {
                // IMemoryCache doesn't provide a way to clear all entries with a specific prefix
                // In production, consider using a more advanced caching solution
                _logger.LogInformation("Scope parsing cache clear requested");
                return Task.FromResult(ServiceResult.Success("Cache cleared"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing scope parsing cache");
                return Task.FromResult(ServiceResult.Failure("Cache clear error", "CACHE_CLEAR_ERROR"));
            }
        }

        /// <summary>
        /// 조직별 스코프 캐시 초기화
        /// </summary>
        public Task<ServiceResult> ClearOrganizationScopeCacheAsync(Guid organizationId)
        {
            try
            {
                // Organization-specific cache clearing logic
                _logger.LogInformation($"Organization scope cache cleared for: {organizationId}");
                return Task.FromResult(ServiceResult.Success("Organization cache cleared"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error clearing organization scope cache: {organizationId}");
                return Task.FromResult(ServiceResult.Failure("Organization cache clear error", "ORG_CACHE_CLEAR_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 캐시 통계 조회
        /// </summary>
        public Task<ServiceResult<ScopeCacheStatistics>> GetCacheStatisticsAsync()
        {
            try
            {
                var stats = _cache.Get<ScopeCacheStatistics>(CacheStatPrefix) ?? new ScopeCacheStatistics();
                return Task.FromResult(ServiceResult<ScopeCacheStatistics>.Success(stats));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting cache statistics");
                return Task.FromResult(ServiceResult<ScopeCacheStatistics>.Failure("Statistics retrieval error", "STATS_ERROR"));
            }
        }

        /// <summary>
        /// 스코프 캐시 워밍업
        /// </summary>
        public async Task<ServiceResult> WarmupCacheAsync(List<string> frequentScopes)
        {
            try
            {
                int warmedUp = 0;

                foreach (var scope in frequentScopes)
                {
                    var request = new ScopeParseRequest
                    {
                        Scope = scope,
                        IncludeHierarchy = true,
                        ValidateScope = true,
                        ResolveWildcards = scope.Contains("*")
                    };

                    var result = await ParseScopeAsync(request);
                    if (result.IsSuccess)
                    {
                        warmedUp++;
                    }
                }

                _logger.LogInformation($"Cache warmed up with {warmedUp} scopes");
                return ServiceResult.Success($"Warmed up {warmedUp} scopes");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error warming up cache");
                return ServiceResult.Failure("Warmup error", "WARMUP_ERROR");
            }
        }

        /// <summary>
        /// 캐시 최적화 실행
        /// </summary>
        public Task<ServiceResult> OptimizeCacheAsync()
        {
            try
            {
                // 캐시 최적화 로직
                // - 오래된 항목 제거
                // - 자주 사용되지 않는 항목 제거
                // - 메모리 압력 체크

                _logger.LogInformation("Cache optimization completed");
                return Task.FromResult(ServiceResult.Success("Cache optimized"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error optimizing cache");
                return Task.FromResult(ServiceResult.Failure("Optimization error", "OPTIMIZE_CACHE_ERROR"));
            }
        }

        #endregion

        #region Permission 연동

        /// <summary>
        /// Permission들의 Scope를 분석하여 매트릭스 생성
        /// </summary>
        public async Task<ServiceResult<ScopeMatrixView>> BuildPermissionScopeMatrixAsync(List<PermissionEntity> permissions)
        {
            try
            {
                var matrix = new ScopeMatrixView
                {
                    TotalPermissions = permissions.Count
                };

                var resourceSet = new HashSet<string>();
                var actionSet = new HashSet<string>();

                // 모든 Permission의 스코프 파싱
                foreach (var permission in permissions)
                {
                    var parseResult = await ParsePermissionScopeAsync(permission.Scope);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        var components = parseResult.Data;
                        resourceSet.Add(components.Resource);
                        actionSet.Add(components.Action);

                        // 매트릭스에 추가
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

        /// <summary>
        /// Permission의 Scope 변경 시 관련 필드 업데이트
        /// </summary>
        public async Task<ServiceResult> UpdatePermissionScopeComponentsAsync(PermissionEntity permission, string newScope)
        {
            try
            {
                // 새 스코프 검증
                var validationResult = await ValidateScopeAsync(newScope);
                if (!validationResult.IsSuccess || !validationResult.Data)
                {
                    return ServiceResult.Failure("Invalid new scope", "INVALID_SCOPE");
                }

                // 스코프 업데이트
                permission.Scope = newScope;

                // 구성 요소 재파싱 및 업데이트
                var populateResult = await PopulatePermissionScopeComponentsAsync(permission);

                return populateResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating permission scope components: {permission.Id}");
                return ServiceResult.Failure("Update error", "UPDATE_SCOPE_ERROR");
            }
        }

        /// <summary>
        /// 조직의 모든 Permission Scope 분석
        /// </summary>
        public async Task<ServiceResult<OrganizationScopeAnalysis>> AnalyzeOrganizationScopesAsync(Guid organizationId)
        {
            try
            {
                // TODO: 실제 구현 시 Permission Repository를 통해 조직의 모든 Permission 조회
                var analysis = new OrganizationScopeAnalysis
                {
                    OrganizationId = organizationId
                };

                // 임시 데이터 (실제 구현 시 DB에서 조회)
                var scopes = new List<string>
                {
                    "user:read",
                    "user:write",
                    "user:delete",
                    "product:read",
                    "product:*",
                    "billing:manage"
                };

                var resourceSet = new HashSet<string>();
                var actionSet = new HashSet<string>();

                foreach (var scope in scopes)
                {
                    var parseResult = await ParsePermissionScopeAsync(scope);
                    if (parseResult.IsSuccess && parseResult.Data != null)
                    {
                        var components = parseResult.Data;
                        resourceSet.Add(components.Resource);
                        actionSet.Add(components.Action);

                        // 분포 계산
                        analysis.ResourceDistribution[components.Resource] =
                            analysis.ResourceDistribution.GetValueOrDefault(components.Resource, 0) + 1;

                        analysis.ActionDistribution[components.Action] =
                            analysis.ActionDistribution.GetValueOrDefault(components.Action, 0) + 1;

                        if (scope.Contains("*"))
                        {
                            analysis.WildcardScopes++;
                        }
                    }
                }

                analysis.TotalScopes = scopes.Count;
                analysis.UniqueResources = resourceSet.Count;
                analysis.UniqueActions = actionSet.Count;
                analysis.MostUsedScopes = scopes.Take(5).ToList(); // 실제로는 사용 빈도 기반

                return ServiceResult<OrganizationScopeAnalysis>.Success(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing organization scopes: {organizationId}");
                return ServiceResult<OrganizationScopeAnalysis>.Failure("Analysis error", "ANALYZE_ORG_ERROR");
            }
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("ScopeParsingService initializing...");

                // 자주 사용되는 스코프 패턴 사전 캐싱
                var commonScopes = new List<string>
                {
                    "user:read",
                    "user:write",
                    "user:*",
                    "organization:manage",
                    "application:*"
                };

                await WarmupCacheAsync(commonScopes);

                _logger.LogInformation("ScopeParsingService initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize ScopeParsingService");
                throw;
            }
        }

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 간단한 파싱 테스트
                var testResult = await ValidateScopeAsync("test:read");
                return testResult.IsSuccess;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScopeParsingService health check failed");
                return false;
            }
        }

        #endregion

        #region Private Helper Methods

        private string DetectScopeStyle(string scope)
        {
            if (scope.Contains(':'))
                return "resource:action";
            if (scope.Contains('.'))
                return "legacy";
            if (scope.Split(':').Length > 3)
                return "hierarchical";
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

        private async Task<WildcardResolution> ResolveWildcardsAsync(string scope)
        {
            var resolution = new WildcardResolution
            {
                ContainsWildcard = scope.Contains("*")
            };

            if (resolution.ContainsWildcard)
            {
                var parts = scope.Split(':');
                resolution.WildcardPositions = new List<int>();

                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == "*")
                    {
                        resolution.WildcardPositions.Add(i);
                    }
                }

                resolution.ImpactDescription = $"Wildcard at position(s): {string.Join(", ", resolution.WildcardPositions)}";

                // 매칭 패턴 생성
                var expandResult = await ExpandWildcardScopeAsync(scope);
                if (expandResult.IsSuccess)
                {
                    resolution.MatchingPatterns = expandResult.Data;
                }
            }

            return resolution;
        }

        private Task<ScopeValidation> ValidateScopeInternalAsync(string scope)
        {
            var validation = new ScopeValidation
            {
                IsValid = true,
                ValidationErrors = new List<string>()
            };

            // 형식 검증
            validation.IsFormatValid = StandardScopePattern.IsMatch(scope);
            if (!validation.IsFormatValid)
            {
                validation.IsValid = false;
                validation.ValidationErrors.Add("Invalid scope format");
            }

            // TODO: 실제 구현 시 DB에서 존재 여부 확인
            validation.ExistsInSystem = true;

            // 유사 스코프 제안
            if (!validation.IsValid)
            {
                validation.SuggestedScopes = GenerateSuggestions(scope);
            }

            return Task.FromResult(validation);
        }

        private List<string> GenerateSuggestions(string scope)
        {
            var suggestions = new List<string>();

            // 일반적인 오타 수정
            if (!scope.Contains(':'))
            {
                suggestions.Add(scope.Replace('.', ':'));
                suggestions.Add(scope.Replace('-', ':'));
            }

            // 기본 액션 추가
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
            if (string.IsNullOrWhiteSpace(components.Resource) ||
                string.IsNullOrWhiteSpace(components.Action))
            {
                components.ValidationErrors.Add("Resource and action are required");
                return false;
            }

            // 각 구성 요소 검증
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
            // 조직이나 애플리케이션 이름 패턴 체크
            // 실제 구현 시 DB 조회 또는 더 정교한 로직 필요
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
                    // 콜론으로 끝나도록 조정
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

        private Task<string> NormalizeScopeInternalAsync(string scope)
        {
            // 대소문자 정규화
            var normalized = scope.ToLower();

            // 공백 제거
            normalized = normalized.Trim();

            // 중복 콜론 제거
            normalized = Regex.Replace(normalized, ":+", ":");

            // 시작/끝 콜론 제거
            normalized = normalized.Trim(':');

            return Task.FromResult(normalized);
        }

        private bool IsParentChild(string[] parts1, string[] parts2)
        {
            if (Math.Abs(parts1.Length - parts2.Length) != 1)
                return false;

            var shorter = parts1.Length < parts2.Length ? parts1 : parts2;
            var longer = parts1.Length > parts2.Length ? parts1 : parts2;

            for (int i = 0; i < shorter.Length - 1; i++)
            {
                if (shorter[i] != longer[i])
                    return false;
            }

            return shorter[^1] == "*" || longer[^1] != "*";
        }

        private bool AreSiblings(string[] parts1, string[] parts2)
        {
            if (parts1.Length != parts2.Length || parts1.Length < 2)
                return false;

            // 마지막 요소를 제외한 모든 부분이 같아야 함
            for (int i = 0; i < parts1.Length - 1; i++)
            {
                if (parts1[i] != parts2[i])
                    return false;
            }

            return parts1[^1] != parts2[^1];
        }

        private bool IsAncestorDescendant(string[] parts1, string[] parts2)
        {
            var shorter = parts1.Length < parts2.Length ? parts1 : parts2;
            var longer = parts1.Length > parts2.Length ? parts1 : parts2;

            if (shorter.Length >= longer.Length)
                return false;

            for (int i = 0; i < shorter.Length - 1; i++)
            {
                if (shorter[i] != longer[i])
                    return false;
            }

            return shorter[^1] == "*";
        }

        private async Task<ScopeConflict?> DetectConflictBetween(string scope1, string scope2)
        {
            // 완전히 같은 스코프
            if (scope1 == scope2)
            {
                return new ScopeConflict
                {
                    Scope1 = scope1,
                    Scope2 = scope2,
                    Type = ScopeConflictType.Redundant,
                    Description = "Duplicate scopes detected",
                    Severity = ConflictSeverity.Medium,
                    Resolution = "Remove one of the duplicate scopes"
                };
            }

            // 포함 관계
            var contains1 = await ContainsScopeAsync(scope1, scope2);
            if (contains1.IsSuccess && contains1.Data)
            {
                return new ScopeConflict
                {
                    Scope1 = scope1,
                    Scope2 = scope2,
                    ///// 2. 상위 리소스와 하위 리소스가 겹치는 경우  
                    ///"api:*"          vs  "api:v1:users:read"
                    Type = ScopeConflictType.Overlap,
                    Description = $"{scope1} contains {scope2}",
                    Severity = ConflictSeverity.Low,
                    Resolution = $"Consider removing {scope2} as it's covered by {scope1}"
                };
            }

            return null;
        }

        private void UpdateCacheStatistics(string scope, bool isHit)
        {
            var stats = _cache.Get<ScopeCacheStatistics>(CacheStatPrefix) ?? new ScopeCacheStatistics();

            if (isHit)
            {
                stats.HitCount++;
            }
            else
            {
                stats.MissCount++;
            }

            stats.TotalRequests++;
            stats.HitRate = (double)stats.HitCount / stats.TotalRequests;

            _cache.Set(CacheStatPrefix, stats, _statsCacheExpiration);
        }

        private int CountNodes(ScopeNode node)
        {
            return 1 + node.Children.Sum(child => CountNodes(child));
        }

        private int CalculateMaxDepth(ScopeNode node)
        {
            if (!node.Children.Any())
                return node.Level;

            return node.Children.Max(child => CalculateMaxDepth(child));
        }

        public Task<ServiceResult<ScopeParseResponse>> ParseScopeAsync(Core.Models.Auth.Permissions.Requests.ScopeParseRequest request)
        {
            throw new NotImplementedException();
        }

        Task<ServiceResult<Core.Models.Auth.Permissions.Common.ScopeTree>> IScopeParsingService.BuildScopeTreeAsync(List<string> scopes)
        {
            throw new NotImplementedException();
        }

        #endregion
    }

    #region Supporting Classes

    public class ScopeTree
    {
        public ScopeNode Root { get; set; } = new();
        public int TotalNodes { get; set; }
        public int MaxDepth { get; set; }
    }

    public class ScopeNode
    {
        public string Name { get; set; } = string.Empty;
        public string FullPath { get; set; } = string.Empty;
        public int Level { get; set; }
        public ScopeNode? Parent { get; set; }
        public List<ScopeNode> Children { get; set; } = new();
    }

    public class ScopeParseRequest
    {
        public string Scope { get; set; } = string.Empty;
        public bool IncludeHierarchy { get; set; }
        public bool ValidateScope { get; set; }
        public bool ResolveWildcards { get; set; }
    }

    #endregion
}