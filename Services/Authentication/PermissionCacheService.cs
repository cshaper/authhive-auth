// Path: AuthHive.Auth/Services/Permissions/PermissionCacheService.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Cache;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.Permissions
{
    /// <summary>
    /// 권한 데이터에 대한 캐싱을 담당하는 서비스 구현체입니다.
    /// 
    /// [누가] AuthHive.Proxy의 PermissionValidationMiddleware, RoleService, ConnectedIdContextService
    /// [언제] API 요청 권한 검증, 역할 생성/수정, 컨텍스트 전환 시
    /// [어디서] Redis 캐시(프로덕션) 또는 메모리 캐시(개발)에 저장
    /// [무엇을] Permission 엔티티, 권한 트리, ConnectedId별 권한 집합
    /// [어떻게] Read-Through 캐시 패턴, 계층적 무효화 전략
    /// [왜] 권한 검증은 모든 API 요청의 Hot Path이므로 밀리초 단위 응답 필요
    /// </summary>
    public class PermissionCacheService : IPermissionCacheService
    {
        private readonly ICacheService _cacheService;
        private readonly IPermissionRepository _permissionRepository;
        private readonly ILogger<PermissionCacheService> _logger;

        // JSON 직렬화 옵션
        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        public PermissionCacheService(
            ICacheService cacheService,
            IPermissionRepository permissionRepository,
            ILogger<PermissionCacheService> logger)
        {
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _permissionRepository = permissionRepository ?? throw new ArgumentNullException(nameof(permissionRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region Core Cache Operations
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("PermissionCacheService Initialized. Starting cache warm-up...");
            // WarmupFrequentlyUsedPermissionsAsync도 CancellationToken을 받도록 수정했다고 가정하고 전달
            return WarmupFrequentlyUsedPermissionsAsync(cancellationToken);
        }

        /// <summary>
        /// 서비스의 건강 상태를 확인합니다. 이 서비스는 캐시 서비스에 의존합니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // _cacheService.IsHealthyAsync에도 CancellationToken을 전달
            return await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion
        /// <summary>
        /// ID로 권한을 조회합니다.
        /// 
        /// [언제] RolePermission 매핑 시, 권한 상세 조회 시
        /// [어떻게] 캐시 히트율 95% 목표, 미스 시 DB 조회 후 캐싱
        /// [왜] ID 기반 조회는 역할 관리 시 빈번하게 발생
        /// </summary>
        public async Task<ServiceResult<PermissionDto>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            try
            {
                if (id == Guid.Empty)
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Invalid permission ID",
                        PermissionConstants.ErrorCodes.InvalidParameter
                    );
                }

                // 작업 시작 전에 취소 요청이 있었는지 확인합니다.
                cancellationToken.ThrowIfCancellationRequested();

                var cacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}id:{id}";

                // GetOrSetAsync에 CancellationToken을 전달합니다.
                var permission = await _cacheService.GetOrSetAsync<PermissionDto>(
                    cacheKey,
                    async () =>
                    {
                        // DB 조회 메서드에도 CancellationToken을 전달합니다.
                        var dto = await LoadPermissionFromDatabaseAsync(id, cancellationToken);
                        if (dto == null)
                            throw new InvalidOperationException($"Permission {id} not found");
                        return dto;
                    },
                    TimeSpan.FromSeconds(PermissionConstants.Cache.PermissionCacheTtl),
                    cancellationToken // ◀◀ GetOrSetAsync 자체에도 CancellationToken 전달
                );

                if (permission == null)
                {
                    _logger.LogWarning("Permission not found: {PermissionId}", id);
                    return ServiceResult<PermissionDto>.NotFound($"Permission with ID {id} not found");
                }

                return ServiceResult<PermissionDto>.Success(permission);
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("GetByIdAsync operation was cancelled for ID: {PermissionId}", id);
                return ServiceResult<PermissionDto>.Failure("Operation was cancelled.", "CANCELLED");
            }
            catch (InvalidOperationException)
            {
                return ServiceResult<PermissionDto>.NotFound($"Permission with ID {id} not found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission by ID: {PermissionId}", id);
                // Fallback 메서드에도 CancellationToken을 전달합니다.
                return await FallbackToDatabase(id, cancellationToken); // ◀◀ 수정
            }
        }
        /// <summary>
        /// Scope로 권한을 조회합니다.
        /// 
        /// [언제] API 엔드포인트 접근 권한 검증 시
        /// [어떻게] Scope 정규화 → 캐시 조회 → 미스 시 DB 조회
        /// [왜] "organization:read" 같은 Scope는 모든 조직 관련 API에서 검증
        /// </summary>
        public async Task<ServiceResult<PermissionDto>> GetByScopeAsync(string scope, CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            try
            {
                if (string.IsNullOrWhiteSpace(scope))
                {
                    return ServiceResult<PermissionDto>.Failure(
                        "Invalid scope",
                        PermissionConstants.ErrorCodes.InvalidScope
                    );
                }

                // 작업 시작 전에 취소 요청이 있었는지 확인
                cancellationToken.ThrowIfCancellationRequested();

                var normalizedScope = NormalizeScope(scope);
                var cacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}scope:{normalizedScope}";

                // GetOrSetAsync에 CancellationToken 전달
                var permission = await _cacheService.GetOrSetAsync<PermissionDto>(
                    cacheKey,
                    async () =>
                    {
                        // DB 조회 메서드에도 CancellationToken 전달
                        var dto = await LoadPermissionByScopeFromDatabaseAsync(normalizedScope, cancellationToken);
                        if (dto == null)
                            throw new InvalidOperationException($"Permission with scope {scope} not found");
                        return dto;
                    },
                    TimeSpan.FromSeconds(PermissionConstants.Cache.PermissionCacheTtl),
                    cancellationToken // ◀◀ GetOrSetAsync 자체에도 CancellationToken 전달
                );

                if (permission == null)
                {
                    _logger.LogWarning("Permission not found for scope: {Scope}", scope);
                    return ServiceResult<PermissionDto>.NotFound($"Permission with scope '{scope}' not found");
                }

                return ServiceResult<PermissionDto>.Success(permission);
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("GetByScopeAsync operation was cancelled for scope: {Scope}", scope);
                return ServiceResult<PermissionDto>.Failure("Operation was cancelled.", "CANCELLED");
            }
            catch (InvalidOperationException)
            {
                return ServiceResult<PermissionDto>.NotFound($"Permission with scope '{scope}' not found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission by scope: {Scope}", scope);
                return ServiceResult<PermissionDto>.Failure(
                    "Failed to retrieve permission",
                    PermissionConstants.ErrorCodes.SystemError
                );
            }
        }
        /// <summary>
        /// 전체 권한 트리를 조회합니다.
        /// 
        /// [언제] 관리자 대시보드 로드, 역할 편집기 오픈 시
        /// [어떻게] 전체 트리 빌드 → 캐싱 → 카테고리별 집계
        /// [왜] 트리 구성은 CPU 집약적 (평균 200ms 소요)
        /// </summary>
        public async Task<ServiceResult<PermissionTreeResponse>> GetTreeAsync(CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            try
            {
                // 작업 시작 전에 취소 요청이 있었는지 확인합니다.
                cancellationToken.ThrowIfCancellationRequested();

                var cacheKey = $"{PermissionConstants.Cache.PermissionTreeCacheKeyPrefix}full";

                var tree = await _cacheService.GetOrSetAsync(
                    cacheKey,
                    // BuildPermissionTreeAsync에도 CancellationToken을 전달합니다.
                    async () => await BuildPermissionTreeAsync(cancellationToken), // ◀◀ 수정
                    PermissionConstants.Cache.TreeCacheTtl,
                    cancellationToken // ◀◀ GetOrSetAsync 자체에도 CancellationToken 전달
                );

                if (tree == null)
                {
                    _logger.LogWarning("Failed to build permission tree");
                    return ServiceResult<PermissionTreeResponse>.Failure(
                        "Failed to build permission tree",
                        PermissionConstants.ErrorCodes.SystemError
                    );
                }

                // 캐시 정보 설정
                tree.CacheKey = cacheKey;
                tree.CacheExpiresAt = DateTime.UtcNow.Add(PermissionConstants.Cache.TreeCacheTtl);

                return ServiceResult<PermissionTreeResponse>.Success(tree);
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("GetTreeAsync operation was cancelled.");
                return ServiceResult<PermissionTreeResponse>.Failure("Operation was cancelled.", "CANCELLED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission tree");
                return ServiceResult<PermissionTreeResponse>.Failure(
                    "Failed to retrieve permission tree",
                    PermissionConstants.ErrorCodes.SystemError
                );
            }
        }


        #region Cache Invalidation

        /// <summary>
        /// 특정 권한과 관련된 모든 캐시를 무효화합니다.
        /// 
        /// [언제] 권한 수정/삭제 시 즉시
        /// [어떻게] 계층적 무효화 - 자신 + 트리
        /// [왜] 권한 변경은 즉시 반영되어야 보안 유지
        /// </summary>
        public async Task InvalidatePermissionAsync(Guid permissionId, CancellationToken cancellationToken = default) 
        {
            try
            {
                _logger.LogInformation("Invalidating cache for permission: {PermissionId}", permissionId);

                // 작업 시작 전에 취소 요청이 있었는지 확인합니다.
                cancellationToken.ThrowIfCancellationRequested();

                var permission = await _permissionRepository.GetWithRelatedDataAsync(
                    permissionId,
                    includeParent: false,
                    includeChildren: false,
                    includeRoles: false,
                    includeValidationLogs: false,
                    cancellationToken // ◀◀ Repository 호출에 CancellationToken 전달
                );

                if (permission == null)
                {
                    _logger.LogWarning("Permission not found for invalidation: {PermissionId}", permissionId);
                    return;
                }

                // ID 캐시 제거
                var idCacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}id:{permissionId}";
                await _cacheService.RemoveAsync(idCacheKey, cancellationToken); // ◀◀ 캐시 제거에 CancellationToken 전달

                // Scope 캐시 제거
                if (!string.IsNullOrEmpty(permission.Scope))
                {
                    var normalizedScope = NormalizeScope(permission.Scope);
                    var scopeCacheKey = $"{PermissionConstants.Cache.PermissionCacheKeyPrefix}scope:{normalizedScope}";
                    await _cacheService.RemoveAsync(scopeCacheKey, cancellationToken); // ◀◀ 캐시 제거에 CancellationToken 전달
                }

                // 트리 캐시 무효화
                await _cacheService.RemoveByPatternAsync($"{PermissionConstants.Cache.PermissionTreeCacheKeyPrefix}*", cancellationToken); // ◀◀ 캐시 제거에 CancellationToken 전달

                _logger.LogInformation(
                    "Cache invalidated for permission: {PermissionId}, Scope: {Scope}",
                    permissionId, permission.Scope
                );
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("Cache invalidation was cancelled for permission: {PermissionId}", permissionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating permission cache: {PermissionId}", permissionId);
            }
        }
        /// <summary>
        /// 모든 권한 캐시를 새로고침합니다.
        /// 
        /// [언제] 시스템 재시작, 대량 권한 변경 후
        /// [어떻게] 패턴 매칭 삭제 → 자주 사용 권한 Warm-up
        /// [왜] 일관성 보장 및 Cold Start 방지
        /// </summary>
        public async Task RefreshAllAsync(CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            try
            {
                _logger.LogInformation("Refreshing all permission caches");

                // 작업 시작 전에 취소 요청이 있었는지 확인합니다.
                cancellationToken.ThrowIfCancellationRequested();

                // 모든 권한 캐시 제거
                await _cacheService.RemoveByPatternAsync($"{PermissionConstants.Cache.PermissionCacheKeyPrefix}*", cancellationToken); // ◀◀ 수정

                // Warm-up
                await WarmupFrequentlyUsedPermissionsAsync(cancellationToken); // ◀◀ 수정

                // 트리 재생성
                await GetTreeAsync(cancellationToken); // ◀◀ 수정

                _logger.LogInformation("All permission caches refreshed successfully");
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("Permission cache refresh was cancelled.");
                // 취소된 경우 예외를 다시 던지지 않아 정상적인 중단으로 처리합니다.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing all permission caches");
                throw; // 취소가 아닌 다른 예외는 다시 던져서 문제를 알립니다.
            }
        }

        #endregion

        #region Private Helper Methods
        private async Task<PermissionDto?> LoadPermissionFromDatabaseAsync(
            Guid id,
            CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            var permission = await _permissionRepository.GetWithRelatedDataAsync(
                id,
                includeParent: true,
                includeChildren: false,
                includeRoles: false,
                includeValidationLogs: false,
                cancellationToken); // ◀◀ CancellationToken 전달

            return permission != null ? MapToDto(permission) : null;
        }
        private async Task<PermissionDto?> LoadPermissionByScopeFromDatabaseAsync(
            string normalizedScope,
            CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            // Repository 호출 시 CancellationToken을 전달합니다.
            var permission = await _permissionRepository.GetByScopeAsync(normalizedScope, cancellationToken); // ◀◀ 수정

            return permission != null ? MapToDto(permission) : null;
        }


        private List<PermissionNode> BuildTreeNodes(List<PermissionEntity> allPermissions, Guid? parentId, int depth)
        {
            var nodes = new List<PermissionNode>();
            var childPermissions = allPermissions.Where(p => p.ParentPermissionId == parentId);

            foreach (var permission in childPermissions)
            {
                var children = BuildTreeNodes(allPermissions, permission.Id, depth + 1);

                var node = new PermissionNode
                {
                    Id = permission.Id,
                    Scope = permission.Scope,
                    Name = permission.Name,
                    Description = permission.Description,
                    Category = permission.Category.ToString(),
                    Level = permission.Level.ToString(),
                    ParentId = parentId,
                    Children = children,
                    Depth = depth,
                    IsActive = permission.IsActive,
                    IsSystemPermission = permission.IsSystemPermission,
                    HasWildcard = permission.HasWildcard,
                    ResourceType = permission.ResourceType,
                    ActionType = permission.ActionType,
                    AssignedRoleCount = permission.RolePermissions?.Count ?? 0,
                    Path = BuildPath(allPermissions, permission)
                };

                nodes.Add(node);
            }

            return nodes.OrderBy(n => n.Category).ThenBy(n => n.Name).ToList();
        }

        private string NormalizeScope(string scope)
        {
            return scope.Trim().ToLowerInvariant();
        }

        private async Task<ServiceResult<PermissionDto>> FallbackToDatabase(
     Guid id,
     CancellationToken cancellationToken = default) // ◀◀ CancellationToken 파라미터 추가
        {
            try
            {
                _logger.LogWarning("Falling back to database for permission: {PermissionId}", id);

                // Repository 호출 시 CancellationToken을 전달합니다.
                var permission = await _permissionRepository.GetByIdAsync(id, cancellationToken); // ◀◀ 수정

                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.NotFound($"Permission with ID {id} not found");
                }

                var dto = MapToDto(permission);
                return ServiceResult<PermissionDto>.Success(dto);
            }
            catch (OperationCanceledException) // ◀◀ 작업 취소 예외 처리 블록 추가
            {
                _logger.LogWarning("FallbackToDatabase operation was cancelled for ID: {PermissionId}", id);
                return ServiceResult<PermissionDto>.Failure("Operation was cancelled.", "CANCELLED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Fallback to database failed for permission: {PermissionId}", id);
                return ServiceResult<PermissionDto>.Failure(
                    "Failed to retrieve permission",
                    PermissionConstants.ErrorCodes.DatabaseError
                );
            }
        }

        private async Task WarmupFrequentlyUsedPermissionsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Warming up frequently used permissions cache");

                // Constants에서 정의된 핵심 권한들
                var coreScopes = PermissionConstants.SystemPermissions.ProtectedScopes
                    .Where(s => !s.Contains("*")) // 와일드카드 제외
                    .ToArray();

                // 추가 핵심 권한들
                var additionalScopes = new[]
                {
            "org:read",
            "org:write",

            "user:read",
            "user:manage",
            "application:read",
            "billing:read"
        };

                var allScopes = coreScopes.Concat(additionalScopes).Distinct();

                // 병렬 처리 (최대 5개 동시)
                var semaphore = new SemaphoreSlim(5);
                var tasks = allScopes.Select(async scope =>
                {
                    // 본격적인 작업 시작 전에 취소 요청이 있었는지 확인합니다.
                    cancellationToken.ThrowIfCancellationRequested(); // ◀◀ 수정

                    // WaitAsync에 CancellationToken을 전달합니다.
                    await semaphore.WaitAsync(cancellationToken); // ◀◀ 수정
                    try
                    {
                        // GetByScopeAsync에도 CancellationToken을 전달합니다.
                        await GetByScopeAsync(scope, cancellationToken); // ◀◀ 수정
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                });

                await Task.WhenAll(tasks);

                _logger.LogInformation("Warmup completed for {Count} core permissions", allScopes.Count());
            }
            catch (OperationCanceledException) // ◀◀ 추가
            {
                // 작업 취소는 오류가 아니므로 경고 로그만 남깁니다.
                _logger.LogWarning("Cache warmup was cancelled.");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during cache warmup");
            }
        }


        private PermissionDto MapToDto(PermissionEntity entity)
        {
            var dto = new PermissionDto
            {
                // 기본 필드
                Id = entity.Id,
                Scope = entity.Scope,
                Name = entity.Name,
                Description = entity.Description,
                Category = entity.Category,
                Level = entity.Level,
                ParentPermissionId = entity.ParentPermissionId,
                IsSystemPermission = entity.IsSystemPermission,
                IsActive = entity.IsActive,
                ResourceType = entity.ResourceType,
                ActionType = entity.ActionType,

                // JSON 필드 역직렬화
                RequiredMembershipTypes = DeserializeJsonList(entity.RequiredMembershipTypes),
                Metadata = DeserializeJsonDictionary(entity.Metadata),

                // 파싱된 스코프 정보
                ScopeOrganization = entity.ScopeOrganization,
                ScopeApplication = entity.ScopeApplication,
                ScopeResource = entity.ScopeResource,
                ScopeAction = entity.ScopeAction,
                HasWildcard = entity.HasWildcard,
                ScopeLevel = entity.ScopeLevel,
                NormalizedScope = entity.NormalizedScope,

                // 감사 필드
                CreatedAt = entity.CreatedAt,
                CreatedByConnectedId = entity.CreatedByConnectedId,
                UpdatedAt = entity.UpdatedAt,
                UpdatedByConnectedId = entity.UpdatedByConnectedId,
                DeletedByConnectedId = entity.DeletedByConnectedId,
                IsDeleted = entity.IsDeleted,
                DeletedAt = entity.DeletedAt
            };

            // 부모 권한 정보
            if (entity.ParentPermission != null)
            {
                dto.ParentPermission = new PermissionParentInfo
                {
                    Id = entity.ParentPermission.Id,
                    Scope = entity.ParentPermission.Scope,
                    Name = entity.ParentPermission.Name,
                    Category = entity.ParentPermission.Category,
                    Level = entity.ParentPermission.Level,
                    IsActive = entity.ParentPermission.IsActive
                };
            }

            // 자식 권한 수
            dto.ChildPermissionCount = entity.ChildPermissions?.Count ?? 0;

            return dto;
        }

        private List<string>? DeserializeJsonList(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                return JsonSerializer.Deserialize<List<string>>(json, _jsonOptions);
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to deserialize JSON list: {Json}", json);
                return null;
            }
        }

        private Dictionary<string, object>? DeserializeJsonDictionary(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, object>>(json, _jsonOptions);
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to deserialize JSON dictionary: {Json}", json);
                return null;
            }
        }

        private int CalculateMaxDepth(List<PermissionNode> nodes)
        {
            if (!nodes.Any()) return 0;

            int maxDepth = 0;
            foreach (var node in nodes)
            {
                var nodeDepth = node.Depth;
                if (node.Children.Any())
                {
                    var childMaxDepth = CalculateMaxDepth(node.Children);
                    nodeDepth = Math.Max(nodeDepth, childMaxDepth);
                }
                maxDepth = Math.Max(maxDepth, nodeDepth);
            }

            return maxDepth;
        }
        private async Task<PermissionTreeResponse> BuildPermissionTreeAsync(
            CancellationToken cancellationToken = default) // ◀◀ CancellationToken 추가
        {
            var allPermissions = await _permissionRepository.GetPermissionTreeAsync(
                rootPermissionId: null,
                maxDepth: null,
                cancellationToken); // ◀◀ CancellationToken 전달

            var permissionList = allPermissions.ToList();

            var response = new PermissionTreeResponse
            {
                TotalNodes = permissionList.Count,
                ActiveCount = permissionList.Count(p => p.IsActive),
                SystemPermissionCount = permissionList.Count(p => p.IsSystemPermission),
                WildcardPermissionCount = permissionList.Count(p => p.HasWildcard),
                Nodes = BuildTreeNodes(permissionList, null, 0),
                GeneratedAt = DateTime.UtcNow
            };

            // 카테고리별 집계
            response.CountByCategory = permissionList
                .GroupBy(p => p.Category)
                .ToDictionary(g => g.Key, g => g.Count());

            // 레벨별 집계
            response.CountByLevel = permissionList
                .GroupBy(p => p.Level)
                .ToDictionary(g => g.Key, g => g.Count());

            // 최대 깊이 계산
            response.MaxDepth = CalculateMaxDepth(response.Nodes);

            return response;
        }
        private string BuildPath(List<PermissionEntity> allPermissions, PermissionEntity permission)
        {
            var path = new List<string> { permission.Scope };
            var current = permission;

            while (current.ParentPermissionId.HasValue)
            {
                current = allPermissions.FirstOrDefault(p => p.Id == current.ParentPermissionId.Value);
                if (current != null)
                {
                    path.Insert(0, current.Scope);
                }
                else
                {
                    break;
                }
            }

            return string.Join(" > ", path);
        }

        #endregion
      
    }
}