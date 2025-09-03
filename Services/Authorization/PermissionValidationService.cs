using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Core.PlatformApplication.Repository;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Entities.PlatformApplications; // UserPlatformApplicationAccess 엔티티 사용을 위해 추가

namespace AuthHive.Auth.Services.Authorization
{
    public class PermissionValidationService : IPermissionValidationService
    {
        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IRoleService _roleService;
        private readonly ILogger<PermissionValidationService> _logger;

        public PermissionValidationService(
            IUserPlatformApplicationAccessRepository accessRepository,
            IRoleService roleService,
            ILogger<PermissionValidationService> logger)
        {
            _accessRepository = accessRepository;
            _roleService = roleService;
            _logger = logger;
        }

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _roleService.GetPermissionsAsync(Guid.Empty, false);
                return _accessRepository != null && _roleService != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PermissionValidationService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("PermissionValidationService initialized.");
            return Task.CompletedTask;
        }

        public async Task<ServiceResult<bool>> HasAllPermissionsAsync(PermissionValidationRequest request)
        {
            var validationResult = await ValidatePermissionsAsync(request);

            if (!validationResult.IsSuccess || validationResult.Data == null)
            {
                return ServiceResult<bool>.Failure(validationResult.ErrorMessage ?? "Validation failed.");
            }

            return ServiceResult<bool>.Success(validationResult.Data.IsAllowed);
        }

        public async Task<ServiceResult<PermissionValidationResponse>> ValidatePermissionsAsync(PermissionValidationRequest request)
        {
            var stopwatch = Stopwatch.StartNew();
            var response = new PermissionValidationResponse 
            { 
                RequestId = request.RequestId,
                CacheStatus = PermissionCacheStatus.Miss // 캐싱 구현 전 기본값
            };

            try
            {
                // 중요: Repository는 Role 정보를 Eager Load 해야 합니다 (.Include(x => x.Role)).
                var accessInfo = await _accessRepository.GetByConnectedIdAndApplicationAsync(request.ConnectedId, request.ApplicationId ?? Guid.Empty);
                
                if (accessInfo == null || !accessInfo.IsActive)
                {
                    response.IsAllowed = false;
                    response.ValidationResult = PermissionValidationResult.ApplicationAccessDenied;
                    response.DenialReason = "User has no active access to the application.";
                    FinalizeResponse(stopwatch, response);
                    return ServiceResult<PermissionValidationResponse>.Success(response);
                }

                var rolePermissions = new List<string>();
                if (accessInfo.RoleId.HasValue)
                {
                    var rolePermsResult = await _roleService.GetPermissionsAsync(accessInfo.RoleId.Value, request.IncludeInheritedPermissions);
                    if (rolePermsResult.IsSuccess && rolePermsResult.Data != null)
                    {
                        rolePermissions = rolePermsResult.Data.Select(p => p.Scope).ToList();
                        response.AppliedRoles.Add(new AppliedRole { RoleId = accessInfo.RoleId.Value, RoleName = accessInfo.Role?.Name ?? "N/A" });
                    }
                    else
                    {
                        _logger.LogWarning("Failed to fetch permissions for RoleId {RoleId}.", accessInfo.RoleId.Value);
                    }
                }

                var excludedPermissions = SafeDeserializePermissions(accessInfo.ExcludedPermissions, nameof(accessInfo.ExcludedPermissions), accessInfo.Id);
                var additionalPermissions = SafeDeserializePermissions(accessInfo.AdditionalPermissions, nameof(accessInfo.AdditionalPermissions), accessInfo.Id);

                foreach (var scope in request.Scopes)
                {
                    var (result, source) = ApplyPermissionWaterfall(
                        scope,
                        accessInfo, // accessInfo 전체를 전달하여 RoleId 존재 여부 확인
                        excludedPermissions,
                        additionalPermissions,
                        rolePermissions
                    );

                    response.ValidatedScopes.Add(new ValidatedScope
                    {
                        RequestedScope = scope,
                        IsAllowed = result == PermissionValidationResult.Granted,
                        PermissionSource = source
                    });
                }

                var firstDenial = response.ValidatedScopes.FirstOrDefault(s => !s.IsAllowed);
                if (firstDenial != null)
                {
                    response.IsAllowed = false;
                    response.ValidationResult = firstDenial.PermissionSource == "ExcludedPermissions" 
                        ? PermissionValidationResult.PolicyViolation 
                        : PermissionValidationResult.NoPermission;
                    response.DenialReason = $"Permission denied for scope: {firstDenial.RequestedScope} (Source: {firstDenial.PermissionSource})";
                }
                else
                {
                    response.IsAllowed = true;
                    response.ValidationResult = PermissionValidationResult.Granted;
                }

                FinalizeResponse(stopwatch, response);
                return ServiceResult<PermissionValidationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during permission validation for ConnectedId {ConnectedId}", request.ConnectedId);
                response.IsAllowed = false;
                response.ValidationResult = PermissionValidationResult.SystemError;
                response.DenialReason = "An unexpected error occurred during validation.";
                response.CacheStatus = PermissionCacheStatus.Error;
                FinalizeResponse(stopwatch, response);
                return ServiceResult<PermissionValidationResponse>.FailureWithData("An unexpected error occurred.", response);
            }
        }

        private void FinalizeResponse(Stopwatch stopwatch, PermissionValidationResponse response)
        {
            stopwatch.Stop();
            response.ValidationDurationMs = stopwatch.ElapsedMilliseconds;
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
                _logger.LogWarning(ex, "Failed to deserialize {PropertyName} JSON for UserPlatformApplicationAccess ID {AccessId}.", propertyName, accessInfoId);
                return new List<string>();
            }
        }
        
        /// <summary>
        /// 권한 폭포수 모델 로직을 적용하고 검증 결과와 결정 출처를 반환합니다.
        /// </summary>
        private (PermissionValidationResult Result, string Source) ApplyPermissionWaterfall(
            string requiredScope,
            UserPlatformApplicationAccess accessInfo, // RoleId 존재 여부 확인을 위해 accessInfo 전체를 받음
            List<string> excludedPermissions,
            List<string> additionalPermissions,
            List<string> rolePermissions)
        {
            // 1단계: 절대적 거부 (ExcludedPermissions)
            if (excludedPermissions.Any(scope => ScopeMatches(requiredScope, scope)))
            {
                return (PermissionValidationResult.PolicyViolation, "ExcludedPermissions");
            }

            // 2단계: 직접적 허용 (AdditionalPermissions)
            if (additionalPermissions.Any(scope => ScopeMatches(requiredScope, scope)))
            {
                return (PermissionValidationResult.Granted, "AdditionalPermissions");
            }

            // 3단계: 역할 기반 확인 (Role)
            if (accessInfo.RoleId.HasValue) // ★★★ 핵심 수정: 역할이 할당되었는지 먼저 확인
            {
                // 역할이 할당되었다면, 이 단계에서 반드시 결정이 나야 함 (가이드 규칙)
                if (rolePermissions.Any(scope => ScopeMatches(requiredScope, scope)))
                {
                    return (PermissionValidationResult.Granted, "Role"); // 역할이 권한을 가짐 -> 허용
                }
                else
                {
                    // 역할이 권한을 가지지 않음 -> 거부. 4단계로 넘어가지 않음.
                    return (PermissionValidationResult.NoPermission, "Role (Denied)"); 
                }
            }

            // 4단계: 기본 수준 확인 (AccessLevel) - 역할이 할당되지 않았을 때만 도달
            if (accessInfo.AccessLevel == ApplicationAccessLevel.Admin ||
                accessInfo.AccessLevel == ApplicationAccessLevel.Owner)
            {
                return (PermissionValidationResult.Granted, "AccessLevel");
            }

            // 모든 단계에서 허용되지 않음
            return (PermissionValidationResult.NoPermission, "None");
        }

        /// <summary>
        /// 요청된 권한(requiredScope)을 사용자의 권한(userScope)으로 수행할 수 있는지 확인합니다.
        /// 계층 구조와 와일드카드('*')를 지원합니다.
        /// </summary>
        /// <param name="requiredScope">수행하려는 작업에 필요한 권한 (예: "organization:application:resource:read")</param>
        /// <param name="userScope">사용자가 보유한 권한 (예: "organization:application:*")</param>
        /// <returns>권한 보유 여부</returns>
        private bool ScopeMatches(string requiredScope, string userScope)
        {
            // 1. 간단한 엣지 케이스 처리
            if (string.IsNullOrWhiteSpace(requiredScope) || string.IsNullOrWhiteSpace(userScope))
            {
                return false;
            }

            // 사용자가 최상위 와일드카드 권한을 가지고 있으면 모든 작업이 가능합니다.
            if (userScope == "*")
            {
                return true;
            }

            // 2. 스코프를 계층 구조로 분할
            var requiredParts = requiredScope.Split(':');
            var userParts = userScope.Split(':');

            // 3. 사용자 권한의 각 부분을 순회하며 비교
            for (int i = 0; i < userParts.Length; i++)
            {
                // 3a. 사용자 권한 부분에 와일드카드가 있는 경우
                // (예: userScope="a:b:*", requiredScope="a:b:c")
                // 와일드카드 이전까지의 모든 부분이 일치했으므로, 권한이 있다고 판단합니다.
                if (userParts[i] == "*")
                {
                    return true;
                }

                // 3b. 필요한 권한이 사용자 권한보다 덜 구체적인 경우
                // (예: userScope="a:b:c", requiredScope="a:b")
                // 사용자의 세부 권한이 상위의 포괄적인 권한을 포함하지 않으므로 거부합니다.
                if (i >= requiredParts.Length)
                {
                    return false;
                }

                // 3c. 각 부분의 문자열이 일치하지 않는 경우
                // (예: userScope="a:b:c", requiredScope="a:d:c")
                // 다른 권한 계층이므로 거부합니다.
                if (!string.Equals(requiredParts[i], userParts[i], StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            // 4. 모든 루프를 통과한 경우 (userScope가 requiredScope의 접두사인 경우)
            // (예: userScope="a:b", requiredScope="a:b:c")
            // 두 스코프의 길이가 정확히 같을 때만 '정확한 일치'로 허용합니다.
            // 사용자의 권한이 더 포괄적이지 않으므로 거부합니다.
            return requiredParts.Length == userParts.Length;
        }
    }
}