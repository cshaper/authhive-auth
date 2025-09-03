using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Context;
using AuthHive.Core.Models.Common;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Provider;
using System.Security.Claims;
using System.Linq;
using System.Collections.Generic;
using AuthHive.Core.Entities.Auth;
using System.Text.Json;
using AuthHive.Core.Enums.Auth;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// ConnectedId의 컨텍스트(세션, 권한, 역할 등)를 관리하는 핵심 서비스 구현체입니다.
    /// 데이터베이스에서 원본 데이터를 조회하고, 성능 최적화를 위해 캐시에 저장하며,
    /// 조직 간 컨텍스트 전환을 처리하는 비즈니스 로직을 담당합니다.
    /// </summary>
    public class ConnectedIdContextService : IConnectedIdContextService
    {
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPermissionRepository _permissionRepository;
        private readonly ICacheService _cacheService;
        private readonly ITokenProvider _tokenProvider;
        private readonly ILogger<ConnectedIdContextService> _logger;

        public ConnectedIdContextService(
            IConnectedIdRepository connectedIdRepository,
            IRoleRepository roleRepository,
            IPermissionRepository permissionRepository,
            ICacheService cacheService,
            ITokenProvider tokenProvider,
            ILogger<ConnectedIdContextService> logger)
        {
            _connectedIdRepository = connectedIdRepository;
            _roleRepository = roleRepository;
            _permissionRepository = permissionRepository;
            _cacheService = cacheService;
            _tokenProvider = tokenProvider;
            _logger = logger;
        }

        public Task<bool> IsHealthyAsync()
        {
            // 필수 리포지토리와 캐시 서비스가 존재하는지 확인하여 서비스 상태를 반환합니다.
            return Task.FromResult(_connectedIdRepository != null && _cacheService != null);
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdContextService initialized.");
            return Task.CompletedTask;
        }

        /// <summary>
        /// ConnectedId의 현재 컨텍스트를 가져옵니다.
        /// 먼저 캐시에서 찾고, 없으면 DB에서 새로 빌드하여 가져옵니다.
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDto>> GetContextAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId cannot be empty.");

            // 권한 컨텍스트를 위한 고유 캐시 키 생성
            var cacheKey = GenerateCacheKeyForContext(connectedId, ConnectedIdContextType.Permissions);
            
            try
            {
                // 1. 캐시에서 먼저 컨텍스트를 찾아봅니다.
                var cachedContext = await _cacheService.GetAsync<ConnectedIdContextDto>(cacheKey);
                if (cachedContext != null && !cachedContext.IsExpired)
                {
                    _logger.LogDebug("Context cache hit for ConnectedId: {ConnectedId}", connectedId);
                    return ServiceResult<ConnectedIdContextDto>.Success(cachedContext);
                }

                // 2. 캐시에 없으면 DB에서 새로 빌드합니다.
                _logger.LogDebug("Context cache miss for ConnectedId: {ConnectedId}. Building from DB.", connectedId);
                return await BuildAndCachePermissionContextAsync(connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDto>.Failure("An error occurred while getting the context.");
            }
        }

        /// <summary>
        /// 캐시와 상관없이 DB에서 직접 컨텍스트를 강제로 다시 빌드하고 갱신합니다.
        /// 역할이나 권한이 변경되었을 때 즉시 적용하기 위해 사용됩니다.
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDto>> RefreshContextAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId cannot be empty.");

            _logger.LogInformation("Force refreshing context for ConnectedId: {ConnectedId}", connectedId);

            try
            {
                // 캐시를 무시하고 DB에서 컨텍스트를 빌드하는 내부 메서드 호출
                return await BuildAndCachePermissionContextAsync(connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDto>.Failure("An error occurred while refreshing the context.");
            }
        }

        /// <summary>
        /// 사용자가 다른 조직으로 컨텍스트를 전환할 때 호출됩니다.
        /// 새로운 조직에 맞는 새 컨텍스트와 새 액세스 토큰을 발급합니다.
        /// </summary>
        public async Task<ServiceResult<SwitchContextResult>> SwitchOrganizationContextAsync(Guid currentConnectedId, Guid targetOrganizationId)
        {
            if (currentConnectedId == Guid.Empty || targetOrganizationId == Guid.Empty)
                return ServiceResult<SwitchContextResult>.Failure("CurrentConnectedId and TargetOrganizationId cannot be empty.");

            try
            {
                // 1. 현재 사용자의 정보를 조회합니다.
                var currentConnection = await _connectedIdRepository.GetByIdAsync(currentConnectedId);
                if (currentConnection == null)
                    return ServiceResult<SwitchContextResult>.Failure("Current ConnectedId not found.");

                // 2. 사용자가 전환하려는 조직의 멤버인지 확인합니다. (같은 UserID를 가졌는지 체크)
                var newConnection = await _connectedIdRepository.FirstOrDefaultAsync(
                    c => c.UserId == currentConnection.UserId && c.OrganizationId == targetOrganizationId);

                if (newConnection == null)
                    return ServiceResult<SwitchContextResult>.Failure("User is not a member of the target organization.");
                
                // 3. 새로운 조직에 맞는 컨텍스트를 생성합니다.
                var newContextResult = await RefreshContextAsync(newConnection.Id);
                if (!newContextResult.IsSuccess || newContextResult.Data == null)
                    return ServiceResult<SwitchContextResult>.Failure("Failed to create context for the new organization.");

                // 4. 새로운 컨텍스트 정보(ConnectedId, OrgId 등)를 담은 새 액세스 토큰을 발급합니다.
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, newConnection.UserId.ToString()),
                    new Claim("connected_id", newConnection.Id.ToString()),
                    new Claim("org_id", newConnection.OrganizationId.ToString()),
                };

                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(newConnection.UserId, newConnection.Id, claims);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                    return ServiceResult<SwitchContextResult>.Failure("Failed to generate new access token.");

                // 5. 최종 결과를 DTO에 담아 반환합니다.
                var result = new SwitchContextResult
                {
                    NewContext = newContextResult.Data,
                    NewAccessToken = tokenResult.Data.AccessToken
                };

                return ServiceResult<SwitchContextResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error switching organization context for ConnectedId: {ConnectedId}", currentConnectedId);
                return ServiceResult<SwitchContextResult>.Failure("An error occurred while switching context.");
            }
        }
        
        /// <summary>
        /// 특정 사용자의 모든 컨텍스트 캐시를 삭제합니다.
        /// 역할/권한 변경 시 호출하여 오래된 캐시 정보를 제거합니다.
        /// </summary>
        public async Task<ServiceResult> InvalidateContextCacheAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult.Failure("ConnectedId cannot be empty.");
            
            // 향후 추가될 다른 컨텍스트 타입(설정, 기능 플래그 등)도 모두 삭제하도록 확장 가능
            var contextTypes = Enum.GetValues(typeof(ConnectedIdContextType)).Cast<ConnectedIdContextType>();
            try
            {
                foreach (var type in contextTypes)
                {
                    var cacheKey = GenerateCacheKeyForContext(connectedId, type);
                    await _cacheService.RemoveAsync(cacheKey);
                }
                _logger.LogInformation("All context caches invalidated for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating cache for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Failure("An error occurred while invalidating the cache.");
            }
        }
        
        /// <summary>
        /// 데이터베이스에서 역할과 권한 정보를 조회하여 컨텍스트를 만들고 캐시에 저장하는 핵심 내부 메서드입니다.
        /// </summary>
        private async Task<ServiceResult<ConnectedIdContextDto>> BuildAndCachePermissionContextAsync(Guid connectedId)
        {
            // 1. 필요한 모든 정보를 DB에서 한 번에 조회합니다.
            var connection = await _connectedIdRepository.GetWithDetailsAsync(connectedId);
            if (connection?.User == null || connection.Organization == null)
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId details (User, Organization) not found.");

            var roles = await _roleRepository.GetByConnectedIdAsync(connectedId);
            var permissions = await _permissionRepository.GetPermissionsForConnectedIdAsync(connectedId);
             
            // 2. 조회한 정보를 DTO가 요구하는 형식으로 가공합니다.
            var roleNames = roles.Select(r => r.Name).ToList();
            var permissionScopes = permissions.Select(p => p.Scope).ToList();

            // 3. 유연한 확장을 위해 실제 데이터는 JSON 객체로 만듭니다.
            var contextData = new
            {
                Roles = roleNames,
                Permissions = permissionScopes
            };
            
            // 4. 최종 DTO를 생성합니다.
            var contextDto = new ConnectedIdContextDto
            {
                Id = Guid.NewGuid(), // 컨텍스트 자체의 고유 ID
                ConnectedId = connection.Id,
                OrganizationId = connection.OrganizationId,
                ContextKey = GenerateCacheKeyForContext(connectedId, ConnectedIdContextType.Permissions),
                ContextType = ConnectedIdContextType.Permissions,
                ContextData = JsonSerializer.Serialize(contextData), // JSON 문자열로 직렬화하여 저장
                ExpiresAt = DateTime.UtcNow.AddHours(1), // 예시: 1시간 유효기간
                CreatedAt = DateTime.UtcNow,
                IsHotPath = true // 권한 컨텍스트는 항상 자주 사용되므로 Hot Path로 표시
            };
            
            // 5. 생성된 DTO를 캐시에 저장합니다.
            await _cacheService.SetAsync(contextDto.ContextKey, contextDto, TimeSpan.FromHours(1));
            _logger.LogInformation("Permission context built and cached for ConnectedId: {ConnectedId}", connectedId);

            return ServiceResult<ConnectedIdContextDto>.Success(contextDto);
        }

        /// <summary>
        /// 컨텍스트 캐시 키를 생성하는 헬퍼 메서드입니다. 일관된 키 형식을 보장합니다.
        /// 예: "context:사용자ID:권한"
        /// </summary>
        private string GenerateCacheKeyForContext(Guid connectedId, ConnectedIdContextType contextType, Guid? applicationId = null)
        {
            var key = $"context:{connectedId}:{contextType}";
            if (applicationId.HasValue)
            {
                key += $":{applicationId}";
            }
            return key;
        }
    }
}
