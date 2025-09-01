using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Context;
using AuthHive.Core.Models.Common;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AutoMapper;
using AuthHive.Core.Interfaces.Auth.Provider;
using System.Security.Claims;
using System.Linq;
using AuthHive.Core.Entities.Auth;
using System.Collections.Generic;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// 사용자의 세션 컨텍스트(역할, 권한 등)를 관리하는 서비스 구현체입니다.
    /// </summary>
    public class ConnectedIdContextService : IConnectedIdContextService
    {
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPermissionRepository _permissionRepository;
        private readonly ICacheService _cacheService;
        private readonly ITokenProvider _tokenProvider;
        private readonly IMapper _mapper;
        private readonly ILogger<ConnectedIdContextService> _logger;

        public ConnectedIdContextService(
            IConnectedIdRepository connectedIdRepository,
            IRoleRepository roleRepository,
            IPermissionRepository permissionRepository,
            ICacheService cacheService,
            ITokenProvider tokenProvider,
            IMapper mapper,
            ILogger<ConnectedIdContextService> logger)
        {
            _connectedIdRepository = connectedIdRepository;
            _roleRepository = roleRepository;
            _permissionRepository = permissionRepository;
            _cacheService = cacheService;
            _tokenProvider = tokenProvider;
            _mapper = mapper;
            _logger = logger;
        }

        /// <summary>
        /// 서비스가 정상 상태인지 확인합니다.
        /// </summary>
        public Task<bool> IsHealthyAsync()
        {
            // 데이터베이스 및 캐시 서비스에 대한 기본 연결 확인
            return Task.FromResult(_connectedIdRepository != null && _cacheService != null);
        }

        /// <summary>
        /// 서비스 초기화 로직 (필요 시 구현)
        /// </summary>
        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdContextService initialized.");
            return Task.CompletedTask;
        }


        /// <summary>
        /// 지정된 ConnectedId에 대한 현재 컨텍스트를 가져옵니다.
        /// 캐시를 먼저 확인하고, 없으면 DB에서 생성 후 캐시에 저장합니다.
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDto>> GetContextAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
            {
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId cannot be empty.");
            }

            var cacheKey = GenerateCacheKey(connectedId);

            try
            {
                // 1. 캐시에서 먼저 조회
                var cachedContext = await _cacheService.GetAsync<ConnectedIdContextDto>(cacheKey);
                if (cachedContext != null)
                {
                    _logger.LogDebug("Context cache hit for ConnectedId: {ConnectedId}", connectedId);
                    return ServiceResult<ConnectedIdContextDto>.Success(cachedContext);
                }

                _logger.LogDebug("Context cache miss for ConnectedId: {ConnectedId}. Building from DB.", connectedId);

                // 2. 캐시에 없으면 DB에서 컨텍스트를 빌드
                return await BuildAndCacheContextAsync(connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDto>.Failure("An error occurred while getting the context.");
            }
        }

        /// <summary>
        /// DB에서 직접 컨텍스트를 새로고침하고 캐시를 업데이트합니다.
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDto>> RefreshContextAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
            {
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId cannot be empty.");
            }
            
            _logger.LogInformation("Force refreshing context for ConnectedId: {ConnectedId}", connectedId);

            try
            {
                // 캐시 조회를 건너뛰고 바로 DB에서 빌드 및 캐싱
                return await BuildAndCacheContextAsync(connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDto>.Failure("An error occurred while refreshing the context.");
            }
        }
        
        /// <summary>
        /// 사용자의 조직 컨텍스트를 전환하고 새 토큰을 발급합니다.
        /// </summary>
        public async Task<ServiceResult<SwitchContextResult>> SwitchOrganizationContextAsync(Guid currentConnectedId, Guid targetOrganizationId)
        {
            if (currentConnectedId == Guid.Empty || targetOrganizationId == Guid.Empty)
            {
                return ServiceResult<SwitchContextResult>.Failure("CurrentConnectedId and TargetOrganizationId cannot be empty.");
            }

            try
            {
                // 1. 현재 ConnectedId 정보로 UserId 조회
                var currentConnection = await _connectedIdRepository.GetByIdAsync(currentConnectedId);
                if (currentConnection == null)
                {
                    return ServiceResult<SwitchContextResult>.Failure("Current ConnectedId not found.");
                }

                // 2. UserId와 TargetOrganizationId로 전환할 새로운 ConnectedId 조회
                var newConnection = await _connectedIdRepository.FirstOrDefaultAsync(
                    c => c.UserId == currentConnection.UserId && c.OrganizationId == targetOrganizationId
                );

                if (newConnection == null)
                {
                    return ServiceResult<SwitchContextResult>.Failure("User is not a member of the target organization.");
                }

                // 3. 새로운 ConnectedId에 대한 컨텍스트를 강제로 새로고침 (캐시 업데이트)
                var newContextResult = await RefreshContextAsync(newConnection.Id);
                if (!newContextResult.IsSuccess || newContextResult.Data == null)
                {
                    return ServiceResult<SwitchContextResult>.Failure("Failed to create context for the new organization.");
                }

                // 4. 새로운 컨텍스트 정보로 새 토큰 생성
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, newConnection.UserId.ToString()),
                    new Claim("sub", newConnection.UserId.ToString()),
                    new Claim("connected_id", newConnection.Id.ToString()),
                    new Claim("org_id", newConnection.OrganizationId.ToString()),
                    // 필요 시 추가 클레임 (예: 세션 ID)
                };

                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(claims);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                     return ServiceResult<SwitchContextResult>.Failure("Failed to generate new access token.");
                }

                var result = new SwitchContextResult
                {
                    NewContext = newContextResult.Data,
                    NewAccessToken = tokenResult.Data.Token
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
        /// 컨텍스트 캐시를 무효화합니다.
        /// </summary>
        public async Task<ServiceResult> InvalidateContextCacheAsync(Guid connectedId)
        {
            if (connectedId == Guid.Empty)
            {
                return ServiceResult.Failure("ConnectedId cannot be empty.");
            }
            
            var cacheKey = GenerateCacheKey(connectedId);
            try
            {
                await _cacheService.RemoveAsync(cacheKey);
                _logger.LogInformation("Context cache invalidated for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating cache for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Failure("An error occurred while invalidating the cache.");
            }
        }
        
        // --- Private Helper Methods ---

        /// <summary>
        /// 데이터베이스에서 컨텍스트 정보를 빌드하고 캐시에 저장합니다.
        /// </summary>
        private async Task<ServiceResult<ConnectedIdContextDto>> BuildAndCacheContextAsync(Guid connectedId)
        {
            // 1. DB에서 필수 정보 조회
            var connection = await _connectedIdRepository.GetWithDetailsAsync(connectedId);
            if (connection == null || connection.User == null || connection.Organization == null)
            {
                return ServiceResult<ConnectedIdContextDto>.Failure("ConnectedId, User, or Organization not found.");
            }

            // 2. 역할 및 권한 조회
            var roles = await _roleRepository.GetRolesForConnectedIdAsync(connectedId);
            var permissions = await _permissionRepository.GetPermissionsForConnectedIdAsync(connectedId);

            // 3. DTO 생성
            var contextDto = new ConnectedIdContextDto
            {
                ConnectedId = connection.Id,
                UserId = connection.UserId,
                OrganizationId = connection.OrganizationId,
                OrganizationName = connection.Organization.Name,
                Roles = roles.Select(r => r.Name).ToList(),
                Permissions = permissions.Select(p => p.PermissionScope).ToList(),
                LastRefreshedAt = DateTime.UtcNow
            };

            // 4. 캐시에 저장 (예: 1시간 동안)
            var cacheKey = GenerateCacheKey(connectedId);
            await _cacheService.SetAsync(cacheKey, contextDto, TimeSpan.FromHours(1));
            _logger.LogInformation("Context built and cached for ConnectedId: {ConnectedId}", connectedId);

            return ServiceResult<ConnectedIdContextDto>.Success(contextDto);
        }

        /// <summary>
        /// 일관된 캐시 키를 생성합니다.
        /// </summary>
        private string GenerateCacheKey(Guid connectedId)
        {
            return $"context:{connectedId}";
        }
    }
}