using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Context;
using AuthHive.Core.Models.Common;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Provider; // ITokenService로 변경 필요
using System.Security.Claims;
using System.Linq;
using System.Collections.Generic;
using AuthHive.Core.Entities.Auth;
using System.Text.Json;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.ConnectedId.Events; // 이벤트 모델
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Enums.Core; // AuthHive 상수
using ConnectedIdContextEntity = AuthHive.Core.Entities.Auth.ConnectedIdContext;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// ConnectedId의 컨텍스트(세션, 권한, 역할 등)를 관리하는 핵심 서비스 구현체입니다. - v16 Refactored
    /// 
    /// 이 서비스의 핵심 역할:
    /// 1. Hot Cache (DTO): 빠른 성능을 위해 ICacheService에 DTO를 직접 캐싱합니다. (기존 로직 유지)
    /// 2. Persistence (Entity): 감사, 모니터링, 관리자 조회를 위해 IConnectedIdContextRepository에 엔티티를 영구 저장합니다. (신규 로직)
    /// 3. Auditing & Events: 모든 컨텍스트의 생성, 수정, 삭제, 접근 이벤트를 IAuditService와 IEventBus로 발행합니다.
    /// </summary>
    public class ConnectedIdContextService : IConnectedIdContextService
    {
        // 1. 컨텍스트 '빌드'에 필요한 원천 데이터 리포지토리
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPermissionRepository _permissionRepository;

        // 2. 컨텍스트 '영구 저장' 리포지토리
        private readonly IConnectedIdContextRepository _contextRepository;

        // 3. 인프라 및 핵심 서비스
        private readonly ICacheService _cacheService;
        private readonly ITokenService _tokenService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IPrincipalAccessor _principalAccessor; // 감사 주체 식별
        private readonly ILogger<ConnectedIdContextService> _logger;

        public ConnectedIdContextService(
            // 빌더 리포지토리
            IConnectedIdRepository connectedIdRepository,
            IRoleRepository roleRepository,
            IPermissionRepository permissionRepository,
            // 영속성 리포지토리
            IConnectedIdContextRepository contextRepository,
            ICacheService cacheService,
            ITokenService tokenService,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IEventBus eventBus,
            IAuditService auditService,
            IPrincipalAccessor principalAccessor,
            ILogger<ConnectedIdContextService> logger)
        {
            _connectedIdRepository = connectedIdRepository;
            _roleRepository = roleRepository;
            _permissionRepository = permissionRepository;
            _contextRepository = contextRepository;
            _cacheService = cacheService;
            _tokenService = tokenService;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _eventBus = eventBus;
            _auditService = auditService;
            _principalAccessor = principalAccessor;
            _logger = logger;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // 필수 서비스가 모두 주입되었는지 확인
            return Task.FromResult(
                _connectedIdRepository != null &&
                _contextRepository != null &&
                _cacheService != null &&
                _unitOfWork != null);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdContextService (v16) initialized.");
            return Task.CompletedTask;
        }

        /// <summary>
        /// ConnectedId의 현재 컨텍스트를 가져옵니다. (Hot Cache 우선)
        /// 1. ICacheService (DTO)에서 찾습니다.
        /// 2. 없으면 DB에서 새로 빌드하고, DTO는 캐시에, Entity는 DB에 저장합니다.
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDetail>> GetContextAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult<ConnectedIdContextDetail>.Failure("ConnectedId cannot be empty.");

            var contextKey = GenerateCacheKeyForContext(connectedId, ConnectedIdContextType.Permissions);

            try
            {
                // 1. Hot Cache (DTO)에서 먼저 조회
                var cachedContext = await _cacheService.GetAsync<ConnectedIdContextDetail>(contextKey, cancellationToken);
                if (cachedContext != null && !cachedContext.IsExpired)
                {
                    _logger.LogDebug("Context cache hit for ConnectedId: {ConnectedId}", connectedId);
                    // 이벤트 발행 (성능 모니터링용)
                    _ = _eventBus.PublishAsync(
                    new CacheHitEvent(contextKey, "ServiceDTO", 0), CancellationToken.None);
                }

                // 2. 캐시에 없으면 (Cache Miss) DB에서 새로 빌드하고 저장
                _logger.LogDebug("Context cache miss for ConnectedId: {ConnectedId}. Building from DB.", connectedId);
                _ = _eventBus.PublishAsync(new CacheMissEvent(contextKey, "ServiceDTO"), CancellationToken.None);
                // Build, Cache (DTO), and Persist (Entity)
                return await BuildCacheAndPersistContextAsync(connectedId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDetail>.Failure("An error occurred while getting the context.");
            }
        }

        /// <summary>
        /// 캐시와 상관없이 DB에서 직접 컨텍스트를 강제로 다시 빌드하고 갱신합니다.
        /// (DTO 캐시 갱신 및 Entity DB 저장)
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextDetail>> RefreshContextAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult<ConnectedIdContextDetail>.Failure("ConnectedId cannot be empty.");

            _logger.LogInformation("Force refreshing context for ConnectedId: {ConnectedId}", connectedId);

            try
            {
                // Build, Cache (DTO), and Persist (Entity)
                return await BuildCacheAndPersistContextAsync(connectedId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing context for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<ConnectedIdContextDetail>.Failure("An error occurred while refreshing the context.");
            }
        }

        /// <summary>
        /// 사용자가 다른 조직으로 컨텍스트를 전환합니다.
        /// </summary>
        public async Task<ServiceResult<SwitchContextResult>> SwitchOrganizationContextAsync(Guid currentConnectedId, Guid targetOrganizationId, CancellationToken cancellationToken = default)
        {
            if (currentConnectedId == Guid.Empty || targetOrganizationId == Guid.Empty)
                return ServiceResult<SwitchContextResult>.Failure("CurrentConnectedId and TargetOrganizationId cannot be empty.");

            try
            {
                var currentConnection = await _connectedIdRepository.GetByIdAsync(currentConnectedId, cancellationToken);
                if (currentConnection?.UserId == null)
                    return ServiceResult<SwitchContextResult>.Failure("Current ConnectedId not found or has no associated user.");

                var newConnection = await _connectedIdRepository.FirstOrDefaultAsync(
                    c => c.UserId == currentConnection.UserId && c.OrganizationId == targetOrganizationId, cancellationToken);

                if (newConnection == null)
                    return ServiceResult<SwitchContextResult>.Failure("User is not a member of the target organization.");

                if (newConnection.UserId == null) // null 체크 강화
                {
                    _logger.LogError("The new connection {NewConnectionId} for target organization {OrgId} has no associated UserId.", newConnection.Id, targetOrganizationId);
                    return ServiceResult<SwitchContextResult>.Failure("Target connection does not have a valid user.");
                }

                // 1. 새 조직의 컨텍스트를 강제 갱신 (빌드, 캐시, DB저장)
                var newContextResult = await RefreshContextAsync(newConnection.Id, cancellationToken);
                if (!newContextResult.IsSuccess || newContextResult.Data == null)
                    return ServiceResult<SwitchContextResult>.Failure("Failed to create context for the new organization.");

                // 2. 새 컨텍스트 기반으로 새 토큰 발급
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, newConnection.UserId.Value.ToString()),
                    new Claim(AuthConstants.ClaimTypes.ConnectedId, newConnection.Id.ToString()), // 상수 사용
                    new Claim(AuthConstants.ClaimTypes.OrganizationId, newConnection.OrganizationId.ToString()), // 상수 사용
                };

                // CORRECTED: The method now returns a 'string' directly.
                string newAccessToken = await _tokenService.GenerateAccessTokenAsync(
                    newConnection.UserId.Value,
                    newConnection.Id,
                    claims,
                    cancellationToken);

                // CORRECTED: Check if the returned string is null or empty.
                if (string.IsNullOrEmpty(newAccessToken))
                    return ServiceResult<SwitchContextResult>.Failure("Failed to generate new access token.");

                // 수정: ITokenProvider -> ITokenService
                var tokenResult = await _tokenService.GenerateAccessTokenAsync(
                    newConnection.UserId.Value,
                    newConnection.Id,
                    claims,
                    cancellationToken);

                // CORRECTED: Check if the returned string is null or empty.
                if (string.IsNullOrEmpty(newAccessToken))
                    return ServiceResult<SwitchContextResult>.Failure("Failed to generate new access token.");

                // 3. 감사 로그 기록 (누가 전환했는지)

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update, // Or a more specific type if available
                    action: "User Context Switched",
                    connectedId: newConnection.Id, // The ID of the context that was activated
                    success: true,
                    resourceType: "UserContext",
                    resourceId: newConnection.Id.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                    { "SwitchedFromOrganizationId", currentConnection.OrganizationId.ToString() },
                    { "SwitchedToOrganizationId", targetOrganizationId.ToString() },
                    { "UserId", newConnection.UserId.Value.ToString() }
                    },
                    cancellationToken: cancellationToken);

                var result = new SwitchContextResult
                {
                    NewContext = newContextResult.Data,
                    // CORRECTED: Assign the string directly.
                    NewAccessToken = newAccessToken
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
        /// 특정 ConnectedId의 컨텍스트 캐시를 무효화하고, DB의 영구 컨텍스트를 논리적으로 삭제합니다.
        /// </summary>
        public async Task<ServiceResult> InvalidateContextCacheAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult.Failure("ConnectedId cannot be empty.");

            var contextTypes = Enum.GetValues(typeof(ConnectedIdContextType)).Cast<ConnectedIdContextType>();
            var now = _dateTimeProvider.UtcNow;
            var principal = await _principalAccessor.GetPrincipalAsync(cancellationToken);
            var deletedBy = _principalAccessor.ConnectedId ?? Guid.Empty;

            try
            {
                // 1. Hot Cache (DTO) 즉시 삭제
                foreach (var type in contextTypes)
                {
                    var cacheKey = GenerateCacheKeyForContext(connectedId, type);
                    await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                }
                _logger.LogInformation("All hot context caches invalidated for ConnectedId: {ConnectedId}", connectedId);

                // 2. Persistent Context (Entity) 논리적 삭제
                // (참고: DeleteByConnectedIdAsync는 BaseRepository의 캐시 무효화 로직을 트리거해야 함)
                int deletedCount = await _contextRepository.DeleteByConnectedIdAsync(connectedId, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken); // 트랜잭션 커밋

                // 3. 감사 및 이벤트 발행
                if (deletedCount > 0)
                {
                    var connection = await _connectedIdRepository.GetByIdAsync(connectedId, CancellationToken.None);
                    var orgId = connection?.OrganizationId ?? Guid.Empty;

                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Delete, // "무효화"는 "삭제"와 의미가 가장 가까움
                        action: "Context.Invalidate",       // 수행된 작업의 이름
                        connectedId: connectedId,           // 작업의 주체
                        success: true,
                        resourceType: "UserContext",        // 영향을 받은 리소스의 종류
                        resourceId: connectedId.ToString(), // 영향을 받은 리소스의 ID
                        metadata: new Dictionary<string, object>
                        {
                            { "InvalidatedCount", deletedCount },
                            { "InvalidatedByUserId", connection?.UserId ?? Guid.Empty }
                        },
                        cancellationToken: CancellationToken.None
                    );

                    _ = _eventBus.PublishAsync(
                        new ContextDeletedEvent(connectedId, orgId, deletedBy, "Invalidated"),
                        CancellationToken.None);
                }

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
        /// [핵심 로직]
        /// 1. DB에서 역할/권한 등 원천 데이터를 조회하여 컨텍스트를 빌드합니다.
        /// 2. DTO를 생성하여 Hot Cache(ICacheService)에 저장합니다. (For Performance)
        /// 3. Entity를 생성하여 DB(IConnectedIdContextRepository)에 저장합니다. (For Auditing & Persistence)
        /// </summary>
        private async Task<ServiceResult<ConnectedIdContextDetail>> BuildCacheAndPersistContextAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // 1. 데이터 빌드 (3개의 리포지토리에서 원천 데이터 조회)
            var connection = await _connectedIdRepository.GetWithDetailsAsync(connectedId, cancellationToken);
            if (connection?.User == null || connection.Organization == null)
                return ServiceResult<ConnectedIdContextDetail>.Failure("ConnectedId details (User, Organization) not found.");

            var roles = await _roleRepository.GetByConnectedIdAsync(connectedId, cancellationToken: cancellationToken);
            var permissions = await _permissionRepository.GetPermissionsForConnectedIdAsync(connectedId, cancellationToken: cancellationToken);

            var roleNames = roles.Select(r => r.Name).ToList();
            var permissionScopes = permissions.Select(p => p.Scope).ToList();
            var contextDataPayload = new { Roles = roleNames, Permissions = permissionScopes };
            string contextDataJson = JsonSerializer.Serialize(contextDataPayload);

            var now = _dateTimeProvider.UtcNow;
            var expiration = TimeSpan.FromHours(1); // TODO: 설정에서 가져오기
            var expiresAt = now.Add(expiration);
            var contextKey = GenerateCacheKeyForContext(connectedId, ConnectedIdContextType.Permissions);

            // 2. Hot Cache용 DTO 생성 및 캐시 저장 (For Performance)
            var contextDto = new ConnectedIdContextDetail
            {
                Id = Guid.NewGuid(),
                ConnectedId = connection.Id,
                OrganizationId = connection.OrganizationId,
                ContextKey = contextKey,
                ContextType = ConnectedIdContextType.Permissions,
                ContextData = contextDataJson,
                ExpiresAt = expiresAt,
                CreatedAt = now,
                IsHotPath = true
            };

            await _cacheService.SetAsync(contextDto.ContextKey, contextDto, expiration, cancellationToken);
            _logger.LogInformation("Permission context DTO built and cached for ConnectedId: {ConnectedId}", connectedId);

            // 3. 영구 저장을 위한 Entity 생성 및 DB 저장 (For Auditing)
            try
            {
                var existingEntity = await _contextRepository.FirstOrDefaultAsync(c => c.ContextKey == contextKey, cancellationToken);

                // CORRECTED: GetPrincipalAsync() 대신 IPrincipalAccessor의 속성을 직접 사용합니다.
                // 이렇게 하면 확장 메서드가 필요 없어지고 코드가 인터페이스의 의도에 더 잘 맞게 됩니다.
                Guid? actorConnectedId = _principalAccessor.ConnectedId;

                if (existingEntity != null)
                {
                    // 업데이트
                    var oldContextData = existingEntity.ContextData; // 변경 추적을 위해 이전 데이터 저장
                    existingEntity.ContextData = contextDataJson;
                    existingEntity.ExpiresAt = expiresAt;
                    existingEntity.LastAccessedAt = now;
                    existingEntity.AccessCount++;
                    existingEntity.Checksum = GenerateChecksum(contextDataJson);

                    await _contextRepository.UpdateAsync(existingEntity, cancellationToken);
                    await _unitOfWork.SaveChangesAsync(cancellationToken);

                    // CORRECTED: 올바른 이벤트(ContextUpdatedEvent)를 생성하여 발행합니다.
                    var changes = new Dictionary<string, object>
                {
                    { "ContextData", new { Old = oldContextData, New = contextDataJson } }, // 더 상세한 변경 내용
                    { "LastAccessedAt", now }
                };

                    _ = _eventBus.PublishAsync(new ContextUpdatedEvent(
                        connectedId: existingEntity.ConnectedId,
                        organizationId: existingEntity.OrganizationId,
                        updatedBy: actorConnectedId ?? Guid.Empty, // 작업을 수행한 주체
                        changes: changes
                    ), CancellationToken.None);
                }
                else
                {
                    // 신규 생성
                    // CORRECTED: using alias로 지정한 ConnectedIdContextEntity를 사용합니다.
                    var newEntity = new ConnectedIdContextEntity
                    {
                        Id = Guid.NewGuid(),
                        ConnectedId = connection.Id,
                        OrganizationId = connection.OrganizationId,
                        UserId = connection.UserId,
                        SessionId = _principalAccessor.SessionId, // CORRECTED: GetSessionId() 대신 속성 직접 사용
                        ApplicationId = null,
                        ContextKey = contextKey,
                        ContextType = ConnectedIdContextType.Permissions,
                        ContextData = contextDataJson,
                        ExpiresAt = expiresAt,
                        LastAccessedAt = now,
                        AccessCount = 1,
                        Priority = 5, // Constants 사용 예시
                        Checksum = GenerateChecksum(contextDataJson),
                        IsHotPath = true
                    };

                    await _contextRepository.AddAsync(newEntity, cancellationToken);
                    await _unitOfWork.SaveChangesAsync(cancellationToken);

                    // CORRECTED: 올바른 이벤트(ContextCreatedEvent)를 생성하여 발행합니다.
                    _ = _eventBus.PublishAsync(new ContextCreatedEvent(
                       connectedId: newEntity.ConnectedId,
                       organizationId: newEntity.OrganizationId,
                       createdBy: actorConnectedId ?? Guid.Empty, // 작업을 수행한 주체
                       contextType: newEntity.ContextType,
                       applicationId: newEntity.ApplicationId
                    ), CancellationToken.None);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to persist context entity for ConnectedId: {ConnectedId}. Hot cache (DTO) was set, but persistence failed.", connectedId);
            }

            return ServiceResult<ConnectedIdContextDetail>.Success(contextDto);
        }
        /// <summary>
        /// 컨텍스트 캐시 키를 생성하는 헬퍼 메서드입니다. 일관된 키 형식을 보장합니다.
        /// </summary>
        private string GenerateCacheKeyForContext(Guid connectedId, ConnectedIdContextType contextType, Guid? applicationId = null)
        {
            // 상수를 사용하여 키 형식 정의
            var key = $"{ConnectedIdConstants.Cache.ContextCacheKeyPrefix}:{connectedId}:{contextType}";
            if (applicationId.HasValue)
            {
                key += $":app:{applicationId}";
            }
            return key;
        }

        /// <summary>
        /// 컨텍스트 데이터 무결성 검증용 체크섬 생성
        /// (이 로직은 ConnectedIdContextRepository에도 존재하므로, 공통 유틸리티로 분리하는 것이 좋습니다)
        /// </summary>
        private string GenerateChecksum(string contextData)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(contextData));
            return Convert.ToBase64String(hashBytes)[..16]; // 16자리로 단축
        }
    }
}