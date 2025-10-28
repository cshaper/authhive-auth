// File: AuthHive.Auth/Services/Handlers/Role/InvalidateOrganizationRoleListCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.Auth.Role.Events; // OrganizationRolesChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Role
{
    /// <summary>
    /// OrganizationRolesChangedEvent 발생 시 조직 단위의 역할 목록 캐시를 무효화합니다.
    /// (대부분의 역할 정의 변경 이벤트에서 간접적으로 호출될 수 있음)
    /// </summary>
    public class InvalidateOrganizationRoleListCacheHandler :
        IDomainEventHandler<OrganizationRolesChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateOrganizationRoleListCacheHandler> _logger;
        // 조직 역할 목록 캐시 키 패턴 (예시: Role:list:{OrgId})
        private const string ORG_ROLES_LIST_KEY_FORMAT = "{0}list:{1}"; 

        public int Priority => 5; // 로깅보다 우선
        public bool IsEnabled => true;

        public InvalidateOrganizationRoleListCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateOrganizationRoleListCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task HandleAsync(OrganizationRolesChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;

            try
            {
                // 조직 역할 목록 캐시 키 생성
                var cacheKey = string.Format(ORG_ROLES_LIST_KEY_FORMAT, AuthConstants.CacheKeys.RolePrefix, organizationId);
                
                _logger.LogInformation(
                    "Invalidating organization role list cache for Org: {OrgId}, Key: {CacheKey}",
                    organizationId, cacheKey);

                // 캐시 제거
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating organization role list cache for Org {OrgId} was canceled.", organizationId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate organization role list cache for Org: {OrgId}", organizationId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}