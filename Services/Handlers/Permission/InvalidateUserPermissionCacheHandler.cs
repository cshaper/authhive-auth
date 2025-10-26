// File: AuthHive.Auth/Services/Handlers/Permission/InvalidateUserPermissionCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.Auth.Permissions.Events; // 권한 이벤트
using AuthHive.Core.Models.Auth.Role.Events; // 역할 이벤트
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
// 역할 변경/삭제 시 영향받는 사용자 조회를 위한 Repository 인터페이스 (필요시 using 추가)
// using AuthHive.Core.Interfaces.PlatformApplication.Repository;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 사용자 권한 또는 역할 변경 시 관련 사용자별 권한 캐시를 무효화합니다.
    /// (Permission 및 Role 관련 이벤트 구독)
    /// </summary>
    public class InvalidateUserPermissionCacheHandler :
        // Permission Events
        IDomainEventHandler<PermissionGrantedEvent>,
        IDomainEventHandler<PermissionRevokedEvent>,
        IDomainEventHandler<PermissionExpiredEvent>,
        IDomainEventHandler<PermissionDelegatedEvent>,
        IDomainEventHandler<PermissionInheritedEvent>,
        // Role Events (역할 변경도 사용자 권한에 영향을 미침)
        IDomainEventHandler<RoleAssignedEvent>,
        IDomainEventHandler<RoleRemovedEvent>,
        IDomainEventHandler<RoleChangedEvent>, // 역할 정의 변경 시 영향받는 모든 사용자 캐시 무효화
        IDomainEventHandler<RoleDeletedEvent>, // 역할 삭제 시 영향받는 모든 사용자 캐시 무효화
        IService
    {
        private readonly ICacheService _cacheService;
        // 역할 변경/삭제 시 영향받는 사용자 조회를 위한 Repository (선택적)
        // private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly ILogger<InvalidateUserPermissionCacheHandler> _logger;

        // 캐시 무효화는 다른 작업들(로깅 제외)보다 먼저 수행 (5)
        public int Priority => 5;
        public bool IsEnabled => true;

        public InvalidateUserPermissionCacheHandler(
            ICacheService cacheService,
            // IUserPlatformApplicationAccessRepository accessRepository, // 필요시 주입
            ILogger<InvalidateUserPermissionCacheHandler> logger)
        {
            _cacheService = cacheService;
            // _accessRepository = accessRepository;
            _logger = logger;
        }

        // --- Permission Events Handlers ---
        public Task HandleAsync(PermissionGrantedEvent @event, CancellationToken cancellationToken = default) =>
            InvalidateCacheInternalAsync(@event.ConnectedId ?? @event.UserId, $"granted:{@event.PermissionScope}", cancellationToken);

        public Task HandleAsync(PermissionRevokedEvent @event, CancellationToken cancellationToken = default) =>
            InvalidateCacheInternalAsync(@event.ConnectedId ?? @event.UserId, $"revoked:{@event.PermissionScope}", cancellationToken);

        public async Task HandleAsync(PermissionExpiredEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.ExpiredPermissions != null)
            {
                var tasks = @event.ExpiredPermissions.Select(scope =>
                    InvalidateCacheInternalAsync(@event.UserId, $"expired:{scope}", cancellationToken));
                await Task.WhenAll(tasks);
                 _logger.LogInformation("Invalidated cache for {Count} expired permissions for User {UserId}", @event.ExpiredPermissions.Count, @event.UserId);
            }
        }

        public async Task HandleAsync(PermissionDelegatedEvent @event, CancellationToken cancellationToken = default)
        {
            // ❗️ 수정됨: ConnectedId 대신 UserId 사용
            var delegatorId = @event.DelegatorUserId;
            var delegateId = @event.DelegateUserId;

            if (@event.DelegatedPermissions != null)
            {
                // 위임자와 수임자 모두의 캐시를 무효화
                var tasks = @event.DelegatedPermissions.SelectMany(scope => new[]
                {
                    InvalidateCacheInternalAsync(delegatorId, $"delegated_from:{scope}", cancellationToken),
                    InvalidateCacheInternalAsync(delegateId, $"delegated_to:{scope}", cancellationToken)
                });
                await Task.WhenAll(tasks);
                _logger.LogInformation("Invalidated cache for delegator {DelegatorId} and delegate {DelegateId} due to permission delegation", delegatorId, delegateId);
            }
        }

        public Task HandleAsync(PermissionInheritedEvent @event, CancellationToken cancellationToken = default) =>
            InvalidateCacheInternalAsync(@event.ConnectedId ?? @event.UserId, $"inherited:{@event.PermissionScope}", cancellationToken);

        // --- Role Events Handlers ---
        public Task HandleAsync(RoleAssignedEvent @event, CancellationToken cancellationToken = default) =>
            // 역할 할당 이벤트의 ConnectedId 사용
            InvalidateCacheInternalAsync(@event.ConnectedId, $"role_assigned:{@event.RoleName}", cancellationToken);

        public Task HandleAsync(RoleRemovedEvent @event, CancellationToken cancellationToken = default) =>
             // 역할 제거 이벤트의 ConnectedId 사용
            InvalidateCacheInternalAsync(@event.ConnectedId, $"role_removed:{@event.RoleName}", cancellationToken);

        public async Task HandleAsync(RoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // 역할 정의가 변경되면 해당 역할을 가진 모든 사용자의 캐시를 무효화해야 함
            _logger.LogInformation("Role definition changed ({RoleName}). Invalidating cache for affected users.", @event.NewRoleName ?? @event.AggregateId.ToString());
            await InvalidateCacheForRoleAsync(@event.AggregateId, "role_changed", cancellationToken);
        }

        public async Task HandleAsync(RoleDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            // 역할이 삭제되면 해당 역할을 가졌던 모든 사용자의 캐시를 무효화해야 함
            _logger.LogInformation("Role deleted ({RoleName}). Invalidating cache for previously affected users.", @event.RoleName ?? @event.AggregateId.ToString());
            await InvalidateCacheForRoleAsync(@event.AggregateId, "role_deleted", cancellationToken);
        }

        /// <summary>
        /// 특정 역할을 가진 모든 사용자의 권한 캐시를 무효화합니다.
        /// </summary>
        private async Task InvalidateCacheForRoleAsync(Guid roleId, string reason, CancellationToken cancellationToken)
        {
            // TODO: _accessRepository 등을 사용하여 roleId를 가진 모든 ConnectedId 목록 조회 구현 필요
            // 이 로직은 성능에 영향을 줄 수 있으므로 주의해서 구현해야 합니다.
            // 예를 들어, 역할-사용자 매핑 정보를 별도로 관리하거나 DB 쿼리를 효율적으로 수행해야 합니다.
            List<Guid> affectedConnectedIds = new List<Guid>(); // 실제 조회 로직 대체 필요

            _logger.LogWarning("InvalidateCacheForRoleAsync requires implementation to find affected users for RoleId {RoleId}", roleId);

            // 실제 구현 예시 (주석 처리됨):
            /*
            try
            {
                // IUserPlatformApplicationAccessRepository 또는 유사한 리포지토리를 사용하여 조회
                // var accessEntries = await _accessRepository.GetByRoleIdAsync(roleId, cancellationToken);
                // affectedConnectedIds = accessEntries.Select(a => a.ConnectedId).Distinct().ToList();
            }
            catch(Exception ex)
            {
                 _logger.LogError(ex, "Failed to retrieve affected users for RoleId {RoleId} during cache invalidation.", roleId);
                 return; // 조회 실패 시 캐시 무효화 중단
            }
            */

            if (affectedConnectedIds.Any())
            {
                var tasks = affectedConnectedIds.Select(connectedId =>
                    InvalidateCacheInternalAsync(connectedId, reason, cancellationToken));
                try
                {
                    await Task.WhenAll(tasks);
                    _logger.LogInformation("Invalidated caches for {Count} users affected by RoleId {RoleId} change/deletion.", affectedConnectedIds.Count, roleId);
                }
                catch (Exception ex) // WhenAll에서 발생할 수 있는 예외 처리
                {
                     _logger.LogError(ex, "Error occurred during bulk cache invalidation for RoleId {RoleId}.", roleId);
                }
            }
            else
            {
                 _logger.LogInformation("No users found for RoleId {RoleId} to invalidate cache.", roleId);
            }
        }


        /// <summary>
        /// 사용자별 권한 캐시를 무효화하는 내부 로직
        /// </summary>
        private async Task InvalidateCacheInternalAsync(Guid userIdentifier, string reason, CancellationToken cancellationToken) // UserId 또는 ConnectedId
        {
             if (userIdentifier == Guid.Empty)
             {
                 _logger.LogDebug("Skipping cache invalidation for empty user identifier. Reason: {Reason}", reason);
                 return;
             }

             try
             {
                 // 사용자 권한 관련 캐시 키 정의 (ConnectedId 사용 가정)
                 // 실제 사용하는 캐시 키 구조에 맞게 수정해야 합니다.
                 var userPermissionsKey = $"{AuthConstants.CacheKeys.PermissionPrefix}{userIdentifier}";
                 var otherUserCacheKey = $"{AuthConstants.CacheKeys.UserPrefix}permissions:{userIdentifier}";

                 // 무효화할 키 목록
                 var cacheKeysToRemove = new List<string> { userPermissionsKey, otherUserCacheKey };

                 // 특정 권한 스코프 관련 키가 있다면 추가 (선택적)
                 // if (reason.Contains(":")) {
                 //     var scope = reason.Split(':')[1];
                 //     if (!string.IsNullOrEmpty(scope)) {
                 //        cacheKeysToRemove.Add($"{AuthConstants.CacheKeys.PermissionPrefix}{userIdentifier}:{scope}");
                 //     }
                 // }

                 _logger.LogDebug("Invalidating user permission cache for Identifier {Identifier} due to {Reason}. Keys: [{Keys}]",
                     userIdentifier, reason, string.Join(", ", cacheKeysToRemove));

                 // 여러 키를 한 번에 제거 (RemoveMultipleAsync가 없다면 개별 RemoveAsync 호출)
                  await _cacheService.RemoveMultipleAsync(cacheKeysToRemove, cancellationToken);
                 // 또는 개별 호출:
                 // foreach (var key in cacheKeysToRemove) { await _cacheService.RemoveAsync(key, cancellationToken); }

             }
             catch (OperationCanceledException)
             {
                  _logger.LogWarning("Invalidating user permission cache for {Identifier} was canceled.", userIdentifier);
                  throw; // 취소는 다시 던져서 상위에서 처리하도록 함
             }
             catch (NotSupportedException nse) // 패턴 삭제 등 미지원 기능 사용 시
             {
                 _logger.LogWarning(nse, "Cache operation not supported during invalidation for identifier {Identifier}.", userIdentifier);
             }
             catch (Exception ex)
             {
                 _logger.LogWarning(ex, "Failed to invalidate user permission cache for identifier {Identifier}", userIdentifier);
                 // 캐시 무효화 실패는 로깅만 하고 계속 진행 (치명적이지 않음)
             }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled); // CacheService 의존성 확인 가능
        #endregion
    }
}