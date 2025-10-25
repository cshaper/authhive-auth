// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/InvalidateUserUpdatedCacheHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserUpdatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자 정보 변경(이름, 이메일 등) 시 관련 캐시를 무효화합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserUpdatedEvent"/>를 처리하는 캐시 무효화 핸들러입니다.
    /// 사용자 ID를 기준으로 권한 및 기타 연관된 캐시를 제거합니다.
    /// </summary>
    public class InvalidateUserUpdatedCacheHandler
        : IDomainEventHandler<UserUpdatedEvent>
    {
        // 캐시 무효화는 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly ICacheService _cacheService;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<InvalidateUserUpdatedCacheHandler> _logger;

        public InvalidateUserUpdatedCacheHandler(
            ICacheService cacheService,
            IUserRepository userRepository,
            ILogger<InvalidateUserUpdatedCacheHandler> logger)
        {
            this._cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            this._userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 사용자 업데이트 이벤트를 처리하여 관련 캐시를 무효화합니다.
        /// </summary>
        public async Task HandleAsync(UserUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Starting cache invalidation for updated user: {UserId}",
                    @event.UserId);

                // 1. 사용자에게 연결된 모든 ConnectedId를 조회합니다.
                // 캐시 키는 종종 ConnectedId를 포함하므로, ConnectedId 목록이 필요합니다.
                var connectedIds = await _userRepository.GetConnectedIdsForUserAsync(@event.UserId, true, cancellationToken);
                
                if (!connectedIds.Any())
                {
                    _logger.LogWarning("No active ConnectedIds found for UserId {UserId}. Skipping specific ConnectedId cache invalidation.", @event.UserId);
                }

                // 2. 캐시 무효화 작업 목록 생성
                var invalidationTasks = new List<Task>();

                // 2a. ConnectedId 기반 캐시 무효화 (권한, 세션 등)
                foreach (var connectedId in connectedIds)
                {
                    // 패턴 1: ConnectedId 기반 권한 캐시 (예: perm:{connectedId}:*)
                    invalidationTasks.Add(InvalidateCacheByPatternAsync($"perm:*:{connectedId}:*", connectedId, cancellationToken));
                    // 패턴 2: ConnectedId 기반 사용자 컨텍스트 캐시 (예: ctx:{connectedId})
                    invalidationTasks.Add(InvalidateCacheByPatternAsync($"ctx:{connectedId}", connectedId, cancellationToken));
                }
                
                // 2b. UserId 기반 캐시 무효화 (프로필, 기본 정보 등)
                // 패턴 3: UserId 기반 캐시 (예: user:{userId}, profile:{userId})
                invalidationTasks.Add(InvalidateCacheByPatternAsync($"user:{@event.UserId}", @event.UserId, cancellationToken));
                invalidationTasks.Add(InvalidateCacheByPatternAsync($"profile:{@event.UserId}", @event.UserId, cancellationToken));


                // 3. 모든 무효화 작업 완료 대기
                await Task.WhenAll(invalidationTasks);
                
                _logger.LogInformation(
                    "Completed cache invalidation for updated user: {UserId}. Total tasks: {Count}",
                    @event.UserId, invalidationTasks.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Cache invalidation for User update was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // 캐시 실패는 심각한 오류가 아니므로 (시스템은 DB에서 데이터를 가져올 수 있어야 함), 
                // 로그만 남기고 예외를 다시 던지지 않습니다.
                _logger.LogError(ex,
                    "Error during cache invalidation for User update. (UserId: {UserId})",
                    @event.UserId);
            }
        }
        
        /// <summary>
        /// 캐시 패턴을 사용하여 캐시를 안전하게 제거하는 헬퍼 메서드
        /// </summary>
        private async Task InvalidateCacheByPatternAsync(string cachePattern, Guid connectedOrUserId, CancellationToken cancellationToken)
        {
            try
            {
                // (가정) ICacheService에 RemoveByPatternAsync 메서드가 존재합니다.
                await _cacheService.RemoveByPatternAsync(cachePattern, cancellationToken);
                _logger.LogDebug("Cache invalidated by pattern: {Pattern} for ID: {Id}", cachePattern, connectedOrUserId);
            }
            catch (NotSupportedException nse)
            {
                // 캐시 서비스가 패턴 삭제를 지원하지 않는 경우 (예: In-Memory, 일부 Redis 구성)
                _logger.LogWarning(nse, "Cache pattern removal not supported for pattern: {Pattern}", cachePattern);
                // 추가로, 개별 키를 알고 있다면 여기서 삭제를 시도할 수 있습니다.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache by pattern: {Pattern}", cachePattern);
            }
        }
    }
}
