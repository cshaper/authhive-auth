// File: authhive.auth/services/handlers/User/Profile/InvalidateProfileCacheHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - CORRECTED]
// ❗️ IEventHandler<T> 대신 IDomainEventHandler<T>를 사용하도록 수정했습니다.
// ❗️ IService 인터페이스를 구현하여 헬스 체크 및 초기화를 지원합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Events.Profile;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Profile
{
    /// <summary>
    /// 프로필 관련 이벤트 발생 시 캐시를 무효화하는 핸들러입니다.
    /// (IDomainEventHandler 및 IService 구현)
    /// </summary>
    public class InvalidateProfileCacheHandler :
        IDomainEventHandler<ProfileUpdatedEvent>,         
        IDomainEventHandler<ProfileDeletedEvent>,         
        IDomainEventHandler<ProfileImageUploadedEvent>,   
        IDomainEventHandler<ProfileImageDeletedEvent>,    
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateProfileCacheHandler> _logger;
        private const string CACHE_KEY_PREFIX = "profile";

        // ❗️ IDomainEventHandler의 계약 (공통 구현)
        public int Priority => 100; // 다른 핸들러가 처리한 후 마지막에 실행
        public bool IsEnabled => true;

        public InvalidateProfileCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateProfileCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // ❗️ IDomainEventHandler<ProfileUpdatedEvent> 구현
        public async Task HandleAsync(ProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheAsync(@event.UserId, "ProfileUpdated", cancellationToken);
        }

        // ❗️ IDomainEventHandler<ProfileDeletedEvent> 구현
        public async Task HandleAsync(ProfileDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheAsync(@event.UserId, "ProfileDeleted", cancellationToken);
        }

        // ❗️ IDomainEventHandler<ProfileImageUploadedEvent> 구현
        public async Task HandleAsync(ProfileImageUploadedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheAsync(@event.UserId, "ProfileImageUploaded", cancellationToken);
        }

        // ❗️ IDomainEventHandler<ProfileImageDeletedEvent> 구현
        public async Task HandleAsync(ProfileImageDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            await InvalidateCacheAsync(@event.UserId, "ProfileImageDeleted", cancellationToken);
        }

        private async Task InvalidateCacheAsync(Guid userId, string reason, CancellationToken cancellationToken)
        {
            try
            {
                var profileCacheKey = $"{CACHE_KEY_PREFIX}:{userId:N}";
                var imageCacheKey = $"{CACHE_KEY_PREFIX}:image:{userId:N}";

                await _cacheService.RemoveAsync(profileCacheKey, cancellationToken);
                await _cacheService.RemoveAsync(imageCacheKey, cancellationToken);

                _logger.LogDebug("Profile cache invalidated for User {UserId} due to {Reason}.", userId, reason);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate profile cache for User {UserId} (Reason: {Reason}).", userId, reason);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("InvalidateProfileCacheHandler initialized.");
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}