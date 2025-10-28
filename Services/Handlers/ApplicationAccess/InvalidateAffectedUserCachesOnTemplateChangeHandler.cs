// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/InvalidateAffectedUserCachesOnTemplateChangeHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Models.PlatformApplication.Events; // ApplicationTemplateChangedEvent
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
// 템플릿을 사용하는 사용자 목록 조회를 위한 리포지토리
using AuthHive.Core.Interfaces.PlatformApplication.Repository; 
using AuthHive.Core.Constants.Auth; // AuthConstants

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 템플릿 정의가 변경/삭제될 때, 해당 템플릿을 사용하는 **모든 사용자**의 접근 권한 캐시를 일괄 무효화합니다.
    /// (ApplicationTemplateChangedEvent 구독)
    /// </summary>
    public class InvalidateAffectedUserCachesOnTemplateChangeHandler :
        IDomainEventHandler<ApplicationTemplateChangedEvent>,
        // ❗️ [수정] ApplicationTemplateRemovedEvent는 단일 사용자 이벤트이므로 여기서 제거
        // IDomainEventHandler<ApplicationTemplateRemovedEvent>, 
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IUserPlatformApplicationAccessRepository _accessRepository; 
        private readonly ILogger<InvalidateAffectedUserCachesOnTemplateChangeHandler> _logger;
        private const string PERMISSION_CACHE_KEY_FORMAT = "permissions:{0}:{1}";
        private const string USER_APPS_CACHE_KEY_FORMAT = "userapps:{0}";

        public int Priority => 20; // 템플릿 정의 캐시(5), 감사 로그(10) 이후 수행
        public bool IsEnabled => true;

        public InvalidateAffectedUserCachesOnTemplateChangeHandler(
            ICacheService cacheService,
            IUserPlatformApplicationAccessRepository accessRepository,
            ILogger<InvalidateAffectedUserCachesOnTemplateChangeHandler> logger)
        {
            _cacheService = cacheService;
            _accessRepository = accessRepository;
            _logger = logger;
        }

        // --- ApplicationTemplateChangedEvent 처리 ---
        public Task HandleAsync(ApplicationTemplateChangedEvent @event, CancellationToken c) =>
            InvalidateAffectedUsersInternalAsync(@event.AggregateId, @event.AffectedUsersCount, "TemplateChanged", c);
        
        // --- ApplicationTemplateRemovedEvent 처리 ---
        // ❗️ [제거] CS1061 오류 수정: 이 핸들러에서 제거
        // public Task HandleAsync(ApplicationTemplateRemovedEvent @event, CancellationToken c) => ...


        private async Task InvalidateAffectedUsersInternalAsync(Guid templateId, int affectedCount, string reason, CancellationToken cancellationToken)
        {
            if (templateId == Guid.Empty || affectedCount == 0) return;

            _logger.LogWarning(
                "Template {Reason} event triggered mass cache invalidation for {AffectedCount} users. TemplateId: {TemplateId}. This is a heavy operation.",
                reason, affectedCount, templateId);

            try
            {
                // 1. 이 템플릿을 사용하는 모든 UserApplicationAccess 항목 조회 (DB 쿼리)
                // ❗️ [수정] CS1061 오류 수정: GetAccessEntriesByTemplateIdAsync -> GetByTemplateIdAsync
                var affectedAccessEntries = await _accessRepository.GetByTemplateIdAsync(templateId, cancellationToken);
                
                var affectedKeys = new HashSet<string>();
                foreach (var entry in affectedAccessEntries)
                {
                    // 2. 각 사용자의 캐시 키 생성
                    var permKey = string.Format(PERMISSION_CACHE_KEY_FORMAT, entry.ApplicationId, entry.ConnectedId);
                    var userAppsKey = string.Format(USER_APPS_CACHE_KEY_FORMAT, entry.ConnectedId);
                    affectedKeys.Add(permKey);
                    affectedKeys.Add(userAppsKey);
                }

                if (affectedKeys.Count > 0)
                {
                    _logger.LogInformation("Removing {Count} cache entries related to TemplateId {TemplateId} change.", affectedKeys.Count, templateId);
                    // 3. 대량 캐시 제거
                    await _cacheService.RemoveMultipleAsync(affectedKeys, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                 _logger.LogWarning("Invalidating affected user caches for TemplateId {TemplateId} was canceled.", templateId);
                 throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate affected user caches for TemplateId: {TemplateId}", templateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}