// File: AuthHive.Auth/Services/Handlers/ApplicationAccess/InvalidateTemplateCacheHandler.cs
using AuthHive.Core.Constants.Auth; // AuthConstants.CacheKeys 가정
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ❗️ ICacheService 사용
using AuthHive.Core.Models.PlatformApplication.Events; // Template 이벤트
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ApplicationAccess
{
    /// <summary>
    /// 템플릿 정의(Definition)가 변경되거나 삭제될 때 템플릿 자체의 캐시를 무효화합니다.
    /// (ApplicationTemplateChangedEvent, ApplicationTemplateRemovedEvent 구독)
    /// </summary>
    public class InvalidateTemplateCacheHandler :
        IDomainEventHandler<ApplicationTemplateChangedEvent>,
        IDomainEventHandler<ApplicationTemplateRemovedEvent>, // (추후 처리)
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<InvalidateTemplateCacheHandler> _logger;
        // 템플릿 캐시 키 (예: "templates:templateId")
        private const string TEMPLATE_CACHE_KEY_FORMAT = "templates:{0}"; 

        public int Priority => 5; // 캐시 무효화는 우선순위 높음
        public bool IsEnabled => true;

        public InvalidateTemplateCacheHandler(
            ICacheService cacheService,
            ILogger<InvalidateTemplateCacheHandler> logger)
        {
            _cacheService = cacheService;
            _logger = logger;
        }

        // --- ApplicationTemplateChangedEvent 처리 ---
        public Task HandleAsync(ApplicationTemplateChangedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.AggregateId, "TemplateChanged", c);
        
        // --- ApplicationTemplateRemovedEvent 처리 ---
        public Task HandleAsync(ApplicationTemplateRemovedEvent @event, CancellationToken c) =>
            InvalidateCacheInternalAsync(@event.AggregateId, "TemplateRemoved", c);


        private async Task InvalidateCacheInternalAsync(Guid templateId, string reason, CancellationToken cancellationToken)
        {
            if (templateId == Guid.Empty) return;
            
            try
            {
                var cacheKey = string.Format(TEMPLATE_CACHE_KEY_FORMAT, templateId);
                _logger.LogInformation("Invalidating template definition cache due to {Reason}. TemplateId: {TemplateId}", reason, templateId);
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate template definition cache for TemplateId: {TemplateId}", templateId);
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}