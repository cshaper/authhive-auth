using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler;
using AuthHive.Core.Models.User.Events;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// SaaS 최적화 사용자 프로필 이벤트 핸들러
    /// 동적 프로필 필드 및 멀티테넌트 지원
    /// </summary>
    public class UserProfileEventHandler : IUserProfileEventHandler, IService
    {
        private readonly ILogger<UserProfileEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;
        
        private const string CACHE_KEY_PREFIX = "profile";
        private const int PROFILE_CACHE_MINUTES = 30;
        
        public int Priority => 3;
        public bool IsEnabled { get; private set; } = true;

        public UserProfileEventHandler(
            ILogger<UserProfileEventHandler> logger,
            IAuditService auditService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork)
        {
            _logger = logger;
            _auditService = auditService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation
        public async Task InitializeAsync()
        {
            _logger.LogInformation("UserProfileEventHandler initialized");
            await Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return IsEnabled && await _cacheService.IsHealthyAsync();
        }
        #endregion

        public async Task OnUserProfileCreatedAsync(UserProfileCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 동적 프로필 데이터 처리
                var profileData = new Dictionary<string, object>
                {
                    ["profile_id"] = @event.ProfileId,
                    ["created_at"] = _dateTimeProvider.UtcNow
                };
                
                // 선택적 필드들 - SaaS 고객이 정의한 필드도 수용
                if (!string.IsNullOrEmpty(@event.PhoneNumber))
                    profileData["phone"] = MaskSensitiveData(@event.PhoneNumber, "phone");
                if (!string.IsNullOrEmpty(@event.TimeZone))
                    profileData["timezone"] = @event.TimeZone;
                if (!string.IsNullOrEmpty(@event.PreferredLanguage))
                    profileData["language"] = @event.PreferredLanguage;
                    
                // 동적 메타데이터 병합
                MergeDynamicMetadata(profileData, @event.Metadata);
                
                // 프로필 캐시 설정 (짧은 TTL)
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.SetAsync(cacheKey, profileData, TimeSpan.FromMinutes(PROFILE_CACHE_MINUTES));
                
                // 감사 로그 (최소화)
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Create,
                    "PROFILE_CREATED",
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceId: @event.ProfileId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile creation processing failed for UserId: {UserId}", @event.UserId);
                // 프로필 생성 실패는 치명적이지 않음
            }
        }

        public async Task OnUserProfileUpdatedAsync(UserProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 무효화
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey);
                
                // 동적 변경 사항 처리
                var changes = new Dictionary<string, object>
                {
                    ["updated_fields"] = @event.UpdatedFields,
                    ["updated_at"] = _dateTimeProvider.UtcNow
                };
                
                // 중요 필드 변경만 감사
                if (ContainsCriticalFields(@event.UpdatedFields))
                {
                    await _auditService.LogActionAsync(
                        Core.Enums.Core.AuditActionType.Update,
                        "PROFILE_CRITICAL_UPDATE",
                        @event.UpdatedByConnectedId ?? @event.UserId,
                        resourceId: @event.ProfileId.ToString(),
                        metadata: changes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile update processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task OnPhoneVerifiedAsync(PhoneVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 보안 레벨 캐시 업데이트
                var securityKey = $"{CACHE_KEY_PREFIX}:security:{@event.UserId:N}";
                var securityData = await _cacheService.GetAsync<Dictionary<string, object>>(securityKey) 
                    ?? new Dictionary<string, object>();
                    
                securityData["phone_verified"] = true;
                securityData["phone_verified_at"] = _dateTimeProvider.UtcNow;
                
                await _cacheService.SetAsync(securityKey, securityData, TimeSpan.FromHours(1));
                
                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "PHONE_VERIFIED",
                    @event.UserId,
                    resourceId: @event.UserId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Phone verification processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task OnNotificationSettingsChangedAsync(NotificationSettingsChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 동적 알림 설정 처리
                Dictionary<string, object> settings;
                try
                {
                    settings = JsonSerializer.Deserialize<Dictionary<string, object>>(@event.NewSettings) 
                        ?? new Dictionary<string, object>();
                }
                catch
                {
                    settings = new Dictionary<string, object> { ["raw"] = @event.NewSettings };
                }
                
                // 알림 설정 캐시
                var cacheKey = $"{CACHE_KEY_PREFIX}:notifications:{@event.UserId:N}";
                await _cacheService.SetAsync(cacheKey, settings, TimeSpan.FromHours(24));
                
                // 변경 카테고리가 중요한 경우만 로그
                if (@event.ChangedCategories.Length > 0)
                {
                    _logger.LogInformation("Notification settings updated for UserId: {UserId}, Categories: {Count}", 
                        @event.UserId, @event.ChangedCategories.Length);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Notification settings update failed for UserId: {UserId}", @event.UserId);
                // 알림 설정 실패는 무시
            }
        }

        #region Helper Methods
        
        private string MaskSensitiveData(string data, string type)
        {
            if (string.IsNullOrEmpty(data)) return "****";
            
            return type switch
            {
                "phone" => data.Length > 4 ? $"***{data.Substring(data.Length - 4)}" : "****",
                "email" => data.Contains('@') ? $"***@{data.Split('@')[1]}" : "****",
                _ => "****"
            };
        }
        
        private void MergeDynamicMetadata(Dictionary<string, object> target, string? metadata)
        {
            if (string.IsNullOrEmpty(metadata)) return;
            
            try
            {
                var dynamicData = JsonSerializer.Deserialize<Dictionary<string, object>>(metadata);
                if (dynamicData != null)
                {
                    foreach (var kvp in dynamicData)
                    {
                        // 동적 필드는 custom_ 프리픽스 추가
                        target[$"custom_{kvp.Key}"] = kvp.Value;
                    }
                }
            }
            catch
            {
                target["custom_metadata"] = metadata;
            }
        }
        
        private bool ContainsCriticalFields(string[] fields)
        {
            // 테넌트별로 다를 수 있는 중요 필드
            var criticalFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { 
                "email", "phone", "legal_name", "tax_id", "ssn"
            };
            
            foreach (var field in fields)
            {
                if (criticalFields.Contains(field))
                    return true;
            }
            return false;
        }
        
        #endregion
    }
}