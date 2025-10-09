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
    public class UserProfileEventHandler : IUserProfileEventHandler
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
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("UserProfileEventHandler initialized");
            return Task.CompletedTask;
        }

        // 1. CancellationToken added to the signature.
        // 2. CancellationToken passed to the dependency's health check.
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Pass the token to the underlying service call.
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }
        #endregion

        #region IUserProfileEventHandler Implementation

        public async Task HandleProfileCreatedAsync(UserProfileCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 동적 프로필 데이터 처리
                var profileData = new Dictionary<string, object>
                {
                    ["profile_id"] = @event.ProfileId,
                    ["created_at"] = _dateTimeProvider.UtcNow,
                    ["user_id"] = @event.UserId
                };

                // 선택적 필드들 - SaaS 고객이 정의한 필드도 수용
                if (!string.IsNullOrEmpty(@event.PhoneNumber))
                    profileData["phone"] = MaskSensitiveData(@event.PhoneNumber, "phone");
                if (!string.IsNullOrEmpty(@event.TimeZone))
                    profileData["timezone"] = @event.TimeZone;
                if (!string.IsNullOrEmpty(@event.PreferredLanguage))
                    profileData["language"] = @event.PreferredLanguage;

                // 프로필 캐시 설정 (짧은 TTL)
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.SetAsync(cacheKey, profileData, TimeSpan.FromMinutes(PROFILE_CACHE_MINUTES));

                // 감사 로그 (최소화)
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Create,
                    "PROFILE_CREATED",
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceId: @event.ProfileId.ToString());

                _logger.LogInformation("Profile created for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile creation processing failed for UserId: {UserId}", @event.UserId);
                // 프로필 생성 실패는 치명적이지 않음
            }
        }

        public async Task HandleProfileViewedAsync(UserProfileViewedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 프로필 조회 이력 기록
                var viewData = new Dictionary<string, object>
                {
                    ["profile_id"] = @event.ProfileId,
                    ["viewer_id"] = @event.ViewerConnectedId ?? Guid.Empty,
                    ["viewed_at"] = @event.ViewedAt,
                    ["view_context"] = @event.ViewContext ?? "Unknown",
                    ["ip_address"] = @event.IpAddress ?? "N/A",
                    ["user_agent"] = @event.UserAgent ?? "N/A"
                };

                // 자기 프로필 조회가 아닌 경우만 감사 로그
                if (@event.ViewerConnectedId.HasValue && @event.ViewerConnectedId != @event.UserId)
                {
                    await _auditService.LogActionAsync(
                        Core.Enums.Core.AuditActionType.Read,
                        "PROFILE_VIEWED",
                        @event.ViewerConnectedId.Value,
                        resourceId: @event.ProfileId.ToString(),
                        metadata: viewData);
                }

                _logger.LogDebug("Profile viewed - ProfileId: {ProfileId}, Viewer: {ViewerId}",
                    @event.ProfileId, @event.ViewerConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile view processing failed for ProfileId: {ProfileId}", @event.ProfileId);
            }
        }

        public async Task HandleProfileUpdatedAsync(ProfileUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 무효화
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey);

                // 변경 사항 처리
                var changes = @event.Changes ?? new Dictionary<string, object>();
                changes["updated_at"] = @event.UpdatedAt;
                changes["updated_by"] = @event.UpdatedByConnectedId;
                changes["new_completion"] = @event.NewCompletionPercentage;

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "PROFILE_UPDATED",
                    @event.UpdatedByConnectedId,
                    resourceId: @event.ProfileId.ToString(),
                    metadata: changes);

                _logger.LogInformation("Profile updated - ProfileId: {ProfileId}, CompletionPercentage: {Percentage}%",
                    @event.ProfileId, @event.NewCompletionPercentage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile update processing failed for ProfileId: {ProfileId}", @event.ProfileId);
            }
        }

        public async Task HandleProfileDeletedAsync(ProfileDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 삭제
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey);

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Delete,
                    "PROFILE_DELETED",
                    @event.DeletedByConnectedId,
                    resourceId: @event.ProfileId.ToString());

                _logger.LogWarning("Profile deleted - ProfileId: {ProfileId}, DeletedBy: {DeletedBy}",
                    @event.ProfileId, @event.DeletedByConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile deletion processing failed for ProfileId: {ProfileId}", @event.ProfileId);
            }
        }

        public async Task HandleProfileErrorAsync(ProfileErrorEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 에러 로깅
                _logger.LogError("Profile error occurred - UserId: {UserId}, ErrorType: {ErrorType}, Message: {Message}",
                    @event.UserId, @event.ErrorType, @event.ErrorMessage);

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Configuration,
                    $"PROFILE_ERROR_{@event.ErrorType}",
                    @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        ["error_type"] = @event.ErrorType,
                        ["error_message"] = @event.ErrorMessage
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile error processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task HandleProfileImageUploadedAsync(ProfileImageUploadedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 이미지 업로드 정보 캐시
                var cacheKey = $"{CACHE_KEY_PREFIX}:image:{@event.UserId:N}";
                var imageData = new Dictionary<string, object>
                {
                    ["url"] = @event.NewImageUrl,
                    ["size"] = @event.ImageSize,
                    ["content_type"] = @event.ContentType,
                    ["uploaded_at"] = @event.UploadedAt
                };

                await _cacheService.SetAsync(cacheKey, imageData, TimeSpan.FromDays(7));

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "PROFILE_IMAGE_UPLOADED",
                    @event.UploadedByConnectedId,
                    resourceId: @event.UserId.ToString(),
                    metadata: imageData);

                _logger.LogInformation("Profile image uploaded - UserId: {UserId}, Size: {Size} bytes",
                    @event.UserId, @event.ImageSize);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile image upload processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task HandleProfileImageDeletedAsync(ProfileImageDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 이미지 캐시 삭제
                var cacheKey = $"{CACHE_KEY_PREFIX}:image:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey);

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Delete,
                    "PROFILE_IMAGE_DELETED",
                    @event.DeletedByConnectedId,
                    resourceId: @event.UserId.ToString());

                _logger.LogInformation("Profile image deleted - UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile image deletion processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task HandleMetadataModeChangedAsync(MetadataModeChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 메타데이터 모드 변경 처리
                var changeData = new Dictionary<string, object>
                {
                    ["old_mode"] = @event.OldMode.ToString(),
                    ["new_mode"] = @event.NewMode.ToString(),
                    ["changed_at"] = @event.ChangedAt,
                    ["changed_by"] = @event.ChangedByConnectedId
                };

                // 캐시 무효화 (모드 변경은 중요한 변경)
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                await _cacheService.RemoveAsync(cacheKey);

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "METADATA_MODE_CHANGED",
                    @event.ChangedByConnectedId,
                    resourceId: @event.UserId.ToString(),
                    metadata: changeData);

                _logger.LogWarning("Metadata mode changed - UserId: {UserId}, From: {OldMode} To: {NewMode}",
                    @event.UserId, @event.OldMode, @event.NewMode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Metadata mode change processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task HandleBulkMetadataCleanedAsync(BulkMetadataCleanedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 대량 메타데이터 정리 처리
                var cleanupData = new Dictionary<string, object>
                {
                    ["mode"] = @event.Mode.ToString(),
                    ["cleaned_count"] = @event.CleanedCount,
                    ["cutoff_date"] = @event.CutoffDate,
                    ["cleaned_at"] = @event.CleanedAt,
                    ["user_count"] = @event.CleanedUserIds.Count
                };

                // 영향받은 사용자들의 캐시 무효화
                foreach (var userId in @event.CleanedUserIds)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}:{userId:N}";
                    await _cacheService.RemoveAsync(cacheKey);
                }

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Delete,
                    "BULK_METADATA_CLEANED",
                    @event.UserId,
                    resourceId: "BULK_OPERATION",
                    metadata: cleanupData);

                _logger.LogWarning("Bulk metadata cleaned - Mode: {Mode}, Count: {Count}, Users: {UserCount}",
                    @event.Mode, @event.CleanedCount, @event.CleanedUserIds.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Bulk metadata cleanup processing failed");
            }
        }

        public async Task HandleDataExportedAsync(DataExportedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 데이터 내보내기 처리
                var exportData = new Dictionary<string, object>
                {
                    ["format"] = @event.Format,
                    ["exported_at"] = @event.ExportedAt,
                    ["data_size"] = @event.DataSize
                };

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Export,
                    "DATA_EXPORTED",
                    @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: exportData);

                _logger.LogInformation("Data exported - UserId: {UserId}, Format: {Format}, Size: {Size} bytes",
                    @event.UserId, @event.Format, @event.DataSize);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Data export processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task HandleTimeZoneChangedAsync(TimeZoneChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 시간대 변경 처리
                var changeData = new Dictionary<string, object>
                {
                    ["old_timezone"] = @event.OldTimeZone,
                    ["new_timezone"] = @event.NewTimeZone,
                    ["changed_at"] = @event.ChangedAt,
                    ["changed_by"] = @event.ChangedByConnectedId
                };

                // 캐시 업데이트
                var cacheKey = $"{CACHE_KEY_PREFIX}:{@event.UserId:N}";
                var profileData = await _cacheService.GetAsync<Dictionary<string, object>>(cacheKey);
                if (profileData != null)
                {
                    profileData["timezone"] = @event.NewTimeZone;
                    await _cacheService.SetAsync(cacheKey, profileData, TimeSpan.FromMinutes(PROFILE_CACHE_MINUTES));
                }

                // 감사 로그
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "TIMEZONE_CHANGED",
                    @event.ChangedByConnectedId,
                    resourceId: @event.UserId.ToString(),
                    metadata: changeData);

                _logger.LogInformation("TimeZone changed - UserId: {UserId}, From: {OldTZ} To: {NewTZ}",
                    @event.UserId, @event.OldTimeZone, @event.NewTimeZone);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TimeZone change processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        #endregion

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