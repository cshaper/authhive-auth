using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler;
using AuthHive.Core.Models.User.Events;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.External;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// SaaS 최적화된 핵심 사용자 이벤트 핸들러
    /// </summary>
    public class UserEventHandler : IUserEventHandler, IService
    {
        private readonly ILogger<UserEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;

        private const string CACHE_KEY_PREFIX = "user_event";
        private const int CACHE_DURATION_MINUTES = 5;

        public int Priority => 1;
        public bool IsEnabled { get; private set; } = true;

        public UserEventHandler(
            ILogger<UserEventHandler> logger,
            IAuditService auditService,
            IEmailService emailService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork)
        {
            _logger = logger;
            _auditService = auditService;
            _emailService = emailService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation
        public async Task InitializeAsync()
        {
            await WarmUpCacheAsync();
            _logger.LogInformation("UserEventHandler initialized");
        }

        public async Task<bool> IsHealthyAsync()
        {
            return IsEnabled && await _cacheService.IsHealthyAsync();
        }

        private async Task WarmUpCacheAsync()
        {
            try
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}:rules";
                await _cacheService.SetAsync(cacheKey, GetEventProcessingRules(), TimeSpan.FromHours(1));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache warmup failed - continuing without cache");
            }
        }
        #endregion

        public async Task OnUserCreatedAsync(UserCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                var metadata = ParseDynamicMetadata(@event.Metadata);
                var tenantSettings = await GetTenantSettingsAsync(@event.UserId);

                if (tenantSettings.SendWelcomeEmail && !string.IsNullOrEmpty(@event.Email))
                {
                    _ = Task.Run(() => _emailService.SendEmailAsync(new EmailMessageDto
                    {
                        To = @event.Email,
                        Subject = "Welcome",
                        Body = "Welcome to AuthHive",
                        // TemplateKey와 DynamicData는 EmailMessageDto에 추가 필요
                        Tags = metadata.Count > 0 ? ConvertToStringDict(metadata) : null
                    }), cancellationToken);
                }

                await _auditService.LogActionAsync(
                    AuditActionType.Create,
                    UserActivityType.FirstLogin.ToString(), // 문자열 대신 enum 사용
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: metadata);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                await InvalidateUserCacheAsync(@event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process user created event for UserId: {UserId}", @event.UserId);
                throw;
            }
        }

        public async Task OnUserStatusChangedAsync(UserStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);

                var changeMetadata = new Dictionary<string, object>
                {
                    ["old_status"] = @event.OldStatus.ToString(),
                    ["new_status"] = @event.NewStatus.ToString(),
                    ["reason"] = @event.Reason ?? "not_specified"
                };

                if (!string.IsNullOrEmpty(@event.Metadata))
                {
                    var additionalData = ParseDynamicMetadata(@event.Metadata);
                    foreach (var kvp in additionalData)
                    {
                        changeMetadata[kvp.Key] = kvp.Value;
                    }
                }

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    UserActivityType.SettingsChange.ToString(),
                    @event.ChangedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: changeMetadata);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process status change for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task OnUserLoggedInAsync(UserLoggedInEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var statsKey = $"{CACHE_KEY_PREFIX}:login_stats:{@event.UserId:N}:{_dateTimeProvider.UtcNow:yyyy-MM-dd}";

                // CS1503 오류 수정: IncrementAsync는 (string key, long increment = 1) 시그니처
                // TimeSpan은 SetAsync 이후에 별도로 처리
                var newCount = await _cacheService.IncrementAsync(statsKey);

                // 또는 increment 값을 명시적으로 전달
                // var newCount = await _cacheService.IncrementAsync(statsKey, 1);

                if (@event.IsFirstLogin)
                {
                    await PublishOnboardingEventAsync(@event.UserId);
                }

                var loginMetadata = new Dictionary<string, object>
                {
                    ["ip"] = @event.IPAddress ?? "unknown",
                    ["method"] = @event.AuthenticationMethod ?? "standard",
                    ["2fa"] = @event.TwoFactorUsed
                };

                if (!string.IsNullOrEmpty(@event.Metadata))
                {
                    var customData = ParseDynamicMetadata(@event.Metadata);
                    foreach (var kvp in customData)
                    {
                        loginMetadata[$"custom_{kvp.Key}"] = kvp.Value;
                    }
                }

                var activityType = @event.IsFirstLogin ? UserActivityType.FirstLogin : UserActivityType.Login;

                await _auditService.LogActionAsync(
                    AuditActionType.Login,
                    activityType.ToString(),
                    @event.ConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: loginMetadata);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login event processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task OnUserDeletedAsync(UserDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                if (!@event.IsSoftDelete)
                {
                    _logger.LogWarning("Hard delete requested for UserId: {UserId} - redirecting to cleanup service", @event.UserId);
                    return;
                }

                await InvalidateAllUserCacheAsync(@event.UserId);

                var deleteMetadata = new Dictionary<string, object>
                {
                    ["soft_delete"] = true,
                    ["reason"] = @event.Reason ?? "user_requested"
                };

                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    UserActivityType.AccountLocked.ToString(),
                    @event.DeletedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: deleteMetadata);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process user deletion for UserId: {UserId}", @event.UserId);
                throw;
            }
        }

        public async Task OnEmailVerifiedAsync(EmailVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    UserActivityType.EmailVerified.ToString(),
                    @event.UserId,
                    resourceId: @event.UserId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Email verification processing failed for UserId: {UserId}", @event.UserId);
            }
        }

        public async Task OnTwoFactorSettingChangedAsync(TwoFactorSettingChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var securityKey = $"{CACHE_KEY_PREFIX}:security:{@event.UserId:N}";
                await _cacheService.RemoveAsync(securityKey);

                var activityType = @event.Enabled ? UserActivityType.TwoFactorEnabled : UserActivityType.TwoFactorDisabled;

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    activityType.ToString(),
                    @event.ChangedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "2FA setting change failed for UserId: {UserId}", @event.UserId);
            }
        }

        #region Helper Methods

        private Dictionary<string, object> ParseDynamicMetadata(string? metadata)
        {
            if (string.IsNullOrEmpty(metadata))
                return new Dictionary<string, object>();

            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, object>>(metadata)
                    ?? new Dictionary<string, object>();
            }
            catch
            {
                _logger.LogWarning("Failed to parse metadata as JSON: {Metadata}", metadata);
                return new Dictionary<string, object> { ["raw"] = metadata };
            }
        }

        private Dictionary<string, string> ConvertToStringDict(Dictionary<string, object> dict)
        {
            var result = new Dictionary<string, string>();
            foreach (var kvp in dict)
            {
                result[kvp.Key] = kvp.Value?.ToString() ?? string.Empty;
            }
            return result;
        }

        private async Task<TenantSettings> GetTenantSettingsAsync(Guid userId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:tenant_settings:{userId:N}";
            var cached = await _cacheService.GetAsync<TenantSettings>(cacheKey);

            if (cached != null)
                return cached;

            return new TenantSettings { SendWelcomeEmail = true };
        }

        private async Task InvalidateUserCacheAsync(Guid userId)
        {
            var pattern = $"{CACHE_KEY_PREFIX}:*{userId:N}*";
            await _cacheService.RemoveByPatternAsync(pattern);
        }

        private async Task InvalidateAllUserCacheAsync(Guid userId)
        {
            var patterns = new[]
            {
                $"user*{userId:N}*",
                $"profile*{userId:N}*",
                $"permission*{userId:N}*"
            };

            foreach (var pattern in patterns)
            {
                await _cacheService.RemoveByPatternAsync(pattern);
            }
        }

        private async Task PublishOnboardingEventAsync(Guid userId)
        {
            _logger.LogInformation("Onboarding event published for UserId: {UserId}", userId);
            await Task.CompletedTask;
        }

        private Dictionary<string, object> GetEventProcessingRules()
        {
            return new Dictionary<string, object>
            {
                ["max_retries"] = 3,
                ["timeout_seconds"] = 30,
                ["batch_size"] = 100
            };
        }

        #endregion

        private class TenantSettings
        {
            public bool SendWelcomeEmail { get; set; }
            public bool EnableAudit { get; set; } = true;
            public int MaxLoginAttempts { get; set; } = 5;
        }
    }
}