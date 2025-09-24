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
    public class UserEventHandler : ICoreUserEventHandler, IService
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

        #region ICoreUserEventHandler Implementation

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
                        Tags = metadata.Count > 0 ? ConvertToStringDict(metadata) : null
                    }), cancellationToken);
                }

                await _auditService.LogActionAsync(
                    AuditActionType.Create,
                    UserActivityType.FirstLogin.ToString(),
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: metadata);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                await InvalidateUserCacheAsync(@event.UserId);
                
                _logger.LogInformation("User created successfully - UserId: {UserId}", @event.UserId);
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
                    
                _logger.LogInformation("User status changed - UserId: {UserId}, From: {OldStatus} To: {NewStatus}", 
                    @event.UserId, @event.OldStatus, @event.NewStatus);
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
                
                // Increment login count
                var newCount = await _cacheService.IncrementAsync(statsKey);
                
                // Store the count as a dictionary to comply with SetAsync<T> reference type requirement
                var statsData = new Dictionary<string, object> { ["count"] = newCount };
                var endOfDay = _dateTimeProvider.UtcNow.Date.AddDays(1);
                await _cacheService.SetAsync(statsKey, statsData, endOfDay - _dateTimeProvider.UtcNow);

                if (@event.IsFirstLogin)
                {
                    await PublishOnboardingEventAsync(@event.UserId);
                }

                var loginMetadata = new Dictionary<string, object>
                {
                    ["ip"] = @event.IPAddress ?? "unknown",
                    ["method"] = @event.AuthenticationMethod ?? "standard",
                    ["2fa"] = @event.TwoFactorUsed,
                    ["first_login"] = @event.IsFirstLogin,
                    ["login_count"] = newCount
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
                    
                _logger.LogInformation("User logged in - UserId: {UserId}, Method: {Method}, FirstLogin: {FirstLogin}", 
                    @event.UserId, @event.AuthenticationMethod, @event.IsFirstLogin);
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
                    // In production, this would trigger a separate cleanup process
                    await _unitOfWork.CommitTransactionAsync(cancellationToken);
                    return;
                }

                await InvalidateAllUserCacheAsync(@event.UserId);

                var deleteMetadata = new Dictionary<string, object>
                {
                    ["soft_delete"] = @event.IsSoftDelete,
                    ["reason"] = @event.Reason ?? "user_requested",
                    ["retention_days"] = 30  // Fixed default retention period
                };

                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    UserActivityType.AccountDeleted.ToString(),
                    @event.DeletedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: deleteMetadata);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                
                _logger.LogWarning("User deleted - UserId: {UserId}, SoftDelete: {SoftDelete}, Reason: {Reason}", 
                    @event.UserId, @event.IsSoftDelete, @event.Reason);
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

                var verificationMetadata = new Dictionary<string, object>
                {
                    ["email"] = @event.Email,
                    ["verified_at"] = @event.VerifiedAt,
                    ["method"] = @event.VerificationMethod ?? "unknown"
                };

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    UserActivityType.EmailVerified.ToString(),
                    @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: verificationMetadata);
                    
                _logger.LogInformation("Email verified - UserId: {UserId}, Email: {Email}", 
                    @event.UserId, @event.Email);
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
                
                var twoFactorMetadata = new Dictionary<string, object>
                {
                    ["enabled"] = @event.Enabled,
                    ["type"] = @event.TwoFactorType,
                    ["changed_at"] = @event.ChangedAt,
                    ["changed_by"] = @event.ChangedByConnectedId ?? @event.UserId
                };

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    activityType.ToString(),
                    @event.ChangedByConnectedId ?? @event.UserId,
                    resourceId: @event.UserId.ToString(),
                    metadata: twoFactorMetadata);
                    
                _logger.LogInformation("2FA setting changed - UserId: {UserId}, Enabled: {Enabled}, Type: {Type}", 
                    @event.UserId, @event.Enabled, @event.TwoFactorType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "2FA setting change failed for UserId: {UserId}", @event.UserId);
            }
        }

        #endregion

        #region IDomainEventHandler Implementation
        
        public async Task HandleAsync(object domainEvent, CancellationToken cancellationToken = default)
        {
            switch (domainEvent)
            {
                case UserCreatedEvent userCreated:
                    await OnUserCreatedAsync(userCreated, cancellationToken);
                    break;
                case UserStatusChangedEvent statusChanged:
                    await OnUserStatusChangedAsync(statusChanged, cancellationToken);
                    break;
                case UserLoggedInEvent loggedIn:
                    await OnUserLoggedInAsync(loggedIn, cancellationToken);
                    break;
                case UserDeletedEvent deleted:
                    await OnUserDeletedAsync(deleted, cancellationToken);
                    break;
                case EmailVerifiedEvent emailVerified:
                    await OnEmailVerifiedAsync(emailVerified, cancellationToken);
                    break;
                case TwoFactorSettingChangedEvent twoFactorChanged:
                    await OnTwoFactorSettingChangedAsync(twoFactorChanged, cancellationToken);
                    break;
                default:
                    _logger.LogWarning("Unknown event type: {EventType}", domainEvent?.GetType().Name);
                    break;
            }
        }

        #endregion

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

            // In production, this would fetch from database
            var settings = new TenantSettings { SendWelcomeEmail = true };
            await _cacheService.SetAsync(cacheKey, settings, TimeSpan.FromHours(1));
            return settings;
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
                $"permission*{userId:N}*",
                $"session*{userId:N}*"
            };

            foreach (var pattern in patterns)
            {
                await _cacheService.RemoveByPatternAsync(pattern);
            }
        }

        private async Task PublishOnboardingEventAsync(Guid userId)
        {
            // In production, this would publish to event bus
            _logger.LogInformation("Onboarding event published for UserId: {UserId}", userId);
            await Task.CompletedTask;
        }

        private Dictionary<string, object> GetEventProcessingRules()
        {
            return new Dictionary<string, object>
            {
                ["max_retries"] = 3,
                ["timeout_seconds"] = 30,
                ["batch_size"] = 100,
                ["enable_dead_letter"] = true
            };
        }

        #endregion

        #region Private Classes
        
        private class TenantSettings
        {
            public bool SendWelcomeEmail { get; set; }
            public bool EnableAudit { get; set; } = true;
            public int MaxLoginAttempts { get; set; } = 5;
            public bool RequireEmailVerification { get; set; } = true;
            public bool AllowMultipleSessions { get; set; } = true;
        }
        
        #endregion
    }
}