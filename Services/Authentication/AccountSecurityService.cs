using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.Audit.Requests; // SearchAuditLogsRequest
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Audit;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Infra.Monitoring;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Models.External;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 계정 보안 서비스 - AuthHive v16 최종 구현체
    /// [Refactored] IMemoryCache를 ICacheService로 교체하고, IAuditService, IEventBus를 연동하여
    /// SaaS 환경에 적합한 확장성과 추적성을 확보했습니다.
    /// </summary>
    public class AccountSecurityService : IAccountSecurityService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITrustedDeviceService _trustedDeviceService;
        private readonly ICacheService _cacheService;
        private readonly ILogger<AccountSecurityService> _logger;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IPasswordPolicyRepository _passwordPolicyRepository;
        private readonly IPasswordHistoryRepository _passwordHistoryRepository;
        private readonly IAccountSecuritySettingsRepository _securitySettingsRepository;
        private readonly IOrganizationHierarchyService _orgHierarchyService;
        private readonly IPlanService _planService;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;

        public AccountSecurityService(
            IUserRepository userRepository,
            ITrustedDeviceService trustedDeviceService,
            ICacheService cacheService,
            IConnectedIdService connectedIdService,
            IAuditService auditService,
            IEventBus eventBus,
            IDateTimeProvider dateTimeProvider,
            IPasswordPolicyRepository passwordPolicyRepository,
            IPasswordHistoryRepository passwordHistoryRepository,
            IAccountSecuritySettingsRepository securitySettingsRepository,
            IOrganizationHierarchyService orgHierarchyService,
            IPlanService planService,
            IMapper mapper,
            IEmailService emailService,
            ILogger<AccountSecurityService> logger)
        {
            _userRepository = userRepository;
            _trustedDeviceService = trustedDeviceService;
            _connectedIdService = connectedIdService;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _dateTimeProvider = dateTimeProvider;
            _passwordPolicyRepository = passwordPolicyRepository;
            _passwordHistoryRepository = passwordHistoryRepository;
            _securitySettingsRepository = securitySettingsRepository;
            _orgHierarchyService = orgHierarchyService;
            _planService = planService;
            _mapper = mapper;
            _emailService = emailService;
            _logger = logger;
        }

        #region 계정 잠금 관리 (Account Lock Management)

        public async Task<ServiceResult<AccountLockStatus>> GetAccountLockStatusAsync(Guid userId)
        {
            try
            {
                var cacheKey = $"account_lock_status_{userId}";
                var cachedStatus = await _cacheService.GetAsync<AccountLockStatus>(cacheKey);
                if (cachedStatus != null)
                {
                    return ServiceResult<AccountLockStatus>.Success(cachedStatus);
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<AccountLockStatus>.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                var status = new AccountLockStatus
                {
                    IsLocked = user.IsAccountLocked,
                    FailedAttempts = user.FailedLoginAttempts,
                    MaxFailedAttempts = AuthConstants.Security.MaxFailedLoginAttempts,
                    LockReason = user.LockReason,
                    LockedUntil = user.AccountLockedUntil
                };

                await _cacheService.SetAsync(cacheKey, status, TimeSpan.FromMinutes(10));
                return ServiceResult<AccountLockStatus>.Success(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get account lock status for user {UserId}", userId);
                return ServiceResult<AccountLockStatus>.Failure("An error occurred while fetching the account lock status.", "LOCK_STATUS_FETCH_FAILED");
            }
        }

        public async Task<ServiceResult> LockAccountAsync(Guid userId, string reason, TimeSpan? duration = null, Guid? lockedBy = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                var lockUntil = duration.HasValue ? _dateTimeProvider.UtcNow.Add(duration.Value) : (DateTime?)null;

                user.IsAccountLocked = true;
                user.LockReason = reason;
                user.AccountLockedUntil = lockUntil;
                await _userRepository.UpdateAsync(user);

                await _cacheService.RemoveAsync($"account_lock_status_{userId}");

                await _auditService.LogActionAsync(lockedBy, "ACCOUNT_LOCKED", AuditActionType.Blocked, "User", userId.ToString(), true, $"Reason: {reason}");
                // Option 3: Simple fix with minimal information
                await _eventBus.PublishAsync(new AccountLockedEvent(userId)
                {
                    Reason = reason,
                    LockedUntil = DateTime.UtcNow.AddHours(1), // Default 1 hour lock
                    FailedAttempts = 0, // Set to 0 if you don't have the count
                    IpAddress = "Unknown" // Set to "Unknown" if not available
                });

                return ServiceResult.Success("Account has been locked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to lock account for user {UserId}", userId);
                return ServiceResult.Failure("An error occurred while locking the account.", "ACCOUNT_LOCK_FAILED");
            }
        }

        public async Task<ServiceResult> UnlockAccountAsync(Guid userId, string? reason = null, Guid? unlockedBy = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                user.IsAccountLocked = false;
                user.LockReason = null;
                user.AccountLockedUntil = null;
                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user);

                await _cacheService.RemoveAsync($"account_lock_status_{userId}");

                await _auditService.LogActionAsync(unlockedBy, "ACCOUNT_UNLOCKED", AuditActionType.StatusChange, "User", userId.ToString(), true, $"Reason: {reason ?? "Manual unlock"}");
                await _eventBus.PublishAsync(new AccountUnlockedEvent { UserId = userId, UnlockReason = reason ?? "Manual unlock", UnlockedByConnectedId = unlockedBy });

                return ServiceResult.Success("Account has been unlocked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unlock account for user {UserId}", userId);
                return ServiceResult.Failure("An error occurred while unlocking the account.", "ACCOUNT_UNLOCK_FAILED");
            }
        }

        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user);

                await _cacheService.RemoveAsync($"account_lock_status_{userId}");

                await _auditService.LogActionAsync(null, "FAILED_ATTEMPTS_RESET", AuditActionType.Update, "User", userId.ToString(), true, "Failed login attempts have been reset.");
                await _eventBus.PublishAsync(new FailedAttemptsResetEvent { UserId = userId });

                return ServiceResult.Success("Failed login attempts have been reset successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset failed attempts for user {UserId}", userId);
                return ServiceResult.Failure("An error occurred while resetting failed attempts.", "RESET_FAILED_ATTEMPTS_FAILED");
            }
        }

        #endregion

        #region 패스워드 정책 (Password Policy)

        public async Task<ServiceResult<PasswordPolicyDto>> GetPasswordPolicyAsync(Guid? organizationId = null)
        {
            try
            {
                var orgId = organizationId ?? Guid.Empty;
                var cacheKey = $"password_policy_{orgId}";

                var cachedPolicyDto = await _cacheService.GetAsync<PasswordPolicyDto>(cacheKey);
                if (cachedPolicyDto != null)
                {
                    return ServiceResult<PasswordPolicyDto>.Success(cachedPolicyDto);
                }

                var policyEntity = await LoadPasswordPolicyWithInheritanceAsync(orgId);
                var policyDto = _mapper.Map<PasswordPolicyDto>(policyEntity);

                var cacheExpiry = policyEntity.IsCustomPolicy ? TimeSpan.FromMinutes(30) : TimeSpan.FromHours(4);
                await _cacheService.SetAsync(cacheKey, policyDto, cacheExpiry);

                return ServiceResult<PasswordPolicyDto>.Success(policyDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get password policy for organization {OrganizationId}", organizationId);
                return ServiceResult<PasswordPolicyDto>.Failure("Failed to retrieve password policy.", "GET_POLICY_FAILED");
            }
        }

        public async Task<ServiceResult> SetPasswordPolicyAsync(Guid organizationId, PasswordPolicyDto policyDto)
        {
            try
            {
                var validationResult = ValidatePasswordPolicy(policyDto);
                if (!validationResult.IsSuccess) return validationResult;

                var authResult = await ValidateOrganizationPolicyPermissionAsync(organizationId);
                if (!authResult.IsSuccess) return authResult;

                var policyEntity = await _passwordPolicyRepository.GetByOrganizationIdAsync(organizationId);
                if (policyEntity != null)
                {
                    _mapper.Map(policyDto, policyEntity);
                    await _passwordPolicyRepository.UpdateAsync(policyEntity);
                }
                else
                {
                    policyEntity = _mapper.Map<PasswordPolicy>(policyDto);
                    policyEntity.OrganizationId = organizationId;
                    policyEntity.IsCustomPolicy = true;
                    policyEntity.PolicySource = "OrganizationCustom";
                    await _passwordPolicyRepository.AddAsync(policyEntity);
                }

                await _cacheService.RemoveAsync($"password_policy_{organizationId}");

                await _auditService.LogActionAsync(null, "PASSWORD_POLICY_SET", AuditActionType.Configuration, "Organization", organizationId.ToString(), true, "Password policy has been updated.");
                await _eventBus.PublishAsync(new PasswordPolicyChangedEvent { OrganizationId = organizationId });

                return ServiceResult.Success("Password policy has been set successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set password policy for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure("Failed to set password policy.", "SET_POLICY_FAILED");
            }
        }

        public async Task<ServiceResult<PasswordExpirationInfo>> CheckPasswordExpirationAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<PasswordExpirationInfo>.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                var policyResult = await GetPasswordPolicyAsync(user.OrganizationId);
                if (!policyResult.IsSuccess || policyResult.Data == null)
                {
                    return ServiceResult<PasswordExpirationInfo>.Failure("Could not retrieve password policy for the user.", "POLICY_FETCH_FAILED");
                }

                var expirationDays = policyResult.Data.ExpirationDays;
                if (expirationDays <= 0) // 0 or less means no expiration
                {
                    return ServiceResult<PasswordExpirationInfo>.Success(new PasswordExpirationInfo { IsExpired = false, RequiresChange = false });
                }

                var lastChanged = user.PasswordChangedAt ?? user.CreatedAt;
                var expirationDate = lastChanged.AddDays(expirationDays);
                var isExpired = _dateTimeProvider.UtcNow >= expirationDate;

                return ServiceResult<PasswordExpirationInfo>.Success(new PasswordExpirationInfo
                {
                    IsExpired = isExpired,
                    ExpirationDate = expirationDate,
                    DaysUntilExpiration = (int)(expirationDate - _dateTimeProvider.UtcNow).TotalDays,
                    LastChangedDate = lastChanged,
                    RequiresChange = isExpired
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check password expiration for user {UserId}", userId);
                return ServiceResult<PasswordExpirationInfo>.Failure("Failed to check password expiration.", "CHECK_EXPIRATION_FAILED");
            }
        }

        public async Task<ServiceResult<bool>> CheckPasswordHistoryAsync(Guid userId, string newPasswordHash)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null) return ServiceResult<bool>.Failure("User not found.", AuthConstants.ErrorCodes.USER_NOT_FOUND);

                var policyResult = await GetPasswordPolicyAsync(user.OrganizationId);
                var historyCount = policyResult.IsSuccess && policyResult.Data != null ? policyResult.Data.PasswordHistoryCount : AuthConstants.PasswordPolicy.DefaultHistoryCount;
                if (historyCount <= 0) return ServiceResult<bool>.Success(true);

                var recentPasswords = await _passwordHistoryRepository.GetRecentPasswordsAsync(userId, historyCount);

                if (recentPasswords.Any(h => h.PasswordHash == newPasswordHash))
                {
                    return ServiceResult<bool>.Failure("New password cannot be the same as recent passwords.", "PASSWORD_REUSED");
                }

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check password history for user {UserId}", userId);
                return ServiceResult<bool>.Failure("Failed to check password history.", AuthConstants.ErrorCodes.HISTORY_CHECK_FAILED);
            }
        }

        #endregion

        #region 신뢰할 수 있는 장치 (Trusted Devices)

        public async Task<ServiceResult> RegisterTrustedDeviceAsync(Guid userId, TrustedDeviceRequest request)
        {
            var resultWithDto = await _trustedDeviceService.RegisterTrustedDeviceAsync(userId, request);

            if (!resultWithDto.IsSuccess)
            {
                return ServiceResult.Failure(resultWithDto.ErrorMessage ?? "Failed to register trusted device.", resultWithDto.ErrorCode);
            }
            return ServiceResult.Success(resultWithDto.Message);
        }

        public Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId)
        {
            return _trustedDeviceService.GetTrustedDevicesAsync(userId);
        }

        public Task<ServiceResult<bool>> IsTrustedDeviceAsync(Guid userId, string deviceId, string deviceFingerprint)
        {
            return _trustedDeviceService.IsDeviceTrustedAsync(userId, deviceId, deviceFingerprint);
        }

        public async Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId)
        {
            var result = await _trustedDeviceService.RemoveTrustedDeviceAsync(userId, deviceId);

            if (!result.IsSuccess)
            {
                return ServiceResult.Failure(result.ErrorMessage ?? "Failed to remove trusted device.", result.ErrorCode);
            }
            return ServiceResult.Success(result.Message);
        }

        public Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId)
        {
            return _trustedDeviceService.RemoveAllTrustedDevicesAsync(userId);
        }

        #endregion

        #region 보안 설정 (Security Settings)

        public async Task<ServiceResult<AccountSecuritySettingsDto>> GetSecuritySettingsAsync(Guid connectedId)
        {
            try
            {
                var cacheKey = $"security_settings_{connectedId}";
                var cachedSettingsDto = await _cacheService.GetAsync<AccountSecuritySettingsDto>(cacheKey);
                if (cachedSettingsDto != null)
                {
                    return ServiceResult<AccountSecuritySettingsDto>.Success(cachedSettingsDto);
                }

                var settingsEntity = await _securitySettingsRepository.GetByConnectedIdAsync(connectedId);
                if (settingsEntity == null)
                {
                    var defaultSettings = new AccountSecuritySettingsDto { ConnectedId = connectedId };
                    return ServiceResult<AccountSecuritySettingsDto>.Success(defaultSettings);
                }

                var settingsDto = _mapper.Map<AccountSecuritySettingsDto>(settingsEntity);
                await _cacheService.SetAsync(cacheKey, settingsDto, TimeSpan.FromMinutes(30));

                return ServiceResult<AccountSecuritySettingsDto>.Success(settingsDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get security settings for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<AccountSecuritySettingsDto>.Failure("Failed to retrieve security settings.", "GET_SETTINGS_FAILED");
            }
        }

        public async Task<ServiceResult> UpdateSecuritySettingsAsync(Guid connectedId, AccountSecuritySettingsDto settingsDto)
        {
            try
            {
                if (settingsDto == null || connectedId != settingsDto.ConnectedId)
                {
                    return ServiceResult.Failure("Invalid settings data provided.", "INVALID_INPUT");
                }

                var settingsEntity = await _securitySettingsRepository.GetByConnectedIdAsync(connectedId);
                if (settingsEntity != null)
                {
                    _mapper.Map(settingsDto, settingsEntity);
                    await _securitySettingsRepository.UpdateAsync(settingsEntity);
                }
                else
                {
                    settingsEntity = _mapper.Map<AccountSecuritySettings>(settingsDto);
                    await _securitySettingsRepository.AddAsync(settingsEntity);
                }

                await _cacheService.RemoveAsync($"security_settings_{connectedId}");

                await _auditService.LogActionAsync(connectedId, "SECURITY_SETTINGS_UPDATED", AuditActionType.Configuration, "AccountSecuritySettings", settingsEntity.Id.ToString(), true, "Security settings were updated.");
                await _eventBus.PublishAsync(new SecuritySettingsUpdatedEvent { ConnectedId = connectedId });

                return ServiceResult.Success("Security settings have been updated successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update security settings for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult.Failure("Failed to update security settings.", "UPDATE_SETTINGS_FAILED");
            }
        }

        #endregion

        #region 보안 이벤트 (Security Events)

        public async Task<ServiceResult> ReportSuspiciousActivityAsync(Guid userId, SuspiciousActivityReport report)
        {
            try
            {
                _logger.LogWarning("Suspicious activity reported for user {UserId}: Type={ActivityType}, IP={IpAddress}",
                    userId, report.ActivityType, report.IpAddress);

                await _auditService.LogActionAsync(userId, report.ActivityType, AuditActionType.UnauthorizedAccess, "User", userId.ToString(), false, $"Suspicious Activity: {report.Description}");

                await _eventBus.PublishAsync(new SuspiciousActivityReportedEvent
                {
                    UserId = userId,
                    Report = report
                });

                return ServiceResult.Success("Suspicious activity has been reported successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to report suspicious activity for user {UserId}", userId);
                return ServiceResult.Failure("Failed to report suspicious activity.", "REPORT_ACTIVITY_FAILED");
            }
        }

        public async Task<ServiceResult<IEnumerable<SecurityEventDto>>> GetSecurityEventsAsync(Guid userId, DateTime? from = null, DateTime? to = null)
        {
            try
            {
                // [Refactored] IAuditService의 GetAuditLogsAsync 메서드 시그니처에 맞게
                // SearchAuditLogsRequest 객체를 생성하여 호출합니다.
                var connectedIdResult = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<SecurityEventDto>>.Failure("Active ConnectedId not found for the user.", "ACTIVE_CID_NOT_FOUND");
                }

                var searchRequest = new SearchAuditLogsRequest
                {
                    UserId = userId,
                    ActionCategory = AuditActionCategory.Security,
                    StartDate = from,
                    EndDate = to
                };

                var pagination = new PaginationRequest(); // 기본 페이지네이션 사용

                var auditLogsResult = await _auditService.GetAuditLogsAsync(searchRequest, pagination, connectedIdResult.Data);

                if (!auditLogsResult.IsSuccess || auditLogsResult.Data == null)
                {
                    return ServiceResult<IEnumerable<SecurityEventDto>>.Failure(auditLogsResult.ErrorMessage ?? "Failed to retrieve audit logs.", auditLogsResult.ErrorCode);
                }

                var securityEvents = _mapper.Map<IEnumerable<SecurityEventDto>>(auditLogsResult.Data.Items);

                return ServiceResult<IEnumerable<SecurityEventDto>>.Success(securityEvents);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get security events for user {UserId}", userId);
                return ServiceResult<IEnumerable<SecurityEventDto>>.Failure("Failed to retrieve security events.", "GET_EVENTS_FAILED");
            }
        }

        #endregion
        // Path: D:/Works/Projects/Auth_V2/AuthHive/authhive.auth/Services/Authentication/AccountSecurityService.cs

        // ... (inside the AccountSecurityService class) ...

        #region 신뢰할 수 있는 장치 (Trusted Devices)

        // ... (your other trusted device methods like RegisterTrustedDeviceAsync, etc.) ...

        /// <summary>
        /// Checks if a device is trusted and sends a notification if it's new.
        /// </summary>
        public async Task<ServiceResult> CheckAndNotifyNewDeviceAsync(
            Guid userId,
            string deviceId,
            string deviceFingerprint,
            string? location,
            string ipAddress,      // <-- Add parameter
            string? userAgent)     // <-- Add parameter
        {
            try
            {
                var isTrustedResult = await _trustedDeviceService.IsDeviceTrustedAsync(userId, deviceId, deviceFingerprint);
                if (isTrustedResult.IsSuccess && isTrustedResult.Data)
                {
                    return ServiceResult.Success();
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("Could not send new device notification for user {UserId} as user was not found.", userId);
                    return ServiceResult.Success();
                }

                _logger.LogInformation("New device detected for user {UserId}. DeviceId: {DeviceId}", userId, deviceId);

                await _auditService.LogActionAsync(
                    userId, "NEW_DEVICE_LOGIN", AuditActionType.Login, "User", userId.ToString(), true,
                    $"New device login detected. DeviceId: {deviceId}, Location: {location ?? "Unknown"}"
                );

                // FINAL FIX: Use the new, complete constructor for the event, not the object initializer.
                var newDeviceEvent = new NewDeviceLoggedInEvent(
                    userId: userId,
                    deviceId: deviceId,
                    ipAddress: ipAddress,
                    userAgent: userAgent ?? "Unknown",
                    location: location
                );
                await _eventBus.PublishAsync(newDeviceEvent);

                var emailMessage = new EmailMessageDto
                {
                    To = user.Email,
                    Subject = "Security Alert: New Device Login",
                    Body = $"We detected a login from a new device in {location ?? "an unknown location"}. If this was not you, please secure your account immediately."
                };
                await _emailService.SendEmailAsync(emailMessage);

                return ServiceResult.Success("New device notification sent.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check and notify for new device for user {UserId}", userId);
                return ServiceResult.Success("An error occurred during new device check, but login process can continue.");
            }
        }
        #endregion
        #region Private Helper Methods


        private async Task<PasswordPolicy> LoadPasswordPolicyWithInheritanceAsync(Guid organizationId)
        {
            if (organizationId != Guid.Empty)
            {
                var currentOrgId = (Guid?)organizationId;
                while (currentOrgId.HasValue)
                {
                    var policyResult = await _passwordPolicyRepository.GetByOrganizationIdAsync(currentOrgId.Value);
                    if (policyResult != null) return policyResult;

                    // [Refactored] ServiceResult<T>의 결과를 올바르게 처리합니다.
                    var parentResult = await _orgHierarchyService.GetParentOrganizationIdAsync(currentOrgId.Value);
                    if (parentResult.IsSuccess)
                    {
                        currentOrgId = parentResult.Data;
                    }
                    else
                    {
                        _logger.LogWarning("Failed to retrieve parent for organization {OrganizationId}. Stopping policy inheritance lookup.", currentOrgId.Value);
                        currentOrgId = null;
                    }
                }
            }
            return GetDefaultPasswordPolicy();
        }


        private PasswordPolicy GetDefaultPasswordPolicy()
        {
            return new PasswordPolicy
            {
                MinimumLength = AuthConstants.PasswordPolicy.MinLength,
                MaximumLength = AuthConstants.PasswordPolicy.MaxLength,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireNumbers = true,
                RequireSpecialCharacters = true,
                PasswordHistoryCount = AuthConstants.PasswordPolicy.DefaultHistoryCount,
                ExpirationDays = AuthConstants.PasswordPolicy.DefaultExpirationDays,
                PreventCommonPasswords = true,
                PreventUserInfoInPassword = true,
                IsCustomPolicy = false,
                PolicySource = "SystemDefault"
            };
        }

        private ServiceResult ValidatePasswordPolicy(PasswordPolicyDto policy)
        {
            if (policy == null) return ServiceResult.Failure("Password policy is required.", "POLICY_REQUIRED");
            var violations = new List<string>();

            if (policy.MinimumLength < AuthConstants.PasswordPolicy.MinLength)
                violations.Add($"Minimum length must be at least {AuthConstants.PasswordPolicy.MinLength} characters.");
            if (policy.MaximumLength > AuthConstants.PasswordPolicy.MaxLength)
                violations.Add($"Maximum length cannot exceed {AuthConstants.PasswordPolicy.MaxLength} characters.");
            if (policy.MinimumLength >= policy.MaximumLength)
                violations.Add("Minimum length must be less than maximum length.");
            if (policy.PasswordHistoryCount < 0 || policy.PasswordHistoryCount > AuthConstants.PasswordPolicy.MaxHistoryCount)
                violations.Add($"Password history count must be between 0 and {AuthConstants.PasswordPolicy.MaxHistoryCount}.");
            if (policy.ExpirationDays < 0 || policy.ExpirationDays > AuthConstants.PasswordPolicy.MaxExpirationDays)
                violations.Add($"Expiration days must be between 0 and {AuthConstants.PasswordPolicy.MaxExpirationDays}.");

            if (violations.Any())
                return ServiceResult.Failure($"Policy validation failed: {string.Join(" ", violations)}", AuthConstants.ErrorCodes.POLICY_VALIDATION_FAILED);

            return ServiceResult.Success();
        }

        private async Task<ServiceResult> ValidateOrganizationPolicyPermissionAsync(Guid organizationId)
        {
            var planResult = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (planResult == null)
            {
                return ServiceResult.Failure("Could not determine organization's plan.", "PLAN_FETCH_FAILED");
            }
            // var planKey = planResult.PlanKey;

            // if (!PricingConstants.SubscriptionPlans.CustomPasswordPolicyEnabled.Contains(planKey))
            // {
            //     return ServiceResult.Failure(
            //         "Custom password policies are not available for the moment.",
            //         AuthConstants.ErrorCodes.InsufficientPermissions);
            // }

            return ServiceResult.Success();
        }

        #endregion

        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _userRepository.CountAsync(
                   predicate: null, // 필터링 조건 (없으므로 null)
                   cancellationToken: cancellationToken);

                return true;
            }
            catch (OperationCanceledException)
            {
                // 취소 요청 시에는 비정상 상태로 간주
                return false;
            }
            catch (Exception ex)
            {
                // DB 연결 실패 등의 일반적인 예외 처리
                _logger.LogWarning(ex, "AccountSecurityService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) // ◀◀ CancellationToken 추가
        {
            _logger.LogInformation("AccountSecurityService initialized.");
            return Task.CompletedTask;
        }

        #endregion
    }
}

