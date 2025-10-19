using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.Audit.Requests;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Audit;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Models.External;
using AuthHive.Core.Models.Infra.Monitoring;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 계정 보안 서비스 - AuthHive v16 최종 구현체
    /// [Refactored] IPrincipalAccessor를 사용하여 작업 주체를 안전하게 식별하고,
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
        private readonly IPrincipalAccessor _principalAccessor; // 수정: IPrincipalAccessor 추가

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
            ILogger<AccountSecurityService> logger,
            IPrincipalAccessor principalAccessor) // 수정: 생성자 주입
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
            _principalAccessor = principalAccessor; // 수정: 필드 할당
        }

        #region 계정 잠금 관리 (Account Lock Management)

        public async Task<ServiceResult<AccountLockStatus>> GetAccountLockStatusAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"account_lock_status:{userId}";
                var cachedStatus = await _cacheService.GetAsync<AccountLockStatus>(cacheKey, cancellationToken);
                if (cachedStatus != null)
                {
                    return ServiceResult<AccountLockStatus>.Success(cachedStatus);
                }

                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult<AccountLockStatus>.NotFound("User not found.");
                }

                var status = new AccountLockStatus
                {
                    IsLocked = user.IsAccountLocked,
                    FailedAttempts = user.FailedLoginAttempts,
                    MaxFailedAttempts = AuthConstants.Security.MaxFailedLoginAttempts,
                    LockReason = user.LockReason,
                    LockedUntil = user.AccountLockedUntil
                };

                await _cacheService.SetAsync(cacheKey, status, TimeSpan.FromMinutes(10), cancellationToken);
                return ServiceResult<AccountLockStatus>.Success(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get account lock status for user {UserId}", userId);
                return ServiceResult<AccountLockStatus>.Failure("An error occurred while fetching the account lock status.", "LOCK_STATUS_FETCH_FAILED");
            }
        }

        public async Task<ServiceResult> LockAccountAsync(Guid userId, string reason, TimeSpan? duration = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found.");
                }

                var lockedBy = _principalAccessor.ConnectedId;
                var lockUntil = duration.HasValue ? _dateTimeProvider.UtcNow.Add(duration.Value) : (DateTime?)null;

                user.IsAccountLocked = true;
                user.LockReason = reason;
                user.AccountLockedUntil = lockUntil;
                await _userRepository.UpdateAsync(user, cancellationToken);

                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogSecurityEventAsync(
                    eventType: "ACCOUNT_LOCKED",
                    severity: AuditEventSeverity.Warning,
                    description: $"Account locked for user {userId}. Reason: {reason}",
                    connectedId: lockedBy,
                    details: new Dictionary<string, object> { { "TargetUserId", userId } },
                    cancellationToken: cancellationToken
                );

                await _eventBus.PublishAsync(new AccountLockedEvent(
                                    userId: userId,
                                    reason: reason,
                                    lockedUntil: lockUntil,
                                    lockedBy: lockedBy,
                                    ipAddress: _principalAccessor.IpAddress ?? "Unknown",
                                    failedAttempts: user.FailedLoginAttempts // 실패 횟수 정보 추가
                                ), cancellationToken);

                return ServiceResult.Success("Account has been locked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to lock account for user {UserId}", userId);
                return ServiceResult.Failure("An error occurred while locking the account.", "ACCOUNT_LOCK_FAILED");
            }
        }

        public async Task<ServiceResult> UnlockAccountAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found.");
                }

                var unlockedBy = _principalAccessor.ConnectedId;

                user.IsAccountLocked = false;
                user.LockReason = null;
                user.AccountLockedUntil = null;
                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user, cancellationToken);

                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogSecurityEventAsync(
                    eventType: "ACCOUNT_UNLOCKED",
                    severity: AuditEventSeverity.Info,
                    description: $"Account unlocked for user {userId}. Reason: {reason ?? "Manual unlock"}",
                    connectedId: unlockedBy,
                    details: new Dictionary<string, object> { { "TargetUserId", userId } },
                    cancellationToken: cancellationToken
                );

                await _eventBus.PublishAsync(new AccountUnlockedEvent(userId, unlockedBy, reason ?? "Manual unlock"), cancellationToken);

                return ServiceResult.Success("Account has been unlocked successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unlock account for user {UserId}", userId);
                return ServiceResult.Failure("An error occurred while unlocking the account.", "ACCOUNT_UNLOCK_FAILED");
            }
        }

        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found.");
                }

                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user, cancellationToken);

                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogSecurityEventAsync(
                     eventType: "FAILED_ATTEMPTS_RESET",
                     severity: AuditEventSeverity.Info,
                     description: "Failed login attempts have been reset.",
                     connectedId: _principalAccessor.ConnectedId,
                     details: new Dictionary<string, object> { { "TargetUserId", userId } },
                     cancellationToken: cancellationToken
                 );
                await _eventBus.PublishAsync(new FailedAttemptsResetEvent(userId), cancellationToken);
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

        public async Task<ServiceResult<PasswordPolicyDto>> GetPasswordPolicyAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var orgId = organizationId ?? Guid.Empty;
                var cacheKey = $"password_policy:{orgId}";

                var cachedPolicyDto = await _cacheService.GetAsync<PasswordPolicyDto>(cacheKey, cancellationToken);
                if (cachedPolicyDto != null)
                {
                    return ServiceResult<PasswordPolicyDto>.Success(cachedPolicyDto);
                }

                var policyEntity = await LoadPasswordPolicyWithInheritanceAsync(organizationId, cancellationToken);
                var policyDto = _mapper.Map<PasswordPolicyDto>(policyEntity);

                var isCustomPolicy = (bool?)policyEntity.GetType().GetProperty("IsCustomPolicy")?.GetValue(policyEntity) ?? false;
                var cacheExpiry = isCustomPolicy ? TimeSpan.FromMinutes(30) : TimeSpan.FromHours(4);
                await _cacheService.SetAsync(cacheKey, policyDto, cacheExpiry, cancellationToken);

                return ServiceResult<PasswordPolicyDto>.Success(policyDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get password policy for organization {OrganizationId}", organizationId);
                return ServiceResult<PasswordPolicyDto>.Failure("Failed to retrieve password policy.", "GET_POLICY_FAILED");
            }
        }

        public async Task<ServiceResult> SetPasswordPolicyAsync(Guid organizationId, PasswordPolicyDto policyDto, CancellationToken cancellationToken = default)
        {
            try
            {
                var validationResult = ValidatePasswordPolicy(policyDto);
                if (!validationResult.IsSuccess) return validationResult;

                var changedBy = _principalAccessor.ConnectedId;
                var policyEntity = await _passwordPolicyRepository.GetByOrganizationIdAsync(organizationId, cancellationToken);
                var oldPolicyJson = policyEntity != null ? System.Text.Json.JsonSerializer.Serialize(policyEntity) : null;


                if (policyEntity != null)
                {
                    _mapper.Map(policyDto, policyEntity);
                    await _passwordPolicyRepository.UpdateAsync(policyEntity, cancellationToken);
                }
                else
                {
                    policyEntity = _mapper.Map<PasswordPolicy>(policyDto);
                    policyEntity.OrganizationId = organizationId;
                    await _passwordPolicyRepository.AddAsync(policyEntity, cancellationToken);
                }

                await _cacheService.RemoveAsync($"password_policy:{organizationId}", cancellationToken);

                await _auditService.LogSettingChangeAsync(
                    settingKey: "PasswordPolicy",
                    oldValue: oldPolicyJson,
                    newValue: System.Text.Json.JsonSerializer.Serialize(policyDto),
                    connectedId: changedBy ?? Guid.Empty,
                    organizationId: organizationId,
                    cancellationToken: cancellationToken
                );

                await _eventBus.PublishAsync(new PasswordPolicyChangedEvent(organizationId, changedBy), cancellationToken);

                return ServiceResult.Success("Password policy has been set successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set password policy for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure("Failed to set password policy.", "SET_POLICY_FAILED");
            }
        }

        #endregion

        #region 신뢰할 수 있는 장치 (Trusted Devices)

        public async Task<ServiceResult> CheckAndNotifyNewDeviceAsync(
            Guid userId,
            string deviceId,
            string fingerprint,
            string? location,
            string ipAddress,
            string? userAgent,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var isTrustedResult = await _trustedDeviceService.IsDeviceTrustedAsync(userId, deviceId, fingerprint, cancellationToken);
                if (isTrustedResult.IsSuccess && isTrustedResult.Data)
                {
                    return ServiceResult.Success();
                }

                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null || string.IsNullOrEmpty(user.Email))
                {
                    _logger.LogWarning("Could not send new device notification for user {UserId} as user/email was not found.", userId);
                    return ServiceResult.Success();
                }

                _logger.LogInformation("New device detected for user {UserId}. DeviceId: {DeviceId}", userId, deviceId);

                await _auditService.LogSecurityEventAsync(
                    eventType: "NEW_DEVICE_LOGIN",
                    severity: AuditEventSeverity.Info,
                    description: $"New device login detected. DeviceId: {deviceId}, Location: {location ?? "Unknown"}",
                    connectedId: null,
                    details: new Dictionary<string, object> { { "TargetUserId", userId } },
                    cancellationToken: cancellationToken
                );

                var newDeviceEvent = new NewDeviceLoggedInEvent(
                              userId: userId,
                              organizationId: _principalAccessor.OrganizationId, // 현재 컨텍스트의 조직 ID
                              deviceId: deviceId,
                              ipAddress: ipAddress,
                              userAgent: userAgent ?? "Unknown",
                              location: location
                          );
                await _eventBus.PublishAsync(newDeviceEvent, cancellationToken);
                var emailMessage = new EmailMessageDto
                {
                    To = new List<string> { user.Email },
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

        #region 보안 설정 (Security Settings)

        public async Task<ServiceResult> UpdateSecuritySettingsAsync(Guid connectedId, AccountSecuritySettingsDto settingsDto, CancellationToken cancellationToken = default)
        {
            try
            {
                if (settingsDto == null || connectedId != settingsDto.ConnectedId)
                {
                    return ServiceResult.Failure("Invalid settings data provided.", "INVALID_INPUT");
                }

                var changedBy = _principalAccessor.ConnectedId;
                if (changedBy != connectedId)
                {
                    // Add authorization check here if needed: can the current user change settings for another user?
                }

                var settingsEntity = await _securitySettingsRepository.GetByConnectedIdAsync(connectedId, cancellationToken);
                var oldSettingsJson = settingsEntity != null ? System.Text.Json.JsonSerializer.Serialize(settingsEntity) : null;

                if (settingsEntity != null)
                {
                    _mapper.Map(settingsDto, settingsEntity);
                    await _securitySettingsRepository.UpdateAsync(settingsEntity, cancellationToken);
                }
                else
                {
                    settingsEntity = _mapper.Map<AccountSecuritySettings>(settingsDto);
                    await _securitySettingsRepository.AddAsync(settingsEntity, cancellationToken);
                }

                await _cacheService.RemoveAsync($"security_settings:{connectedId}", cancellationToken);

                await _auditService.LogSettingChangeAsync(
                    settingKey: $"SecuritySettings:{connectedId}",
                    oldValue: oldSettingsJson,
                    newValue: System.Text.Json.JsonSerializer.Serialize(settingsDto),
                    connectedId: changedBy ?? Guid.Empty,
                    cancellationToken: cancellationToken
                );
                await _eventBus.PublishAsync(new SecuritySettingsUpdatedEvent(connectedId, changedBy), cancellationToken);

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

        public async Task<ServiceResult> ReportSuspiciousActivityAsync(Guid userId, SuspiciousActivityReport report, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Suspicious activity reported for user {UserId}: Type={ActivityType}, IP={IpAddress}",
                    userId, report.ActivityType, report.IpAddress);

                await _auditService.LogSecurityEventAsync(
                    eventType: report.ActivityType,
                    severity: AuditEventSeverity.Critical,
                    description: report.Description,
                    connectedId: report.ConnectedId,
                    details: report.AdditionalData,
                    cancellationToken: cancellationToken
                );

                await _eventBus.PublishAsync(new SuspiciousActivityReportedEvent(userId, report), cancellationToken);

                return ServiceResult.Success("Suspicious activity has been reported successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to report suspicious activity for user {UserId}", userId);
                return ServiceResult.Failure("Failed to report suspicious activity.", "REPORT_ACTIVITY_FAILED");
            }
        }

        #endregion

        #region Private Helper Methods & Dummy Implementations

        private async Task<PasswordPolicy> LoadPasswordPolicyWithInheritanceAsync(Guid? organizationId, CancellationToken cancellationToken)
        {
            if (organizationId.HasValue && organizationId != Guid.Empty)
            {
                var currentOrgId = organizationId;
                while (currentOrgId.HasValue)
                {
                    var policy = await _passwordPolicyRepository.GetByOrganizationIdAsync(currentOrgId.Value, cancellationToken);
                    if (policy != null) return policy;

                    var parentResult = await _orgHierarchyService.GetParentOrganizationIdAsync(currentOrgId.Value);
                    currentOrgId = (parentResult.IsSuccess && parentResult.Data.HasValue) ? parentResult.Data : null;
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
            };
        }

        private ServiceResult ValidatePasswordPolicy(PasswordPolicyDto policy)
        {
            if (policy == null) return ServiceResult.Failure("Password policy is required.", "POLICY_REQUIRED");
            // Add more validation logic here as needed
            return ServiceResult.Success();
        }

        public Task<ServiceResult<IEnumerable<SecurityEventDto>>> GetSecurityEventsAsync(Guid userId, DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RegisterTrustedDeviceAsync(Guid userId, TrustedDeviceRequest request, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> IsTrustedDeviceAsync(Guid userId, string deviceId, string deviceFingerprint, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<AccountSecuritySettingsDto>> GetSecuritySettingsAsync(Guid connectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<PasswordExpirationInfo>> CheckPasswordExpirationAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> CheckPasswordHistoryAsync(Guid userId, string newPasswordHash, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        #endregion
    }
}

