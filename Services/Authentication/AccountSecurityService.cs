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
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 계정 보안 서비스 - AuthHive v16 최종 구현체
    /// [리팩토링] IPrincipalAccessor를 사용하여 작업 주체를 안전하게 식별하고,
    /// IUnitOfWork를 통해 트랜잭션의 원자성을 보장하며, 리포지토리 패턴을 준수합니다.
    /// 계정 잠금, 패스워드 정책, 신뢰 장치 등 계정 보안과 관련된 모든 기능을 총괄합니다.
    /// </summary>
    public class AccountSecurityService : IAccountSecurityService
    {
        // 데이터 접근을 위한 리포지토리 및 서비스 의존성
        private readonly IUserRepository _userRepository;
        private readonly ITrustedDeviceService _trustedDeviceService;
        private readonly IPasswordPolicyRepository _passwordPolicyRepository;
        private readonly IPasswordHistoryRepository _passwordHistoryRepository;
        private readonly IAccountSecuritySettingsRepository _securitySettingsRepository;
        private readonly IOrganizationHierarchyService _orgHierarchyService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IPlanService _planService;

        // 인프라 및 공통 서비스 의존성
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<AccountSecurityService> _logger;

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
            IPrincipalAccessor principalAccessor,
            IUnitOfWork unitOfWork)
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
            _principalAccessor = principalAccessor;
            _unitOfWork = unitOfWork;
        }

        #region IService 구현
        /// <summary>
        /// 서비스의 상태를 확인합니다. 핵심 의존성(UserRepository)의 상태를 확인하여 반환합니다.
        /// </summary>
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return _userRepository.IsHealthyAsync(cancellationToken);
        }

        /// <summary>
        /// 서비스 초기화 로직입니다. 현재는 별도 작업이 필요하지 않습니다.
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        #endregion

        #region 계정 잠금 관리 (Account Lock Management)
        /// <summary>
        /// 지정된 사용자의 로그인 실패 횟수를 1 증가시키고, 정책에 따라 계정을 자동으로 잠급니다.
        /// </summary>
        public async Task<ServiceResult> IncrementFailedAttemptsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // 데이터베이스 변경 작업을 원자적으로 처리하기 위해 트랜잭션을 시작합니다.
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult.NotFound("사용자를 찾을 수 없습니다.");
                }

                user.FailedLoginAttempts++;

                // 사용자에게 적용될 잠금 정책을 가져옵니다. (이 예제에서는 시스템 기본 정책을 사용)
                var policyResult = await GetPasswordPolicyAsync(null, cancellationToken);
                var policy = policyResult.Data ?? GetDefaultPasswordPolicyDto();

                // 실패 횟수가 정책의 최대 허용치를 초과했는지 확인합니다.
                if (user.FailedLoginAttempts >= policy.MaxFailedAttempts)
                {
                    var lockoutDuration = TimeSpan.FromMinutes(policy.LockoutDurationMinutes);
                    user.Status = UserStatus.IsLocked;
                    user.AccountLockedUntil = _dateTimeProvider.UtcNow.Add(lockoutDuration);
                    user.LockReason = $"Exceeded max failed attempts ({policy.MaxFailedAttempts})";

                    // 감사 로그를 기록하고, 계정 잠금 이벤트를 발행합니다.
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.AccountLocked,
                        action: "Account automatically locked due to failed attempts",
                        connectedId: Guid.Empty, // 시스템이 수행한 작업이므로 ConnectedId 없음
                        resourceType: "User",
                        resourceId: user.Id.ToString(),
                        cancellationToken: cancellationToken);

                    // user.Id (잠긴 사용자 ID), null (lockedBy, 시스템 잠금), user.LockReason (잠금 이유)
                    await _eventBus.PublishAsync(
                        new AccountLockedEvent(
                            user.Id,
                            user.LockReason,
                            user.AccountLockedUntil, // (1) lockedUntil (DateTime?)
                            null,                    // (2) lockedBy (Guid?)
                            string.Empty,            // (3) ipAddress (string) - 현재 서비스 코드에서는 알 수 없으므로 임시로 빈 값 사용.
                            user.FailedLoginAttempts // (4) failedAttempts (int)
                        ),
                        cancellationToken);

                }

                await _userRepository.UpdateAsync(user, cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId})의 로그인 실패 횟수 증가 처리 중 오류 발생", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("로그인 실패 횟수를 처리하는 중 오류가 발생했습니다.");
            }
        }

        /// <summary>
        /// 지정된 사용자의 계정 잠금 상태를 조회합니다. 성능을 위해 캐싱을 사용합니다.
        /// </summary>
        public async Task<ServiceResult<AccountLockStatus>> GetAccountLockStatusAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                string cacheKey = $"account_lock_status:{userId}";
                // 1. 먼저 캐시에서 상태 정보를 조회합니다.
                var cachedStatus = await _cacheService.GetAsync<AccountLockStatus>(cacheKey, cancellationToken);
                if (cachedStatus != null)
                {
                    return ServiceResult<AccountLockStatus>.Success(cachedStatus);
                }

                // 2. 캐시에 없으면 데이터베이스에서 사용자 정보를 조회합니다.
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult<AccountLockStatus>.NotFound("사용자를 찾을 수 없습니다.");
                }

                var status = new AccountLockStatus
                {
                    IsLocked = user.Status == UserStatus.IsLocked && user.AccountLockedUntil > _dateTimeProvider.UtcNow,
                    FailedAttempts = user.FailedLoginAttempts,
                    LockedUntil = user.AccountLockedUntil,
                    LockReason = user.LockReason,
                };

                // 3. 조회한 정보를 다음에 사용할 수 있도록 캐시에 저장합니다.
                await _cacheService.SetAsync(cacheKey, status, TimeSpan.FromMinutes(10), cancellationToken);
                return ServiceResult<AccountLockStatus>.Success(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId})의 계정 잠금 상태 조회 실패", userId);
                return ServiceResult<AccountLockStatus>.Failure("계정 잠금 상태 조회 중 오류 발생", "LOCK_STATUS_FETCH_FAILED");
            }
        }

        /// <summary>
        /// 관리자가 특정 사용자의 계정을 수동으로 잠급니다.
        /// </summary>
        public async Task<ServiceResult> LockAccountAsync(Guid userId, string reason, TimeSpan? duration = null, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("사용자를 찾을 수 없습니다.");
                }

                // IPrincipalAccessor를 통해 작업을 수행하는 관리자를 식별합니다.
                var lockedBy = _principalAccessor.ConnectedId;
                var lockUntil = duration.HasValue ? _dateTimeProvider.UtcNow.Add(duration.Value) : (DateTime?)null;

                user.Status = UserStatus.IsLocked;
                user.LockReason = reason;
                user.AccountLockedUntil = lockUntil;
                await _userRepository.UpdateAsync(user, cancellationToken);

                // 관련 캐시를 무효화하여 데이터 일관성을 유지합니다.
                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.AccountLocked,
                    action: "Account manually locked by administrator",
                    connectedId: lockedBy ?? Guid.Empty,
                    resourceType: "User",
                    resourceId: userId.ToString(),
                    metadata: new Dictionary<string, object> { { "Reason", reason } },
                    cancellationToken: cancellationToken);
                await _eventBus.PublishAsync(
                    new AccountLockedEvent(
                        userId,
                        reason,
                        lockUntil,
                        lockedBy,
                        string.Empty // (1) ipAddress (string) - 현재 서비스 코드에서는 알 수 없으므로 임시로 빈 값 사용.
                    ),
                    cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                return ServiceResult.Success("계정이 성공적으로 잠겼습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId}) 계정 잠금 실패", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("계정 잠금 중 오류 발생", "ACCOUNT_LOCK_FAILED");
            }
        }

        /// <summary>
        /// 관리자가 잠긴 사용자의 계정을 수동으로 해제합니다.
        /// </summary>
        public async Task<ServiceResult> UnlockAccountAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("사용자를 찾을 수 없습니다.");
                }

                var unlockedBy = _principalAccessor.ConnectedId;

                user.Status = UserStatus.Active;
                user.LockReason = null;
                user.AccountLockedUntil = null;
                user.FailedLoginAttempts = 0; // 잠금 해제 시 실패 횟수도 초기화합니다.
                await _userRepository.UpdateAsync(user, cancellationToken);

                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.AccountUnlocked,
                    action: "Account manually unlocked by administrator",
                    connectedId: unlockedBy ?? Guid.Empty,
                    resourceType: "User",
                    resourceId: userId.ToString(),
                    metadata: new Dictionary<string, object> { { "Reason", reason ?? "Manual unlock" } },
                    cancellationToken: cancellationToken);

                await _eventBus.PublishAsync(new AccountUnlockedEvent(userId, unlockedBy, reason ?? "Manual unlock"), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                return ServiceResult.Success("계정 잠금이 성공적으로 해제되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId}) 계정 잠금 해제 실패", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("계정 잠금 해제 중 오류 발생", "ACCOUNT_UNLOCK_FAILED");
            }
        }

        /// <summary>
        /// 사용자의 로그인 실패 횟수를 0으로 초기화합니다. (예: 로그인 성공 시)
        /// </summary>
        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.NotFound("사용자를 찾을 수 없습니다.");
                }

                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user, cancellationToken);

                await _cacheService.RemoveAsync($"account_lock_status:{userId}", cancellationToken);

                await _auditService.LogActionAsync(
                   actionType: AuditActionType.SecuritySettingChanged,
                   action: "Failed login attempts reset",
                   connectedId: _principalAccessor.ConnectedId ?? Guid.Empty,
                   resourceType: "User",
                   resourceId: userId.ToString(),
                   cancellationToken: cancellationToken);

                await _eventBus.PublishAsync(new FailedAttemptsResetEvent(userId), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                return ServiceResult.Success("로그인 실패 횟수가 성공적으로 초기화되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId})의 로그인 실패 횟수 초기화 실패", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("로그인 실패 횟수 초기화 중 오류 발생", "RESET_FAILED_ATTEMPTS_FAILED");
            }
        }
        #endregion

        #region 패스워드 정책 (Password Policy)
        /// <summary>
        /// 지정된 조직 또는 시스템의 패스워드 정책을 조회합니다. 조직 계층 구조를 따라 상속된 정책을 찾습니다.
        /// </summary>
        public async Task<ServiceResult<PasswordPolicyDto>> GetPasswordPolicyAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"password_policy:{organizationId ?? Guid.Empty}";

                var policyDto = await _cacheService.GetOrSetAsync(cacheKey, async () =>
                {
                    var policyEntity = await LoadPasswordPolicyWithInheritanceAsync(organizationId, cancellationToken);
                    return _mapper.Map<PasswordPolicyDto>(policyEntity);
                }, TimeSpan.FromHours(1), cancellationToken);

                return ServiceResult<PasswordPolicyDto>.Success(policyDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "조직({OrganizationId})의 패스워드 정책 조회 실패", organizationId);
                return ServiceResult<PasswordPolicyDto>.Failure("패스워드 정책 조회 실패", "GET_POLICY_FAILED");
            }
        }

        /// <summary>
        /// 특정 조직의 커스텀 패스워드 정책을 설정합니다.
        /// </summary>
        public async Task<ServiceResult> SetPasswordPolicyAsync(Guid organizationId, PasswordPolicyDto policyDto, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
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

                // 정책이 변경되었으므로 관련 캐시를 반드시 무효화합니다.
                await _cacheService.RemoveAsync($"password_policy:{organizationId}", cancellationToken);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.SecurityPolicyChanged,
                    action: "Password policy updated",
                    connectedId: changedBy ?? Guid.Empty,
                    resourceType: "Organization",
                    resourceId: organizationId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        { "OldPolicy", oldPolicyJson ?? "N/A" },
                        { "NewPolicy", System.Text.Json.JsonSerializer.Serialize(policyDto) }
                    },
                    cancellationToken: cancellationToken);

                await _eventBus.PublishAsync(new PasswordPolicyChangedEvent(organizationId, changedBy), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                return ServiceResult.Success("패스워드 정책이 성공적으로 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "조직({OrganizationId})의 패스워드 정책 설정 실패", organizationId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("패스워드 정책 설정 실패", "SET_POLICY_FAILED");
            }
        }
        #endregion

        #region 헬퍼 및 미구현 메서드
        /// <summary>
        /// 조직의 계층 구조를 따라 올라가며 적용할 패스워드 정책을 찾습니다. 없으면 시스템 기본값을 반환합니다.
        /// </summary>
        private async Task<PasswordPolicy> LoadPasswordPolicyWithInheritanceAsync(Guid? organizationId, CancellationToken cancellationToken)
        {
            if (organizationId.HasValue && organizationId != Guid.Empty)
            {
                var currentOrgId = organizationId;
                while (currentOrgId.HasValue)
                {
                    var policy = await _passwordPolicyRepository.GetByOrganizationIdAsync(currentOrgId.Value, cancellationToken);
                    if (policy != null) return policy;

                    var parentResult = await _orgHierarchyService.GetParentOrganizationIdAsync(currentOrgId.Value, cancellationToken);
                    currentOrgId = (parentResult.IsSuccess && parentResult.Data.HasValue) ? parentResult.Data : null;
                }
            }
            // 상속할 정책이 없으면 시스템 기본 정책을 반환합니다.
            return GetDefaultPasswordPolicy();
        }

        /// <summary>
        /// 시스템의 하드코딩된 기본 패스워드 정책을 생성합니다.
        /// </summary>
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

        /// <summary>
        /// 기본 패스워드 정책 엔티티를 DTO로 변환하여 반환합니다.
        /// </summary>
        private PasswordPolicyDto GetDefaultPasswordPolicyDto()
        {
            return _mapper.Map<PasswordPolicyDto>(GetDefaultPasswordPolicy());
        }

        /// <summary>
        /// DTO 형태로 전달된 패스워드 정책의 유효성을 검사합니다.
        /// </summary>
        private ServiceResult ValidatePasswordPolicy(PasswordPolicyDto policy)
        {
            if (policy == null) return ServiceResult.Failure("패스워드 정책은 null일 수 없습니다.", "POLICY_REQUIRED");
            // 필요에 따라 최소/최대 길이 제약 등 더 많은 유효성 검사 로직 추가 가능
            return ServiceResult.Success();
        }

        // 아래는 아직 구현되지 않은 메서드들입니다.
        public Task<ServiceResult<IEnumerable<SecurityEventDto>>> GetSecurityEventsAsync(Guid userId, DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RegisterTrustedDeviceAsync(Guid userId, TrustedDeviceRequest request, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> IsTrustedDeviceAsync(Guid userId, string deviceId, string deviceFingerprint, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> CheckAndNotifyNewDeviceAsync(Guid userId, string deviceId, string fingerprint, string? location, string ipAddress, string? userAgent, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<AccountSecuritySettingsDto>> GetSecuritySettingsAsync(Guid connectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> UpdateSecuritySettingsAsync(Guid connectedId, AccountSecuritySettingsDto settingsDto, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<PasswordExpirationInfo>> CheckPasswordExpirationAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> CheckPasswordHistoryAsync(Guid userId, string newPasswordHash, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> ReportSuspiciousActivityAsync(Guid userId, SuspiciousActivityReport report, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        #endregion
    }
}

