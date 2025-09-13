// Path: AuthHive.Auth/Services/Authentication/AccountSecurityService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Constants.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Infra.Monitoring;
using AuthHive.Core.Models.Infra.Monitoring;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 계정 보안 서비스 - AuthHive v15
    /// 계정 잠금, 패스워드 정책, 신뢰할 수 있는 장치 관리 및 보안 기능 제공
    /// </summary>
    public class AccountSecurityService : IAccountSecurityService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITrustedDeviceService _trustedDeviceService;
        private readonly IMemoryCache _cache;
        private readonly ILogger<AccountSecurityService> _logger;
        private readonly IConnectedIdService _connectedIdService;
        // ConnectedId 조회를 위한 서비스 (임시로 UserRepository 사용)
        // TODO: 실제로는 IConnectedIdService 또는 IUserContextService 사용 권장

        public AccountSecurityService(
            IUserRepository userRepository,
            ITrustedDeviceService trustedDeviceService,
            IMemoryCache cache,
            IConnectedIdService connectedIdService,
            ILogger<AccountSecurityService> logger)
        {
            _userRepository = userRepository;
            _trustedDeviceService = trustedDeviceService;
            _connectedIdService = connectedIdService;
            _cache = cache;
            _logger = logger;
        }

        /// <summary>
        /// UserId로부터 현재 활성 ConnectedId 조회
        /// TODO: 실제 구현에서는 IConnectedIdService 사용 권장
        /// </summary>
        private Guid? GetActiveConnectedId(Guid userId)
        {
            try
            {
                // 캐시에서 먼저 확인
                var cacheKey = $"active_connected_id_{userId}";
                if (_cache.TryGetValue(cacheKey, out Guid cachedConnectedId))
                {
                    return cachedConnectedId;
                }

                // TODO: 실제로는 다음과 같은 서비스를 사용해야 함
                // var connectedId = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId);

                // 임시 구현: userId를 ConnectedId로 사용 (1:1 매핑 가정)
                // 실제 구현에서는 ConnectedId 테이블에서 조회해야 함
                var connectedId = userId; // 임시 처리

                // 캐시에 저장 (5분)
                _cache.Set(cacheKey, connectedId, TimeSpan.FromMinutes(5));

                return connectedId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active ConnectedId for user {UserId}", userId);
                return null;
            }
        }

        #region 계정 잠금 관리

        /// <summary>
        /// 계정 잠금 상태 조회
        /// </summary>
        public async Task<ServiceResult<AccountLockStatus>> GetAccountLockStatusAsync(Guid userId)
        {
            try
            {
                _logger.LogDebug("Getting account lock status for user {UserId}", userId);

                // 사용자 존재 확인
                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<AccountLockStatus>.Failure("사용자를 찾을 수 없습니다.");
                }

                // 캐시에서 잠금 상태 확인
                var cacheKey = $"account_lock_status_{userId}";
                if (_cache.TryGetValue(cacheKey, out AccountLockStatus? cachedStatus) && cachedStatus != null)
                {
                    return ServiceResult<AccountLockStatus>.Success(cachedStatus);
                }

                // TODO: 실제 데이터베이스에서 계정 잠금 상태 조회
                var status = new AccountLockStatus
                {
                    IsLocked = false,
                    FailedAttempts = 0,
                    MaxFailedAttempts = AuthConstants.Security.MaxFailedLoginAttempts
                };

                // 캐시에 저장
                _cache.Set(cacheKey, status, TimeSpan.FromMinutes(10));

                return ServiceResult<AccountLockStatus>.Success(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get account lock status for user {UserId}", userId);
                return ServiceResult<AccountLockStatus>.Failure("계정 잠금 상태 조회에 실패했습니다.");
            }
        }

        /// <summary>
        /// 계정 잠금
        /// </summary>
        public async Task<ServiceResult> LockAccountAsync(Guid userId, string reason, TimeSpan? duration = null, Guid? lockedBy = null)
        {
            try
            {
                _logger.LogWarning("Locking account for user {UserId}. Reason: {Reason}", userId, reason);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 계정 잠금 로직 구현
                var lockStatus = new AccountLockStatus
                {
                    IsLocked = true,
                    LockReason = reason,
                    LockedAt = DateTime.UtcNow,
                    LockedUntil = duration.HasValue ? DateTime.UtcNow.Add(duration.Value) : null
                };

                var cacheKey = $"account_lock_status_{userId}";
                _cache.Set(cacheKey, lockStatus, TimeSpan.FromHours(24));

                // 보안 이벤트 로깅
                await _trustedDeviceService.LogSecurityEventAsync(
                    "ACCOUNT_LOCKED",
                    $"Account locked. Reason: {reason}",
                    userId,
                    null);

                return ServiceResult.Success("계정이 잠금 처리되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to lock account for user {UserId}", userId);
                return ServiceResult.Failure("계정 잠금에 실패했습니다.");
            }
        }

        /// <summary>
        /// 계정 잠금 해제
        /// </summary>
        public async Task<ServiceResult> UnlockAccountAsync(Guid userId, string? reason = null, Guid? unlockedBy = null)
        {
            try
            {
                _logger.LogInformation("Unlocking account for user {UserId}. Reason: {Reason}", userId, reason);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 계정 잠금 해제 로직 구현
                var lockStatus = new AccountLockStatus
                {
                    IsLocked = false,
                    FailedAttempts = 0,
                    MaxFailedAttempts = AuthConstants.MAX_FAILED_LOGIN_ATTEMPTS
                };

                var cacheKey = $"account_lock_status_{userId}";
                _cache.Set(cacheKey, lockStatus, TimeSpan.FromMinutes(10));

                // 보안 이벤트 로깅
                await _trustedDeviceService.LogSecurityEventAsync(
                    "ACCOUNT_UNLOCKED",
                    $"Account unlocked. Reason: {reason ?? "Manual unlock"}",
                    userId,
                    null);

                return ServiceResult.Success("계정 잠금이 해제되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unlock account for user {UserId}", userId);
                return ServiceResult.Failure("계정 잠금 해제에 실패했습니다.");
            }
        }

        /// <summary>
        /// 실패 횟수 초기화
        /// </summary>
        public async Task<ServiceResult> ResetFailedAttemptsAsync(Guid userId)
        {
            try
            {
                _logger.LogInformation("Resetting failed login attempts for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // 캐시에서 잠금 상태 업데이트
                var cacheKey = $"account_lock_status_{userId}";
                var lockStatus = new AccountLockStatus
                {
                    IsLocked = false,
                    FailedAttempts = 0,
                    MaxFailedAttempts = AuthConstants.Security.MaxFailedLoginAttempts,
                    LastFailedAttempt = null
                };

                _cache.Set(cacheKey, lockStatus, TimeSpan.FromMinutes(10));

                // 보안 이벤트 로깅
                await _trustedDeviceService.LogSecurityEventAsync(
                    "FAILED_ATTEMPTS_RESET",
                    "Failed login attempts reset",
                    userId,
                    null);

                return ServiceResult.Success("실패한 로그인 시도 횟수가 초기화되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset failed attempts for user {UserId}", userId);
                return ServiceResult.Failure("실패한 로그인 시도 횟수 초기화에 실패했습니다.");
            }
        }

        /// <summary>
        /// 자동 잠금 정책 설정
        /// </summary>
        public async Task<ServiceResult> SetAutoLockPolicyAsync(Guid? organizationId, AutoLockPolicy policy)
        {
            try
            {
                var orgId = organizationId ?? Guid.Empty;
                _logger.LogInformation("Setting auto lock policy for organization {OrganizationId}", orgId);

                if (policy == null)
                {
                    return ServiceResult.Failure("자동 잠금 정책은 필수입니다.");
                }

                // TODO: 실제 데이터베이스에 정책 저장 - 비동기로 구현 예정
                // await _dbContext.AutoLockPolicies.AddAsync(policy);
                // await _dbContext.SaveChangesAsync();

                // 현재는 캐시만 사용하므로 Task.CompletedTask 반환
                await Task.CompletedTask;

                var cacheKey = $"auto_lock_policy_{orgId}";
                _cache.Set(cacheKey, policy, TimeSpan.FromHours(24));

                _logger.LogInformation("Auto lock policy set for organization {OrganizationId}", orgId);
                return ServiceResult.Success("자동 잠금 정책이 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set auto lock policy for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure("자동 잠금 정책 설정에 실패했습니다.");
            }
        }
        #endregion

        #region 패스워드 정책

        /// <summary>
        /// 패스워드 정책 조회 - AuthHive 통합 구현
        /// 조직별 정책 → 상위 조직 정책 → 시스템 기본 정책 순으로 조회
        /// </summary>
        public async Task<ServiceResult<PasswordPolicy>> GetPasswordPolicyAsync(Guid? organizationId = null)
        {
            try
            {
                var orgId = organizationId ?? Guid.Empty;
                _logger.LogDebug("Getting password policy for organization {OrganizationId}", orgId);

                // 1. 캐시 확인 (성능 최적화)
                var cacheKey = $"password_policy_{orgId}";
                if (_cache.TryGetValue(cacheKey, out PasswordPolicy? cachedPolicy) && cachedPolicy != null)
                {
                    return ServiceResult<PasswordPolicy>.Success(cachedPolicy);
                }

                // 2. AuthHive 계층적 정책 로딩 (조직 → 상위 → 시스템)
                var policy = await LoadPasswordPolicyWithInheritanceAsync(orgId);

                // 3. 캐시에 저장 (AuthHive 성능 전략)
                var cacheExpiry = policy.IsCustomPolicy ? TimeSpan.FromMinutes(30) : TimeSpan.FromHours(4);
                _cache.Set(cacheKey, policy, cacheExpiry);

                _logger.LogDebug("Password policy loaded for organization {OrganizationId}, IsCustom: {IsCustom}",
                    orgId, policy.IsCustomPolicy);

                return ServiceResult<PasswordPolicy>.Success(policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get password policy for organization {OrganizationId}", organizationId);
                return ServiceResult<PasswordPolicy>.Failure("패스워드 정책 조회에 실패했습니다.");
            }
        }

        /// <summary>
        /// AuthHive 계층적 상속 방식으로 패스워드 정책 로딩
        /// </summary>
        private async Task<PasswordPolicy> LoadPasswordPolicyWithInheritanceAsync(Guid organizationId)
        {
            // AuthHive v15 조직 계층 구조 지원
            if (organizationId != Guid.Empty)
            {
                // TODO: 실제 구현 시 OrganizationHierarchyService 사용
                // var orgPolicy = await _organizationService.GetPasswordPolicyAsync(organizationId);
                // if (orgPolicy != null) return orgPolicy;

                // TODO: 상위 조직 정책 상속 확인
                // var parentPolicy = await GetParentOrganizationPolicyAsync(organizationId);
                // if (parentPolicy != null) return parentPolicy;
            }

            // 비동기 시그니처 유지
            await Task.CompletedTask;

            // AuthHive 시스템 기본 정책 (PricingConstants 기반)
            return new PasswordPolicy
            {
                MinimumLength = 8,
                MaximumLength = 128,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireNumbers = true,
                RequireSpecialCharacters = true,
                MinimumUniqueCharacters = 4,
                PasswordHistoryCount = 5,
                ExpirationDays = 90,
                PreventCommonPasswords = true,
                PreventUserInfoInPassword = true,
                IsCustomPolicy = false,
                PolicySource = "SystemDefault"
            };
        }


        private async Task<PasswordPolicy> LoadPasswordPolicyFromSourceAsync(Guid organizationId)
        {
            // 현재는 기본 정책 반환, 향후 DB 조회로 변경 예정
            await Task.CompletedTask; // 비동기 시그니처 유지

            // TODO: 실제 구현
            // return await _dbContext.PasswordPolicies
            //     .FirstOrDefaultAsync(p => p.OrganizationId == organizationId) 
            //     ?? GetDefaultPasswordPolicy();

            return new PasswordPolicy
            {
                MinimumLength = 8,
                MaximumLength = 128,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireNumbers = true,
                RequireSpecialCharacters = true,
                MinimumUniqueCharacters = 4,
                PasswordHistoryCount = 5,
                ExpirationDays = 90,
                PreventCommonPasswords = true,
                PreventUserInfoInPassword = true
            };
        }
        /// <summary>
        /// 패스워드 만료 확인
        /// </summary>
        public async Task<ServiceResult<PasswordExpirationInfo>> CheckPasswordExpirationAsync(Guid userId)
        {
            try
            {
                _logger.LogDebug("Checking password expiration for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<PasswordExpirationInfo>.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 패스워드 만료 확인 로직
                var expirationInfo = new PasswordExpirationInfo
                {
                    IsExpired = false,
                    ExpirationDate = DateTime.UtcNow.AddDays(90),
                    DaysUntilExpiration = 90,
                    LastChangedDate = DateTime.UtcNow.AddDays(-10),
                    RequiresChange = false
                };

                return ServiceResult<PasswordExpirationInfo>.Success(expirationInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check password expiration for user {UserId}", userId);
                return ServiceResult<PasswordExpirationInfo>.Failure("패스워드 만료 확인에 실패했습니다.");
            }
        }

        /// <summary>
        /// 패스워드 이력 확인
        /// </summary>
        public async Task<ServiceResult<bool>> CheckPasswordHistoryAsync(Guid userId, string newPasswordHash)
        {
            try
            {
                _logger.LogDebug("Checking password history for user {UserId}", userId);

                if (string.IsNullOrWhiteSpace(newPasswordHash))
                {
                    return ServiceResult<bool>.Failure("새 패스워드 해시는 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<bool>.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 패스워드 히스토리 확인 로직 구현
                var isNewPassword = true;

                return ServiceResult<bool>.Success(isNewPassword);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check password history for user {UserId}", userId);
                return ServiceResult<bool>.Failure("패스워드 히스토리 확인에 실패했습니다.");
            }
        }

        #endregion
        #region 패스워드 정책 설정

        /// <summary>
        /// 패스워드 정책 설정 - AuthHive 엔터프라이즈 정책 관리
        /// Business 플랜 이상에서만 조직별 커스텀 정책 설정 가능
        /// </summary>
        public async Task<ServiceResult> SetPasswordPolicyAsync(Guid organizationId, PasswordPolicy policy)
        {
            try
            {
                _logger.LogInformation("Setting password policy for organization {OrganizationId}", organizationId);

                // 1. 입력 검증 (AuthHive 보안 원칙)
                var validationResult = ValidatePasswordPolicy(policy);
                if (!validationResult.IsSuccess)
                {
                    return validationResult;
                }

                // 2. 조직 권한 확인 (AuthHive 멀티테넌시 보안)
                var authorizationResult = await ValidateOrganizationPolicyPermissionAsync(organizationId);
                if (!authorizationResult.IsSuccess)
                {
                    return authorizationResult;
                }

                // 3. AuthHive 정책 설정 및 캐싱
                await SetPasswordPolicyWithCacheAsync(organizationId, policy);

                _logger.LogInformation("Password policy successfully set for organization {OrganizationId}", organizationId);
                return ServiceResult.Success("패스워드 정책이 성공적으로 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set password policy for organization {OrganizationId}", organizationId);
                return ServiceResult.Failure("패스워드 정책 설정에 실패했습니다.");
            }
        }

        /// <summary>
        /// 패스워드 정책 검증 - AuthHive 보안 기준
        /// </summary>
        private ServiceResult ValidatePasswordPolicy(PasswordPolicy policy)
        {
            if (policy == null)
            {
                return ServiceResult.Failure("패스워드 정책은 필수입니다.");
            }

            // AuthHive 최소 보안 기준 (PricingConstants 기반)
            var violations = new List<string>();

            if (policy.MinimumLength < 6)
                violations.Add("최소 길이는 6자 이상이어야 합니다.");

            if (policy.MaximumLength > 256)
                violations.Add("최대 길이는 256자를 초과할 수 없습니다.");

            if (policy.MinimumLength >= policy.MaximumLength)
                violations.Add("최소 길이는 최대 길이보다 작아야 합니다.");

            if (policy.PasswordHistoryCount < 0 || policy.PasswordHistoryCount > 24)
                violations.Add("패스워드 히스토리는 0-24 범위여야 합니다.");

            if (policy.ExpirationDays < 0 || policy.ExpirationDays > 365)
                violations.Add("만료 기간은 0-365일 범위여야 합니다.");

            if (violations.Any())
            {
                return ServiceResult.Failure($"정책 검증 실패: {string.Join(", ", violations)}");
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// 조직 정책 설정 권한 확인 - AuthHive 플랜 기반 제어
        /// </summary>
        private async Task<ServiceResult> ValidateOrganizationPolicyPermissionAsync(Guid organizationId)
        {
            try
            {
                // TODO: 실제 구현 시 OrganizationService 및 SubscriptionService 사용
                // var organization = await _organizationService.GetByIdAsync(organizationId);
                // var subscription = await _subscriptionService.GetActiveSubscriptionAsync(organizationId);

                // AuthHive 플랜별 정책 커스터마이징 권한 확인
                // if (subscription.PlanType == PlanType.Basic || subscription.PlanType == PlanType.Pro)
                // {
                //     return ServiceResult.Failure("커스텀 패스워드 정책은 Business 플랜 이상에서 사용할 수 있습니다.");
                // }

                // 현재는 검증 통과 (향후 실제 구현)
                await Task.CompletedTask;
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate organization policy permission for {OrganizationId}", organizationId);
                return ServiceResult.Failure("조직 권한 확인에 실패했습니다.");
            }
        }

        /// <summary>
        /// 패스워드 정책 저장 및 캐시 관리 - AuthHive 성능 최적화
        /// </summary>
        private async Task SetPasswordPolicyWithCacheAsync(Guid organizationId, PasswordPolicy policy)
        {
            // 정책에 AuthHive 메타데이터 설정
            policy.OrganizationId = organizationId;
            policy.IsCustomPolicy = true;
            policy.PolicySource = "OrganizationCustom";

            // TODO: 실제 데이터베이스 저장
            // await _dbContext.PasswordPolicies.AddOrUpdateAsync(policy);
            // await _dbContext.SaveChangesAsync();

            // AuthHive 캐시 전략: 즉시 캐시 업데이트
            var cacheKey = $"password_policy_{organizationId}";
            _cache.Set(cacheKey, policy, TimeSpan.FromMinutes(30)); // 커스텀 정책은 짧은 TTL

            // AuthHive 이벤트 발행 (향후 Platform 모듈 연동)
            // await _eventPublisher.PublishAsync(new PasswordPolicyChangedEvent 
            // { 
            //     OrganizationId = organizationId, 
            //     Policy = policy 
            // });

            await Task.CompletedTask;
        }

        #endregion
        #region 신뢰할 수 있는 장치

        /// <summary>
        /// 신뢰할 수 있는 장치 등록
        /// </summary>
        public async Task<ServiceResult> RegisterTrustedDeviceAsync(Guid userId, TrustedDeviceRequest request)
        {
            try
            {
                _logger.LogInformation("Registering trusted device for user {UserId}: {DeviceName}",
                    userId, request.DeviceName);

                // 입력값 검증
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                {
                    return ServiceResult.Failure("장치 ID는 필수입니다.");
                }

                if (string.IsNullOrWhiteSpace(request.DeviceName))
                {
                    return ServiceResult.Failure("장치 이름은 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                var result = await _trustedDeviceService.RegisterTrustedDeviceAsync(userId, request);

                if (result.IsSuccess)
                {
                    // 캐시 무효화
                    InvalidateTrustedDeviceCache(userId);
                }

                return ServiceResult.Success("신뢰할 수 있는 장치가 등록되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register trusted device for user {UserId}", userId);
                return ServiceResult.Failure("신뢰할 수 있는 장치 등록에 실패했습니다.");
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 장치 목록 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId)
        {
            try
            {
                _logger.LogDebug("Getting trusted devices for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure("사용자를 찾을 수 없습니다.");
                }

                return await _trustedDeviceService.GetTrustedDevicesAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get trusted devices for user {UserId}", userId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure("신뢰할 수 있는 장치 조회에 실패했습니다.");
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 장치 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsTrustedDeviceAsync(Guid userId, string deviceFingerprint)
        {
            try
            {
                _logger.LogDebug("Checking if device is trusted for user {UserId}", userId);

                if (string.IsNullOrWhiteSpace(deviceFingerprint))
                {
                    return ServiceResult<bool>.Success(false);
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<bool>.Success(false);
                }

                var devicesResult = await _trustedDeviceService.GetTrustedDevicesAsync(userId);
                if (devicesResult.IsSuccess && devicesResult.Data != null)
                {
                    var isTrusted = devicesResult.Data.Any(d =>
                        d.DeviceFingerprint == deviceFingerprint &&
                        d.IsActive &&
                        !d.IsExpired);

                    return ServiceResult<bool>.Success(isTrusted);
                }

                return ServiceResult<bool>.Success(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check if device is trusted for user {UserId}", userId);
                return ServiceResult<bool>.Success(false);
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 장치 제거
        /// </summary>
        public async Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId)
        {
            try
            {
                _logger.LogInformation("Removing trusted device {DeviceId} for user {UserId}", deviceId, userId);

                if (string.IsNullOrWhiteSpace(deviceId))
                {
                    return ServiceResult.Failure("장치 ID는 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                var result = await _trustedDeviceService.RemoveTrustedDeviceAsync(userId, deviceId);

                if (result.IsSuccess)
                {
                    InvalidateTrustedDeviceCache(userId);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove trusted device {DeviceId} for user {UserId}", deviceId, userId);
                return ServiceResult.Failure("신뢰할 수 있는 장치 제거에 실패했습니다.");
            }
        }

        /// <summary>
        /// 모든 신뢰할 수 있는 장치 제거
        /// </summary>
        public async Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId)
        {
            try
            {
                _logger.LogInformation("Removing all trusted devices for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<int>.Failure("사용자를 찾을 수 없습니다.");
                }

                var result = await _trustedDeviceService.RemoveAllTrustedDevicesAsync(userId);

                if (result.IsSuccess)
                {
                    InvalidateTrustedDeviceCache(userId);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove all trusted devices for user {UserId}", userId);
                return ServiceResult<int>.Failure("모든 신뢰할 수 있는 장치 제거에 실패했습니다.");
            }
        }

        #endregion

        #region 보안 설정

        /// <summary>
        /// 계정 보안 설정 조회
        /// </summary>
        public async Task<ServiceResult<AccountSecuritySettings>> GetSecuritySettingsAsync(Guid userId)
        {
            try
            {
                _logger.LogDebug("Getting security settings for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<AccountSecuritySettings>.Failure("사용자를 찾을 수 없습니다.");
                }

                // ConnectedId 조회
                var connectedId = GetActiveConnectedId(userId);
                if (!connectedId.HasValue)
                {
                    return ServiceResult<AccountSecuritySettings>.Failure("활성 ConnectedId를 찾을 수 없습니다.");
                }

                // 캐시에서 보안 설정 확인
                var cacheKey = $"security_settings_{connectedId.Value}";
                if (_cache.TryGetValue(cacheKey, out AccountSecuritySettings? cachedSettings) && cachedSettings != null)
                {
                    return ServiceResult<AccountSecuritySettings>.Success(cachedSettings);
                }

                // TODO: 실제 데이터베이스에서 보안 설정 조회
                var settings = new AccountSecuritySettings
                {
                    ConnectedId = connectedId.Value,
                    RequireMfa = false,
                    RequireTrustedDevice = true,
                    NotifyOnNewDevice = true,
                    NotifyOnSuspiciousActivity = true,
                    EnableIpWhitelist = false,
                    EnableAccessTimeRestriction = false,
                    SessionTimeout = 30,
                    MaxConcurrentSessions = 5
                };

                // 캐시에 저장 (30분)
                _cache.Set(cacheKey, settings, TimeSpan.FromMinutes(30));

                return ServiceResult<AccountSecuritySettings>.Success(settings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get security settings for user {UserId}", userId);
                return ServiceResult<AccountSecuritySettings>.Failure("보안 설정 조회에 실패했습니다.");
            }
        }

        /// <summary>
        /// 계정 보안 설정 업데이트
        /// </summary>
        public async Task<ServiceResult> UpdateSecuritySettingsAsync(Guid userId, AccountSecuritySettings settings)
        {
            try
            {
                _logger.LogInformation("Updating security settings for user {UserId}", userId);

                if (settings == null)
                {
                    return ServiceResult.Failure("보안 설정은 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 데이터베이스에 보안 설정 저장
                var cacheKey = $"security_settings_{userId}";
                _cache.Set(cacheKey, settings, TimeSpan.FromMinutes(30));

                return ServiceResult.Success("보안 설정이 업데이트되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update security settings for user {UserId}", userId);
                return ServiceResult.Failure("보안 설정 업데이트에 실패했습니다.");
            }
        }

        /// <summary>
        /// IP 화이트리스트 설정
        /// </summary>
        public async Task<ServiceResult> SetIpWhitelistAsync(Guid userId, List<string> ipAddresses)
        {
            try
            {
                _logger.LogInformation("Setting IP whitelist for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 IP 화이트리스트 저장 로직
                var cacheKey = $"ip_whitelist_{userId}";
                _cache.Set(cacheKey, ipAddresses, TimeSpan.FromHours(1));

                return ServiceResult.Success("IP 화이트리스트가 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set IP whitelist for user {UserId}", userId);
                return ServiceResult.Failure("IP 화이트리스트 설정에 실패했습니다.");
            }
        }

        /// <summary>
        /// 접근 시간 제한 설정
        /// </summary>
        public async Task<ServiceResult> SetAccessTimeRestrictionAsync(Guid userId, AccessTimeRestriction restriction)
        {
            try
            {
                _logger.LogInformation("Setting access time restriction for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 접근 시간 제한 저장 로직
                var cacheKey = $"access_time_restriction_{userId}";
                _cache.Set(cacheKey, restriction, TimeSpan.FromHours(1));

                return ServiceResult.Success("접근 시간 제한이 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set access time restriction for user {UserId}", userId);
                return ServiceResult.Failure("접근 시간 제한 설정에 실패했습니다.");
            }
        }

        #endregion

        #region 보안 이벤트

        /// <summary>
        /// 의심스러운 활동 보고
        /// </summary>
        public async Task<ServiceResult> ReportSuspiciousActivityAsync(Guid userId, SuspiciousActivityReport report)
        {
            try
            {
                _logger.LogWarning("Suspicious activity reported for user {UserId}: {ActivityType}",
                    userId, report.ActivityType);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // 의심스러운 활동 저장 및 처리 로직
                await _trustedDeviceService.LogSecurityEventAsync(
                    "SUSPICIOUS_ACTIVITY",
                    report.Description,
                    userId,
                    report.IpAddress);

                return ServiceResult.Success("의심스러운 활동이 보고되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to report suspicious activity for user {UserId}", userId);
                return ServiceResult.Failure("의심스러운 활동 보고에 실패했습니다.");
            }
        }

        /// <summary>
        /// 보안 이벤트 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<SecurityEventDto>>> GetSecurityEventsAsync(Guid userId, DateTime? from = null, DateTime? to = null)
        {
            try
            {
                _logger.LogDebug("Getting security events for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<IEnumerable<SecurityEventDto>>.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 보안 이벤트 조회 로직
                var events = new List<SecurityEventDto>();

                return ServiceResult<IEnumerable<SecurityEventDto>>.Success(events);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get security events for user {UserId}", userId);
                return ServiceResult<IEnumerable<SecurityEventDto>>.Failure("보안 이벤트 조회에 실패했습니다.");
            }
        }

        /// <summary>
        /// 보안 알림 설정
        /// </summary>
        public async Task<ServiceResult> ConfigureSecurityAlertsAsync(Guid userId, SecurityAlertConfiguration configuration)
        {
            try
            {
                _logger.LogInformation("Configuring security alerts for user {UserId}", userId);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 보안 알림 설정 저장 로직
                var cacheKey = $"security_alerts_{userId}";
                _cache.Set(cacheKey, configuration, TimeSpan.FromHours(1));

                return ServiceResult.Success("보안 알림이 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure security alerts for user {UserId}", userId);
                return ServiceResult.Failure("보안 알림 설정에 실패했습니다.");
            }
        }

        #endregion

        #region 복구 옵션

        /// <summary>
        /// 복구 이메일 설정
        /// </summary>
        public async Task<ServiceResult> SetRecoveryEmailAsync(Guid userId, string email)
        {
            try
            {
                _logger.LogInformation("Setting recovery email for user {UserId}", userId);

                if (string.IsNullOrWhiteSpace(email))
                {
                    return ServiceResult.Failure("복구 이메일은 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 복구 이메일 저장 로직
                var cacheKey = $"recovery_email_{userId}";
                _cache.Set(cacheKey, email, TimeSpan.FromHours(1));

                return ServiceResult.Success("복구 이메일이 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set recovery email for user {UserId}", userId);
                return ServiceResult.Failure("복구 이메일 설정에 실패했습니다.");
            }
        }

        /// <summary>
        /// 복구 전화번호 설정
        /// </summary>
        public async Task<ServiceResult> SetRecoveryPhoneAsync(Guid userId, string phoneNumber)
        {
            try
            {
                _logger.LogInformation("Setting recovery phone for user {UserId}", userId);

                if (string.IsNullOrWhiteSpace(phoneNumber))
                {
                    return ServiceResult.Failure("복구 전화번호는 필수입니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 복구 전화번호 저장 로직
                var cacheKey = $"recovery_phone_{userId}";
                _cache.Set(cacheKey, phoneNumber, TimeSpan.FromHours(1));

                return ServiceResult.Success("복구 전화번호가 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set recovery phone for user {UserId}", userId);
                return ServiceResult.Failure("복구 전화번호 설정에 실패했습니다.");
            }
        }

        /// <summary>
        /// 보안 질문 설정
        /// </summary>
        public async Task<ServiceResult> SetSecurityQuestionsAsync(Guid userId, List<SecurityQuestion> questions)
        {
            try
            {
                _logger.LogInformation("Setting security questions for user {UserId}", userId);

                if (questions == null || !questions.Any())
                {
                    return ServiceResult.Failure("보안 질문은 최소 1개 이상이어야 합니다.");
                }

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 보안 질문 저장 로직
                var cacheKey = $"security_questions_{userId}";
                _cache.Set(cacheKey, questions, TimeSpan.FromHours(1));

                return ServiceResult.Success("보안 질문이 설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set security questions for user {UserId}", userId);
                return ServiceResult.Failure("보안 질문 설정에 실패했습니다.");
            }
        }

        /// <summary>
        /// 복구 코드 생성
        /// </summary>
        public async Task<ServiceResult<List<string>>> GenerateRecoveryCodesAsync(Guid userId, int count = 10)
        {
            try
            {
                _logger.LogInformation("Generating recovery codes for user {UserId}, count: {Count}", userId, count);

                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    return ServiceResult<List<string>>.Failure("사용자를 찾을 수 없습니다.");
                }

                // TODO: 실제 복구 코드 생성 및 저장 로직
                var recoveryCodes = new List<string>();
                var random = new Random();

                for (int i = 0; i < count; i++)
                {
                    var code = random.Next(100000, 999999).ToString();
                    recoveryCodes.Add($"RC-{code}");
                }

                // 캐시에 저장
                var cacheKey = $"recovery_codes_{userId}";
                _cache.Set(cacheKey, recoveryCodes, TimeSpan.FromHours(24));

                return ServiceResult<List<string>>.Success(recoveryCodes);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate recovery codes for user {UserId}", userId);
                return ServiceResult<List<string>>.Failure("복구 코드 생성에 실패했습니다.");
            }
        }

        #endregion

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                var userRepositoryHealthy = await _userRepository.CountAsync() >= 0;
                return userRepositoryHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AccountSecurityService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("AccountSecurityService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 신뢰할 수 있는 장치 캐시 무효화
        /// </summary>
        private void InvalidateTrustedDeviceCache(Guid userId)
        {
            var keys = new[]
            {
                $"trusted_devices_{userId}",
                $"security_settings_{userId}"
            };

            foreach (var key in keys)
            {
                _cache.Remove(key);
            }
        }

        #endregion
    }
}
