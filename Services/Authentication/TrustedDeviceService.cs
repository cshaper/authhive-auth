using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Entities.Auth;
using System.Text.Json;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Auth.Authentication.Events;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 신뢰할 수 있는 장치 관리 서비스 구현체 - AuthHive v16
    /// MFA에서 사용되는 핵심 서비스입니다.
    /// AuthConstants와 PricingConstants의 모든 제한사항을 엄격히 적용합니다.
    /// </summary>
    public class TrustedDeviceService : ITrustedDeviceService
    {
        private readonly ITrustedDeviceRepository _repository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<TrustedDeviceService> _logger;
        private readonly ICacheService _cacheService;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IOrganizationSettingsRepository _orgSettingsRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUserRepository _userRepository;

        // 캐시 키 패턴 - AuthConstants.CacheKeys 사용
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromSeconds(AuthConstants.CacheKeys.SecurityCacheTTL);

        public TrustedDeviceService(
            ITrustedDeviceRepository repository,
            ILogger<TrustedDeviceService> logger,
            IUnitOfWork unitOfWork,
            ICacheService cacheService,
            IEventBus eventBus,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            IOrganizationSettingsRepository orgSettingsRepository,
            IOrganizationRepository organizationRepository,
            IUserRepository userRepository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _orgSettingsRepository = orgSettingsRepository ?? throw new ArgumentNullException(nameof(orgSettingsRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        }

        #region 장치 등록 및 관리

        /// <summary>
        /// 신뢰할 수 있는 장치 등록
        /// AuthConstants.Security와 PricingConstants의 플랜별 제한사항을 엄격히 검증합니다.
        /// </summary>
        public async Task<ServiceResult<TrustedDeviceDto>> RegisterTrustedDeviceAsync(
            Guid userId,
            TrustedDeviceRequest request)
        {
            try
            {
                // 입력 검증
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "DeviceId is required",
                        AuthConstants.ErrorCodes.INVALID_REQUEST);
                }

                if (string.IsNullOrWhiteSpace(request.DeviceFingerprint))
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Device fingerprint is required",
                        AuthConstants.ErrorCodes.INVALID_REQUEST);
                }

                // 지문 길이 검증
                if (request.DeviceFingerprint.Length > AuthConstants.Security.DeviceFingerprintLength)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        $"Device fingerprint exceeds maximum length ({AuthConstants.Security.DeviceFingerprintLength})",
                        AuthConstants.ErrorCodes.INVALID_REQUEST);
                }

                // 사용자의 조직 및 플랜 정보 가져오기
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "User not found",
                        AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                if (!user.OrganizationId.HasValue)
                {
                    // 사용자에게 조직이 할당되지 않은 경우의 예외 처리 로직
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "User is not associated with an organization.",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                var organization = await _organizationRepository.GetByIdAsync(user.OrganizationId.Value);
                if (organization == null)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Organization not found",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 플랜별 장치 제한 가져오기
                var maxDevicesPerUser = await GetMaxDevicesPerUserAsync(organization.PricingTier);

                // 현재 장치 수 확인
                var currentDeviceCount = await _repository.GetTrustedDeviceCountAsync(userId, onlyActive: true);

                // Rate Limiting 체크
                var rateLimitKey = string.Format(AuthConstants.CacheKeys.FailedAttemptsPattern, $"device_register:{userId}");
                var attempts = await GetRateLimitCountAsync(rateLimitKey);

                if (attempts > AuthConstants.OAuth.MaxFailedAttemptsBeforeBlock)
                {
                    await _auditService.LogSecurityEventAsync(
                        "DEVICE_REGISTRATION_RATE_LIMIT",
                        AuditEventSeverity.Warning,
                        "Too many device registration attempts",
                        userId,
                        new Dictionary<string, object>
                        {
                            ["attempts"] = attempts,
                            ["ipAddress"] = request.IpAddress ?? CommonDefaults.DefaultLocalIpV4
                        });

                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Too many registration attempts. Please try again later.",
                        AuthConstants.ErrorCodes.RateLimitExceeded);
                }

                // PricingConstants와 AuthConstants 기반 제한 검증
                if (currentDeviceCount >= maxDevicesPerUser)
                {
                    var errorMessage = $"Maximum number of trusted devices ({maxDevicesPerUser}) exceeded for {organization.PricingTier} plan.";

                    var limitEvent = new PlanLimitReachedEvent(
                        organizationId: organization.Id,
                        planKey: organization.PricingTier,
                        limitType: PlanLimitType.TrustedDevice,
                        currentValue: currentDeviceCount,
                        maxValue: maxDevicesPerUser,
                        triggeredBy: userId
                    );

                    limitEvent.RecommendedPlan = GetRequiredPlanForDeviceCount(currentDeviceCount + 1);
                    await _eventBus.PublishAsync(limitEvent);

                    return ServiceResult<TrustedDeviceDto>.Failure(errorMessage, "PLAN_LIMIT_EXCEEDED");
                }

                // 중복 장치 ID 확인
                var isDuplicate = await _repository.IsDeviceIdDuplicateAsync(request.DeviceId, userId);
                if (isDuplicate)
                {
                    await IncrementRateLimitAsync(rateLimitKey);

                    // 감사로그: 단순 검증 실패
                    await _auditService.LogActionAsync(
                        userId,
                        "DEVICE_REGISTRATION_FAILED",
                        AuditActionType.Create,
                        "TrustedDevice",
                        request.DeviceId,
                        false,
                        JsonSerializer.Serialize(new { Error = "Duplicate device ID detected" }));

                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Device with this ID already exists",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 트랜잭션 시작
                await _unitOfWork.BeginTransactionAsync();

                try
                {
                    // 신뢰할 수 있는 장치 엔티티 생성
                    var trustedDevice = new TrustedDevice
                    {
                        Id = Guid.NewGuid(),
                        UserId = userId,
                        DeviceId = request.DeviceId,
                        DeviceName = request.DeviceName ?? $"Device {_dateTimeProvider.UtcNow:yyyy-MM-dd}",
                        DeviceType = request.DeviceType ?? CommonDefaults.UnknownDeviceType,
                        DeviceFingerprint = request.DeviceFingerprint,
                        TrustedAt = _dateTimeProvider.UtcNow,
                        IsActive = true,
                        IpAddress = request.IpAddress ?? CommonDefaults.DefaultLocalIpV4,
                        UserAgent = request.UserAgent ?? CommonDefaults.UnknownUserAgent,
                        OrganizationId = organization.Id
                    };

                    // 플랜별 만료일 설정 (AuthConstants.Security.TrustedDeviceLifetime 기반)
                    var expirationDays = GetDeviceExpirationDaysAsync(organization.PricingTier, request.TrustDurationDays);
                    if (expirationDays > 0)
                    {
                        trustedDevice.SetExpiration(_dateTimeProvider.UtcNow.AddDays(expirationDays));
                    }

                    // UserAgent 파싱
                    if (!string.IsNullOrEmpty(request.UserAgent))
                    {
                        ParseUserAgent(request.UserAgent, out string? browser, out string? os);
                        trustedDevice.Browser = browser;
                        trustedDevice.OperatingSystem = os;
                    }

                    // 플랜별 신뢰 레벨 설정 (TrustLevel enum 사용)
                    var trustLevel = GetPlanBasedTrustLevel(organization.PricingTier);
                    var metadata = new Dictionary<string, object>
                    {
                        ["trustLevel"] = trustLevel,
                        ["registeredAt"] = _dateTimeProvider.UtcNow,
                        ["registrationIp"] = request.IpAddress ?? CommonDefaults.DefaultLocalIpV4,
                        ["planType"] = organization.PricingTier,
                        ["organizationId"] = organization.Id,
                        ["authenticationStrength"] = GetAuthenticationStrength(request.AuthMethod)
                    };

                    trustedDevice.Metadata = JsonSerializer.Serialize(metadata);

                    // 저장
                    await _repository.AddAsync(trustedDevice);
                    await _unitOfWork.SaveChangesAsync();

                    // 트랜잭션 커밋
                    await _unitOfWork.CommitTransactionAsync();

                    // Rate Limit 성공 시 초기화
                    await ClearRateLimitAsync(rateLimitKey);

                    // 캐시 무효화
                    await InvalidateUserDeviceCacheAsync(userId);

                    // 이벤트 발행: 새 장치 등록됨
                    // 이벤트 발행: 새 장치 등록됨
                    await _eventBus.PublishAsync(new TrustedDeviceRegisteredEvent(
                        userId: userId,
                        deviceId: trustedDevice.Id,
                        deviceName: trustedDevice.DeviceName,
                        deviceType: trustedDevice.DeviceType,
                        deviceFingerprint: trustedDevice.DeviceFingerprint,
                        expiresAt: trustedDevice.ExpiresAt,
                        ipAddress: request.IpAddress ?? CommonDefaults.DefaultLocalIpV4,
                        planType: organization.PricingTier,
                        currentDeviceCount: currentDeviceCount + 1,
                        maxDeviceLimit: maxDevicesPerUser,
                        organizationId: organization.Id,
                        triggeredBy: userId
                    ));
                    // 사용량이 80% 도달 시 경고 이벤트
                    var usagePercentage = (decimal)(currentDeviceCount + 1) / maxDevicesPerUser * 100;
                    if (usagePercentage >= 80)
                    {
                        await _eventBus.PublishAsync(new UsageWarningEvent(
                       organizationId: organization.Id,
                       resourceType: "TrustedDevices",
                       currentUsage: currentDeviceCount + 1,
                       maxLimit: maxDevicesPerUser,
                       usagePercentage: usagePercentage,
                       warningLevel: usagePercentage >= 90 ? "CRITICAL" : "WARNING",
                       triggeredBy: userId
                   ));
                    }

                    // 감사로그: 성공
                    await _auditService.LogActionAsync(
                        userId,
                        AuthConstants.Events.DeviceTrusted,
                        AuditActionType.Create,
                        "TrustedDevice",
                        trustedDevice.Id.ToString(),
                        true,
                        JsonSerializer.Serialize(new
                        {
                            DeviceId = trustedDevice.DeviceId,
                            DeviceType = trustedDevice.DeviceType,
                            PlanType = organization.PricingTier,
                            DeviceCount = $"{currentDeviceCount + 1}/{maxDevicesPerUser}"
                        }));

                    _logger.LogInformation(
                        "Trusted device registered successfully for user {UserId}: {DeviceId} (Plan: {PlanType}, Devices: {Current}/{Max})",
                        userId, trustedDevice.DeviceId, organization.PricingTier, currentDeviceCount + 1, maxDevicesPerUser);

                    return ServiceResult<TrustedDeviceDto>.Success(MapToDto(trustedDevice));
                }
                catch
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering trusted device for user {UserId}", userId);

                // 보안 이벤트
                await _auditService.LogSecurityEventAsync(
                    AuthConstants.Events.SuspiciousActivity,
                    AuditEventSeverity.Warning,
                    "Failed to register trusted device",
                    userId,
                    new Dictionary<string, object>
                    {
                        ["error"] = ex.Message,
                        ["deviceId"] = request.DeviceId
                    });

                return ServiceResult<TrustedDeviceDto>.Failure(
                    "Failed to register trusted device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 장치 제거
        /// </summary>
        public async Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId);
                if (device == null)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.Deactivate();
                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "DEVICE_REMOVED",
                    AuditActionType.Delete,
                    "TrustedDevice",
                    deviceId,
                    true);

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {DeviceId} for user {UserId}", deviceId, userId);
                return ServiceResult.Failure(
                    "Failed to remove device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 신뢰할 수 있는 장치 제거 (ID로)
        /// </summary>
        public async Task<ServiceResult> RemoveTrustedDeviceByIdAsync(Guid id, Guid userId)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.Deactivate();
                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "DEVICE_REMOVED_BY_ID",
                    AuditActionType.Delete,
                    "TrustedDevice",
                    id.ToString(),
                    true);

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {Id} for user {UserId}", id, userId);
                return ServiceResult.Failure(
                    "Failed to remove device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 모든 신뢰할 수 있는 장치 제거
        /// </summary>
        public async Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId)
        {
            try
            {
                var count = await _repository.DeactivateAllUserDevicesAsync(userId, "User requested removal of all devices");

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "ALL_DEVICES_REMOVED",
                    AuditActionType.Delete,
                    "TrustedDevice",
                    "ALL",
                    true,
                    JsonSerializer.Serialize(new { Count = count }));

                return ServiceResult<int>.Success(count, $"Removed {count} devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing all trusted devices for user {UserId}", userId);
                return ServiceResult<int>.Failure(
                    "Failed to remove devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 장치 조회 및 검증

        /// <summary>
        /// 사용자의 신뢰할 수 있는 장치 목록 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId)
        {
            try
            {
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: false);
                var dtos = devices.Select(MapToDto);

                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting trusted devices for user {UserId}", userId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure(
                    "Failed to get devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치가 신뢰할 수 있는지 검증 (MFA 핵심 메서드)
        /// </summary>
        public async Task<ServiceResult<bool>> IsDeviceTrustedAsync(Guid userId, string deviceId, string fingerprint)
        {
            try
            {
                var isTrusted = await _repository.IsDeviceTrustedAsync(deviceId, fingerprint, userId);
                return ServiceResult<bool>.Success(isTrusted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if device is trusted for user {UserId}", userId);
                return ServiceResult<bool>.Failure(
                    "Failed to check device trust status",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 신뢰 검증 및 사용 정보 업데이트
        /// </summary>
        public async Task<ServiceResult<TrustedDeviceVerificationResult>> VerifyAndUpdateDeviceAsync(
            Guid userId, string deviceId, string fingerprint,
            string? ipAddress = null, string? userAgent = null, string? location = null)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId);
                if (device == null)
                {
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult
                    {
                        IsTrusted = false,
                        Reason = "Device not found"
                    });
                }

                if (device.DeviceFingerprint != fingerprint)
                {
                    // 의심스러운 활동 로깅
                    await _auditService.LogSecurityEventAsync(
                        "DEVICE_FINGERPRINT_MISMATCH",
                        AuditEventSeverity.Warning,
                        "Device fingerprint mismatch detected",
                        userId,
                        new Dictionary<string, object>
                        {
                            ["deviceId"] = deviceId,
                            ["ipAddress"] = ipAddress ?? "unknown"
                        });

                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult
                    {
                        IsTrusted = false,
                        Reason = "Device fingerprint mismatch"
                    });
                }

                if (!device.IsValid)
                {
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult
                    {
                        IsTrusted = false,
                        Reason = device.IsExpired ? "Device expired" : "Device inactive"
                    });
                }

                // 사용 정보 업데이트
                await _repository.UpdateLastUsedAsync(deviceId, userId, ipAddress, userAgent, location);

                return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult
                {
                    IsTrusted = true,
                    Device = MapToDto(device)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying device for user {UserId}", userId);
                return ServiceResult<TrustedDeviceVerificationResult>.Failure(
                    "Failed to verify device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 상세 정보 조회
        /// </summary>
        public async Task<ServiceResult<TrustedDeviceDto>> GetTrustedDeviceAsync(Guid id, Guid userId)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                return ServiceResult<TrustedDeviceDto>.Success(MapToDto(device));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting trusted device {Id} for user {UserId}", id, userId);
                return ServiceResult<TrustedDeviceDto>.Failure(
                    "Failed to get device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 장치 상태 관리

        /// <summary>
        /// 장치 활성화/비활성화
        /// </summary>
        public async Task<ServiceResult> UpdateDeviceStatusAsync(Guid id, Guid userId, bool isActive, string? reason = null)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.UpdateActiveStatusAsync(id, isActive, reason);

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    isActive ? "DEVICE_ACTIVATED" : "DEVICE_DEACTIVATED",
                    AuditActionType.Update,
                    "TrustedDevice",
                    id.ToString(),
                    true,
                    reason);

                return ServiceResult.Success("Device status updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device status for {Id}", id);
                return ServiceResult.Failure(
                    "Failed to update device status",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 신뢰 레벨 변경
        /// </summary>
        public async Task<ServiceResult> UpdateTrustLevelAsync(Guid id, Guid userId, int trustLevel)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.UpdateTrustLevelAsync(id, trustLevel);

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "DEVICE_TRUST_LEVEL_UPDATED",
                    AuditActionType.Update,
                    "TrustedDevice",
                    id.ToString(),
                    true,
                    JsonSerializer.Serialize(new { TrustLevel = trustLevel }));

                return ServiceResult.Success("Trust level updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating trust level for device {Id}", id);
                return ServiceResult.Failure(
                    "Failed to update trust level",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 만료일 설정
        /// </summary>
        public async Task<ServiceResult> SetDeviceExpirationAsync(Guid id, Guid userId, DateTime? expiresAt)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.SetExpirationAsync(id, expiresAt);

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "DEVICE_EXPIRATION_SET",
                    AuditActionType.Update,
                    "TrustedDevice",
                    id.ToString(),
                    true,
                    JsonSerializer.Serialize(new { ExpiresAt = expiresAt }));

                return ServiceResult.Success("Device expiration updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting device expiration for {Id}", id);
                return ServiceResult.Failure(
                    "Failed to set device expiration",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 이름 변경
        /// </summary>
        public async Task<ServiceResult> UpdateDeviceNameAsync(Guid id, Guid userId, string deviceName)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.DeviceName = deviceName;
                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    userId,
                    "DEVICE_NAME_UPDATED",
                    AuditActionType.Update,
                    "TrustedDevice",
                    id.ToString(),
                    true,
                    JsonSerializer.Serialize(new { DeviceName = deviceName }));

                return ServiceResult.Success("Device name updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device name for {Id}", id);
                return ServiceResult.Failure(
                    "Failed to update device name",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 보안 및 관리자 기능

        /// <summary>
        /// 조직의 모든 신뢰할 수 있는 장치 조회 (관리자용)
        /// </summary>
        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetOrganizationDevicesAsync(Guid organizationId, bool includeInactive = false)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive);
                var dtos = devices.Select(MapToDto);

                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization devices for {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure(
                    "Failed to get organization devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 의심스러운 장치 활동 감지
        /// </summary>
        public async Task<ServiceResult<IEnumerable<SuspiciousDeviceReport>>> DetectSuspiciousDevicesAsync(Guid organizationId, int days = 30)
        {
            try
            {
                var fromDate = _dateTimeProvider.UtcNow.AddDays(-days);
                var toDate = _dateTimeProvider.UtcNow;

                var devices = await _repository.GetRecentlyRegisteredDevicesAsync(organizationId, days * 24);

                var suspiciousReports = new List<SuspiciousDeviceReport>();

                // 동일 IP에서 여러 장치 등록 감지
                var devicesByIp = devices.GroupBy(d => d.IpAddress)
                    .Where(g => g.Count() > 3)
                    .Select(g => new SuspiciousDeviceReport
                    {
                        Type = "MULTIPLE_DEVICES_SAME_IP",
                        Description = $"Multiple devices ({g.Count()}) registered from same IP: {g.Key}",
                        Devices = g.Select(MapToDto).ToList(),
                        DetectedAt = _dateTimeProvider.UtcNow
                    });

                suspiciousReports.AddRange(devicesByIp);

                // 짧은 시간 내 여러 장치 등록 감지
                var devicesByUser = devices.GroupBy(d => d.UserId)
                    .Where(g => g.Count() > 5)
                    .Select(g => new SuspiciousDeviceReport
                    {
                        Type = "EXCESSIVE_DEVICE_REGISTRATION",
                        Description = $"User registered {g.Count()} devices in {days} days",
                        UserId = g.Key,
                        Devices = g.Select(MapToDto).ToList(),
                        DetectedAt = _dateTimeProvider.UtcNow
                    });

                suspiciousReports.AddRange(devicesByUser);

                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Success(suspiciousReports);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting suspicious devices for organization {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Failure(
                    "Failed to detect suspicious devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 만료된 장치 정리
        /// </summary>
        public async Task<ServiceResult<int>> CleanupExpiredDevicesAsync(Guid organizationId)
        {
            try
            {
                var count = await _repository.CleanupExpiredDevicesAsync(organizationId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    null,
                    "EXPIRED_DEVICES_CLEANUP",
                    AuditActionType.Delete,
                    "TrustedDevice",
                    "EXPIRED",
                    true,
                    JsonSerializer.Serialize(new { OrganizationId = organizationId, Count = count }));

                return ServiceResult<int>.Success(count, $"Cleaned up {count} expired devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up expired devices for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure(
                    "Failed to cleanup expired devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 오래된 비활성 장치 삭제
        /// </summary>
        public async Task<ServiceResult<int>> DeleteOldInactiveDevicesAsync(Guid organizationId, int olderThanDays = 90)
        {
            try
            {
                var count = await _repository.DeleteOldInactiveDevicesAsync(olderThanDays, organizationId);

                // 감사 로그
                await _auditService.LogActionAsync(
                    null,
                    "OLD_DEVICES_DELETED",
                    AuditActionType.Delete,
                    "TrustedDevice",
                    "OLD",
                    true,
                    JsonSerializer.Serialize(new { OrganizationId = organizationId, OlderThanDays = olderThanDays, Count = count }));

                return ServiceResult<int>.Success(count, $"Deleted {count} old inactive devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting old inactive devices for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure(
                    "Failed to delete old devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 사용자별 장치 통계
        /// </summary>
        public async Task<ServiceResult<TrustedDeviceStats>> GetDeviceStatsAsync(Guid userId)
        {
            try
            {
                // 1. 해당 유저의 모든 디바이스 정보를 가져옵니다.
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: true);

                // '최근'의 기준을 정의합니다 (예: 30일 이내).
                var recentDateThreshold = DateTime.UtcNow.AddDays(-30);

                var stats = new TrustedDeviceStats
                {
                    // 2. 모델에 정의된 속성에 맞춰 통계를 계산합니다.
                    TotalDevices = devices.Count(),
                    ActiveDevices = devices.Count(d => d.IsActive),
                    ExpiredDevices = devices.Count(d => d.ExpiresAt.HasValue && d.ExpiresAt.Value < DateTime.UtcNow),
                    RecentlyUsedDevices = devices.Count(d => d.LastUsedAt is DateTime lastUsed && lastUsed >= recentDateThreshold),

                    // DeviceType을 기준으로 그룹화하여 개수를 셉니다.
                    DeviceTypeBreakdown = devices
                        .GroupBy(d => d.DeviceType ?? "Unknown")
                        .ToDictionary(g => g.Key, g => g.Count()),

                    // Browser를 기준으로 그룹화하여 개수를 셉니다.
                    BrowserBreakdown = devices
                        .Where(d => !string.IsNullOrEmpty(d.Browser))
                        .GroupBy(d => d.Browser!)
                        .ToDictionary(g => g.Key, g => g.Count()),

                    // TrustLevel이 TrustedDevice 엔티티에 int 타입으로 존재한다고 가정합니다.
                    TrustLevelBreakdown = devices
                        .GroupBy(d => d.TrustLevel)
                        .ToDictionary(g => g.Key, g => g.Count())
                };

                return ServiceResult<TrustedDeviceStats>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device stats for user {UserId}", userId);
                return ServiceResult<TrustedDeviceStats>.Failure(
                    "Failed to get device stats",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 조직별 장치 통계
        /// </summary>
        public async Task<ServiceResult<OrganizationDeviceStats>> GetOrganizationDeviceStatsAsync(Guid organizationId)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive: true);

                // --- (이전 계산 로직은 동일) ---
                var distinctUserIds = devices.Select(d => d.UserId).Distinct().ToList();
                int totalUserCount = distinctUserIds.Count;
                int totalDeviceCount = devices.Count();

                // --- RegistrationTrends 생성 로직 수정 ---

                // 1. 최근 30일간의 등록 데이터를 날짜별로 그룹화합니다.
                var startDate = DateTime.UtcNow.AddDays(-29).Date; // 30일 전 날짜
                var endDate = DateTime.UtcNow.Date; // 오늘 날짜

                var dailyRegistrations = devices
                    .Where(d => d.TrustedAt.Date >= startDate)
                    .GroupBy(d => d.TrustedAt.Date)
                    .ToDictionary(g => g.Key, g => g.Count());

                // 참고: DeactivatedCount를 계산하려면 TrustedDevice 엔티티에
                // '비활성화된 날짜' (예: DeactivatedAt) 속성이 필요합니다.
                // var dailyDeactivations = devices...

                // 2. 최근 30일 전체에 대한 트렌드 리스트를 생성합니다. (등록이 없는 날도 포함)
                var trends = new List<DeviceRegistrationTrend>();
                for (var date = startDate; date <= endDate; date = date.AddDays(1))
                {
                    dailyRegistrations.TryGetValue(date, out int registeredCount);
                    // dailyDeactivations.TryGetValue(date, out int deactivatedCount);

                    trends.Add(new DeviceRegistrationTrend
                    {
                        Date = date,
                        RegisteredCount = registeredCount,
                        DeactivatedCount = 0 // 현재는 계산할 수 없으므로 0으로 설정
                    });
                }

                var stats = new OrganizationDeviceStats
                {
                    TotalUsers = totalUserCount,
                    TotalDevices = totalDeviceCount,
                    ActiveDevices = devices.Count(d => d.IsActive),
                    AverageDevicesPerUser = totalUserCount > 0 ? (double)totalDeviceCount / totalUserCount : 0,
                    UserDeviceCounts = devices
                        .GroupBy(d => d.UserId)
                        .ToDictionary(g => g.Key, g => g.Count()),

                    // 3. 위에서 생성한 트렌드 리스트를 할당합니다.
                    RegistrationTrends = trends.OrderBy(t => t.Date).ToList()
                };

                return ServiceResult<OrganizationDeviceStats>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization device stats for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDeviceStats>.Failure(
                    "Failed to get organization device stats",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }
        /// <summary>
        /// 장치 사용 패턴 분석
        /// </summary>
        /// <summary>
        /// 사용자의 장치 사용 패턴을 분석합니다.
        /// </summary>
        public async Task<ServiceResult<DeviceUsagePattern>> AnalyzeUsagePatternAsync(Guid userId, int days = 30)
        {
            try
            {
                var fromDate = _dateTimeProvider.UtcNow.AddDays(-days);
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: false);
                var recentDevices = devices.Where(d => d.LastUsedAt >= fromDate).ToList();

                if (!recentDevices.Any())
                {
                    // 분석할 데이터가 없으면 빈 패턴을 반환
                    return ServiceResult<DeviceUsagePattern>.Success(new DeviceUsagePattern());
                }

                var pattern = new DeviceUsagePattern
                {
                    // 시간대별 사용 분포 (마지막 사용 시각 기준)
                    HourlyUsage = recentDevices
                        .Where(d => d.LastUsedAt.HasValue)
                        .GroupBy(d => d.LastUsedAt!.Value.ToString("HH")) // "00", "01", ..., "23"
                        .ToDictionary(g => g.Key, g => g.Count()),

                    // 요일별 사용 분포 (마지막 사용 시각 기준)
                    DailyUsage = recentDevices
                        .Where(d => d.LastUsedAt.HasValue)
                        .GroupBy(d => d.LastUsedAt!.Value.DayOfWeek.ToString()) // "Monday", "Tuesday", ...
                        .ToDictionary(g => g.Key, g => g.Count()),

                    // 자주 사용된 위치 (상위 3개)
                    FrequentLocations = recentDevices
                        .Where(d => !string.IsNullOrEmpty(d.Location))
                        .GroupBy(d => d.Location!)
                        .OrderByDescending(g => g.Count())
                        .Select(g => g.Key)
                        .Take(3)
                        .ToList(),

                    // 최근 사용된 IP 주소 목록 (중복 제거)
                    RecentIpAddresses = recentDevices
                        .Where(d => !string.IsNullOrEmpty(d.IpAddress))
                        .Select(d => d.IpAddress!)
                        .Distinct()
                        .ToList()
                };

                // 의심스러운 패턴 분석 로직 (예시)
                var alerts = new List<string>();
                if (pattern.RecentIpAddresses.Count > 5)
                {
                    alerts.Add($"Too many unique IP addresses ({pattern.RecentIpAddresses.Count}) detected in the last {days} days.");
                }
                if (pattern.FrequentLocations.Count > 3)
                {
                    alerts.Add($"Usage from multiple distinct locations ({pattern.FrequentLocations.Count}) detected.");
                }

                if (alerts.Any())
                {
                    pattern.HasSuspiciousPattern = true;
                    pattern.PatternAlerts = alerts;
                }

                return ServiceResult<DeviceUsagePattern>.Success(pattern);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing usage pattern for user {UserId}", userId);
                return ServiceResult<DeviceUsagePattern>.Failure(
                    "Failed to analyze usage pattern",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 배치 작업 및 유틸리티

        /// <summary>
        /// 장치 정보 동기화 (브라우저 정보 업데이트 등)
        /// </summary>
        public async Task<ServiceResult> SyncDeviceInfoAsync(Guid userId, string deviceId, DeviceInfoUpdate deviceInfo)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId);
                if (device == null)
                {
                    return ServiceResult.Failure(
                        "Device not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                if (!string.IsNullOrEmpty(deviceInfo.UserAgent))
                {
                    ParseUserAgent(deviceInfo.UserAgent, out string? browser, out string? os);
                    device.Browser = browser;
                    device.OperatingSystem = os;
                    device.UserAgent = deviceInfo.UserAgent;
                }

                if (!string.IsNullOrEmpty(deviceInfo.IpAddress))
                {
                    device.IpAddress = deviceInfo.IpAddress;
                }

                if (!string.IsNullOrEmpty(deviceInfo.Location))
                {
                    device.Location = deviceInfo.Location;
                }

                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                await InvalidateUserDeviceCacheAsync(userId);

                return ServiceResult.Success("Device info synchronized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing device info for {DeviceId}", deviceId);
                return ServiceResult.Failure(
                    "Failed to sync device info",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 대량 장치 상태 변경 (관리자용)
        /// </summary>
        public async Task<ServiceResult<BulkUpdateResult>> BulkUpdateDeviceStatusAsync(
            IEnumerable<Guid> deviceIds, Guid organizationId, bool isActive, string? reason = null)
        {
            try
            {
                var result = new BulkUpdateResult
                {
                    TotalRequested = deviceIds.Count(),
                    SuccessCount = 0,
                    FailedCount = 0,
                };

                foreach (var deviceId in deviceIds)
                {
                    try
                    {
                        var device = await _repository.GetByIdAsync(deviceId);
                        if (device != null && device.OrganizationId == organizationId)
                        {
                            await _repository.UpdateActiveStatusAsync(deviceId, isActive, reason);
                            result.SuccessCount++;
                        }
                        else
                        {
                            result.FailedCount++;
                            result.FailedIds.Add(deviceId);
                        }
                    }
                    catch
                    {
                        result.FailedCount++;
                        result.FailedIds.Add(deviceId);
                    }
                }

                // 감사 로그
                await _auditService.LogActionAsync(
                    null,
                    "BULK_DEVICE_STATUS_UPDATE",
                    AuditActionType.Update,
                    "TrustedDevice",
                    "BULK",
                    result.SuccessCount > 0,
                    JsonSerializer.Serialize(new
                    {
                        OrganizationId = organizationId,
                        IsActive = isActive,
                        Reason = reason,
                        Result = result
                    }));

                return ServiceResult<BulkUpdateResult>.Success(result,
                    $"Updated {result.SuccessCount} devices, {result.FailedCount} failed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk device status update for organization {OrganizationId}", organizationId);
                return ServiceResult<BulkUpdateResult>.Failure(
                    "Failed to update devices",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        /// <summary>
        /// 장치 검증 규칙 확인
        /// </summary>
        public async Task<ServiceResult<DeviceValidationRules>> GetValidationRulesAsync(Guid organizationId)
        {
            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<DeviceValidationRules>.Failure(
                        "Organization not found",
                        AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                var maxDevicesPerUser = await GetMaxDevicesPerUserAsync(organization.PricingTier);
                var expirationDays = GetDeviceExpirationDaysAsync(organization.PricingTier, null);

                var rules = new DeviceValidationRules
                {
                    MaxDevicesPerUser = maxDevicesPerUser,
                    DefaultExpirationDays = expirationDays,
                    RequireFingerprint = true,
                    RequireUserAgent = false,
                    RequireIpAddress = true,
                    AllowedDeviceTypes = new List<string> { "Mobile", "Desktop", "Tablet", "Browser" },
                    MinFingerprintLength = 32,
                    MaxFingerprintLength = AuthConstants.Security.DeviceFingerprintLength,
                    PlanType = organization.PricingTier
                };

                return ServiceResult<DeviceValidationRules>.Success(rules);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting validation rules for organization {OrganizationId}", organizationId);
                return ServiceResult<DeviceValidationRules>.Failure(
                    "Failed to get validation rules",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region IAuditableService Implementation

        /// <summary>
        /// 엔티티 변경 이력 추적
        /// </summary>
        public async Task TrackChangeAsync(
            string entityName,
            Guid entityId,
            string action,
            object? oldValue,
            object? newValue,
            Guid? connectedId = null,
            string? additionalInfo = null)
        {
            await _auditService.LogActionAsync(
                connectedId,
                action,
                AuditActionType.Update,
                entityName,
                entityId.ToString(),
                true,
                JsonSerializer.Serialize(new
                {
                    OldValue = oldValue,
                    NewValue = newValue,
                    AdditionalInfo = additionalInfo
                }));
        }

        /// <summary>
        /// 사용자 활동 로깅
        /// </summary>
        public async Task LogActivityAsync(
            Guid connectedId,
            string activity,
            string details,
            string? ipAddress = null,
            string? userAgent = null)
        {
            await _auditService.LogActionAsync(
                connectedId,
                activity,
                AuditActionType.View,
                "UserActivity",
                null,
                true,
                JsonSerializer.Serialize(new
                {
                    Details = details,
                    IpAddress = ipAddress,
                    UserAgent = userAgent
                }));
        }

        /// <summary>
        /// 보안 이벤트 로깅
        /// </summary>
        public async Task LogSecurityEventAsync(
            string eventType,
            string description,
            Guid? connectedId = null,
            string? ipAddress = null,
            SecurityEventSeverity severity = SecurityEventSeverity.Info)
        {
            var auditSeverity = severity switch
            {
                SecurityEventSeverity.Critical => AuditEventSeverity.Critical,
                SecurityEventSeverity.Error => AuditEventSeverity.High,
                SecurityEventSeverity.Warning => AuditEventSeverity.Medium,
                _ => AuditEventSeverity.Low
            };

            await _auditService.LogSecurityEventAsync(
                eventType,
                auditSeverity,
                description,
                connectedId,
                new Dictionary<string, object> { ["ipAddress"] = ipAddress ?? "unknown" });
        }

        /// <summary>
        /// 주요 감사 이벤트 기록
        /// </summary>
        public async Task AuditActionAsync(
            string action,
            string description,
            Guid? connectedId = null)
        {
            await _auditService.LogActionAsync(
                connectedId,
                action,
                AuditActionType.Custom,
                "TrustedDevice",
                null,
                true,
                description);
        }

        #endregion

        #region Helper Methods

        // ... (이전 헬퍼 메소드들 유지)
        private async Task<int> GetMaxDevicesPerUserAsync(string planType)
        {
            var cacheKey = $"{AuthConstants.CacheKeys.OrganizationPrefix}plan_limits:{planType}:max_devices";

            // string으로 캐시 조회
            var cached = await _cacheService.GetAsync<string>(cacheKey);
            if (!string.IsNullOrEmpty(cached) && int.TryParse(cached, out var cachedValue))
                return cachedValue;

            int maxDevices = planType switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => 3,
                PricingConstants.SubscriptionPlans.PRO_KEY => 10,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => 50,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => AuthConstants.Security.MaxTrustedDevicesPerUser * 10,
                _ => AuthConstants.Security.MaxTrustedDevicesPerUser
            };

            // string으로 캐시 저장
            await _cacheService.SetAsync(cacheKey, maxDevices.ToString(),
                TimeSpan.FromSeconds(AuthConstants.CacheKeys.SecurityCacheTTL));
            return maxDevices;
        }
        private int GetDeviceExpirationDaysAsync(string planType, int? requestedDays)
        {
            var defaultDays = AuthConstants.Security.TrustedDeviceLifetime / (60 * 60 * 24);

            if (requestedDays.HasValue)
            {
                var maxDays = planType switch
                {
                    PricingConstants.SubscriptionPlans.BASIC_KEY => defaultDays / 3,
                    PricingConstants.SubscriptionPlans.PRO_KEY => defaultDays / 2,
                    PricingConstants.SubscriptionPlans.BUSINESS_KEY => defaultDays,
                    PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => defaultDays * 3,
                    _ => defaultDays
                };
                return Math.Min(requestedDays.Value, maxDays);
            }

            return planType switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => defaultDays / 3,
                PricingConstants.SubscriptionPlans.PRO_KEY => defaultDays / 2,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => defaultDays,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => defaultDays * 3,
                _ => defaultDays
            };
        }

        private int GetPlanBasedTrustLevel(string planType)
        {
            return planType switch
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY => (int)TrustLevel.Low,
                PricingConstants.SubscriptionPlans.PRO_KEY => (int)TrustLevel.Medium,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY => (int)TrustLevel.High,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY => (int)TrustLevel.VeryHigh,
                _ => (int)TrustLevel.Low
            };
        }
        private int GetAuthenticationStrength(AuthenticationMethod? method)
        {
            if (!method.HasValue)
                return (int)AuthenticationStrength.Low;

            return method.Value switch
            {
                AuthenticationMethod.Biometric => (int)AuthenticationStrength.VeryHigh,
                AuthenticationMethod.Certificate => (int)AuthenticationStrength.VeryHigh,
                AuthenticationMethod.TwoFactor => (int)AuthenticationStrength.High,
                AuthenticationMethod.Passkey => (int)AuthenticationStrength.High,
                AuthenticationMethod.SSO => (int)AuthenticationStrength.Medium,
                AuthenticationMethod.OAuth => (int)AuthenticationStrength.Medium,
                AuthenticationMethod.Password => (int)AuthenticationStrength.Low,
                AuthenticationMethod.MagicLink => (int)AuthenticationStrength.Low,
                _ => (int)AuthenticationStrength.Low
            };
        }


        private string GetRequiredPlanForDeviceCount(int deviceCount)
        {
            if (deviceCount <= 3) return PricingConstants.SubscriptionPlans.BASIC_KEY;
            if (deviceCount <= 10) return PricingConstants.SubscriptionPlans.PRO_KEY;
            if (deviceCount <= 50) return PricingConstants.SubscriptionPlans.BUSINESS_KEY;
            return PricingConstants.SubscriptionPlans.ENTERPRISE_KEY;
        }

        private TrustedDeviceDto MapToDto(TrustedDevice device)
        {
            return new TrustedDeviceDto
            {
                Id = device.Id,
                ConnectedId = device.UserId,
                DeviceId = device.DeviceId,
                DeviceName = device.DeviceName,
                DeviceFingerprint = device.DeviceFingerprint,
                TrustedAt = device.TrustedAt,
                LastUsedAt = device.LastUsedAt,
                ExpiresAt = device.ExpiresAt,
                IsActive = device.IsActive,
                DeviceType = device.DeviceType ?? CommonDefaults.UnknownDeviceType,
                Browser = device.Browser,
                OperatingSystem = device.OperatingSystem,
                IpAddress = device.IpAddress
            };
        }

        private void ParseUserAgent(string userAgent, out string? browser, out string? os)
        {
            browser = null;
            os = null;

            if (userAgent.Contains("Chrome")) browser = "Chrome";
            else if (userAgent.Contains("Firefox")) browser = "Firefox";
            else if (userAgent.Contains("Safari")) browser = "Safari";
            else if (userAgent.Contains("Edge")) browser = "Edge";

            if (userAgent.Contains("Windows")) os = "Windows";
            else if (userAgent.Contains("Mac")) os = "macOS";
            else if (userAgent.Contains("Linux")) os = "Linux";
            else if (userAgent.Contains("Android")) os = "Android";
            else if (userAgent.Contains("iOS") || userAgent.Contains("iPhone")) os = "iOS";
        }

        private async Task InvalidateUserDeviceCacheAsync(Guid userId)
        {
            var cacheKeys = new[]
            {
                $"{AuthConstants.CacheKeys.SecurityPrefix}devices:{userId}",
                $"{AuthConstants.CacheKeys.SecurityPrefix}device_list:{userId}",
                $"{AuthConstants.CacheKeys.SecurityPrefix}device_stats:{userId}"
            };

            foreach (var key in cacheKeys)
            {
                await _cacheService.RemoveAsync(key);
            }
        }

        private async Task<int> GetRateLimitCountAsync(string key)
        {
            // string으로 캐시 조회
            var cached = await _cacheService.GetAsync<string>(key);
            if (!string.IsNullOrEmpty(cached) && int.TryParse(cached, out var count))
                return count;
            return 0;
        }

        private async Task IncrementRateLimitAsync(string key)
        {
            var count = await GetRateLimitCountAsync(key);
            await _cacheService.SetAsync(
                key,
                (count + 1).ToString(),
                TimeSpan.FromMinutes(AuthConstants.OAuth.BlockDurationMinutes));
        }

        private async Task ClearRateLimitAsync(string key)
        {
            await _cacheService.RemoveAsync(key);
        }

        private int CalculateRiskScore(List<TrustedDevice> devices)
        {
            var riskScore = 0;

            // Multiple IPs increases risk
            var uniqueIps = devices.Select(d => d.IpAddress).Distinct().Count();
            if (uniqueIps > 5) riskScore += 20;
            else if (uniqueIps > 3) riskScore += 10;

            // Old devices increase risk
            var oldDevices = devices.Count(d => d.TrustedAt < _dateTimeProvider.UtcNow.AddMonths(-6));
            if (oldDevices > 0) riskScore += oldDevices * 5;

            // Inactive devices increase risk
            var inactiveDevices = devices.Count(d => !d.IsActive);
            if (inactiveDevices > 0) riskScore += inactiveDevices * 10;

            return Math.Min(100, riskScore);
        }

        #endregion
    }
}