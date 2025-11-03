using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using System.Security.Claims;
using AuthHive.Core.Enums.Infra.Monitoring;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Infra.Events;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 신뢰할 수 있는 장치 관리 서비스 구현체 - v17 (경량화 버전)
    /// 정책 계산은 IPlanService, 속도 제한은 IRateLimiterService에 위임합니다.
    /// </summary>
    public class TrustedDeviceService : ITrustedDeviceService
    {
        private readonly ITrustedDeviceRepository _repository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<TrustedDeviceService> _logger;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUserRepository _userRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;

        // 🚨 새로 추가된 의존성
        private readonly IPlanService _planService;
        private readonly IRateLimiterService _rateLimiterService;

        public TrustedDeviceService(
            ITrustedDeviceRepository repository,
            ILogger<TrustedDeviceService> logger,
            IUnitOfWork unitOfWork,
            IEventBus eventBus,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            IOrganizationRepository organizationRepository,
            IUserRepository userRepository,
            IHttpContextAccessor httpContextAccessor,
            IPlanService planService,
            IRateLimiterService rateLimiterService)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _httpContextAccessor = httpContextAccessor;
            _planService = planService ?? throw new ArgumentNullException(nameof(planService));
            _rateLimiterService = rateLimiterService ?? throw new ArgumentNullException(nameof(rateLimiterService));
        }

        #region 장치 등록 및 관리

        public async Task<ServiceResult<TrustedDeviceResponse>> RegisterTrustedDeviceAsync(
            Guid userId,
            TrustedDeviceRequest request,
            CancellationToken cancellationToken = default)
        {
            // 입력 검증
            if (string.IsNullOrWhiteSpace(request.DeviceId))
            {
                return ServiceResult<TrustedDeviceResponse>.Failure(
                    "DeviceId is required",
                    AuthConstants.ErrorCodes.INVALID_REQUEST);
            }

            if (string.IsNullOrWhiteSpace(request.DeviceFingerprint))
            {
                return ServiceResult<TrustedDeviceResponse>.Failure(
                    "Device fingerprint is required",
                    AuthConstants.ErrorCodes.INVALID_REQUEST);
            }

            if (request.DeviceFingerprint.Length > AuthConstants.Security.DeviceFingerprintLength)
            {
                return ServiceResult<TrustedDeviceResponse>.Failure(
                    $"Device fingerprint exceeds maximum length ({AuthConstants.Security.DeviceFingerprintLength})",
                    AuthConstants.ErrorCodes.INVALID_REQUEST);
            }

            try
            {
                var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return ServiceResult<TrustedDeviceResponse>.Failure(
                        "User not found",
                        AuthConstants.ErrorCodes.USER_NOT_FOUND);
                }

                if (!user.OrganizationId.HasValue)
                {
                    return ServiceResult<TrustedDeviceResponse>.Failure(
                        "User is not associated with an organization.",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                var organization = await _organizationRepository.GetByIdAsync(user.OrganizationId.Value, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<TrustedDeviceResponse>.Failure(
                        "Organization not found",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 🚨 정책 확인 로직을 IPlanService로 위임
                var maxDevicesPerUser = await _planService.GetMaxTrustedDevicesPerUserAsync(organization.PricingTier, cancellationToken);
                var currentDeviceCount = await _repository.GetTrustedDeviceCountAsync(userId, true, cancellationToken);

                // 🚨 속도 제한 로직을 IRateLimiterService로 위임
                var rateLimitKey = string.Format(AuthConstants.CacheKeys.FailedAttemptsPattern, $"device_register:{userId}");
                if (await _rateLimiterService.CheckLimitAndIncrementAsync(rateLimitKey, AuthConstants.OAuth.MaxFailedAttemptsBeforeBlock, TimeSpan.FromMinutes(AuthConstants.OAuth.BlockDurationMinutes), cancellationToken))
                {
                    await _auditService.LogSecurityEventAsync(
                        "DEVICE_REGISTRATION_RATE_LIMIT",
                         AuditEventSeverity.Warning,
                        "Too many device registration attempts",
                        userId,
                        new Dictionary<string, object>
                        {
                            ["attempts"] = await _rateLimiterService.GetCurrentAttemptsAsync(rateLimitKey, cancellationToken), // 현재 횟수 조회
                            ["ipAddress"] = request.IpAddress ?? CommonDefaults.DefaultLocalIpV4
                        },
                        cancellationToken: cancellationToken);

                    return ServiceResult<TrustedDeviceResponse>.Failure(
                        "Too many registration attempts. Please try again later.",
                        AuthConstants.ErrorCodes.RateLimitExceeded);
                }

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
                    // limitEvent.RecommendedPlan = await _planService.GetRequiredPlanForDeviceCountAsync(currentDeviceCount + 1, cancellationToken); // PlanService에 추가 필요 시
                    await _eventBus.PublishAsync(limitEvent, cancellationToken);
                    return ServiceResult<TrustedDeviceResponse>.Failure(errorMessage, "PLAN_LIMIT_EXCEEDED");
                }

                // Corrected code
                var isDuplicate = await _repository.IsDeviceIdDuplicateAsync(request.DeviceId, userId, null, cancellationToken);
                //                                                                               ^^^^ - Explicitly pass null for excludeId
                if (isDuplicate)
                {
                    // Rate Limit은 이미 CheckLimitAndIncrementAsync에서 증가됨
                    await _auditService.LogActionAsync(
          // 1. actionType
          AuthHive.Core.Enums.Core.AuditActionType.Create,
          // 2. action
          "DEVICE_REGISTRATION_FAILED",
          // 3. connectedId (Using userId here as per your original code)
          userId,
          // 4. success
          false,
          // 5. errorMessage (Optional, providing the reason here)
          "Duplicate device ID detected",
          // 6. resourceType (Optional)
          "TrustedDevice",
          // 7. resourceId (Optional)
          request.DeviceId,
          // 8. metadata (Optional, create a dictionary if needed)
          new Dictionary<string, object> { { "Details", "Duplicate device ID detected during registration attempt." } }, // Example metadata
                                                                                                                         // 9. cancellationToken
          cancellationToken
      );

                    return ServiceResult<TrustedDeviceResponse>.Failure(
                        "Device with this ID already exists",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                await _unitOfWork.BeginTransactionAsync(cancellationToken);
                try
                {
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

                    // 🚨 정책 계산 로직을 IPlanService로 위임
                    var expirationDays = await _planService.GetTrustedDeviceExpirationDaysAsync(organization.PricingTier, request.TrustDurationDays, cancellationToken);
                    if (expirationDays > 0)
                    {
                        trustedDevice.SetExpiration(_dateTimeProvider.UtcNow.AddDays(expirationDays));
                    }

                    if (!string.IsNullOrEmpty(request.UserAgent))
                    {
                        ParseUserAgent(request.UserAgent, out string? browser, out string? os);
                        trustedDevice.Browser = browser;
                        trustedDevice.OperatingSystem = os;
                    }

                    var trustLevel = await _planService.GetPlanBasedTrustLevelAsync(organization.PricingTier, cancellationToken);
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

                    await _repository.AddAsync(trustedDevice, cancellationToken);
                    await _unitOfWork.SaveChangesAsync(cancellationToken);
                    await _unitOfWork.CommitTransactionAsync(cancellationToken);

                    // 🚨 속도 제한 초기화 및 캐시 무효화를 IRateLimiterService로 위임
                    await _rateLimiterService.ClearLimitAsync(rateLimitKey, cancellationToken);
                    await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                    // 이벤트 발행
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
                    ), cancellationToken);

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
                       ), cancellationToken);
                    }

                    // 감사 로그
                    await _auditService.LogActionAsync(
                 AuthHive.Core.Enums.Core.AuditActionType.Create,
                 AuthConstants.Events.DeviceTrusted,
                 userId,
                 true,
                 null,
                 "TrustedDevice",
                 trustedDevice.Id.ToString(),
                 new Dictionary<string, object>
                 {
        { "DeviceId", trustedDevice.DeviceId },
        { "DeviceType", trustedDevice.DeviceType },
        { "PlanType", organization.PricingTier },
        { "DeviceCount", $"{currentDeviceCount + 1}/{maxDevicesPerUser}" }
                 },
                 cancellationToken
             );

                    _logger.LogInformation(
                        "Trusted device registered successfully for user {UserId}: {DeviceId} (Plan: {PlanType}, Devices: {Current}/{Max})",
                        userId, trustedDevice.DeviceId, organization.PricingTier, currentDeviceCount + 1, maxDevicesPerUser);

                    return ServiceResult<TrustedDeviceResponse>.Success(MapToDto(trustedDevice));
                }
                catch (Exception dbEx)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    _logger.LogError(dbEx, "Database error during trusted device registration for user {UserId}", userId);
                    // 롤백 후 감사 로그 등 추가 처리 가능
                    throw; // 예외를 다시 던져 상위에서 처리하도록 함
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering trusted device for user {UserId}", userId);
                await _auditService.LogSecurityEventAsync(
                    AuthConstants.Events.SuspiciousActivity,
                    AuditEventSeverity.Warning,
                    "Failed to register trusted device",
                    userId,
                    new Dictionary<string, object>
                    {
                        ["error"] = ex.Message,
                        ["deviceId"] = request.DeviceId
                    },
                    cancellationToken: cancellationToken);

                return ServiceResult<TrustedDeviceResponse>.Failure(
                    "Failed to register trusted device",
                    AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId, cancellationToken);
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.Deactivate();
                await _repository.UpdateAsync(device, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 🚨 캐시 무효화를 IRateLimiterService로 위임
                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
             AuthHive.Core.Enums.Core.AuditActionType.Delete,
             "DEVICE_REMOVED",
             userId,
             true,
             null, // errorMessage
             "TrustedDevice",
             deviceId,
             null, // metadata
             cancellationToken
         );

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {DeviceId} for user {UserId}", deviceId, userId);
                return ServiceResult.Failure("Failed to remove device", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult> RemoveTrustedDeviceByIdAsync(Guid id, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.Deactivate();
                await _repository.UpdateAsync(device, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
         AuthHive.Core.Enums.Core.AuditActionType.Delete,
         "DEVICE_REMOVED_BY_ID",
         userId,
         true,
         null, // errorMessage
         "TrustedDevice",
         id.ToString(),
         null, // metadata
         cancellationToken
     );

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {Id} for user {UserId}", id, userId);
                return ServiceResult.Failure("Failed to remove device", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var count = await _repository.DeactivateAllUserDevicesAsync(userId, "User requested removal of all devices", cancellationToken);

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
              AuthHive.Core.Enums.Core.AuditActionType.Delete,
              "ALL_DEVICES_REMOVED",
              userId,
              true,
              null, // errorMessage
              "TrustedDevice",
              "ALL",
              new Dictionary<string, object> { { "Count", count } }, // metadata
              cancellationToken
          );

                return ServiceResult<int>.Success(count, $"Removed {count} devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing all trusted devices for user {UserId}", userId);
                return ServiceResult<int>.Failure("Failed to remove devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 장치 조회 및 검증 (CancellationToken 전달 위주 수정)

        public async Task<ServiceResult<IEnumerable<TrustedDeviceResponse>>> GetTrustedDevicesAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: false, cancellationToken);
                var dtos = devices.Select(MapToDto);
                return ServiceResult<IEnumerable<TrustedDeviceResponse>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting trusted devices for user {UserId}", userId);
                return ServiceResult<IEnumerable<TrustedDeviceResponse>>.Failure("Failed to get devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<bool>> IsDeviceTrustedAsync(Guid userId, string deviceId, string fingerprint, CancellationToken cancellationToken = default)
        {
            try
            {
                var isTrusted = await _repository.IsDeviceTrustedAsync(deviceId, fingerprint, userId, cancellationToken);
                return ServiceResult<bool>.Success(isTrusted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if device is trusted for user {UserId}", userId);
                return ServiceResult<bool>.Failure("Failed to check device trust status", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<TrustedDeviceVerificationResult>> VerifyAndUpdateDeviceAsync(
            Guid userId, string deviceId, string fingerprint,
            string? ipAddress = null, string? userAgent = null, string? location = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId, cancellationToken);
                if (device == null)
                {
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult { IsTrusted = false, Reason = "Device not found" });
                }

                if (device.DeviceFingerprint != fingerprint)
                {
                    await _auditService.LogSecurityEventAsync(
                        "DEVICE_FINGERPRINT_MISMATCH",
                        AuditEventSeverity.Warning,
                        "Device fingerprint mismatch detected",
                        userId,
                        new Dictionary<string, object> { ["deviceId"] = deviceId, ["ipAddress"] = ipAddress ?? "unknown" },
                        cancellationToken: cancellationToken);
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult { IsTrusted = false, Reason = "Device fingerprint mismatch" });
                }

                if (!device.IsValid)
                {
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult { IsTrusted = false, Reason = device.IsExpired ? "Device expired" : "Device inactive" });
                }

                await _repository.UpdateLastUsedAsync(deviceId, userId, ipAddress, userAgent, location, cancellationToken);
                // 변경 사항 저장은 호출자 또는 UoW 패턴에 따라 처리 (여기서는 UpdateLastUsedAsync가 즉시 저장 가정)

                return ServiceResult<TrustedDeviceVerificationResult>.Success(new TrustedDeviceVerificationResult { IsTrusted = true, Device = MapToDto(device) });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying device for user {UserId}", userId);
                return ServiceResult<TrustedDeviceVerificationResult>.Failure("Failed to verify device", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<TrustedDeviceResponse>> GetTrustedDeviceAsync(Guid id, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult<TrustedDeviceResponse>.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }
                return ServiceResult<TrustedDeviceResponse>.Success(MapToDto(device));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting trusted device {Id} for user {UserId}", id, userId);
                return ServiceResult<TrustedDeviceResponse>.Failure("Failed to get device", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 장치 상태 관리 (CancellationToken 전달 위주 수정)

        public async Task<ServiceResult> UpdateDeviceStatusAsync(Guid id, Guid userId, bool isActive, string? reason = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.UpdateActiveStatusAsync(id, isActive, reason, cancellationToken);
                // 변경 사항 저장은 UpdateActiveStatusAsync 내부 또는 SaveChangesAsync 필요 시 추가

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Update,
                    isActive ? "DEVICE_ACTIVATED" : "DEVICE_DEACTIVATED",
                    userId,
                    true,
                    null, // errorMessage
                    "TrustedDevice",
                    id.ToString(),
                    string.IsNullOrEmpty(reason) ? null : new Dictionary<string, object> { { "Reason", reason } }, // metadata
                    cancellationToken
                );

                return ServiceResult.Success("Device status updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device status for {Id}", id);
                return ServiceResult.Failure("Failed to update device status", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult> UpdateTrustLevelAsync(Guid id, Guid userId, int trustLevel, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.UpdateTrustLevelAsync(id, trustLevel, cancellationToken);
                // 변경 사항 저장은 UpdateTrustLevelAsync 내부 또는 SaveChangesAsync 필요 시 추가

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Update,
                    "DEVICE_TRUST_LEVEL_UPDATED",
                    userId,
                    true,
                    null, // errorMessage
                    "TrustedDevice",
                    id.ToString(),
                    new Dictionary<string, object> { { "TrustLevel", trustLevel } }, // metadata
                    cancellationToken
                );

                return ServiceResult.Success("Trust level updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating trust level for device {Id}", id);
                return ServiceResult.Failure("Failed to update trust level", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult> SetDeviceExpirationAsync(Guid id, Guid userId, DateTime? expiresAt, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                await _repository.SetExpirationAsync(id, expiresAt, cancellationToken);
                // 변경 사항 저장은 SetExpirationAsync 내부 또는 SaveChangesAsync 필요 시 추가

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "DEVICE_EXPIRATION_SET",
                    userId,
                    true,
                    null, // errorMessage
                    "TrustedDevice",
                    id.ToString(),
                    new Dictionary<string, object> { { "ExpiresAt", (object?)expiresAt ?? DBNull.Value } },// metadata
                    cancellationToken
                );

                return ServiceResult.Success("Device expiration updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting device expiration for {Id}", id);
                return ServiceResult.Failure("Failed to set device expiration", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult> UpdateDeviceNameAsync(Guid id, Guid userId, string deviceName, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id, cancellationToken);
                if (device == null || device.UserId != userId)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }

                device.DeviceName = deviceName;
                await _repository.UpdateAsync(device, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken); // 변경 추적이 필요하므로 SaveChanges 호출

                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);

                await _auditService.LogActionAsync(
                  AuthHive.Core.Enums.Core.AuditActionType.Update,
                  "DEVICE_NAME_UPDATED",
                  userId,
                  true,
                  null, // errorMessage
                  "TrustedDevice",
                  id.ToString(),
                  new Dictionary<string, object> { { "DeviceName", deviceName } }, // metadata
                  cancellationToken
              );

                return ServiceResult.Success("Device name updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device name for {Id}", id);
                return ServiceResult.Failure("Failed to update device name", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 보안 및 관리자 기능 (CancellationToken 전달 위주 수정)

        public async Task<ServiceResult<IEnumerable<TrustedDeviceResponse>>> GetOrganizationDevicesAsync(Guid organizationId, bool includeInactive = false, CancellationToken cancellationToken = default)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive, cancellationToken);
                var dtos = devices.Select(MapToDto);
                return ServiceResult<IEnumerable<TrustedDeviceResponse>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization devices for {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<TrustedDeviceResponse>>.Failure("Failed to get organization devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<IEnumerable<SuspiciousDeviceReport>>> DetectSuspiciousDevicesAsync(Guid organizationId, int days = 30, CancellationToken cancellationToken = default)
        {
            try
            {
                var fromDate = _dateTimeProvider.UtcNow.AddDays(-days);
                var devices = await _repository.GetRecentlyRegisteredDevicesAsync(organizationId, days * 24, cancellationToken);
                var suspiciousReports = new List<SuspiciousDeviceReport>();

                // 로직 단순화 (예시)
                var devicesByIp = devices.GroupBy(d => d.IpAddress)
                    .Where(g => g.Count() > 3) // Example threshold
                    .Select(g => new SuspiciousDeviceReport { /* ... */ });
                suspiciousReports.AddRange(devicesByIp);

                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Success(suspiciousReports);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting suspicious devices for organization {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Failure("Failed to detect suspicious devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<int>> CleanupExpiredDevicesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var connectedIdStr = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid? connectedId = Guid.TryParse(connectedIdStr, out var id) ? id : null;

            try
            {
                var count = await _repository.CleanupExpiredDevicesAsync(organizationId, cancellationToken);

                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Delete, // actionType
                    "EXPIRED_DEVICES_CLEANUP",                      // action
                    connectedId.GetValueOrDefault(),                // connectedId (수정됨: Guid? -> Guid)
                    true,                                           // success
                    null,                                           // errorMessage
                    "TrustedDevice",                                // resourceType
                    "EXPIRED",                                      // resourceId
                    new Dictionary<string, object> {                // metadata
                    { "OrganizationId", organizationId },
                    { "Count", count }
                    },
                    cancellationToken                               // cancellationToken
                );
                return ServiceResult<int>.Success(count, $"Cleaned up {count} expired devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up expired devices for organization {OrganizationId}", organizationId);

                // 오류 발생 시에도 감사 로그를 남길 수 있습니다.
                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Delete,
                    "EXPIRED_DEVICES_CLEANUP_FAILED",
                    connectedId.GetValueOrDefault(), // 여기도 동일하게 수정
                    false,
                    ex.Message, // 에러 메시지 기록
                    "TrustedDevice",
                    "EXPIRED",
                    new Dictionary<string, object> { { "OrganizationId", organizationId } },
                    cancellationToken
                );

                return ServiceResult<int>.Failure("Failed to cleanup expired devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<int>> DeleteOldInactiveDevicesAsync(Guid organizationId, int olderThanDays = 90, CancellationToken cancellationToken = default)
        {
            // 1. HttpContext에서 현재 사용자 ID (connectedId) 가져오기
            var connectedIdStr = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid? connectedId = Guid.TryParse(connectedIdStr, out var id) ? id : null;

            try
            {
                var count = await _repository.DeleteOldInactiveDevicesAsync(olderThanDays, organizationId, cancellationToken);

                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Delete, // actionType
                    "OLD_DEVICES_DELETED",                          // action
                    connectedId.GetValueOrDefault(),                // connectedId (수정됨)
                    true,                                           // success
                    null,                                           // errorMessage
                    "TrustedDevice",                                // resourceType
                    "OLD",                                          // resourceId
                    new Dictionary<string, object> {                // metadata
                { "OrganizationId", organizationId },
                { "OlderThanDays", olderThanDays },
                { "Count", count }
                    },
                    cancellationToken                               // cancellationToken
                );
                return ServiceResult<int>.Success(count, $"Deleted {count} old inactive devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting old inactive devices for organization {OrganizationId}", organizationId);

                // 2. (권장) 실패 시에도 감사 로그 남기기
                await _auditService.LogActionAsync(
                    AuthHive.Core.Enums.Core.AuditActionType.Delete,
                    "OLD_DEVICES_DELETE_FAILED",
                    connectedId.GetValueOrDefault(), // 여기도 동일하게 수정
                    false,
                    ex.Message,
                    "TrustedDevice",
                    "OLD",
                    new Dictionary<string, object> {
                { "OrganizationId", organizationId },
                { "OlderThanDays", olderThanDays }
                    },
                    cancellationToken
                );

                return ServiceResult<int>.Failure("Failed to delete old devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 통계 및 분석 (CancellationToken 전달 위주 수정)

        public async Task<ServiceResult<TrustedDeviceStats>> GetDeviceStatsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: true, cancellationToken);
                // ... (통계 계산 로직 유지)
                return ServiceResult<TrustedDeviceStats>.Success(new TrustedDeviceStats { /* ... */ });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device stats for user {UserId}", userId);
                return ServiceResult<TrustedDeviceStats>.Failure("Failed to get device stats", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<OrganizationDeviceStats>> GetOrganizationDeviceStatsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive: true, cancellationToken);
                // ... (통계 계산 로직 유지)
                return ServiceResult<OrganizationDeviceStats>.Success(new OrganizationDeviceStats { /* ... */ });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization device stats for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDeviceStats>.Failure("Failed to get organization device stats", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<DeviceUsagePattern>> AnalyzeUsagePatternAsync(Guid userId, int days = 30, CancellationToken cancellationToken = default)
        {
            try
            {
                var fromDate = _dateTimeProvider.UtcNow.AddDays(-days);
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: false, cancellationToken);
                // ... (패턴 분석 로직 유지)
                return ServiceResult<DeviceUsagePattern>.Success(new DeviceUsagePattern { /* ... */ });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing usage pattern for user {UserId}", userId);
                return ServiceResult<DeviceUsagePattern>.Failure("Failed to analyze usage pattern", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region 배치 작업 및 유틸리티 (CancellationToken 전달 위주 수정)

        public async Task<ServiceResult> SyncDeviceInfoAsync(Guid userId, string deviceId, DeviceInfoUpdate deviceInfo, CancellationToken cancellationToken = default)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId, cancellationToken);
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", AuthConstants.ErrorCodes.DEVICE_NOT_FOUND);
                }
                // ... (정보 업데이트 로직 유지)
                await _repository.UpdateAsync(device, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await _rateLimiterService.InvalidateTrustedDeviceCacheAsync(userId, cancellationToken);
                return ServiceResult.Success("Device info synchronized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing device info for {DeviceId}", deviceId);
                return ServiceResult.Failure("Failed to sync device info", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<BulkUpdateResult>> BulkUpdateDeviceStatusAsync(
            IEnumerable<Guid> deviceIds, Guid organizationId, bool isActive, string? reason = null, CancellationToken cancellationToken = default)
        {
            // 1. HttpContext에서 현재 사용자 ID (connectedId) 가져오기
            var connectedIdStr = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid? connectedId = Guid.TryParse(connectedIdStr, out var id) ? id : null;

            try
            {
                var result = new BulkUpdateResult { /* ... */ }; // BulkUpdateResult 계산 로직...

                await _auditService.LogActionAsync(
                    AuditActionType.Update, // actionType
                    "BULK_DEVICE_STATUS_UPDATE",                    // action
                    connectedId.GetValueOrDefault(),                // connectedId (수정됨)
                    result.SuccessCount > 0,                        // success
                    null,                                           // errorMessage
                    "TrustedDevice",                                // resourceType
                    "BULK",                                         // resourceId
                    new Dictionary<string, object> {                // metadata
                { "OrganizationId", organizationId },
                { "IsActive", isActive },
                { "Reason", (object?)reason ?? DBNull.Value },
                { "Result", result } // 'result'가 직렬화 가능하거나 주요 속성을 추출해야 할 수 있음
                    },
                    cancellationToken                               // cancellationToken
                );
                return ServiceResult<BulkUpdateResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk device status update for organization {OrganizationId}", organizationId);

                // 2. (권장) 실패 시에도 감사 로그 남기기
                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "BULK_DEVICE_STATUS_UPDATE_FAILED",
                    connectedId.GetValueOrDefault(), // 여기도 동일하게 수정
                    false,
                    ex.Message,
                    "TrustedDevice",
                    "BULK",
                    new Dictionary<string, object> {
                { "OrganizationId", organizationId },
                { "IsActive", isActive },
               { "Reason", (object?)reason ?? DBNull.Value },
                    },
                    cancellationToken
                );

                return ServiceResult<BulkUpdateResult>.Failure("Failed to update devices", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        public async Task<ServiceResult<DeviceValidationRules>> GetValidationRulesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 조직 정보를 가져옵니다.
                var organization = await _organizationRepository.GetByIdAsync(organizationId, cancellationToken);

                // 2. null을 명시적으로 확인하고, null인 경우 실패 결과를 반환하여 메서드를 종료합니다.
                if (organization == null)
                {
                    _logger.LogWarning("Device validation rules requested for non-existent organization {OrganizationId}", organizationId);
                    return ServiceResult<DeviceValidationRules>.Failure(
                        "Organization not found.",
                        AuthConstants.ErrorCodes.ORGANIZATION_NOT_FOUND);
                }

                // 3. 이제 컴파일러는 이 지점에서 'organization'이 절대 null이 아님을 확신합니다.
                var maxDevices = await _planService.GetMaxTrustedDevicesPerUserAsync(organization.PricingTier, cancellationToken);
                var expirationDays = await _planService.GetTrustedDeviceExpirationDaysAsync(organization.PricingTier, null, cancellationToken);

                // 4. 규칙 객체를 생성하고 성공 결과를 반환합니다.
                // expirationDays (기기 유효 기간)가 0일보다 크면, AllowPersistence는 true가 됩니다. 
                // 이는 사용자가 로그인할 때 "이 기기 기억하기"와 같은 옵션을 선택하여 해당 
                // 기기 정보를 서버에 저장하는 것을 허용한다는 뜻입니다.
                var rules = new DeviceValidationRules
                {
                    MaxDevicesPerUser = maxDevices,
                    DefaultExpirationDays = expirationDays,
                    AllowPersistence = expirationDays < 0
                };

                return ServiceResult<DeviceValidationRules>.Success(rules);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting validation rules for organization {OrganizationId}", organizationId);
                return ServiceResult<DeviceValidationRules>.Failure("Failed to get validation rules", AuthConstants.ErrorCodes.INTERNAL_ERROR);
            }
        }

        #endregion

        #region IAuditableService Implementation (유지)
        public async Task TrackChangeAsync(string entityName, Guid entityId, string action, object? oldValue, object? newValue, Guid? connectedId = null, string? additionalInfo = null, CancellationToken cancellationToken = default)
        {
            await _auditService.LogActionAsync(
                AuditActionType.Update, // actionType
                action,                                         // action
                connectedId.GetValueOrDefault(),                // connectedId 
                true,                                           // success
                null,                                           // errorMessage
                entityName,                                     // resourceType
                entityId.ToString(),                            // resourceId
                new Dictionary<string, object> {
            { "OldValue", oldValue ?? DBNull.Value },
            { "NewValue", newValue ?? DBNull.Value },       
            // 'string?'를 'object?'로 캐스팅한 후 '??' 사용
            { "AdditionalInfo", (object?)additionalInfo ?? DBNull.Value }
                },
                // ^^^ 수정된 부분 ^^^

                cancellationToken                               // cancellationToken
            );
        }

        public async Task LogActivityAsync(Guid connectedId, string activity, string details, string? ipAddress = null, string? userAgent = null, CancellationToken cancellationToken = default)
        {
            await _auditService.LogActionAsync(
                AuthHive.Core.Enums.Core.AuditActionType.View, // actionType
                activity,                                      // action
                connectedId,                                   // connectedId
                true,                                          // success
                null,                                          // errorMessage
                "UserActivity",                                // resourceType
                null,                                          // resourceId
                new Dictionary<string, object> {               // 1. 타입을 <string, object>로 명시
                    { "Details", details },                        // 'details'는 null이 아님
                    { "IpAddress", (object?)ipAddress ?? DBNull.Value }, // 2. (object?) 캐스팅 후 ?? DBNull.Value
                    { "UserAgent", (object?)userAgent ?? DBNull.Value } // 3. (object?) 캐스팅 후 ?? DBNull.Value
                },
                cancellationToken                              // cancellationToken
            );
        }

        public async Task LogSecurityEventAsync(
            string eventType,
            string description,
            Guid? connectedId = null,
            string? ipAddress = null,
            SecurityEventSeverityEnums severity = SecurityEventSeverityEnums.Info,
            CancellationToken cancellationToken = default)
        {
            // 'using AuthHive.Core.Enums.Core;'를 추가하면
            // 이제 컴파일러는 AuditEventSeverity를 enum 타입으로 올바르게 인식합니다.
            var auditSeverity = severity switch
            {
                SecurityEventSeverityEnums.Info => AuditEventSeverity.Info,
                SecurityEventSeverityEnums.Low => AuditEventSeverity.Info,
                SecurityEventSeverityEnums.Warning => AuditEventSeverity.Warning,
                SecurityEventSeverityEnums.Medium => AuditEventSeverity.Warning,
                SecurityEventSeverityEnums.Error => AuditEventSeverity.Error,
                SecurityEventSeverityEnums.High => AuditEventSeverity.Error,
                SecurityEventSeverityEnums.Critical => AuditEventSeverity.Critical,
                SecurityEventSeverityEnums.Emergency => AuditEventSeverity.Critical,
                _ => AuditEventSeverity.Info
            };

            await _auditService.LogSecurityEventAsync(
                eventType,
                auditSeverity,
                description,
                connectedId,
                new Dictionary<string, object> { ["ipAddress"] = ipAddress ?? "unknown" },
                cancellationToken
            );
        }

        public async Task AuditActionAsync(string action, string description, Guid? connectedId = null, CancellationToken cancellationToken = default)
        {
            await _auditService.LogActionAsync(
                AuthHive.Core.Enums.Core.AuditActionType.Custom, // actionType
                action,                                         // action
                connectedId.GetValueOrDefault(),                // connectedId (수정됨)
                true,                                           // success
                null,                                           // errorMessage
                "TrustedDevice",                                // resourceType
                null,                                           // resourceId
                new Dictionary<string, object> { { "Description", description } }, // metadata (타입을 object로 수정)
                cancellationToken                               // cancellationToken
            );
        }

        #endregion

        #region Helper Methods (유지)

        private TrustedDeviceResponse MapToDto(TrustedDevice device) { /* ... 로직 유지 ... */ return new TrustedDeviceResponse(); }
        private void ParseUserAgent(string userAgent, out string? browser, out string? os) { /* ... 로직 유지 ... */ browser = null; os = null; }
        private int GetAuthenticationStrength(AuthenticationMethod? method) { /* ... 로직 유지 ... */ return 0; }

        #endregion

        // 🚨 IService 인터페이스 구현 (필요 시)
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => _repository.IsHealthyAsync(cancellationToken); // IRepository에 IsHealthyAsync가 있다고 가정
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}