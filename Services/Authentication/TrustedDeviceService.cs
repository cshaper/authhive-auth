using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Entities.Auth;
using System.Text.Json;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 신뢰할 수 있는 장치 관리 서비스 구현체 - AuthHive v15
    /// MFA에서 사용되는 핵심 서비스입니다.
    /// </summary>
    public class TrustedDeviceService : ITrustedDeviceService
    {
        private readonly ITrustedDeviceRepository _repository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<TrustedDeviceService> _logger;
        private readonly IMemoryCache _cache;
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        // 기본 설정값
        private const int DEFAULT_MAX_DEVICES_PER_USER = 10;
        private const int DEFAULT_EXPIRATION_DAYS = 90;
        private const int DEFAULT_TRUST_LEVEL = 1;
        private const int MIN_TRUST_LEVEL = 1;
        private const int MAX_TRUST_LEVEL = 3;

        public TrustedDeviceService(
            ITrustedDeviceRepository repository,
            ILogger<TrustedDeviceService> logger,
            IUnitOfWork unitOfWork,
            IMemoryCache cache)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _unitOfWork = unitOfWork;
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        #region 장치 등록 및 관리

        /// <summary>
        /// 신뢰할 수 있는 장치 등록
        /// </summary>
        public async Task<ServiceResult<TrustedDeviceDto>> RegisterTrustedDeviceAsync(Guid userId, TrustedDeviceRequest request)
        {
            try
            {
                // 입력 검증
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                    return ServiceResult<TrustedDeviceDto>.Failure("DeviceId is required", "INVALID_DEVICE_ID");

                if (string.IsNullOrWhiteSpace(request.DeviceFingerprint))
                    return ServiceResult<TrustedDeviceDto>.Failure("Device fingerprint is required", "INVALID_FINGERPRINT");

                // 장치 개수 제한 확인
                var currentDeviceCount = await _repository.GetTrustedDeviceCountAsync(userId, onlyActive: true);
                if (currentDeviceCount >= DEFAULT_MAX_DEVICES_PER_USER)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        $"Maximum number of trusted devices ({DEFAULT_MAX_DEVICES_PER_USER}) reached",
                        "MAX_DEVICES_REACHED");
                }

                // 중복 장치 ID 확인
                var isDuplicate = await _repository.IsDeviceIdDuplicateAsync(request.DeviceId, userId);
                if (isDuplicate)
                {
                    return ServiceResult<TrustedDeviceDto>.Failure(
                        "Device with this ID already exists",
                        "DUPLICATE_DEVICE_ID");
                }

                // 신뢰할 수 있는 장치 엔티티 생성
                var trustedDevice = new TrustedDevice
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    DeviceId = request.DeviceId,
                    DeviceName = request.DeviceName ?? $"Device {DateTime.UtcNow:yyyy-MM-dd}",
                    DeviceType = request.DeviceType ?? "Unknown",
                    DeviceFingerprint = request.DeviceFingerprint,
                    TrustedAt = DateTime.UtcNow,
                    IsActive = true,
                    IpAddress = request.IpAddress,
                    UserAgent = request.UserAgent
                };

                // 만료일 설정
                var expirationDays = request.TrustDurationDays ?? DEFAULT_EXPIRATION_DAYS;
                if (expirationDays > 0)
                {
                    trustedDevice.SetExpiration(DateTime.UtcNow.AddDays(expirationDays));
                }

                // UserAgent 파싱하여 브라우저와 OS 정보 추출
                if (!string.IsNullOrEmpty(request.UserAgent))
                {
                    ParseUserAgent(request.UserAgent, out string? browser, out string? os);
                    trustedDevice.Browser = browser;
                    trustedDevice.OperatingSystem = os;
                }

                // 메타데이터에 초기 신뢰 레벨 설정
                var metadata = new Dictionary<string, object>
                {
                    ["trustLevel"] = DEFAULT_TRUST_LEVEL,
                    ["registeredAt"] = DateTime.UtcNow,
                    ["registrationIp"] = request.IpAddress ?? "Unknown"
                };
                trustedDevice.Metadata = JsonSerializer.Serialize(metadata);

                // 저장
                await _repository.AddAsync(trustedDevice);
                await _unitOfWork.SaveChangesAsync();

                // 감사 로그
                await AuditActionAsync(
                    "DEVICE_REGISTERED",
                    $"New trusted device registered: {trustedDevice.DeviceName}",
                    userId);

                _logger.LogInformation(
                    "Trusted device registered successfully for user {UserId}: {DeviceId}",
                    userId, trustedDevice.DeviceId);

                return ServiceResult<TrustedDeviceDto>.Success(MapToDto(trustedDevice));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering trusted device for user {UserId}", userId);
                return ServiceResult<TrustedDeviceDto>.Failure(
                    "Failed to register trusted device",
                    "REGISTRATION_ERROR");
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
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                await _repository.DeleteAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                InvalidateDeviceCache(userId, deviceId);

                // 감사 로그
                await AuditActionAsync(
                    "DEVICE_REMOVED",
                    $"Trusted device removed: {device.DeviceName}",
                    userId);

                _logger.LogInformation(
                    "Trusted device removed for user {UserId}: {DeviceId}",
                    userId, deviceId);

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {DeviceId} for user {UserId}",
                    deviceId, userId);
                return ServiceResult.Failure("Failed to remove device", "REMOVAL_ERROR");
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
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult.Failure("Unauthorized access to device", "UNAUTHORIZED");
                }

                await _repository.DeleteAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                InvalidateDeviceCache(userId, device.DeviceId);

                // 감사 로그
                await AuditActionAsync(
                    "DEVICE_REMOVED_BY_ID",
                    $"Trusted device removed by ID: {device.DeviceName}",
                    userId);

                return ServiceResult.Success("Device removed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing trusted device {Id} for user {UserId}", id, userId);
                return ServiceResult.Failure("Failed to remove device", "REMOVAL_ERROR");
            }
        }

        /// <summary>
        /// 모든 신뢰할 수 있는 장치 제거
        /// </summary>
        public async Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId)
        {
            try
            {
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: true);
                var deviceList = devices.ToList();

                if (!deviceList.Any())
                {
                    return ServiceResult<int>.Success(0, "No devices to remove");
                }

                await _repository.DeleteRangeAsync(deviceList);
                await _unitOfWork.SaveChangesAsync();

                // 캐시 무효화
                foreach (var device in deviceList)
                {
                    InvalidateDeviceCache(userId, device.DeviceId);
                }

                // 감사 로그
                await AuditActionAsync(
                    "ALL_DEVICES_REMOVED",
                    $"All {deviceList.Count} trusted devices removed",
                    userId);

                _logger.LogInformation(
                    "All {Count} trusted devices removed for user {UserId}",
                    deviceList.Count, userId);

                return ServiceResult<int>.Success(deviceList.Count,
                    $"Successfully removed {deviceList.Count} devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing all trusted devices for user {UserId}", userId);
                return ServiceResult<int>.Failure("Failed to remove devices", "REMOVAL_ERROR");
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
                var deviceDtos = devices.Select(MapToDto).ToList();

                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(
                    deviceDtos,
                    $"Found {deviceDtos.Count} trusted devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting trusted devices for user {UserId}", userId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure(
                    "Failed to retrieve devices",
                    "RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// 장치가 신뢰할 수 있는지 검증 (MFA 핵심 메서드)
        /// </summary>
        public async Task<ServiceResult<bool>> IsDeviceTrustedAsync(
            Guid userId, string deviceId, string fingerprint)
        {
            try
            {
                var cacheKey = GetDeviceTrustCacheKey(userId, deviceId, fingerprint);
                
                // 캐시 확인
                if (_cache.TryGetValue<bool>(cacheKey, out var cachedResult))
                {
                    return ServiceResult<bool>.Success(cachedResult);
                }

                var isTrusted = await _repository.IsDeviceTrustedAsync(deviceId, fingerprint, userId);

                // 캐시 저장
                _cache.Set(cacheKey, isTrusted, _cacheExpiration);

                return ServiceResult<bool>.Success(isTrusted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying device trust for user {UserId}", userId);
                return ServiceResult<bool>.Failure("Failed to verify device", "VERIFICATION_ERROR");
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
                
                var result = new TrustedDeviceVerificationResult
                {
                    IsValid = false,
                    IsTrusted = false,
                    TrustLevel = 0
                };

                if (device == null)
                {
                    result.ValidationMessage = "Device not found";
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(result);
                }

                // 지문 검증
                if (device.DeviceFingerprint != fingerprint)
                {
                    result.ValidationMessage = "Device fingerprint mismatch";
                    
                    // 보안 이벤트 로그
                    await LogSecurityEventAsync(
                        "FINGERPRINT_MISMATCH",
                        $"Fingerprint mismatch for device {deviceId}",
                        userId,
                        ipAddress,
                        SecurityEventSeverity.Warning);
                    
                    return ServiceResult<TrustedDeviceVerificationResult>.Success(result);
                }

                // 장치 상태 검증
                result.IsValid = device.IsValid;
                result.IsTrusted = device.IsActive && !device.IsExpired;
                result.LastUsedAt = device.LastUsedAt;
                result.Device = MapToDto(device);

                // 신뢰 레벨 추출
                if (!string.IsNullOrEmpty(device.Metadata))
                {
                    var metadata = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(device.Metadata);
                    if (metadata != null && metadata.TryGetValue("trustLevel", out var trustLevel))
                    {
                        result.TrustLevel = trustLevel.GetInt32();
                    }
                }

                // 검증 성공 시 사용 정보 업데이트
                if (result.IsTrusted)
                {
                    await _repository.UpdateLastUsedAsync(deviceId, userId, ipAddress, userAgent, location);
                    result.ValidationMessage = "Device verified successfully";
                }
                else
                {
                    result.ValidationMessage = device.IsExpired ? "Device expired" : "Device inactive";
                }

                return ServiceResult<TrustedDeviceVerificationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying and updating device for user {UserId}", userId);
                return ServiceResult<TrustedDeviceVerificationResult>.Failure(
                    "Failed to verify device",
                    "VERIFICATION_ERROR");
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
                
                if (device == null)
                {
                    return ServiceResult<TrustedDeviceDto>.NotFound("Device not found");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult<TrustedDeviceDto>.Unauthorized("Access denied");
                }

                return ServiceResult<TrustedDeviceDto>.Success(MapToDto(device));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device {Id} for user {UserId}", id, userId);
                return ServiceResult<TrustedDeviceDto>.Failure(
                    "Failed to retrieve device",
                    "RETRIEVAL_ERROR");
            }
        }

        #endregion

        #region 장치 상태 관리

        /// <summary>
        /// 장치 활성화/비활성화
        /// </summary>
        public async Task<ServiceResult> UpdateDeviceStatusAsync(
            Guid id, Guid userId, bool isActive, string? reason = null)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult.Failure("Unauthorized access", "UNAUTHORIZED");
                }

                var success = await _repository.UpdateActiveStatusAsync(id, isActive, reason);
                
                if (!success)
                {
                    return ServiceResult.Failure("Failed to update device status", "UPDATE_ERROR");
                }

                // 캐시 무효화
                InvalidateDeviceCache(userId, device.DeviceId);

                // 감사 로그
                await AuditActionAsync(
                    isActive ? "DEVICE_ACTIVATED" : "DEVICE_DEACTIVATED",
                    $"Device {device.DeviceName} status changed to {(isActive ? "active" : "inactive")}",
                    userId);

                return ServiceResult.Success($"Device {(isActive ? "activated" : "deactivated")} successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device status for {Id}", id);
                return ServiceResult.Failure("Failed to update device status", "UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 장치 신뢰 레벨 변경
        /// </summary>
        public async Task<ServiceResult> UpdateTrustLevelAsync(Guid id, Guid userId, int trustLevel)
        {
            try
            {
                // 신뢰 레벨 검증
                if (trustLevel < MIN_TRUST_LEVEL || trustLevel > MAX_TRUST_LEVEL)
                {
                    return ServiceResult.Failure(
                        $"Trust level must be between {MIN_TRUST_LEVEL} and {MAX_TRUST_LEVEL}",
                        "INVALID_TRUST_LEVEL");
                }

                var device = await _repository.GetByIdAsync(id);
                
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult.Failure("Unauthorized access", "UNAUTHORIZED");
                }

                var success = await _repository.UpdateTrustLevelAsync(id, trustLevel);
                
                if (!success)
                {
                    return ServiceResult.Failure("Failed to update trust level", "UPDATE_ERROR");
                }

                // 캐시 무효화
                InvalidateDeviceCache(userId, device.DeviceId);

                // 감사 로그
                await AuditActionAsync(
                    "TRUST_LEVEL_CHANGED",
                    $"Device {device.DeviceName} trust level changed to {trustLevel}",
                    userId);

                return ServiceResult.Success($"Trust level updated to {trustLevel}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating trust level for device {Id}", id);
                return ServiceResult.Failure("Failed to update trust level", "UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 장치 만료일 설정
        /// </summary>
        public async Task<ServiceResult> SetDeviceExpirationAsync(
            Guid id, Guid userId, DateTime? expiresAt)
        {
            try
            {
                var device = await _repository.GetByIdAsync(id);
                
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult.Failure("Unauthorized access", "UNAUTHORIZED");
                }

                // 과거 날짜 검증
                if (expiresAt.HasValue && expiresAt.Value <= DateTime.UtcNow)
                {
                    return ServiceResult.Failure("Expiration date must be in the future", "INVALID_DATE");
                }

                var success = await _repository.SetExpirationAsync(id, expiresAt);
                
                if (!success)
                {
                    return ServiceResult.Failure("Failed to set expiration", "UPDATE_ERROR");
                }

                // 캐시 무효화
                InvalidateDeviceCache(userId, device.DeviceId);

                // 감사 로그
                var expirationMsg = expiresAt.HasValue
                    ? $"expires at {expiresAt.Value:yyyy-MM-dd HH:mm}"
                    : "never expires";
                    
                await AuditActionAsync(
                    "EXPIRATION_SET",
                    $"Device {device.DeviceName} {expirationMsg}",
                    userId);

                return ServiceResult.Success($"Expiration date updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting expiration for device {Id}", id);
                return ServiceResult.Failure("Failed to set expiration", "UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 장치 이름 변경
        /// </summary>
        public async Task<ServiceResult> UpdateDeviceNameAsync(Guid id, Guid userId, string deviceName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(deviceName))
                {
                    return ServiceResult.Failure("Device name cannot be empty", "INVALID_NAME");
                }

                var device = await _repository.GetByIdAsync(id);
                
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }

                // 소유권 확인
                if (device.UserId != userId)
                {
                    return ServiceResult.Failure("Unauthorized access", "UNAUTHORIZED");
                }

                var oldName = device.DeviceName;
                device.DeviceName = deviceName;
                
                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();

                // 감사 로그
                await TrackChangeAsync(
                    "TrustedDevice",
                    id,
                    "NAME_CHANGED",
                    oldName,
                    deviceName,
                    userId,
                    "Device name updated");

                return ServiceResult.Success("Device name updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating device name for {Id}", id);
                return ServiceResult.Failure("Failed to update device name", "UPDATE_ERROR");
            }
        }

        #endregion

        #region 보안 및 관리자 기능

        /// <summary>
        /// 조직의 모든 신뢰할 수 있는 장치 조회 (관리자용)
        /// </summary>
        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetOrganizationDevicesAsync(
            Guid organizationId, bool includeInactive = false)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive);
                var deviceDtos = devices.Select(MapToDto).ToList();

                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(
                    deviceDtos,
                    $"Found {deviceDtos.Count} devices in organization");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization devices for {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure(
                    "Failed to retrieve organization devices",
                    "RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// 의심스러운 장치 활동 감지
        /// </summary>
        public async Task<ServiceResult<IEnumerable<SuspiciousDeviceReport>>> DetectSuspiciousDevicesAsync(
            Guid organizationId, int days = 30)
        {
            try
            {
                var fromDate = DateTime.UtcNow.AddDays(-days);
                var toDate = DateTime.UtcNow;
                
                var reports = new List<SuspiciousDeviceReport>();
                
                // 조직의 모든 사용자 장치 통계 조회
                var registrationStats = await _repository.GetDeviceRegistrationStatsAsync(
                    organizationId, fromDate, toDate);
                
                // 비정상적으로 많은 장치를 등록한 사용자 찾기
                foreach (var kvp in registrationStats.Where(x => x.Value > 5))
                {
                    var userDevices = await _repository.GetByUserIdAsync(kvp.Key, includeInactive: true);
                    
                    foreach (var device in userDevices)
                    {
                        var suspiciousActivities = new List<string>();
                        var riskScore = 0;
                        
                        // 다중 장치 등록
                        if (kvp.Value > 5)
                        {
                            suspiciousActivities.Add($"User registered {kvp.Value} devices in {days} days");
                            riskScore += 30;
                        }
                        
                        // 짧은 시간 내 등록
                        var recentDevices = userDevices
                            .Where(d => Math.Abs((d.CreatedAt - device.CreatedAt).TotalHours) < 1)
                            .Count();
                        
                        if (recentDevices > 2)
                        {
                            suspiciousActivities.Add($"{recentDevices} devices registered within 1 hour");
                            riskScore += 40;
                        }
                        
                        // 동일 IP에서 여러 사용자
                        if (!string.IsNullOrEmpty(device.IpAddress))
                        {
                            var sameIpDevices = await _repository.GetDevicesByIpAddressAsync(
                                device.IpAddress, organizationId, days);
                            
                            var uniqueUsers = sameIpDevices.Select(d => d.UserId).Distinct().Count();
                            if (uniqueUsers > 3)
                            {
                                suspiciousActivities.Add($"{uniqueUsers} users from same IP");
                                riskScore += 20;
                            }
                        }
                        
                        if (suspiciousActivities.Any())
                        {
                            reports.Add(new SuspiciousDeviceReport
                            {
                                Device = MapToDto(device),
                                SuspiciousActivities = suspiciousActivities,
                                RiskScore = Math.Min(riskScore, 100),
                                DetectedAt = DateTime.UtcNow,
                                RecommendedAction = riskScore > 60 
                                    ? "Review and consider deactivation"
                                    : "Monitor activity"
                            });
                        }
                    }
                }
                
                // 보안 이벤트 로그
                if (reports.Any())
                {
                    await LogSecurityEventAsync(
                        "SUSPICIOUS_DEVICES_DETECTED",
                        $"Found {reports.Count} suspicious devices in organization",
                        null,
                        null,
                        SecurityEventSeverity.Warning);
                }
                
                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Success(
                    reports.OrderByDescending(r => r.RiskScore));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting suspicious devices for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<IEnumerable<SuspiciousDeviceReport>>.Failure(
                    "Failed to detect suspicious devices",
                    "DETECTION_ERROR");
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
                await AuditActionAsync(
                    "EXPIRED_DEVICES_CLEANUP",
                    $"Cleaned up {count} expired devices in organization",
                    null);
                
                _logger.LogInformation(
                    "Cleaned up {Count} expired devices for organization {OrganizationId}",
                    count, organizationId);
                
                return ServiceResult<int>.Success(count,
                    $"Successfully cleaned up {count} expired devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up expired devices for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<int>.Failure("Failed to cleanup expired devices", "CLEANUP_ERROR");
            }
        }

        /// <summary>
        /// 오래된 비활성 장치 삭제
        /// </summary>
        public async Task<ServiceResult<int>> DeleteOldInactiveDevicesAsync(
            Guid organizationId, int olderThanDays = 90)
        {
            try
            {
                if (olderThanDays < 30)
                {
                    return ServiceResult<int>.Failure(
                        "Cannot delete devices newer than 30 days",
                        "INVALID_PARAMETER");
                }
                
                var count = await _repository.DeleteOldInactiveDevicesAsync(olderThanDays, organizationId);
                
                // 감사 로그
                await AuditActionAsync(
                    "OLD_DEVICES_DELETED",
                    $"Deleted {count} inactive devices older than {olderThanDays} days",
                    null);
                
                _logger.LogInformation(
                    "Deleted {Count} old inactive devices for organization {OrganizationId}",
                    count, organizationId);
                
                return ServiceResult<int>.Success(count,
                    $"Successfully deleted {count} old inactive devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Error deleting old inactive devices for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<int>.Failure("Failed to delete old devices", "DELETION_ERROR");
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
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: true);
                var deviceList = devices.ToList();
                
                var stats = new TrustedDeviceStats
                {
                    TotalDevices = deviceList.Count,
                    ActiveDevices = deviceList.Count(d => d.IsActive),
                    ExpiredDevices = deviceList.Count(d => d.IsExpired),
                    RecentlyUsedDevices = deviceList.Count(d => 
                        d.LastUsedAt.HasValue && 
                        d.LastUsedAt.Value > DateTime.UtcNow.AddDays(-7))
                };
                
                // 장치 유형별 분류
                stats.DeviceTypeBreakdown = deviceList
                    .GroupBy(d => d.DeviceType ?? "Unknown")
                    .ToDictionary(g => g.Key, g => g.Count());
                
                // 브라우저별 분류
                stats.BrowserBreakdown = deviceList
                    .Where(d => !string.IsNullOrEmpty(d.Browser))
                    .GroupBy(d => d.Browser!)
                    .ToDictionary(g => g.Key, g => g.Count());
                
                // 신뢰 레벨별 분류
                foreach (var device in deviceList)
                {
                    var trustLevel = GetTrustLevelFromMetadata(device.Metadata);
                    if (!stats.TrustLevelBreakdown.ContainsKey(trustLevel))
                    {
                        stats.TrustLevelBreakdown[trustLevel] = 0;
                    }
                    stats.TrustLevelBreakdown[trustLevel]++;
                }
                
                return ServiceResult<TrustedDeviceStats>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device stats for user {UserId}", userId);
                return ServiceResult<TrustedDeviceStats>.Failure(
                    "Failed to get device statistics",
                    "STATS_ERROR");
            }
        }

        /// <summary>
        /// 조직별 장치 통계
        /// </summary>
        public async Task<ServiceResult<OrganizationDeviceStats>> GetOrganizationDeviceStatsAsync(
            Guid organizationId)
        {
            try
            {
                var devices = await _repository.GetByOrganizationIdAsync(organizationId, includeInactive: true);
                var deviceList = devices.ToList();
                
                var userDeviceCounts = deviceList
                    .GroupBy(d => d.UserId)
                    .ToDictionary(g => g.Key, g => g.Count());
                
                var stats = new OrganizationDeviceStats
                {
                    TotalUsers = userDeviceCounts.Count,
                    TotalDevices = deviceList.Count,
                    ActiveDevices = deviceList.Count(d => d.IsActive),
                    AverageDevicesPerUser = userDeviceCounts.Any() 
                        ? userDeviceCounts.Values.Average() 
                        : 0,
                    UserDeviceCounts = userDeviceCounts
                };
                
                // 최근 30일간 등록 트렌드
                var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
                var registrationTrends = deviceList
                    .Where(d => d.CreatedAt >= thirtyDaysAgo)
                    .GroupBy(d => d.CreatedAt.Date)
                    .Select(g => new DeviceRegistrationTrend
                    {
                        Date = g.Key,
                        RegisteredCount = g.Count(),
                        DeactivatedCount = g.Count(d => !d.IsActive)
                    })
                    .OrderBy(t => t.Date)
                    .ToList();
                
                stats.RegistrationTrends = registrationTrends;
                
                return ServiceResult<OrganizationDeviceStats>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting organization device stats for {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationDeviceStats>.Failure(
                    "Failed to get organization statistics",
                    "STATS_ERROR");
            }
        }

        /// <summary>
        /// 장치 사용 패턴 분석
        /// </summary>
        public async Task<ServiceResult<DeviceUsagePattern>> AnalyzeUsagePatternAsync(
            Guid userId, int days = 30)
        {
            try
            {
                var fromDate = DateTime.UtcNow.AddDays(-days);
                var devices = await _repository.GetByUserIdAsync(userId, includeInactive: false);
                var deviceList = devices.ToList();
                
                var pattern = new DeviceUsagePattern();
                
                // 시간대별 사용 패턴 (실제 구현에서는 활동 로그 테이블 참조 필요)
                // 여기서는 LastUsedAt 기준으로 간단히 구현
                foreach (var device in deviceList.Where(d => d.LastUsedAt.HasValue))
                {
                    var hour = device.LastUsedAt!.Value.Hour.ToString("00");
                    if (!pattern.HourlyUsage.ContainsKey(hour))
                    {
                        pattern.HourlyUsage[hour] = 0;
                    }
                    pattern.HourlyUsage[hour]++;
                    
                    var dayOfWeek = device.LastUsedAt.Value.DayOfWeek.ToString();
                    if (!pattern.DailyUsage.ContainsKey(dayOfWeek))
                    {
                        pattern.DailyUsage[dayOfWeek] = 0;
                    }
                    pattern.DailyUsage[dayOfWeek]++;
                }
                
                // 자주 사용하는 위치
                pattern.FrequentLocations = deviceList
                    .Where(d => !string.IsNullOrEmpty(d.Location))
                    .GroupBy(d => d.Location!)
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .Select(g => g.Key)
                    .ToList();
                
                // 최근 IP 주소
                pattern.RecentIpAddresses = deviceList
                    .Where(d => !string.IsNullOrEmpty(d.IpAddress))
                    .OrderByDescending(d => d.LastUsedAt ?? d.CreatedAt)
                    .Select(d => d.IpAddress!)
                    .Distinct()
                    .Take(10)
                    .ToList();
                
                // 의심스러운 패턴 감지
                var suspiciousDevices = await _repository.GetSuspiciousDevicesAsync(
                    userId, fromDate, DateTime.UtcNow);
                
                if (suspiciousDevices.Any())
                {
                    pattern.HasSuspiciousPattern = true;
                    pattern.PatternAlerts.Add($"Found {suspiciousDevices.Count()} suspicious device activities");
                }
                
                // IP 변경이 잦은 경우
                if (pattern.RecentIpAddresses.Count > 5)
                {
                    pattern.HasSuspiciousPattern = true;
                    pattern.PatternAlerts.Add("Frequent IP address changes detected");
                }
                
                return ServiceResult<DeviceUsagePattern>.Success(pattern);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing usage pattern for user {UserId}", userId);
                return ServiceResult<DeviceUsagePattern>.Failure(
                    "Failed to analyze usage pattern",
                    "ANALYSIS_ERROR");
            }
        }

        #endregion

        #region 배치 작업 및 유틸리티

        /// <summary>
        /// 장치 정보 동기화
        /// </summary>
        public async Task<ServiceResult> SyncDeviceInfoAsync(
            Guid userId, string deviceId, DeviceInfoUpdate deviceInfo)
        {
            try
            {
                var device = await _repository.GetByDeviceIdAsync(deviceId, userId);
                
                if (device == null)
                {
                    return ServiceResult.Failure("Device not found", "DEVICE_NOT_FOUND");
                }
                
                // 정보 업데이트
                if (!string.IsNullOrEmpty(deviceInfo.Browser))
                    device.Browser = deviceInfo.Browser;
                
                if (!string.IsNullOrEmpty(deviceInfo.OperatingSystem))
                    device.OperatingSystem = deviceInfo.OperatingSystem;
                
                if (!string.IsNullOrEmpty(deviceInfo.UserAgent))
                    device.UserAgent = deviceInfo.UserAgent;
                
                if (!string.IsNullOrEmpty(deviceInfo.Location))
                    device.Location = deviceInfo.Location;
                
                // 메타데이터 병합
                if (deviceInfo.AdditionalMetadata != null && deviceInfo.AdditionalMetadata.Any())
                {
                    var metadata = string.IsNullOrEmpty(device.Metadata)
                        ? new Dictionary<string, object>()
                        : JsonSerializer.Deserialize<Dictionary<string, object>>(device.Metadata) ?? new();
                    
                    foreach (var kvp in deviceInfo.AdditionalMetadata)
                    {
                        metadata[kvp.Key] = kvp.Value;
                    }
                    
                    metadata["lastSyncedAt"] = DateTime.UtcNow;
                    device.Metadata = JsonSerializer.Serialize(metadata);
                }
                
                await _repository.UpdateAsync(device);
                await _unitOfWork.SaveChangesAsync();
                
                // 캐시 무효화
                InvalidateDeviceCache(userId, deviceId);
                
                _logger.LogInformation(
                    "Device info synced for user {UserId}, device {DeviceId}",
                    userId, deviceId);
                
                return ServiceResult.Success("Device information synchronized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing device info for {DeviceId}", deviceId);
                return ServiceResult.Failure("Failed to sync device information", "SYNC_ERROR");
            }
        }

        /// <summary>
        /// 대량 장치 상태 변경
        /// </summary>
        public async Task<ServiceResult<BulkUpdateResult>> BulkUpdateDeviceStatusAsync(
            IEnumerable<Guid> deviceIds, Guid organizationId, bool isActive, string? reason = null)
        {
            try
            {
                var result = new BulkUpdateResult
                {
                    TotalRequested = deviceIds.Count()
                };
                
                foreach (var deviceId in deviceIds)
                {
                    try
                    {
                        var device = await _repository.GetByIdAsync(deviceId);
                        
                        if (device == null)
                        {
                            result.FailedCount++;
                            result.Errors.Add($"Device {deviceId} not found");
                            continue;
                        }
                        
                        // 조직 확인 (실제 구현에서는 User 테이블과 조인 필요)
                        // 여기서는 간단히 처리
                        
                        var success = await _repository.UpdateActiveStatusAsync(deviceId, isActive, reason);
                        
                        if (success)
                        {
                            result.SuccessCount++;
                            result.ProcessedDeviceIds.Add(deviceId);
                        }
                        else
                        {
                            result.FailedCount++;
                            result.Errors.Add($"Failed to update device {deviceId}");
                        }
                    }
                    catch (Exception deviceEx)
                    {
                        result.FailedCount++;
                        result.Errors.Add($"Error processing device {deviceId}: {deviceEx.Message}");
                    }
                }
                
                // 감사 로그
                await AuditActionAsync(
                    "BULK_STATUS_UPDATE",
                    $"Bulk updated {result.SuccessCount}/{result.TotalRequested} devices to {(isActive ? "active" : "inactive")}",
                    null);
                
                _logger.LogInformation(
                    "Bulk status update completed: {Success}/{Total} devices updated",
                    result.SuccessCount, result.TotalRequested);
                
                return ServiceResult<BulkUpdateResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in bulk device status update");
                return ServiceResult<BulkUpdateResult>.Failure(
                    "Failed to perform bulk update",
                    "BULK_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 장치 검증 규칙 확인
        /// </summary>
        public async Task<ServiceResult<DeviceValidationRules>> GetValidationRulesAsync(Guid organizationId)
        {
            try
            {
                // 실제 구현에서는 조직별 설정을 데이터베이스에서 조회
                // 여기서는 기본값 반환
                var rules = new DeviceValidationRules
                {
                    MaxDevicesPerUser = DEFAULT_MAX_DEVICES_PER_USER,
                    DefaultExpirationDays = DEFAULT_EXPIRATION_DAYS,
                    RequireLocationValidation = false,
                    RequireIpValidation = true,
                    AllowedDeviceTypes = new List<string> { "Desktop", "Mobile", "Tablet" },
                    BlockedDeviceTypes = new List<string>(),
                    MinTrustLevel = MIN_TRUST_LEVEL,
                    MaxTrustLevel = MAX_TRUST_LEVEL
                };
                
                return await Task.FromResult(ServiceResult<DeviceValidationRules>.Success(rules));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting validation rules for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<DeviceValidationRules>.Failure(
                    "Failed to get validation rules",
                    "RULES_ERROR");
            }
        }

        #endregion

        #region IAuditableService Implementation

        public async Task TrackChangeAsync(
            string entityName,
            Guid entityId,
            string action,
            object? oldValue,
            object? newValue,
            Guid? connectedId = null,
            string? additionalInfo = null)
        {
            // 실제 구현에서는 감사 로그 테이블에 저장
            _logger.LogInformation(
                "Audit: {EntityName}:{EntityId} - {Action} by {ConnectedId}",
                entityName, entityId, action, connectedId);
            
            await Task.CompletedTask;
        }

        public async Task LogActivityAsync(
            Guid connectedId,
            string activity,
            string details,
            string? ipAddress = null,
            string? userAgent = null)
        {
            // 실제 구현에서는 활동 로그 테이블에 저장
            _logger.LogInformation(
                "Activity: {ConnectedId} - {Activity}: {Details}",
                connectedId, activity, details);
            
            await Task.CompletedTask;
        }

        public async Task LogSecurityEventAsync(
            string eventType,
            string description,
            Guid? connectedId = null,
            string? ipAddress = null,
            SecurityEventSeverity severity = SecurityEventSeverity.Info)
        {
            // 실제 구현에서는 보안 이벤트 테이블에 저장
            _logger.LogWarning(
                "Security Event [{Severity}]: {EventType} - {Description} for {ConnectedId}",
                severity, eventType, description, connectedId);
            
            await Task.CompletedTask;
        }

        public async Task AuditActionAsync(
            string action,
            string description,
            Guid? connectedId = null)
        {
            // 실제 구현에서는 감사 로그 테이블에 저장
            _logger.LogInformation(
                "Audit Action: {Action} - {Description} by {ConnectedId}",
                action, description, connectedId);
            
            await Task.CompletedTask;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 엔티티를 DTO로 매핑
        /// </summary>
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
                DeviceType = device.DeviceType ?? "Unknown",
                Browser = device.Browser,
                OperatingSystem = device.OperatingSystem,
                IpAddress = device.IpAddress
            };
        }

        /// <summary>
        /// 메타데이터에서 신뢰 레벨 추출
        /// </summary>
        private int GetTrustLevelFromMetadata(string? metadata)
        {
            if (string.IsNullOrEmpty(metadata))
                return DEFAULT_TRUST_LEVEL;
            
            try
            {
                var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(metadata);
                if (dict != null && dict.TryGetValue("trustLevel", out var trustLevel))
                {
                    return trustLevel.GetInt32();
                }
            }
            catch
            {
                // 파싱 실패 시 기본값 반환
            }
            
            return DEFAULT_TRUST_LEVEL;
        }

        /// <summary>
        /// UserAgent 파싱
        /// </summary>
        private void ParseUserAgent(string userAgent, out string? browser, out string? os)
        {
            browser = null;
            os = null;
            
            // 간단한 UserAgent 파싱 (실제 구현에서는 전문 라이브러리 사용)
            if (userAgent.Contains("Chrome"))
                browser = "Chrome";
            else if (userAgent.Contains("Firefox"))
                browser = "Firefox";
            else if (userAgent.Contains("Safari"))
                browser = "Safari";
            else if (userAgent.Contains("Edge"))
                browser = "Edge";
            
            if (userAgent.Contains("Windows"))
                os = "Windows";
            else if (userAgent.Contains("Mac"))
                os = "macOS";
            else if (userAgent.Contains("Linux"))
                os = "Linux";
            else if (userAgent.Contains("Android"))
                os = "Android";
            else if (userAgent.Contains("iOS") || userAgent.Contains("iPhone"))
                os = "iOS";
        }

        /// <summary>
        /// 장치 캐시 무효화
        /// </summary>
        private void InvalidateDeviceCache(Guid userId, string deviceId)
        {
            var cacheKeys = new[]
            {
                GetDeviceTrustCacheKey(userId, deviceId, "*"),
                $"device_list_{userId}",
                $"device_stats_{userId}"
            };
            
            foreach (var key in cacheKeys)
            {
                _cache.Remove(key);
            }
        }

        /// <summary>
        /// 장치 신뢰 캐시 키 생성
        /// </summary>
        private string GetDeviceTrustCacheKey(Guid userId, string deviceId, string fingerprint)
        {
            return $"device_trust_{userId}_{deviceId}_{fingerprint}";
        }

        #endregion
    }
}