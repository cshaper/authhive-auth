using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 신뢰할 수 있는 장치 Repository 구현체 - AuthHive v15
    /// MFA에서 사용되는 신뢰할 수 있는 장치 관리를 담당합니다.
    /// </summary>
    public class TrustedDeviceRepository : BaseRepository<TrustedDevice>, ITrustedDeviceRepository
    {
        private const string CACHE_KEY_PREFIX = "trusted_device_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public TrustedDeviceRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회 메서드

        /// <summary>
        /// 특정 사용자의 모든 신뢰할 수 있는 장치 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetByUserIdAsync(Guid userId, bool includeInactive = false)
        {
            var query = Query()
                .Include(td => td.User)
                .Where(td => td.UserId == userId);

            if (!includeInactive)
            {
                query = query.Where(td => td.IsActive);
            }

            return await query
                .OrderByDescending(td => td.LastUsedAt ?? td.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 특정 조직의 모든 신뢰할 수 있는 장치 조회 (관리자용)
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetByOrganizationIdAsync(Guid organizationId, bool includeInactive = false)
        {
            IQueryable<TrustedDevice> query = QueryForOrganization(organizationId)
                .Include(td => td.User);

            if (!includeInactive)
            {
                query = query.Where(td => td.IsActive);
            }

            return await query
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync();
        }
        /// <summary>
        /// 장치 ID로 신뢰할 수 있는 장치 조회
        /// </summary>
        public async Task<TrustedDevice?> GetByDeviceIdAsync(string deviceId, Guid userId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}device_{deviceId}_{userId}";

            if (_cache != null && _cache.TryGetValue<TrustedDevice>(cacheKey, out var cached))
            {
                return cached;
            }

            var device = await Query()
                .Include(td => td.User)
                .FirstOrDefaultAsync(td => td.DeviceId == deviceId && td.UserId == userId);

            if (device != null && _cache != null)
            {
                _cache.Set(cacheKey, device, _cacheExpiration);
            }

            return device;
        }

        /// <summary>
        /// 장치 지문으로 신뢰할 수 있는 장치 조회
        /// </summary>
        public async Task<TrustedDevice?> GetByFingerprintAsync(string fingerprint, Guid userId)
        {
            return await Query()
                .Include(td => td.User)
                .FirstOrDefaultAsync(td => td.DeviceFingerprint == fingerprint && td.UserId == userId);
        }

        #endregion

        #region 검증 메서드

        /// <summary>
        /// 장치가 신뢰할 수 있는지 검증
        /// </summary>
        public async Task<bool> IsDeviceTrustedAsync(string deviceId, string fingerprint, Guid userId)
        {
            var device = await GetByDeviceIdAsync(deviceId, userId);

            if (device == null)
                return false;

            return device.IsValid &&
                   device.DeviceFingerprint == fingerprint &&
                   device.IsActive &&
                   !device.IsExpired;
        }

        /// <summary>
        /// 장치가 유효한지 확인 (활성화 + 만료되지 않음)
        /// </summary>
        public async Task<bool> IsDeviceValidAsync(string deviceId, Guid userId)
        {
            var device = await GetByDeviceIdAsync(deviceId, userId);
            return device?.IsValid ?? false;
        }

        /// <summary>
        /// 사용자의 신뢰할 수 있는 장치 개수 조회
        /// </summary>
        public async Task<int> GetTrustedDeviceCountAsync(Guid userId, bool onlyActive = true)
        {
            var query = Query().Where(td => td.UserId == userId);

            if (onlyActive)
            {
                query = query.Where(td => td.IsActive && !td.IsDeleted);

                // 만료된 장치 제외
                var now = DateTime.UtcNow;
                query = query.Where(td => td.ExpiresAt == null || td.ExpiresAt > now);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 장치 ID 중복 확인
        /// </summary>
        public async Task<bool> IsDeviceIdDuplicateAsync(string deviceId, Guid userId, Guid? excludeId = null)
        {
            var query = Query()
                .Where(td => td.DeviceId == deviceId && td.UserId == userId);

            if (excludeId.HasValue)
            {
                query = query.Where(td => td.Id != excludeId.Value);
            }

            return await query.AnyAsync();
        }

        #endregion

        #region 상태 관리 메서드

        /// <summary>
        /// 장치 마지막 사용 정보 업데이트
        /// </summary>
        public async Task<bool> UpdateLastUsedAsync(
            string deviceId,
            Guid userId,
            string? ipAddress = null,
            string? userAgent = null,
            string? location = null)
        {
            var device = await GetByDeviceIdAsync(deviceId, userId);

            if (device == null)
                return false;

            device.UpdateLastUsed(ipAddress, location);

            // 캐시 무효화
            InvalidateDeviceCache(deviceId, userId);

            await UpdateAsync(device);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// 장치 활성화 상태 변경
        /// </summary>
        public async Task<bool> UpdateActiveStatusAsync(Guid id, bool isActive, string? reason = null)
        {
            var device = await GetByIdAsync(id);

            if (device == null)
                return false;

            if (isActive)
                device.Activate();
            else
                device.Deactivate();

            // 메타데이터에 사유 기록
            if (!string.IsNullOrEmpty(reason))
            {
                var metadata = string.IsNullOrEmpty(device.Metadata)
                    ? new Dictionary<string, object>()
                    : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(device.Metadata) ?? new();

                metadata["statusChangeReason"] = reason;
                metadata["statusChangedAt"] = DateTime.UtcNow;

                device.Metadata = System.Text.Json.JsonSerializer.Serialize(metadata);
            }

            await UpdateAsync(device);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// 장치 신뢰 레벨 변경
        /// </summary>
        public async Task<bool> UpdateTrustLevelAsync(Guid id, int trustLevel)
        {
            var device = await GetByIdAsync(id);

            if (device == null)
                return false;

            // 메타데이터에 신뢰 레벨 저장
            var metadata = string.IsNullOrEmpty(device.Metadata)
                ? new Dictionary<string, object>()
                : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(device.Metadata) ?? new();

            metadata["trustLevel"] = trustLevel;
            metadata["trustLevelUpdatedAt"] = DateTime.UtcNow;

            device.Metadata = System.Text.Json.JsonSerializer.Serialize(metadata);

            await UpdateAsync(device);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// 장치 만료일 설정
        /// </summary>
        public async Task<bool> SetExpirationAsync(Guid id, DateTime? expiresAt)
        {
            var device = await GetByIdAsync(id);

            if (device == null)
                return false;

            if (expiresAt.HasValue)
                device.SetExpiration(expiresAt.Value);
            else
                device.RemoveExpiration();

            await UpdateAsync(device);
            await _context.SaveChangesAsync();

            return true;
        }

        #endregion

        #region 일괄 처리 메서드

        /// <summary>
        /// 사용자의 모든 신뢰할 수 있는 장치 비활성화
        /// </summary>
        public async Task<int> DeactivateAllUserDevicesAsync(Guid userId, string? reason = null)
        {
            var devices = await GetByUserIdAsync(userId, true);
            var count = 0;

            foreach (var device in devices.Where(d => d.IsActive))
            {
                device.Deactivate();

                // 메타데이터에 사유 기록
                if (!string.IsNullOrEmpty(reason))
                {
                    var metadata = string.IsNullOrEmpty(device.Metadata)
                        ? new Dictionary<string, object>()
                        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(device.Metadata) ?? new();

                    metadata["deactivationReason"] = reason;
                    metadata["deactivatedAt"] = DateTime.UtcNow;

                    device.Metadata = System.Text.Json.JsonSerializer.Serialize(metadata);
                }

                count++;
            }

            if (count > 0)
            {
                await UpdateRangeAsync(devices);
                await _context.SaveChangesAsync();
            }

            return count;
        }

        /// <summary>
        /// 만료된 장치들 정리
        /// </summary>
        public async Task<int> CleanupExpiredDevicesAsync(Guid? organizationId = null)
        {
            var now = DateTime.UtcNow;
            IQueryable<TrustedDevice> query;

            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value);
            }
            else
            {
                query = _dbSet.Where(td => !td.IsDeleted);
            }

            var expiredDevices = await query
                .Where(td => td.ExpiresAt != null && td.ExpiresAt < now)
                .ToListAsync();

            foreach (var device in expiredDevices)
            {
                device.Deactivate();
            }

            if (expiredDevices.Any())
            {
                await UpdateRangeAsync(expiredDevices);
                await _context.SaveChangesAsync();
            }

            return expiredDevices.Count;
        }

        /// <summary>
        /// 오래된 비활성 장치들 삭제
        /// </summary>
        public async Task<int> DeleteOldInactiveDevicesAsync(int olderThanDays = 90, Guid? organizationId = null)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
            IQueryable<TrustedDevice> query;

            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value);
            }
            else
            {
                query = _dbSet.Where(td => !td.IsDeleted);
            }

            var oldDevices = await query
                .Where(td => !td.IsActive &&
                            (td.LastUsedAt == null || td.LastUsedAt < cutoffDate) &&
                            td.CreatedAt < cutoffDate)
                .ToListAsync();

            if (oldDevices.Any())
            {
                await DeleteRangeAsync(oldDevices);
                await _context.SaveChangesAsync();
            }

            return oldDevices.Count;
        }

        #endregion

        #region 보안 및 감사 메서드

        /// <summary>
        /// 의심스러운 장치 활동 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetSuspiciousDevicesAsync(
            Guid userId,
            DateTime fromDate,
            DateTime toDate)
        {
            // 짧은 시간 내 여러 장치 등록, IP 변경이 잦은 장치 등
            var devices = await Query()
                .Where(td => td.UserId == userId &&
                            td.CreatedAt >= fromDate &&
                            td.CreatedAt <= toDate)
                .ToListAsync();

            // 동일 시간대(1시간)에 여러 장치가 등록된 경우
            var suspiciousDevices = devices
                .GroupBy(d => new { Date = d.CreatedAt.Date, Hour = d.CreatedAt.Hour })
                .Where(g => g.Count() > 2)
                .SelectMany(g => g)
                .ToList();

            return suspiciousDevices;
        }

        /// <summary>
        /// 동일한 IP에서 등록된 장치들 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetDevicesByIpAddressAsync(
            string ipAddress,
            Guid organizationId,
            int dayRange = 30)
        {
            var fromDate = DateTime.UtcNow.AddDays(-dayRange);

            return await QueryForOrganization(organizationId)
                .Where(td => td.IpAddress == ipAddress &&
                            td.CreatedAt >= fromDate)
                .Include(td => td.User)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 최근 등록된 장치들 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetRecentlyRegisteredDevicesAsync(
            Guid organizationId,
            int hours = 24)
        {
            var fromDate = DateTime.UtcNow.AddHours(-hours);

            return await QueryForOrganization(organizationId)
                .Where(td => td.CreatedAt >= fromDate)
                .Include(td => td.User)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 사용자별 장치 등록 통계
        /// </summary>
        public async Task<Dictionary<Guid, int>> GetDeviceRegistrationStatsAsync(
            Guid organizationId,
            DateTime fromDate,
            DateTime toDate)
        {
            return await QueryForOrganization(organizationId)
                .Where(td => td.CreatedAt >= fromDate && td.CreatedAt <= toDate)
                .GroupBy(td => td.UserId)
                .Select(g => new { UserId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.UserId, x => x.Count);
        }

        #endregion

        #region 고급 검색 메서드

        /// <summary>
        /// 장치 유형별 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetByDeviceTypeAsync(string deviceType, Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .Where(td => td.DeviceType == deviceType)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 브라우저별 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetByBrowserAsync(string browser, Guid organizationId)
        {
            return await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .Where(td => td.Browser == browser)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 신뢰 레벨별 조회
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> GetByTrustLevelAsync(int trustLevel, Guid organizationId)
        {
            // 메타데이터에서 trustLevel 필터링
            var allDevices = await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .ToListAsync();

            return allDevices.Where(td =>
            {
                if (string.IsNullOrEmpty(td.Metadata))
                    return false;

                var metadata = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(td.Metadata);
                if (metadata != null && metadata.TryGetValue("trustLevel", out var level))
                {
                    if (level is System.Text.Json.JsonElement jsonElement)
                    {
                        return jsonElement.GetInt32() == trustLevel;
                    }
                }
                return false;
            }).ToList();
        }

        /// <summary>
        /// 복합 조건으로 장치 검색
        /// </summary>
        public async Task<IEnumerable<TrustedDevice>> SearchDevicesAsync(
            Guid? userId = null,
            string? deviceType = null,
            string? browser = null,
            bool? isActive = null,
            int? trustLevel = null,
            DateTime? fromDate = null,
            DateTime? toDate = null)
        {
            IQueryable<TrustedDevice> query = Query()
                .Include(td => td.User);

            if (userId.HasValue)
                query = query.Where(td => td.UserId == userId.Value);

            if (!string.IsNullOrEmpty(deviceType))
                query = query.Where(td => td.DeviceType == deviceType);

            if (!string.IsNullOrEmpty(browser))
                query = query.Where(td => td.Browser == browser);

            if (isActive.HasValue)
                query = query.Where(td => td.IsActive == isActive.Value);

            if (fromDate.HasValue)
                query = query.Where(td => td.CreatedAt >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(td => td.CreatedAt <= toDate.Value);

            var devices = await query.ToListAsync();

            // 신뢰 레벨 필터링 (메타데이터 기반)
            if (trustLevel.HasValue)
            {
                devices = devices.Where(td =>
                {
                    if (string.IsNullOrEmpty(td.Metadata))
                        return false;

                    var metadata = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(td.Metadata);
                    if (metadata != null && metadata.TryGetValue("trustLevel", out var level))
                    {
                        if (level is System.Text.Json.JsonElement jsonElement)
                        {
                            return jsonElement.GetInt32() == trustLevel.Value;
                        }
                    }
                    return false;
                }).ToList();
            }

            return devices;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 장치 캐시 무효화
        /// </summary>
        private void InvalidateDeviceCache(string deviceId, Guid userId)
        {
            if (_cache == null) return;

            var cacheKey = $"{CACHE_KEY_PREFIX}device_{deviceId}_{userId}";
            _cache.Remove(cacheKey);
        }

        #endregion
    }
}