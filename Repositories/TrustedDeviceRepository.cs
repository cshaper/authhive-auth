using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 신뢰할 수 있는 장치 Repository 구현체 - v17 (ICacheService 및 CancellationToken 적용)
    /// </summary>
    public class TrustedDeviceRepository : BaseRepository<TrustedDevice>, ITrustedDeviceRepository
    {
        private const string CACHE_KEY_PREFIX = "trusted_device_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);
        private readonly IDateTimeProvider _dateTimeProvider;

        public TrustedDeviceRepository(
            AuthDbContext context,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider)
            : base(context, cacheService)
        {
            _dateTimeProvider = dateTimeProvider;
        }

        protected override bool IsOrganizationBaseEntity() => true;

        #region 기본 조회 메서드

        public async Task<IEnumerable<TrustedDevice>> GetByUserIdAsync(Guid userId, bool includeInactive = false, CancellationToken cancellationToken = default)
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
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<TrustedDevice>> GetByOrganizationIdAsync(Guid organizationId, bool includeInactive = false, CancellationToken cancellationToken = default)
        {
            IQueryable<TrustedDevice> query = QueryForOrganization(organizationId)
                .Include(td => td.User);

            if (!includeInactive)
            {
                query = query.Where(td => td.IsActive);
            }

            return await query
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<TrustedDevice?> GetByDeviceIdAsync(string deviceId, Guid userId, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}device_{deviceId}_{userId}";

            // [수정] 캐시 서비스가 주입되었는지 확인 후 사용 (CS8602 경고 해결)
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<TrustedDevice>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    // 캐시에 데이터가 있으면 DB 조회 없이 바로 반환합니다.
                    return cached;
                }
            }
            
            var device = await Query()
                .Include(td => td.User)
                .FirstOrDefaultAsync(td => td.DeviceId == deviceId && td.UserId == userId, cancellationToken);

            // [수정] DB 조회 후 캐시 서비스가 유효할 때만 캐시에 저장합니다.
            if (device != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, device, _cacheExpiration, cancellationToken);
            }

            return device;
        }

        public async Task<TrustedDevice?> GetByFingerprintAsync(string fingerprint, Guid userId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(td => td.User)
                .FirstOrDefaultAsync(td => td.DeviceFingerprint == fingerprint && td.UserId == userId, cancellationToken);
        }

        #endregion

        #region 검증 메서드

        public async Task<bool> IsDeviceTrustedAsync(string deviceId, string fingerprint, Guid userId, CancellationToken cancellationToken = default)
        {
            var device = await GetByDeviceIdAsync(deviceId, userId, cancellationToken);
            if (device == null) return false;
            return device.IsValid && device.DeviceFingerprint == fingerprint;
        }

        public async Task<bool> IsDeviceValidAsync(string deviceId, Guid userId, CancellationToken cancellationToken = default)
        {
            var device = await GetByDeviceIdAsync(deviceId, userId, cancellationToken);
            return device?.IsValid ?? false;
        }

        public async Task<int> GetTrustedDeviceCountAsync(Guid userId, bool onlyActive = true, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(td => td.UserId == userId);

            if (onlyActive)
            {
                query = query.Where(td => td.IsActive && !td.IsDeleted);
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(td => td.ExpiresAt == null || td.ExpiresAt > now);
            }

            return await query.CountAsync(cancellationToken);
        }

        public async Task<bool> IsDeviceIdDuplicateAsync(string deviceId, Guid userId, Guid? excludeId = null, CancellationToken cancellationToken = default)
        {
            var query = Query()
                .Where(td => td.DeviceId == deviceId && td.UserId == userId);

            if (excludeId.HasValue)
            {
                query = query.Where(td => td.Id != excludeId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region 상태 관리 메서드

        public async Task<bool> UpdateLastUsedAsync(
            string deviceId, Guid userId, string? ipAddress = null,
            string? userAgent = null, string? location = null, CancellationToken cancellationToken = default)
        {
            var deviceToUpdate = await Query().FirstOrDefaultAsync(d => d.DeviceId == deviceId && d.UserId == userId, cancellationToken);
            if (deviceToUpdate == null) return false;

            // [수정] 엔티티의 UpdateLastUsed 호출과 별도로 UserAgent도 업데이트합니다.
            deviceToUpdate.UpdateLastUsed(ipAddress, location);
            if (!string.IsNullOrEmpty(userAgent))
            {
                deviceToUpdate.UserAgent = userAgent;
            }
            
            await UpdateAsync(deviceToUpdate, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            return true;
        }

        public async Task<bool> UpdateActiveStatusAsync(Guid id, bool isActive, string? reason = null, CancellationToken cancellationToken = default)
        {
            var device = await GetByIdAsync(id, cancellationToken);
            if (device == null) return false;

            if (isActive)
                device.Activate();
            else
                device.Deactivate();

            // Metadata update logic can be added here if needed

            await UpdateAsync(device, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            
            await InvalidateDeviceCacheAsync(device.DeviceId, device.UserId, cancellationToken);

            return true;
        }
        
        public async Task<bool> UpdateTrustLevelAsync(Guid id, int trustLevel, CancellationToken cancellationToken = default)
        {
            var device = await GetByIdAsync(id, cancellationToken);
            if (device == null) return false;

            var metadata = string.IsNullOrEmpty(device.Metadata)
                ? new Dictionary<string, object>()
                : JsonSerializer.Deserialize<Dictionary<string, object>>(device.Metadata) ?? new();

            metadata["trustLevel"] = trustLevel;
            metadata["trustLevelUpdatedAt"] = _dateTimeProvider.UtcNow;
            device.Metadata = JsonSerializer.Serialize(metadata);

            await UpdateAsync(device, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            await InvalidateDeviceCacheAsync(device.DeviceId, device.UserId, cancellationToken);

            return true;
        }

        public async Task<bool> SetExpirationAsync(Guid id, DateTime? expiresAt, CancellationToken cancellationToken = default)
        {
            var device = await GetByIdAsync(id, cancellationToken);
            if (device == null) return false;

            if (expiresAt.HasValue)
                device.SetExpiration(expiresAt.Value);
            else
                device.RemoveExpiration();

            await UpdateAsync(device, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            await InvalidateDeviceCacheAsync(device.DeviceId, device.UserId, cancellationToken);

            return true;
        }
        
        #endregion
        
        #region 일괄 처리 메서드
        
        public async Task<int> DeactivateAllUserDevicesAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default)
        {
            var devices = await GetByUserIdAsync(userId, true, cancellationToken);
            var activeDevices = devices.Where(d => d.IsActive).ToList();
            if (!activeDevices.Any()) return 0;
            
            foreach (var device in activeDevices)
            {
                device.Deactivate();
                // Metadata update logic can be added here
            }

            await UpdateRangeAsync(activeDevices, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            var cacheKeys = activeDevices.Select(d => $"{CACHE_KEY_PREFIX}device_{d.DeviceId}_{d.UserId}").ToList();
            if (_cacheService != null)
            {
                await _cacheService.RemoveMultipleAsync(cacheKeys, cancellationToken);
            }
            
            return activeDevices.Count;
        }

        public async Task<int> CleanupExpiredDevicesAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            IQueryable<TrustedDevice> query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            
            var expiredDevices = await query
                .Where(td => td.IsActive && td.ExpiresAt != null && td.ExpiresAt < now)
                .ToListAsync(cancellationToken);

            if (!expiredDevices.Any()) return 0;

            foreach (var device in expiredDevices)
            {
                device.Deactivate();
            }
            
            await UpdateRangeAsync(expiredDevices, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            
            if (_cacheService != null)
            {
                 var cacheKeys = expiredDevices.Select(d => $"{CACHE_KEY_PREFIX}device_{d.DeviceId}_{d.UserId}").ToList();
                 await _cacheService.RemoveMultipleAsync(cacheKeys, cancellationToken);
            }

            return expiredDevices.Count;
        }

        public async Task<int> DeleteOldInactiveDevicesAsync(int olderThanDays = 90, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var cutoffDate = _dateTimeProvider.UtcNow.AddDays(-olderThanDays);
            IQueryable<TrustedDevice> query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();

            var oldDevices = await query
                 .Where(td => !td.IsActive && (td.LastUsedAt == null || td.LastUsedAt < cutoffDate) && td.CreatedAt < cutoffDate)
                 .ToListAsync(cancellationToken);
            
            if (oldDevices.Any())
            {
                await DeleteRangeAsync(oldDevices, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }

            return oldDevices.Count;
        }
        
        #endregion
        
        #region 보안/감사/고급 검색

        public async Task<IEnumerable<TrustedDevice>> GetSuspiciousDevicesAsync(Guid userId, DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default)
        {
            var devices = await Query()
                .Where(td => td.UserId == userId && td.CreatedAt >= fromDate && td.CreatedAt <= toDate)
                .ToListAsync(cancellationToken);

            // Example of a simple suspicion rule: more than 2 devices registered within the same hour
            var suspiciousDevices = devices
                .GroupBy(d => new { Date = d.CreatedAt.Date, Hour = d.CreatedAt.Hour })
                .Where(g => g.Count() > 2)
                .SelectMany(g => g)
                .ToList();

            return suspiciousDevices;
        }

        public async Task<IEnumerable<TrustedDevice>> GetDevicesByIpAddressAsync(string ipAddress, Guid organizationId, int dayRange = 30, CancellationToken cancellationToken = default)
        {
            var fromDate = _dateTimeProvider.UtcNow.AddDays(-dayRange);

            return await QueryForOrganization(organizationId)
                .Where(td => td.IpAddress == ipAddress && td.CreatedAt >= fromDate)
                .Include(td => td.User)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync(cancellationToken);
        }
        
        public async Task<IEnumerable<TrustedDevice>> GetRecentlyRegisteredDevicesAsync(Guid organizationId, int hours = 24, CancellationToken cancellationToken = default)
        {
            var fromDate = _dateTimeProvider.UtcNow.AddHours(-hours);

            return await QueryForOrganization(organizationId)
                .Where(td => td.CreatedAt >= fromDate)
                .Include(td => td.User)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<Dictionary<Guid, int>> GetDeviceRegistrationStatsAsync(Guid organizationId, DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(td => td.CreatedAt >= fromDate && td.CreatedAt <= toDate)
                .GroupBy(td => td.UserId)
                .Select(g => new { UserId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.UserId, x => x.Count, cancellationToken);
        }

        public async Task<IEnumerable<TrustedDevice>> GetByDeviceTypeAsync(string deviceType, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .Where(td => td.DeviceType == deviceType)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<TrustedDevice>> GetByBrowserAsync(string browser, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .Where(td => td.Browser == browser)
                .OrderByDescending(td => td.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<TrustedDevice>> GetByTrustLevelAsync(int trustLevel, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var allDevices = await QueryForOrganization(organizationId)
                .Include(td => td.User)
                .ToListAsync(cancellationToken);

            return allDevices.Where(td =>
            {
                if (string.IsNullOrEmpty(td.Metadata)) return false;
                try
                {
                    var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(td.Metadata);
                    if (metadata != null && metadata.TryGetValue("trustLevel", out var levelObj) && levelObj is JsonElement levelElement)
                    {
                        if (levelElement.TryGetInt32(out int currentTrustLevel))
                        {
                            return currentTrustLevel == trustLevel;
                        }
                    }
                }
                catch (JsonException) { /* Malformed JSON, ignore */ }
                return false;
            }).ToList();
        }

        // [수정] 인터페이스와 시그니처를 일치시키기 위해 organizationId 매개변수 제거
        public async Task<IEnumerable<TrustedDevice>> SearchDevicesAsync(
            Guid? userId = null, string? deviceType = null, 
            string? browser = null, bool? isActive = null, int? trustLevel = null, 
            DateTime? fromDate = null, DateTime? toDate = null, CancellationToken cancellationToken = default)
        {
            // [수정] 조직 ID가 없으므로 기본 Query()에서 시작
            IQueryable<TrustedDevice> query = Query().Include(td => td.User);

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

            var devices = await query.ToListAsync(cancellationToken);

            if (trustLevel.HasValue)
            {
                devices = devices.Where(td =>
                {
                    if (string.IsNullOrEmpty(td.Metadata)) return false;
                    try
                    {
                        var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(td.Metadata);
                        if (metadata != null && metadata.TryGetValue("trustLevel", out var levelObj) && levelObj is JsonElement levelElement)
                        {
                            if (levelElement.TryGetInt32(out int currentTrustLevel))
                            {
                                return currentTrustLevel == trustLevel.Value;
                            }
                        }
                    }
                    catch (JsonException) { /* Malformed JSON, ignore */ }
                    return false;
                }).ToList();
            }

            return devices;
        }

        #endregion

        #region Helper Methods

        private async Task InvalidateDeviceCacheAsync(string deviceId, Guid userId, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return;
            var cacheKey = $"{CACHE_KEY_PREFIX}device_{deviceId}_{userId}";
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
        }

        #endregion
    }
}

