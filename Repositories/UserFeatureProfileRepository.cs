using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 기능 프로필 저장소 구현 - AuthHive v15
    /// BaseRepository를 활용하여 최적화된 구조
    /// </summary>
    public class UserFeatureProfileRepository : BaseRepository<UserFeatureProfile>, IUserFeatureProfileRepository
    {
        private readonly ILogger<UserFeatureProfileRepository> _logger;

        public UserFeatureProfileRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserFeatureProfileRepository> logger,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>ConnectedId로 기능 프로필 조회 (캐시 활용)</summary>
        public async Task<UserFeatureProfile?> GetByConnectedIdAsync(
            Guid connectedId, 
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인
            if (_cache != null)
            {
                string cacheKey = GetConnectedIdCacheKey(connectedId);
                if (_cache.TryGetValue(cacheKey, out UserFeatureProfile? cachedProfile))
                {
                    return cachedProfile;
                }
            }

            // ConnectedId → User → UserFeatureProfile 경로로 조회
            var connectedIdEntity = await _context.ConnectedIds
                .Include(c => c.User)
                .ThenInclude(u => u.UserFeatureProfile)
                .FirstOrDefaultAsync(c => c.Id == connectedId && !c.IsDeleted, cancellationToken);

            var profile = connectedIdEntity?.User?.UserFeatureProfile;
            
            // 캐시 저장
            if (profile != null && _cache != null)
            {
                string cacheKey = GetConnectedIdCacheKey(connectedId);
                _cache.Set(cacheKey, profile, GetCacheOptions());
            }

            return profile;
        }

        /// <summary>여러 ConnectedId의 기능 프로필 일괄 조회</summary>
        public async Task<IEnumerable<UserFeatureProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds, 
            CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any()) return new List<UserFeatureProfile>();

            var profiles = await _context.ConnectedIds
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                .Include(c => c.User)
                .ThenInclude(u => u.UserFeatureProfile)
                .Select(c => c.User.UserFeatureProfile)
                .Where(p => p != null)
                .ToListAsync(cancellationToken);

            return profiles!;
        }

        /// <summary>조직별 기능 프로필 조회</summary>
        public async Task<PagedResult<UserFeatureProfile>> GetByOrganizationAsync(
            Guid organizationId, 
            int pageNumber = 1, 
            int pageSize = 50, 
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetPagedByOrganizationAsync 활용
            var (items, totalCount) = await GetPagedByOrganizationAsync(
                organizationId,
                pageNumber,
                pageSize,
                null, // additionalPredicate
                p => p.LastActivityAt ?? p.CreatedAt, // orderBy
                true // isDescending
            );

            return PagedResult<UserFeatureProfile>.Create(items, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 프로필 관리

        /// <summary>사용자 기능 프로필 생성 또는 업데이트 (Upsert)</summary>
        public async Task<UserFeatureProfile> UpsertAsync(
            UserFeatureProfile profile, 
            CancellationToken cancellationToken = default)
        {
            var existing = await FirstOrDefaultAsync(p => p.UserId == profile.UserId);

            if (existing == null)
            {
                // 새 프로필 생성
                profile.ProfileCompleteness = CalculateProfileCompleteness(profile);
                profile.ActiveAddonCount = CountActiveAddons(profile.ActiveAddons);
                return await AddAsync(profile);
            }
            else
            {
                // 기존 프로필 업데이트
                UpdateProfileFromSource(existing, profile);
                await UpdateAsync(existing);
                return existing;
            }
        }

        /// <summary>마지막 활동 시간 업데이트</summary>
        public async Task<bool> UpdateLastActivityAsync(
            Guid connectedId, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.LastActivityAt = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;
            
            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>프로필 메타데이터 업데이트</summary>
        public async Task<bool> UpdateMetadataAsync(
            Guid connectedId, 
            Dictionary<string, object> metadata, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.Metadata = JsonSerializer.Serialize(metadata);
            profile.UpdatedAt = DateTime.UtcNow;
            
            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        #endregion

        #region 애드온 관리

        /// <summary>활성 애드온 추가</summary>
        public async Task<bool> AddActiveAddonAsync(
            Guid connectedId, 
            string addonKey, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var currentAddons = DeserializeStringArray(profile.ActiveAddons);
            if (currentAddons.Contains(addonKey)) return true;

            currentAddons.Add(addonKey);
            profile.ActiveAddons = JsonSerializer.Serialize(currentAddons);
            profile.ActiveAddonCount = currentAddons.Count;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>활성 애드온 제거</summary>
        public async Task<bool> RemoveActiveAddonAsync(
            Guid connectedId, 
            string addonKey, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var currentAddons = DeserializeStringArray(profile.ActiveAddons);
            if (!currentAddons.Remove(addonKey)) return false;

            profile.ActiveAddons = JsonSerializer.Serialize(currentAddons);
            profile.ActiveAddonCount = currentAddons.Count;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>활성 애드온 목록 업데이트</summary>
        public async Task<bool> UpdateActiveAddonsAsync(
            Guid connectedId, 
            IEnumerable<string> addonKeys, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var addonList = addonKeys.ToList();
            profile.ActiveAddons = JsonSerializer.Serialize(addonList);
            profile.ActiveAddonCount = addonList.Count;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>특정 애드온을 활성화한 사용자들 조회</summary>
        public async Task<IEnumerable<UserFeatureProfile>> GetUsersWithAddonAsync(
            string addonKey, 
            Guid? organizationId = null, 
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(p => p.ActiveAddons.Contains($"\"{addonKey}\""));

            if (organizationId.HasValue)
            {
                query = QueryForOrganization(organizationId.Value)
                    .Where(p => p.ActiveAddons.Contains($"\"{addonKey}\""));
            }

            return await query
                .Include(p => p.User)
                .OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region API 접근 관리

        /// <summary>API 접근 권한 목록 업데이트</summary>
        public async Task<bool> UpdateApiAccessAsync(
            Guid connectedId, 
            IEnumerable<string> apiScopes, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.ApiAccess = JsonSerializer.Serialize(apiScopes.ToList());
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>API 호출 수 증가</summary>
        public async Task<int> IncrementApiCallsAsync(
            Guid connectedId, 
            int increment = 1, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return 0;

            profile.TotalApiCalls += increment;
            profile.LastActivityAt = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return profile.TotalApiCalls;
        }

        #endregion

        #region 기능 사용 추적

        /// <summary>기능 사용 기록</summary>
        public async Task<bool> RecordFeatureUsageAsync(
            Guid connectedId, 
            string featureKey, 
            Dictionary<string, object>? usageData = null, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var usageStats = DeserializeUsageStats(profile.FeatureUsageStats);
            UpdateFeatureUsageStats(usageStats, featureKey, usageData);

            profile.FeatureUsageStats = JsonSerializer.Serialize(usageStats);
            profile.LastActivityAt = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;
            profile.MostUsedFeature = GetMostUsedFeature(usageStats);

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        /// <summary>기능 설정 업데이트</summary>
        public async Task<bool> UpdateFeatureSettingsAsync(
            Guid connectedId, 
            string featureKey, 
            Dictionary<string, object> settings, 
            CancellationToken cancellationToken = default)
        {
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var featureSettings = string.IsNullOrEmpty(profile.FeatureSettings) 
                ? new Dictionary<string, object>() 
                : JsonSerializer.Deserialize<Dictionary<string, object>>(profile.FeatureSettings) 
                  ?? new Dictionary<string, object>();

            featureSettings[featureKey] = settings;

            profile.FeatureSettings = JsonSerializer.Serialize(featureSettings);
            profile.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(profile);
            InvalidateConnectedIdCache(connectedId);
            
            return true;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>비활성 사용자 프로필 조회</summary>
        public async Task<IEnumerable<UserFeatureProfile>> GetInactiveProfilesAsync(
            int inactiveDays, 
            Guid? organizationId = null, 
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();
                
            query = query.Where(p => 
                (p.LastActivityAt == null && p.CreatedAt < cutoffDate) ||
                (p.LastActivityAt < cutoffDate));

            return await query
                .Include(p => p.User)
                .OrderBy(p => p.LastActivityAt ?? p.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>프로필 검색</summary>
        public async Task<PagedResult<UserFeatureProfile>> SearchAsync(
            SearchUserFeatureProfileRequest request, 
            CancellationToken cancellationToken = default)
        {
            var query = request.OrganizationId.HasValue
                ? QueryForOrganization(request.OrganizationId.Value)
                : Query();

            // ConnectedId 필터
            if (request.ConnectedId.HasValue)
            {
                query = query.Where(p => _context.ConnectedIds
                    .Any(c => c.UserId == p.UserId && 
                              c.Id == request.ConnectedId.Value && 
                              !c.IsDeleted));
            }

            // 활성 애드온 필터
            if (request.ActiveAddons?.Any() == true)
            {
                foreach (var addon in request.ActiveAddons)
                {
                    query = query.Where(p => p.ActiveAddons.Contains($"\"{addon}\""));
                }
            }

            // 프로필 완성도 필터
            if (request.MinProfileCompleteness.HasValue)
                query = query.Where(p => p.ProfileCompleteness >= request.MinProfileCompleteness.Value);

            // 마지막 활동 시간 필터
            if (request.LastActivityAfter.HasValue)
                query = query.Where(p => p.LastActivityAt >= request.LastActivityAfter.Value);

            if (request.LastActivityBefore.HasValue)
                query = query.Where(p => p.LastActivityAt <= request.LastActivityBefore.Value);

            // API 접근 권한 필터
            if (request.HasApiAccess.HasValue)
            {
                query = request.HasApiAccess.Value
                    ? query.Where(p => !string.IsNullOrEmpty(p.ApiAccess) && p.ApiAccess != "[]")
                    : query.Where(p => string.IsNullOrEmpty(p.ApiAccess) || p.ApiAccess == "[]");
            }

            // 정렬 및 페이징
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);
            
            var totalCount = await query.CountAsync(cancellationToken);
            var profiles = await sortedQuery
                .Include(p => p.User)
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<UserFeatureProfile>.Create(
                profiles, totalCount, request.PageNumber, request.PageSize);
        }

        #endregion

        #region 집계

        /// <summary>애드온별 사용자 수</summary>
        public async Task<Dictionary<string, int>> GetAddonUserCountAsync(
            Guid? organizationId = null, 
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            var profiles = await query
                .Where(p => !string.IsNullOrEmpty(p.ActiveAddons) && p.ActiveAddons != "[]")
                .Select(p => p.ActiveAddons)
                .ToListAsync(cancellationToken);

            var addonCounts = new Dictionary<string, int>();
            foreach (var addonsJson in profiles)
            {
                try
                {
                    var addons = JsonSerializer.Deserialize<List<string>>(addonsJson) ?? new List<string>();
                    foreach (var addon in addons)
                    {
                        addonCounts[addon] = addonCounts.GetValueOrDefault(addon, 0) + 1;
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogWarning(ex, "Failed to deserialize ActiveAddons JSON: {Json}", addonsJson);
                }
            }

            return addonCounts;
        }

        /// <summary>활성 프로필 수</summary>
        public async Task<int> GetActiveProfileCountAsync(
            Guid? organizationId = null, 
            DateTime? since = null, 
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            if (since.HasValue)
                query = query.Where(p => p.LastActivityAt >= since.Value);

            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>ConnectedId용 캐시 키 생성</summary>
        private string GetConnectedIdCacheKey(Guid connectedId)
        {
            return $"UserFeatureProfile:ConnectedId:{connectedId}";
        }

        /// <summary>ConnectedId 캐시 무효화</summary>
        private void InvalidateConnectedIdCache(Guid connectedId)
        {
            _cache?.Remove(GetConnectedIdCacheKey(connectedId));
        }

        /// <summary>캐시 옵션 가져오기</summary>
        private MemoryCacheEntryOptions GetCacheOptions()
        {
            return new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
                SlidingExpiration = TimeSpan.FromMinutes(5),
                Priority = CacheItemPriority.Normal
            };
        }

        /// <summary>JSON 문자열 배열 역직렬화</summary>
        private List<string> DeserializeStringArray(string? json)
        {
            if (string.IsNullOrEmpty(json)) return new List<string>();
            
            try
            {
                return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            }
            catch (JsonException)
            {
                return new List<string>();
            }
        }

        /// <summary>사용 통계 역직렬화</summary>
        private Dictionary<string, object> DeserializeUsageStats(string? json)
        {
            if (string.IsNullOrEmpty(json)) return new Dictionary<string, object>();
            
            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, object>>(json) 
                    ?? new Dictionary<string, object>();
            }
            catch (JsonException)
            {
                return new Dictionary<string, object>();
            }
        }

        /// <summary>기능 사용 통계 업데이트</summary>
        private void UpdateFeatureUsageStats(
            Dictionary<string, object> usageStats, 
            string featureKey, 
            Dictionary<string, object>? additionalData)
        {
            if (!usageStats.ContainsKey(featureKey))
            {
                usageStats[featureKey] = new Dictionary<string, object>
                {
                    ["usageCount"] = 1,
                    ["lastUsed"] = DateTime.UtcNow,
                    ["firstUsed"] = DateTime.UtcNow
                };
            }
            else if (usageStats[featureKey] is JsonElement element)
            {
                var featureStats = JsonSerializer.Deserialize<Dictionary<string, object>>(element.GetRawText()) 
                    ?? new Dictionary<string, object>();
                
                var currentCount = GetIntFromJsonElement(featureStats.GetValueOrDefault("usageCount", 0));
                featureStats["usageCount"] = currentCount + 1;
                featureStats["lastUsed"] = DateTime.UtcNow;
                usageStats[featureKey] = featureStats;
            }

            if (additionalData != null && usageStats[featureKey] is Dictionary<string, object> stats)
            {
                foreach (var kvp in additionalData)
                {
                    stats[kvp.Key] = kvp.Value;
                }
            }
        }

        /// <summary>JsonElement에서 int 값 추출</summary>
        private int GetIntFromJsonElement(object? value)
        {
            return value switch
            {
                JsonElement element when element.ValueKind == JsonValueKind.Number => element.GetInt32(),
                int intValue => intValue,
                _ => 0
            };
        }

        /// <summary>활성 애드온 수 계산</summary>
        private int CountActiveAddons(string? activeAddonsJson)
        {
            return DeserializeStringArray(activeAddonsJson).Count;
        }

        /// <summary>프로필 완성도 계산 (0-100)</summary>
        private int CalculateProfileCompleteness(UserFeatureProfile profile)
        {
            int score = 0;
            
            if (!string.IsNullOrEmpty(profile.ActiveAddons) && profile.ActiveAddons != "[]") 
                score += 30;
            if (!string.IsNullOrEmpty(profile.ApiAccess) && profile.ApiAccess != "[]") 
                score += 25;
            if (!string.IsNullOrEmpty(profile.FeatureSettings)) 
                score += 20;
            if (profile.LastActivityAt.HasValue) 
                score += 15;
            if (!string.IsNullOrEmpty(profile.Metadata)) 
                score += 10;

            return Math.Min(score, 100);
        }

        /// <summary>기존 프로필을 새 데이터로 업데이트</summary>
        private void UpdateProfileFromSource(UserFeatureProfile existing, UserFeatureProfile source)
        {
            existing.ActiveAddons = source.ActiveAddons;
            existing.ApiAccess = source.ApiAccess;
            existing.FeatureSettings = source.FeatureSettings;
            existing.FeatureUsageStats = source.FeatureUsageStats;
            existing.LastActivityAt = source.LastActivityAt ?? existing.LastActivityAt;
            existing.TotalApiCalls = source.TotalApiCalls;
            existing.ActiveAddonCount = CountActiveAddons(source.ActiveAddons);
            existing.ProfileCompleteness = CalculateProfileCompleteness(existing);
            existing.MostUsedFeature = source.MostUsedFeature;
            existing.RecommendedAddons = source.RecommendedAddons;
            existing.Metadata = source.Metadata;
            existing.UpdatedAt = DateTime.UtcNow;
        }

        /// <summary>가장 많이 사용한 기능 계산</summary>
        private string? GetMostUsedFeature(Dictionary<string, object> usageStats)
        {
            if (!usageStats.Any()) return null;

            string? mostUsedFeature = null;
            int maxUsage = 0;

            foreach (var kvp in usageStats)
            {
                if (kvp.Value is JsonElement element && element.ValueKind == JsonValueKind.Object)
                {
                    if (element.TryGetProperty("usageCount", out var usageCountElement) && 
                        usageCountElement.TryGetInt32(out var usageCount) && 
                        usageCount > maxUsage)
                    {
                        maxUsage = usageCount;
                        mostUsedFeature = kvp.Key;
                    }
                }
                else if (kvp.Value is Dictionary<string, object> dict)
                {
                    var usageCount = GetIntFromJsonElement(dict.GetValueOrDefault("usageCount", 0));
                    if (usageCount > maxUsage)
                    {
                        maxUsage = usageCount;
                        mostUsedFeature = kvp.Key;
                    }
                }
            }

            return mostUsedFeature;
        }

        /// <summary>정렬 적용</summary>
        private IOrderedQueryable<UserFeatureProfile> ApplySorting(
            IQueryable<UserFeatureProfile> query, 
            string? sortBy, 
            bool descending)
        {
            return sortBy?.ToLower() switch
            {
                "lastactivity" => descending 
                    ? query.OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
                    : query.OrderBy(p => p.LastActivityAt ?? p.CreatedAt),
                "addons" => descending 
                    ? query.OrderByDescending(p => p.ActiveAddonCount)
                    : query.OrderBy(p => p.ActiveAddonCount),
                "apicalls" => descending 
                    ? query.OrderByDescending(p => p.TotalApiCalls)
                    : query.OrderBy(p => p.TotalApiCalls),
                "completeness" => descending 
                    ? query.OrderByDescending(p => p.ProfileCompleteness)
                    : query.OrderBy(p => p.ProfileCompleteness),
                _ => descending 
                    ? query.OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
                    : query.OrderBy(p => p.LastActivityAt ?? p.CreatedAt)
            };
        }

        #endregion
    }
}