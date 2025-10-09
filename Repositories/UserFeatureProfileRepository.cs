using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache; // REFACTORED: Use the core caching interface

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 기능 프로필 저장소 구현 - AuthHive v15
    /// ICacheService 추상화를 통해 캐싱 전략을 캡슐화하고, BaseRepository를 활용하여 최적화된 구조
    /// </summary>
    public class UserFeatureProfileRepository : BaseRepository<UserFeatureProfile>, IUserFeatureProfileRepository
    {
        private readonly ILogger<UserFeatureProfileRepository> _logger;
        // REFACTORED: ICacheService is now the single source for caching, inherited from BaseRepository.
        private readonly ICacheService _cacheService;

        public UserFeatureProfileRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<UserFeatureProfileRepository> logger,
            // REFACTORED: Removed direct dependency on IMemoryCache.
            // The more generic ICacheService is injected and passed to the base class.
            ICacheService cacheService)
            : base(context, organizationContext, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cacheService = cacheService; // REFACTORED: Assign the injected cache service.
        }


        #region 기본 조회



        /// <summary>여러 ConnectedId의 기능 프로필 일괄 조회</summary>
        public async Task<UserFeatureProfile?> GetByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = GetConnectedIdCacheKey(connectedId);

            // 1. ICacheService에서 GetAsync를 사용하여 먼저 캐시 조회를 시도합니다.
            var cachedProfile = await _cacheService.GetAsync<UserFeatureProfile>(cacheKey);

            // 2. 캐시에서 데이터를 찾았다면, 즉시 반환합니다 (Cache Hit)
            if (cachedProfile != null)
            {
                _logger.LogDebug("Cache hit for UserFeatureProfile with ConnectedId: {ConnectedId}.", connectedId);
                return cachedProfile;
            }

            // 3. 캐시에 데이터가 없다면 (Cache Miss), 데이터베이스에서 조회합니다.
            _logger.LogDebug("Cache miss for UserFeatureProfile with ConnectedId: {ConnectedId}. Fetching from database.", connectedId);

            var profileFromDb = await _context.ConnectedIds
                .AsNoTracking()
                .Include(c => c.User)
                .ThenInclude(u => u!.UserFeatureProfile)
                .Select(c => c.User!.UserFeatureProfile) // 필요한 데이터만 선택하여 효율성 증대
                .FirstOrDefaultAsync(p => p != null && _context.ConnectedIds.Any(c => c.Id == connectedId && c.UserId == p.UserId && !c.IsDeleted), cancellationToken);

            // 4. 데이터베이스에서 조회한 결과를 캐시에 저장합니다.
            //    (다음 요청부터는 캐시에서 바로 가져올 수 있도록)
            if (profileFromDb != null)
            {
                // 캐시 만료 정책은 SetAsync 메서드 내부의 ICacheService 구현체가 담당합니다.
                await _cacheService.SetAsync(cacheKey, profileFromDb);
            }

            // 5. 조회된 결과를 반환합니다.
            return profileFromDb;
        }

        /// <summary>조직별 기능 프로필 조회</summary>
        public async Task<PagedResult<UserFeatureProfile>> GetByOrganizationAsync(
            Guid organizationId,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var (items, totalCount) = await GetPagedByOrganizationAsync(
                organizationId,
                pageNumber,
                pageSize,
                null,
                p => p.LastActivityAt ?? p.CreatedAt,
                true
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
            // NOTE: The service layer is responsible for invalidating the cache after this operation,
            // as it has the 'connectedId' context which this method lacks.
            var existing = await FirstOrDefaultAsync(p => p.UserId == profile.UserId);

            if (existing == null)
            {
                profile.ProfileCompleteness = CalculateProfileCompleteness(profile);
                profile.ActiveAddonCount = CountActiveAddons(profile.ActiveAddons);
                return await AddAsync(profile);
            }
            else
            {
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
            await UpdateAsync(profile);

            // REFACTORED: Use the async cache service for invalidation.
            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));

            return true;
        }
        /// <summary>
        /// 여러 ConnectedId에 해당하는 기능 프로필 목록을 한 번에 조회합니다.
        /// </summary>
        /// <param name="connectedIds">조회할 ConnectedId의 컬렉션</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>요청된 UserFeatureProfile의 컬렉션</returns>
        public async Task<IEnumerable<UserFeatureProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds,
            CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any())
            {
                return Enumerable.Empty<UserFeatureProfile>();
            }

            // 이 쿼리는 효율적으로 동작하므로 변경할 필요가 없습니다.
            var profiles = await _context.ConnectedIds
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                .Where(c => c.User != null && c.User.UserFeatureProfile != null)
                .Select(c => c.User!.UserFeatureProfile!)
                .ToListAsync(cancellationToken);

            return profiles;
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
            await UpdateAsync(profile);

            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));

            return true;
        }

        #endregion



        #region 애드온 관리
        /// <summary>
        /// [최종] 특정 애드온을 구독한 조직에 속한 모든 사용자의 프로필 목록을 조회합니다.
        /// 이 메서드는 AuthHive라는 SaaS 서비스를 운영하는 내부 팀이 특정 상황에서 반드시 필요로 하는 기능입니다.
        /// OrganizationAddon 테이블을 사용하여 정확하고 효율적으로 검색합니다.
        /// </summary>
        /// <param name="addonKey">조회할 애드온의 고유 키</param>
        /// <param name="organizationId">
        ///   (선택 사항) 검색 범위를 특정 조직으로 더욱 제한하고 싶을 때 사용합니다.
        ///   예: '보안 애드온'을 사용하는 'A조직'의 사용자만 조회
        /// </param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 사용자 프로필의 컬렉션</returns>
        public async Task<IEnumerable<UserFeatureProfile>> GetProfilesInOrgsWithAddonAsync(
            string addonKey,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // 1. OrganizationAddon 테이블에서 특정 애드온을 구독한 조직들의 ID를 찾습니다.
            var orgIdsWithAddonQuery = _context.OrganizationAddons
                .Where(oa => oa.AddonKey == addonKey)
                .Select(oa => oa.OrganizationId);

            // 2. (선택적 필터링) 만약 특정 조직 ID가 주어졌다면, 그 조직이 애드온을 사용하는지 확인하며 검색 범위를 좁힙니다.
            if (organizationId.HasValue)
            {
                orgIdsWithAddonQuery = orgIdsWithAddonQuery.Where(id => id == organizationId.Value);
            }

            // 3. UserFeatureProfile을 기준으로 쿼리를 시작합니다.
            var profilesQuery = Query();

            // 4. 위에서 찾은 조직(orgIdsWithAddonQuery)에 속한 사용자의 프로필만 필터링합니다.
            // UserFeatureProfile -> User -> ConnectedId -> OrganizationId 경로로 연결하여 확인합니다.
            profilesQuery = profilesQuery.Where(profile =>
                _context.ConnectedIds.Any(c =>
                    c.UserId == profile.UserId &&
                    orgIdsWithAddonQuery.Contains(c.OrganizationId) // 사용자가 속한 조직이 애드온을 구독했는지 확인
                )
            );

            // 5. 최종 결과를 가져옵니다.
            return await profilesQuery
                .Include(p => p.User)
                .OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
                .ToListAsync(cancellationToken);
        }
        /// <summary>활성 애드온 추가</summary>
        public async Task<bool> AddActiveAddonAsync(
            Guid connectedId,
            string addonKey,
            CancellationToken cancellationToken = default)
        {
            // Pricing/plan validation should be done in the service layer BEFORE calling this repository method.
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            var currentAddons = DeserializeStringArray(profile.ActiveAddons);
            if (currentAddons.Contains(addonKey)) return true;

            currentAddons.Add(addonKey);
            profile.ActiveAddons = JsonSerializer.Serialize(currentAddons);
            profile.ActiveAddonCount = currentAddons.Count;

            await UpdateAsync(profile);
            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));

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

            await UpdateAsync(profile);
            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));

            return true;
        }

        /// <summary>활성 애드온 목록 업데이트</summary>

        /// <summary>
        /// 활성 애드온 목록을 한 번에 업데이트합니다.
        /// </summary>
        /// <param name="connectedId">사용자의 고유 연결 ID</param>
        /// <param name="addonKeys">새롭게 설정할 애드온 키 목록</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>업데이트 성공 여부</returns>
        public async Task<bool> UpdateActiveAddonsAsync(
            Guid connectedId,
            IEnumerable<string> addonKeys,
            CancellationToken cancellationToken = default)
        {
            // 1. GetByConnectedIdAsync는 이제 ICacheService를 통해 캐시된 프로필을 가져옵니다.
            var profile = await GetByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null)
            {
                return false;
            }

            // 2. 비즈니스 로직: 프로필의 애드온 목록을 업데이트합니다.
            var addonList = addonKeys.Distinct().ToList(); // 중복된 애드온 키를 제거합니다.
            profile.ActiveAddons = JsonSerializer.Serialize(addonList);
            profile.ActiveAddonCount = addonList.Count;
            profile.UpdatedAt = DateTime.UtcNow;

            // 3. 데이터베이스에 변경 사항을 저장합니다.
            await UpdateAsync(profile);

            // 4. REFACTORED: ICacheService를 사용하여 비동기적으로 캐시를 무효화합니다.
            // 이전 InvalidateConnectedIdCache(connectedId) 호출이 이 코드로 대체되었습니다.
            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));

            return true;
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
            await InvalidateConnectedIdCacheAsync(connectedId);

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
            await InvalidateConnectedIdCacheAsync(connectedId);

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
            await InvalidateConnectedIdCacheAsync(connectedId);

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
            await InvalidateConnectedIdCacheAsync(connectedId);

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
        private async Task InvalidateConnectedIdCacheAsync(Guid connectedId)
        {
            // _cache 대신 _cacheService를 사용하고, 비동기 메서드를 호출합니다.
            await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId));
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