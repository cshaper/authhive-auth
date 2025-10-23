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
using AuthHive.Core.Interfaces.Infra.Cache;
// [v16.2] Product 및 ProductSubscription 엔티티 참조 추가
using AuthHive.Core.Entities.Business.Marketplace;
using AuthHive.Core.Entities.Business.Marketplace.Core;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Entities.Business.ProductSubscriptions;


namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 사용자 기능 프로필 저장소 구현 - AuthHive v16.2
    ///
    /// [v16.2 변경 사항]
    /// 1. (오류 수정) GetProfilesInOrgsWithAddonAsync: 존재하지 않는 OrganizationAddons 대신
    ///    Products 및 ProductSubscriptions 테이블을 사용하도록 로직 수정
    /// --- 이하 v16.1 변경 사항 ---
    /// </summary>
    public class UserFeatureProfileRepository : BaseRepository<UserFeatureProfile>, IUserFeatureProfileRepository
    {
        private readonly ILogger<UserFeatureProfileRepository> _logger;

        public UserFeatureProfileRepository(
            AuthDbContext context,
            ILogger<UserFeatureProfileRepository> logger,
            ICacheService? cacheService)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override bool IsOrganizationScopedEntity() => false;

        #region ConnectedId 기반 조회 (UserFeatureProfile 특화)
        // ... (이전 코드와 동일) ...
        public async Task<UserFeatureProfile?> GetByConnectedIdAsync(
           Guid connectedId,
           CancellationToken cancellationToken = default)
        {
            string cacheKey = GetConnectedIdCacheKey(connectedId);

            if (_cacheService != null)
            {
                var cachedProfile = await _cacheService.GetAsync<UserFeatureProfile>(cacheKey, cancellationToken);
                if (cachedProfile != null)
                {
                    _logger.LogDebug("[캐시 히트] ConnectedId: {ConnectedId}의 UserFeatureProfile.", connectedId);
                    return cachedProfile;
                }
                _logger.LogDebug("[캐시 미스] ConnectedId: {ConnectedId}의 UserFeatureProfile. DB 조회 시작.", connectedId);
            }

            // DB 조회: ConnectedId -> User -> UserFeatureProfile 경로로 조회
            var profileFromDb = await _context.ConnectedIds
                // 💡 [v16.2 수정] Where 절에서 User와 UserFeatureProfile이 null이 아닌지 먼저 확인
                .Where(c => c.Id == connectedId && !c.IsDeleted && c.User != null && c.User.UserFeatureProfile != null)
                .Select(c => c.User!.UserFeatureProfile!) // 이제 null 아님 보장됨 (UserFeatureProfile)
                .AsNoTracking() // Non-nullable 타입이므로 AsNoTracking() 가능
                .FirstOrDefaultAsync(cancellationToken); // 조건에 맞는 첫 번째 결과 또는 null 반환

            if (profileFromDb != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, profileFromDb, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return profileFromDb;
        }

        public async Task<IEnumerable<UserFeatureProfile>> GetByConnectedIdsAsync(
            IEnumerable<Guid> connectedIds,
            CancellationToken cancellationToken = default)
        {
            var connectedIdList = connectedIds.ToList();
            if (!connectedIdList.Any())
            {
                return Enumerable.Empty<UserFeatureProfile>();
            }

            var profiles = await _context.ConnectedIds
                .Where(c => connectedIdList.Contains(c.Id) && !c.IsDeleted)
                .Where(c => c.User != null && c.User.UserFeatureProfile != null)
                .Select(c => c.User!.UserFeatureProfile!)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return profiles;
        }

        public async Task<PagedResult<UserFeatureProfile>> GetByOrganizationAsync(
           Guid organizationId,
           int pageNumber = 1,
           int pageSize = 50,
           CancellationToken cancellationToken = default)
        {
            var query = _context.ConnectedIds
                 .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)
                 .Where(c => c.User != null && c.User.UserFeatureProfile != null)
                 .Select(c => c.User!.UserFeatureProfile!);

            var totalCount = await query.CountAsync(cancellationToken);

            var items = await query
                .OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return PagedResult<UserFeatureProfile>.Create(items, totalCount, pageNumber, pageSize);
        }
        #endregion

        #region 프로필 관리 (UoW 적용)
        // ... (이전 코드와 동일) ...
        public async Task<UserFeatureProfile> UpsertAsync(
          UserFeatureProfile profile,
          CancellationToken cancellationToken = default)
        {
            var existing = await FirstOrDefaultAsync(p => p.UserId == profile.UserId, cancellationToken);

            if (existing == null)
            {
                profile.ProfileCompleteness = CalculateProfileCompleteness(profile);
                profile.ActiveAddonCount = CountActiveAddons(profile.ActiveAddons);
                return await AddAsync(profile, cancellationToken);
            }
            else
            {
                UpdateProfileFromSource(existing, profile);
                await UpdateAsync(existing, cancellationToken);
                return existing;
            }
        }

        public async Task<bool> UpdateLastActivityAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.LastActivityAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateMetadataAsync(
            Guid connectedId,
            Dictionary<string, object> metadata,
            CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;

            profile.Metadata = JsonSerializer.Serialize(metadata);
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }
        #endregion

        #region 애드온 관리 (UoW 적용, Addon 로직 수정)

        /// <summary>
        /// [v16.2 수정] 특정 애드온('Product'의 한 종류)을 구독 중인 조직들에 속한 모든 사용자의 프로필 목록을 조회합니다.
        /// ProductSubscription 테이블을 사용하여 조직의 애드온 활성화 여부를 확인합니다.
        /// </summary>
        /// <param name="addonKey">조회할 애드온의 ProductKey (예: AddonConstants.AddonKeys.X)</param>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 좁힐 때 사용</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 사용자 프로필 목록</returns>
        /// <remarks>
        /// 사용 예시: 특정 유료 기능을 사용하는 모든 고객사 사용자 목록을 추출하여 분석 리포트를 생성합니다.
        /// </remarks>
        public async Task<IEnumerable<UserFeatureProfile>> GetProfilesInOrgsWithAddonAsync(
            string addonKey,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // 1. addonKey를 사용하여 Product 테이블에서 해당 애드온 Product의 ID를 찾습니다.
            //    ProductType이 Addon인 것만 대상으로 합니다.
            var addonProductId = await _context.Set<Product>()
                .Where(p => p.ProductKey == addonKey && p.ProductType == ProductType.Addon)
                .Select(p => (Guid?)p.Id) // Id를 Nullable Guid로 선택
                .FirstOrDefaultAsync(cancellationToken);

            // 해당 addonKey를 가진 Product(애드온)가 없으면 빈 목록 반환
            if (!addonProductId.HasValue)
            {
                _logger.LogWarning("ProductKey '{AddonKey}'에 해당하는 Product(애드온)를 찾을 수 없습니다.", addonKey);
                return Enumerable.Empty<UserFeatureProfile>();
            }

            // 2. ProductSubscription 테이블에서 해당 ProductId에 대해 활성 구독(Status == Active) 중인 조직 ID 목록을 찾습니다.
            var orgIdsWithActiveSubscription = _context.Set<ProductSubscription>()
                .Where(sub => sub.ProductId == addonProductId.Value && sub.Status == SubscriptionStatus.Active)
                .Select(sub => sub.OrganizationId); // 조직 ID 선택

            // 3. (선택적 필터링) 특정 organizationId가 주어졌다면, 해당 조직 ID만 포함하도록 필터링합니다.
            if (organizationId.HasValue)
            {
                orgIdsWithActiveSubscription = orgIdsWithActiveSubscription.Where(id => id == organizationId.Value);
            }

            // 4. 해당 조직들에 속한 ConnectedId들의 UserId 목록을 조회합니다.
            var userIdsInTargetOrgs = _context.ConnectedIds
                .Where(c => !c.IsDeleted && orgIdsWithActiveSubscription.Contains(c.OrganizationId)) // 활성 구독 조직 필터링
                .Select(c => c.UserId)
                .Distinct(); // UserId는 여러 조직에 속할 수 있으므로 중복 제거

            // 5. 해당 UserId를 가진 UserFeatureProfile 목록을 조회합니다.
            var profilesQuery = Query() // BaseRepository의 Query() 사용 (IsDeleted=false 필터 자동 적용)
                .Where(profile => userIdsInTargetOrgs.Contains(profile.UserId)); // UserId 필터링

            // 6. 최종 결과를 조회하여 반환합니다.
            return await profilesQuery
                .AsNoTracking() // 읽기 전용 최적화
                .Include(p => p.User) // 필요 시 User 정보 로드
                .OrderByDescending(p => p.LastActivityAt ?? p.CreatedAt) // 정렬
                .ToListAsync(cancellationToken);
        }

        // --- AddActiveAddonAsync, RemoveActiveAddonAsync, UpdateActiveAddonsAsync ---
        // 이 메서드들은 UserFeatureProfile의 ActiveAddons (JSON 문자열) 필드를 직접 수정하므로,
        // Product/ProductSubscription 테이블과는 직접적인 관련이 없습니다.
        // 서비스 레이어에서 ProductSubscription 상태 변경 후 이 메서드들을 호출하여 동기화하는 방식입니다.
        // 따라서 이 메서드들의 내부 로직은 수정할 필요가 없습니다. (UoW, Cache 등은 이미 v16.1에서 수정됨)

        public async Task<bool> AddActiveAddonAsync(
            Guid connectedId, string addonKey, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            var currentAddons = DeserializeStringArray(profile.ActiveAddons);
            if (currentAddons.Contains(addonKey)) return true;
            currentAddons.Add(addonKey);
            profile.ActiveAddons = JsonSerializer.Serialize(currentAddons);
            profile.ActiveAddonCount = currentAddons.Count;
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        public async Task<bool> RemoveActiveAddonAsync(
            Guid connectedId, string addonKey, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            var currentAddons = DeserializeStringArray(profile.ActiveAddons);
            if (!currentAddons.Remove(addonKey)) return false;
            profile.ActiveAddons = JsonSerializer.Serialize(currentAddons);
            profile.ActiveAddonCount = currentAddons.Count;
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateActiveAddonsAsync(
            Guid connectedId, IEnumerable<string> addonKeys, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            var addonList = addonKeys.Distinct().ToList();
            profile.ActiveAddons = JsonSerializer.Serialize(addonList);
            profile.ActiveAddonCount = addonList.Count;
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        #endregion

        #region API 접근 관리 (UoW 적용)
        // ... (이전 코드와 동일) ...
        public async Task<bool> UpdateApiAccessAsync(
            Guid connectedId, IEnumerable<string> apiScopes, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            profile.ApiAccess = JsonSerializer.Serialize(apiScopes.Distinct().ToList());
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        public async Task<int> IncrementApiCallsAsync(
            Guid connectedId, int increment = 1, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return 0;
            profile.TotalApiCalls += increment;
            profile.LastActivityAt = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return profile.TotalApiCalls;
        }
        #endregion

        #region 기능 사용 추적 (UoW 적용)
        // ... (이전 코드와 동일) ...
        public async Task<bool> RecordFeatureUsageAsync(
            Guid connectedId, string featureKey, Dictionary<string, object>? usageData = null, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            var usageStats = DeserializeUsageStats(profile.FeatureUsageStats);
            UpdateFeatureUsageStats(usageStats, featureKey, usageData);
            profile.FeatureUsageStats = JsonSerializer.Serialize(usageStats);
            profile.LastActivityAt = DateTime.UtcNow;
            profile.UpdatedAt = DateTime.UtcNow;
            profile.MostUsedFeature = GetMostUsedFeature(usageStats);
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }

        public async Task<bool> UpdateFeatureSettingsAsync(
            Guid connectedId, string featureKey, Dictionary<string, object> settings, CancellationToken cancellationToken = default)
        {
            var profile = await GetProfileForUpdateByConnectedIdAsync(connectedId, cancellationToken);
            if (profile == null) return false;
            var featureSettings = DeserializeDictionary(profile.FeatureSettings);
            featureSettings[featureKey] = settings;
            profile.FeatureSettings = JsonSerializer.Serialize(featureSettings);
            profile.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(profile, cancellationToken);
            await InvalidateConnectedIdCacheAsync(connectedId, cancellationToken);
            return true;
        }
        #endregion

        #region 검색 및 필터링 (AsNoTracking 적용)
        // ... (이전 코드와 동일, v16.1에서 조직 필터링 수정됨) ...
        public async Task<IEnumerable<UserFeatureProfile>> GetInactiveProfilesAsync(
           int inactiveDays, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
            var query = Query();
            query = query.Where(p => (p.LastActivityAt == null && p.CreatedAt < cutoffDate) || (p.LastActivityAt < cutoffDate));

            if (organizationId.HasValue)
            {
                var userIdsInOrg = _context.ConnectedIds
                   .Where(c => c.OrganizationId == organizationId.Value && !c.IsDeleted)
                   .Select(c => c.UserId).Distinct();
                query = query.Where(p => userIdsInOrg.Contains(p.UserId));
            }

            return await query.AsNoTracking().Include(p => p.User)
                .OrderBy(p => p.LastActivityAt ?? p.CreatedAt).ToListAsync(cancellationToken);
        }

        public async Task<PagedResult<UserFeatureProfile>> SearchAsync(
            SearchUserFeatureProfileRequest request, CancellationToken cancellationToken = default)
        {
            var query = Query();

            if (request.OrganizationId.HasValue)
            {
                var userIdsInOrg = _context.ConnectedIds
                   .Where(c => c.OrganizationId == request.OrganizationId.Value && !c.IsDeleted)
                   .Select(c => c.UserId).Distinct();
                query = query.Where(p => userIdsInOrg.Contains(p.UserId));
            }

            if (request.ConnectedId.HasValue)
            {
                var userId = await _context.ConnectedIds
                    .Where(c => c.Id == request.ConnectedId.Value && !c.IsDeleted)
                    .Select(c => c.UserId).FirstOrDefaultAsync(cancellationToken);
                if (userId != default) { query = query.Where(p => p.UserId == userId); }
                else { return PagedResult<UserFeatureProfile>.Empty(request.PageNumber, request.PageSize); }
            }
            // ... (기타 필터 로직) ...
            if (request.ActiveAddons?.Any() == true) { /* ... */ }
            if (request.MinProfileCompleteness.HasValue) { /* ... */ }
            if (request.LastActivityAfter.HasValue) { /* ... */ }
            if (request.LastActivityBefore.HasValue) { /* ... */ }
            if (request.HasApiAccess.HasValue) { /* ... */ }

            var totalCount = await query.CountAsync(cancellationToken);
            var sortedQuery = ApplySorting(query, request.SortBy, request.SortDescending);
            var profiles = await sortedQuery.AsNoTracking().Include(p => p.User)
                .Skip((request.PageNumber - 1) * request.PageSize).Take(request.PageSize).ToListAsync(cancellationToken);
            return PagedResult<UserFeatureProfile>.Create(profiles, totalCount, request.PageNumber, request.PageSize);
        }
        #endregion

        #region 집계 및 통계 (Addon 로직 수정)

        /// <summary>
        /// [v16.2 수정] 각 애드온(Product)을 사용하는 활성 사용자 수를 계산합니다.
        /// ProductSubscription 테이블을 사용하여 조직별 애드온 활성화 여부를 확인 후 집계합니다.
        /// </summary>
        /// <param name="organizationId">(선택) 특정 조직으로 범위를 제한할 때 사용</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>애드온 키와 사용자 수를 담은 Dictionary</returns>
        public async Task<Dictionary<string, int>> GetAddonUserCountAsync(
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // 1. 활성 구독 중인 모든 (OrganizationId, ProductKey) 쌍을 조회합니다.
            //    ProductType이 Addon인 것만 대상으로 합니다.
            var activeOrgAddonKeysQuery = _context.Set<ProductSubscription>()
                // 💡 [v16.2 수정] IsActive 대신 Status 열거형 비교
                .Where(sub => sub.Status == SubscriptionStatus.Active && sub.Product.ProductType == ProductType.Addon)
                .Select(sub => new { sub.OrganizationId, sub.Product.ProductKey }); // 조직 ID와 애드온 키 선택
            // 2. (선택적 필터링) 특정 organizationId가 주어졌다면 해당 조직만 필터링합니다.
            if (organizationId.HasValue)
            {
                activeOrgAddonKeysQuery = activeOrgAddonKeysQuery.Where(oa => oa.OrganizationId == organizationId.Value);
            }

            // 3. 메모리로 로드하여 (조직ID, 애드온키) 목록 생성
            var activeOrgAddonKeys = await activeOrgAddonKeysQuery
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            // 애드온 키별로 해당 애드온을 사용하는 조직 ID 목록을 그룹화합니다.
            var addonToOrgs = activeOrgAddonKeys
                .GroupBy(oa => oa.ProductKey)
                .ToDictionary(g => g.Key, g => g.Select(x => x.OrganizationId).ToHashSet()); // 중복 제거를 위해 HashSet 사용

            var addonUserCounts = new Dictionary<string, int>();

            // 4. 각 애드온 키에 대해, 해당 애드온을 사용하는 조직들에 속한 사용자 수를 계산합니다.
            foreach (var kvp in addonToOrgs)
            {
                var addonKey = kvp.Key;
                var orgIds = kvp.Value; // 이 애드온을 사용하는 조직 ID 목록

                // 해당 조직들에 속한 고유 사용자(UserId) 수를 계산합니다.
                var userCount = await _context.ConnectedIds
                    .Where(c => !c.IsDeleted && orgIds.Contains(c.OrganizationId)) // 해당 조직 필터링
                    .Select(c => c.UserId) // UserId 선택
                    .Distinct() // 고유 UserId 계산
                    .CountAsync(cancellationToken); // 개수 계산

                addonUserCounts[addonKey] = userCount;
            }

            return addonUserCounts;
        }


        public async Task<int> GetActiveProfileCountAsync(
            Guid? organizationId = null, DateTime? since = null, CancellationToken cancellationToken = default)
        {
            var query = Query();
            if (organizationId.HasValue)
            {
                var userIdsInOrg = _context.ConnectedIds
                   .Where(c => c.OrganizationId == organizationId.Value && !c.IsDeleted)
                   .Select(c => c.UserId).Distinct();
                query = query.Where(p => userIdsInOrg.Contains(p.UserId));
            }
            if (since.HasValue)
                query = query.Where(p => p.LastActivityAt >= since.Value);
            return await query.CountAsync(cancellationToken);
        }

        #endregion

        #region Helper Methods
        // ... (GetConnectedIdCacheKey, InvalidateConnectedIdCacheAsync 등 이전 코드와 동일) ...
        private string GetConnectedIdCacheKey(Guid connectedId) => $"{typeof(UserFeatureProfile).Name}:ConnectedId:{connectedId}";
        private async Task InvalidateConnectedIdCacheAsync(Guid connectedId, CancellationToken cancellationToken = default) { if (_cacheService != null) await _cacheService.RemoveAsync(GetConnectedIdCacheKey(connectedId), cancellationToken); }
        private async Task<UserFeatureProfile?> GetProfileForUpdateByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken) { return await _context.ConnectedIds.Where(c => c.Id == connectedId && !c.IsDeleted).Select(c => c.User!.UserFeatureProfile).FirstOrDefaultAsync(cancellationToken); }
        private List<string> DeserializeStringArray(string? json) { /* ... */ return new List<string>(); }
        private Dictionary<string, object> DeserializeDictionary(string? json) { /* ... */ return new Dictionary<string, object>(); }
        private Dictionary<string, object> DeserializeUsageStats(string? json) => DeserializeDictionary(json);
        private void UpdateFeatureUsageStats(Dictionary<string, object> usageStats, string featureKey, Dictionary<string, object>? additionalData) { /* ... */ }
        private int GetIntFromJsonElement(object? value) { /* ... */ return 0; }
        private int CountActiveAddons(string? activeAddonsJson) => DeserializeStringArray(activeAddonsJson).Count;
        private int CalculateProfileCompleteness(UserFeatureProfile profile) { /* ... */ return 0; }
        private void UpdateProfileFromSource(UserFeatureProfile existing, UserFeatureProfile source) { /* ... */ }
        private string? GetMostUsedFeature(Dictionary<string, object> usageStats) { /* ... */ return null; }
        private IOrderedQueryable<UserFeatureProfile> ApplySorting(IQueryable<UserFeatureProfile> query, string? sortBy, bool descending) { /* ... */ return query.OrderBy(p => p.Id); }


        #endregion
    }
}