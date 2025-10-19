using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
// 엔티티 이름 충돌을 피하기 위해 using 별칭(alias)을 사용합니다.
using ConnectedIdContextEntity = AuthHive.Core.Entities.Auth.ConnectedIdContext;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 컨텍스트 데이터 관리 Repository - AuthHive v16 최종본
    /// IConnectedIdContextAdminService가 필요로 하는 모든 데이터 접근 로직을 포함합니다.
    /// </summary>
    public class ConnectedIdContextRepository : BaseRepository<ConnectedIdContextEntity>, IConnectedIdContextRepository
    {
        /// <summary>
        /// 생성자에서 ICacheService를 주입받아 BaseRepository로 올바르게 전달합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="cacheService">하이브리드 캐시 서비스</param>
        public ConnectedIdContextRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            // CORRECTED: cacheService를 base 생성자로 전달하여 캐싱 기능을 활성화합니다.
            : base(context, cacheService)
        {
        }

        /// <summary>
        /// BaseRepository의 추상 메서드를 구현합니다.
        /// ConnectedIdContext는 OrganizationId를 포함하므로 조직 범위 엔티티입니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region IConnectedIdContextRepository 기본 구현

        public Task<ConnectedIdContextEntity?> GetByContextKeyAsync(string contextKey, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return Query()
                .Where(c => c.ContextKey == contextKey && c.ExpiresAt > now)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<(IEnumerable<ConnectedIdContextEntity> Items, int TotalCount)> SearchAsync(SearchConnectedIdContextsRequest request, CancellationToken cancellationToken = default)
        {
            var query = Query();

            // 요청 모델의 각 조건에 따라 동적으로 쿼리를 구성합니다.
            if (request.OrganizationId.HasValue) query = query.Where(c => c.OrganizationId == request.OrganizationId.Value);
            if (request.ConnectedId.HasValue) query = query.Where(c => c.ConnectedId == request.ConnectedId.Value);
            if (request.ContextType.HasValue) query = query.Where(c => c.ContextType == request.ContextType.Value);
            if (request.IsHotPath.HasValue) query = query.Where(c => c.IsHotPath == request.IsHotPath.Value);

            var totalCount = await query.CountAsync(cancellationToken);

            // TODO: 동적 정렬 로직 구현
            query = request.SortDescending 
                ? query.OrderByDescending(c => c.LastAccessedAt) 
                : query.OrderBy(c => c.LastAccessedAt);

            var items = await query
                .Skip((request.PageNumber - 1) * request.PageSize)
                .Take(request.PageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }

        public Task<int> DeleteByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            // IsDeleted 필터링을 위해 BaseRepository의 Query()를 사용합니다.
            return Query()
                .Where(c => c.ConnectedId == connectedId)
                .ExecuteDeleteAsync(cancellationToken);
        }

        public Task<int> DeleteBySessionIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return Query()
                .Where(c => c.SessionId == sessionId)
                .ExecuteDeleteAsync(cancellationToken);
        }

        public Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default)
        {
            // 만료된 데이터는 IsDeleted 상태와 관계없이 삭제해야 할 수 있으므로 _dbSet을 직접 사용합니다.
            return _dbSet
                .Where(c => c.ExpiresAt <= before)
                .ExecuteDeleteAsync(cancellationToken);
        }

        public Task<int> DeleteInactiveBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default)
        {
            return Query()
                .Where(c => c.LastAccessedAt <= before)
                .ExecuteDeleteAsync(cancellationToken);
        }

        #endregion

        #region AdminService를 위한 추가 구현

        public Task<int> UpdateHotPathStatusAsync(int threshold, TimeSpan timeWindow, CancellationToken cancellationToken = default)
        {
            var since = DateTime.UtcNow.Subtract(timeWindow);
            // Hot Path가 아닌 것들 중에서만 조건을 검색하여 불필요한 업데이트를 줄입니다.
            return Query()
                .Where(c => !c.IsHotPath && c.AccessCount >= threshold && c.LastAccessedAt >= since)
                .ExecuteUpdateAsync(s => s.SetProperty(c => c.IsHotPath, true), cancellationToken);
        }

        public async Task<IEnumerable<ConnectedIdContextEntity>> GetContextsNeedingRefreshAsync(TimeSpan within, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var expiryLimit = now.Add(within);
            return await Query()
                .Where(c => c.AutoRefresh && c.ExpiresAt > now && c.ExpiresAt <= expiryLimit)
                .ToListAsync(cancellationToken);
        }

        public async Task<(bool IsValid, string? ErrorMessage)> ValidateContextIntegrityAsync(Guid contextId, CancellationToken cancellationToken = default)
        {
            // GetByIdAsync를 사용해 캐시를 활용합니다.
            var context = await GetByIdAsync(contextId, cancellationToken);
            if (context == null) return (false, "Context not found.");

            try 
            {
                // 간단한 JSON 유효성 검사
                JsonDocument.Parse(context.ContextData); 
            }
            catch (JsonException ex) 
            {
                return (false, $"Invalid JSON data: {ex.Message}"); 
            }

            var currentChecksum = GenerateChecksum(context.ContextData);
            if (context.Checksum != currentChecksum)
            {
                return (false, "Checksum mismatch.");
            }

            return (true, null);
        }

        public async Task<string?> RecalculateChecksumAsync(Guid contextId, CancellationToken cancellationToken = default)
        {
            var context = await GetByIdAsync(contextId, cancellationToken);
            if (context == null) return null;
            
            var newChecksum = GenerateChecksum(context.ContextData);
            // 변경된 경우에만 업데이트하여 DB 부하를 줄입니다.
            if (context.Checksum != newChecksum)
            {
                context.Checksum = newChecksum;
                await UpdateAsync(context, cancellationToken);
            }
            return newChecksum;
        }

        public async Task<string> ExportContextsAsJsonAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            var contexts = await Query()
                .Where(c => c.ConnectedId == connectedId)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            // 직렬화 옵션을 사용하여 가독성 좋게 출력
            return JsonSerializer.Serialize(contexts, new JsonSerializerOptions { WriteIndented = true });
        }

        public async Task<int> ImportContextsFromJsonAsync(string jsonData, bool overwrite, CancellationToken cancellationToken = default)
        {
            var contexts = JsonSerializer.Deserialize<List<ConnectedIdContextEntity>>(jsonData);
            if (contexts == null || !contexts.Any()) return 0;
            
            if(overwrite)
            {
                 var connectedIds = contexts.Select(c => c.ConnectedId).Distinct();
                 await Query().Where(c => connectedIds.Contains(c.ConnectedId)).ExecuteDeleteAsync(cancellationToken);
            }
            
            await AddRangeAsync(contexts, cancellationToken);
            return contexts.Count;
        }

        #endregion

        #region Helper Methods
        /// <summary>
        /// 주어진 데이터 문자열에 대한 SHA256 체크섬을 생성합니다.
        /// </summary>
        private static string GenerateChecksum(string data)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        #endregion
    }
}

