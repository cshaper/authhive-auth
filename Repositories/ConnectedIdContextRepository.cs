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
// [CS0535/CS0246 해결] Query DTO 네임스페이스 추가
using AuthHive.Core.Models.Auth.ConnectedId.Queries; 

// 엔티티 이름 충돌을 피하기 위해 using 별칭(alias)을 사용합니다.
using ConnectedIdContextEntity = AuthHive.Core.Entities.Auth.Context.ConnectedIdContext; 

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId 컨텍스트 데이터 관리 Repository - v17 최종본
    /// </summary>
    public class ConnectedIdContextRepository : BaseRepository<ConnectedIdContextEntity>, IPrincipalAccessorRepository
    {
        public ConnectedIdContextRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
        }

        protected override bool IsOrganizationBaseEntity() => true;

        #region IPrincipalAccessorRepository 기본 구현

        public Task<ConnectedIdContextEntity?> GetByContextKeyAsync(string contextKey, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return Query()
                .Where(c => c.ContextKey == contextKey && c.ExpiresAt > now)
                .FirstOrDefaultAsync(cancellationToken);
        }

        // [CS0535 해결] 인터페이스와 시그니처 통일 완료
        public async Task<(IEnumerable<ConnectedIdContextEntity> Items, int TotalCount)> SearchAsync(
            SearchConnectedIdContextsQuery query, 
            CancellationToken cancellationToken = default)
        {
            var ef_core_query = Query();

            // v17 Query DTO의 필드를 사용하여 쿼리를 구성합니다.
            if (query.OrganizationId.HasValue) ef_core_query = ef_core_query.Where(c => c.OrganizationId == query.OrganizationId.Value);
            if (query.ConnectedId.HasValue) ef_core_query = ef_core_query.Where(c => c.ConnectedId == query.ConnectedId.Value);
            if (query.ContextType.HasValue) ef_core_query = ef_core_query.Where(c => c.ContextType == query.ContextType.Value);
            if (query.IsHotPath.HasValue) ef_core_query = ef_core_query.Where(c => c.IsHotPath == query.IsHotPath.Value);

            var totalCount = await ef_core_query.CountAsync(cancellationToken);

            // 동적 정렬 로직 (BaseQuery 속성 사용)
            ef_core_query = query.SortDescending 
                ? ef_core_query.OrderByDescending(c => c.LastAccessedAt) 
                : ef_core_query.OrderBy(c => c.LastAccessedAt);

            var items = await ef_core_query
                .Skip((query.PageNumber - 1) * query.PageSize) 
                .Take(query.PageSize)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }

        public Task<int> DeleteByConnectedIdAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
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

        #region AdminService를 위한 추가 구현 (Integrity & Maintenance)

        public Task<int> UpdateHotPathStatusAsync(int threshold, TimeSpan timeWindow, CancellationToken cancellationToken = default)
        {
            var since = DateTime.UtcNow.Subtract(timeWindow);
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
            var context = await GetByIdAsync(contextId, cancellationToken);
            if (context == null) return (false, "Context not found.");

            try 
            {
                 System.Text.Json.JsonDocument.Parse(context.ContextData); 
            }
            catch (Exception ex) 
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
            
            // Export 로직은 서비스 레이어로 이관 권장
            // return System.Text.Json.JsonSerializer.Serialize(contexts, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            return "Export logic moved to service layer.";
        }

        public async Task<int> ImportContextsFromJsonAsync(string jsonData, bool overwrite, CancellationToken cancellationToken = default)
        {
            var contexts = await Task.Run(() => 
                System.Text.Json.JsonSerializer.Deserialize<List<ConnectedIdContextEntity>>(jsonData), cancellationToken);

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

        #region Helper Methods (Checksum)

        private static string GenerateChecksum(string data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        #endregion
    }
}