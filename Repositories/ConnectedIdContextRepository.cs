using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Constants.Auth;
using AuthHive.Auth.Data.Context;
using System.Text.Json;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// ConnectedId 컨텍스트 데이터 관리 Repository - AuthHive v15 핵심 캐싱 메커니즘
/// Hot Path 데이터와 권한 캐싱을 담당하는 고성능 Repository
/// </summary>
public class ConnectedIdContextRepository : BaseRepository<ConnectedIdContext>, IConnectedIdContextRepository
{
    public ConnectedIdContextRepository(AuthDbContext context) : base(context)
    {
    }

    #region 기본 조회 메서드

    /// <summary>
    /// ConnectedId와 컨텍스트 타입으로 컨텍스트 조회
    /// </summary>
    public async Task<ConnectedIdContext?> GetByConnectedIdAndTypeAsync(
        Guid connectedId, 
        ConnectedIdContextType contextType,
        Guid? applicationId = null)
    {
        var query = Query()
            .Where(c => c.ConnectedId == connectedId && 
                       c.ContextType == contextType &&
                       c.ExpiresAt > DateTime.UtcNow);

        if (applicationId.HasValue)
        {
            query = query.Where(c => c.ApplicationId == applicationId);
        }

        var context = await query.FirstOrDefaultAsync();

        // 접근 통계 업데이트
        if (context != null)
        {
            _ = Task.Run(() => RecordAccessAsync(context.Id));
        }

        return context;
    }

    /// <summary>
    /// 컨텍스트 키로 조회 (캐시 키 기반 조회)
    /// </summary>
    public async Task<ConnectedIdContext?> GetByContextKeyAsync(string contextKey)
    {
        var context = await Query()
            .Where(c => c.ContextKey == contextKey && c.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefaultAsync();

        if (context != null)
        {
            _ = Task.Run(() => RecordAccessAsync(context.Id));
        }

        return context;
    }

    /// <summary>
    /// ConnectedId의 모든 활성 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetByConnectedIdAsync(
        Guid connectedId, 
        bool includeExpired = false)
    {
        var query = Query().Where(c => c.ConnectedId == connectedId);

        if (!includeExpired)
        {
            query = query.Where(c => c.ExpiresAt > DateTime.UtcNow);
        }

        return await query
            .OrderBy(c => c.Priority)
            .ThenByDescending(c => c.LastAccessedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 세션의 모든 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetBySessionIdAsync(Guid sessionId)
    {
        return await Query()
            .Where(c => c.SessionId == sessionId && c.ExpiresAt > DateTime.UtcNow)
            .OrderBy(c => c.Priority)
            .ToListAsync();
    }

    /// <summary>
    /// 애플리케이션별 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetByApplicationIdAsync(
        Guid applicationId,
        ConnectedIdContextType? contextType = null)
    {
        var query = Query()
            .Where(c => c.ApplicationId == applicationId && c.ExpiresAt > DateTime.UtcNow);

        if (contextType.HasValue)
        {
            query = query.Where(c => c.ContextType == contextType.Value);
        }

        return await query.OrderBy(c => c.Priority).ToListAsync();
    }

    #endregion

    #region Hot Path 및 캐시 관련

    /// <summary>
    /// Hot Path 컨텍스트 조회 (자주 접근되는 데이터)
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetHotPathContextsAsync(
        Guid organizationId,
        int limit = 100)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId && 
                       c.IsHotPath && 
                       c.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(c => c.AccessCount)
            .ThenByDescending(c => c.LastAccessedAt)
            .Take(limit)
            .ToListAsync();
    }

    /// <summary>
    /// gRPC 캐시가 활성화된 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetGrpcCacheEnabledContextsAsync(Guid organizationId)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId && 
                       c.GrpcCacheEnabled && 
                       c.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(c => c.AccessCount)
            .ToListAsync();
    }

    /// <summary>
    /// 자동 갱신이 필요한 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetContextsNeedingRefreshAsync(int expiryThreshold = 5)
    {
        var threshold = DateTime.UtcNow.AddMinutes(expiryThreshold);
        
        return await Query()
            .Where(c => c.AutoRefresh && c.ExpiresAt <= threshold)
            .ToListAsync();
    }

    /// <summary>
    /// 컨텍스트 접근 기록 및 Hot Path 상태 업데이트
    /// </summary>
    public async Task<bool> RecordAccessAsync(Guid contextId)
    {
        try
        {
            // Raw SQL을 사용한 성능 최적화
            var result = await _context.Database.ExecuteSqlRawAsync(
                """
                UPDATE "ConnectedIdContexts" 
                SET 
                    "AccessCount" = "AccessCount" + 1,
                    "LastAccessedAt" = @now,
                    "IsHotPath" = CASE 
                        WHEN "AccessCount" + 1 >= @threshold THEN true
                        ELSE "IsHotPath"
                    END,
                    "GrpcCacheEnabled" = CASE 
                        WHEN "AccessCount" + 1 >= @threshold THEN true
                        ELSE "GrpcCacheEnabled"
                    END
                WHERE "Id" = @contextId
                """,
                new object[] { DateTime.UtcNow, ConnectedIdConstants.Limits.HighPriorityThreshold, contextId });

            return result > 0;
        }
        catch
        {
            return false; // 통계 업데이트 실패는 전체 프로세스를 중단하지 않음
        }
    }

    /// <summary>
    /// Hot Path 상태 일괄 업데이트
    /// </summary>
    public async Task<int> UpdateHotPathStatusAsync(int threshold = ConnectedIdConstants.Limits.HighPriorityThreshold, int timeWindow = 1)
    {
        var cutoffTime = DateTime.UtcNow.AddHours(-timeWindow);
        
        return await _context.Database.ExecuteSqlRawAsync(
            """
            UPDATE "ConnectedIdContexts" 
            SET 
                "IsHotPath" = true,
                "GrpcCacheEnabled" = true
            WHERE 
                "AccessCount" >= @threshold 
                AND "LastAccessedAt" >= @cutoffTime
                AND "IsDeleted" = false
            """,
            threshold, cutoffTime);
    }

    #endregion

    #region 만료 및 정리

    /// <summary>
    /// 만료된 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetExpiredContextsAsync(Guid? organizationId = null)
    {
        var query = Query().Where(c => c.ExpiresAt <= DateTime.UtcNow);
        
        if (organizationId.HasValue)
        {
            query = query.Where(c => c.OrganizationId == organizationId);
        }

        return await query.ToListAsync();
    }

    /// <summary>
    /// 컨텍스트 만료 시간 연장
    /// </summary>
    public async Task<bool> ExtendExpiryAsync(Guid contextId, int extensionMinutes)
    {
        var context = await GetByIdAsync(contextId);
        if (context == null) return false;

        context.ExpiresAt = context.ExpiresAt.AddMinutes(extensionMinutes);
        await UpdateAsync(context);
        return true;
    }

    /// <summary>
    /// 만료된 컨텍스트 일괄 삭제
    /// </summary>
    public async Task<int> CleanupExpiredContextsAsync(int retentionDays = 7)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
        
        return await _context.Database.ExecuteSqlRawAsync(
            """
            DELETE FROM "ConnectedIdContexts" 
            WHERE "ExpiresAt" <= @cutoffDate
            """,
            cutoffDate);
    }

    /// <summary>
    /// 비활성 컨텍스트 정리
    /// </summary>
    public async Task<int> CleanupInactiveContextsAsync(int inactiveDays = 30)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
        
        return await _context.Database.ExecuteSqlRawAsync(
            """
            DELETE FROM "ConnectedIdContexts" 
            WHERE "LastAccessedAt" <= @cutoffDate
            """,
            cutoffDate);
    }

    #endregion

    #region 일괄 작업

    /// <summary>
    /// ConnectedId의 모든 컨텍스트 삭제
    /// </summary>
    public async Task<int> DeleteByConnectedIdAsync(Guid connectedId)
    {
        return await _context.Database.ExecuteSqlRawAsync(
            """
            UPDATE "ConnectedIdContexts" 
            SET 
                "IsDeleted" = true,
                "DeletedAt" = @now
            WHERE "ConnectedId" = @connectedId
            """,
            DateTime.UtcNow, connectedId);
    }

    /// <summary>
    /// 세션의 모든 컨텍스트 삭제
    /// </summary>
    public async Task<int> DeleteBySessionIdAsync(Guid sessionId)
    {
        return await _context.Database.ExecuteSqlRawAsync(
            """
            UPDATE "ConnectedIdContexts" 
            SET 
                "IsDeleted" = true,
                "DeletedAt" = @now
            WHERE "SessionId" = @sessionId
            """,
            DateTime.UtcNow, sessionId);
    }

    /// <summary>
    /// 애플리케이션의 모든 컨텍스트 삭제
    /// </summary>
    public async Task<int> DeleteByApplicationIdAsync(Guid applicationId)
    {
        return await _context.Database.ExecuteSqlRawAsync(
            """
            UPDATE "ConnectedIdContexts" 
            SET 
                "IsDeleted" = true,
                "DeletedAt" = @now
            WHERE "ApplicationId" = @applicationId
            """,
            DateTime.UtcNow, applicationId);
    }

    /// <summary>
    /// 컨텍스트 일괄 생성 또는 업데이트
    /// </summary>
    public async Task<int> BulkUpsertAsync(IEnumerable<ConnectedIdContext> contexts)
    {
        var contextList = contexts.ToList();
        var processedCount = 0;

        foreach (var context in contextList)
        {
            var existing = await Query()
                .FirstOrDefaultAsync(c => c.ConnectedId == context.ConnectedId && 
                                        c.ContextKey == context.ContextKey);

            if (existing != null)
            {
                // Update existing
                existing.ContextData = context.ContextData;
                existing.MetadataJson = context.MetadataJson;
                existing.ExpiresAt = context.ExpiresAt;
                existing.LastAccessedAt = DateTime.UtcNow;
                existing.Checksum = GenerateChecksum(context.ContextData);
                
                await UpdateAsync(existing);
            }
            else
            {
                // Create new
                context.Checksum = GenerateChecksum(context.ContextData);
                await AddAsync(context);
            }
            processedCount++;
        }

        return processedCount;
    }

    /// <summary>
    /// 컨텍스트 타입별 일괄 삭제
    /// </summary>
    public async Task<int> DeleteByContextTypeAsync(Guid organizationId, ConnectedIdContextType contextType)
    {
        return await _context.Database.ExecuteSqlRawAsync(
            """
            UPDATE "ConnectedIdContexts" 
            SET 
                "IsDeleted" = true,
                "DeletedAt" = @now
            WHERE 
                "OrganizationId" = @organizationId 
                AND "ContextType" = @contextType
            """,
            DateTime.UtcNow, organizationId, (int)contextType);
    }

    #endregion

    #region 검증 및 무결성

    /// <summary>
    /// 컨텍스트 데이터 무결성 검증
    /// </summary>
    public async Task<(bool IsValid, string? ErrorMessage)> ValidateContextIntegrityAsync(Guid contextId)
    {
        var context = await GetByIdAsync(contextId);
        if (context == null)
        {
            return (false, "컨텍스트를 찾을 수 없습니다.");
        }

        var expectedChecksum = GenerateChecksum(context.ContextData);
        if (context.Checksum != expectedChecksum)
        {
            return (false, "체크섬이 일치하지 않습니다. 데이터 무결성 문제가 있을 수 있습니다.");
        }

        // JSON 유효성 검사
        try
        {
            JsonDocument.Parse(context.ContextData);
        }
        catch (JsonException)
        {
            return (false, "컨텍스트 데이터가 유효한 JSON 형식이 아닙니다.");
        }

        return (true, null);
    }

    /// <summary>
    /// 체크섬 재계산 및 업데이트
    /// </summary>
    public async Task<string> RecalculateChecksumAsync(Guid contextId)
    {
        var context = await GetByIdAsync(contextId);
        if (context == null)
        {
            throw new ArgumentException("컨텍스트를 찾을 수 없습니다.", nameof(contextId));
        }

        var newChecksum = GenerateChecksum(context.ContextData);
        context.Checksum = newChecksum;
        await UpdateAsync(context);

        return newChecksum;
    }

    /// <summary>
    /// 중복 컨텍스트 확인
    /// </summary>
    public async Task<bool> ExistsDuplicateAsync(
        Guid connectedId,
        ConnectedIdContextType contextType,
        Guid? applicationId)
    {
        var query = Query()
            .Where(c => c.ConnectedId == connectedId && c.ContextType == contextType);

        if (applicationId.HasValue)
        {
            query = query.Where(c => c.ApplicationId == applicationId);
        }
        else
        {
            query = query.Where(c => c.ApplicationId == null);
        }

        return await query.AnyAsync();
    }

    #endregion

    #region 통계 및 분석

    /// <summary>
    /// 컨텍스트 타입별 통계 조회
    /// </summary>
    public async Task<Dictionary<ConnectedIdContextType, (int Count, double AvgAccessCount)>> 
        GetContextStatisticsByTypeAsync(Guid organizationId)
    {
        var stats = await Query()
            .Where(c => c.OrganizationId == organizationId)
            .GroupBy(c => c.ContextType)
            .Select(g => new 
            {
                ContextType = g.Key,
                Count = g.Count(),
                AvgAccessCount = g.Average(c => c.AccessCount)
            })
            .ToListAsync();

        return stats.ToDictionary(
            s => s.ContextType, 
            s => (s.Count, s.AvgAccessCount));
    }

    /// <summary>
    /// 우선순위별 컨텍스트 분포 조회
    /// </summary>
    public async Task<Dictionary<int, int>> GetContextDistributionByPriorityAsync(Guid organizationId)
    {
        var distribution = await Query()
            .Where(c => c.OrganizationId == organizationId)
            .GroupBy(c => c.Priority)
            .Select(g => new { Priority = g.Key, Count = g.Count() })
            .ToListAsync();

        return distribution.ToDictionary(d => d.Priority, d => d.Count);
    }

    /// <summary>
    /// 컨텍스트 사용량 분석
    /// </summary>
    public async Task<object> GetUsageAnalyticsAsync(
        Guid organizationId,
        DateTime startDate,
        DateTime endDate)
    {
        var analytics = await Query()
            .Where(c => c.OrganizationId == organizationId && 
                       c.LastAccessedAt >= startDate && 
                       c.LastAccessedAt <= endDate)
            .GroupBy(c => c.LastAccessedAt.Date)
            .Select(g => new 
            {
                Date = g.Key,
                TotalAccess = g.Sum(c => c.AccessCount),
                UniqueContexts = g.Count(),
                HotPathCount = g.Count(c => c.IsHotPath)
            })
            .OrderBy(a => a.Date)
            .ToListAsync();

        return analytics;
    }

    #endregion

    #region 마이그레이션 지원

    /// <summary>
    /// 컨텍스트 내보내기 (JSON 형식)
    /// </summary>
    public async Task<string> ExportContextsAsJsonAsync(Guid connectedId)
    {
        var contexts = await GetByConnectedIdAsync(connectedId, true);
        return JsonSerializer.Serialize(contexts, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        });
    }

    /// <summary>
    /// 컨텍스트 가져오기 (JSON 형식)
    /// </summary>
    public async Task<int> ImportContextsFromJsonAsync(string jsonData, bool overwrite = false)
    {
        var contexts = JsonSerializer.Deserialize<List<ConnectedIdContext>>(jsonData);
        if (contexts == null) return 0;

        var importedCount = 0;
        foreach (var context in contexts)
        {
            var existing = await Query()
                .FirstOrDefaultAsync(c => c.ConnectedId == context.ConnectedId && 
                                        c.ContextKey == context.ContextKey);

            if (existing == null || overwrite)
            {
                if (existing != null && overwrite)
                {
                    await DeleteAsync(existing);
                }

                context.Id = Guid.NewGuid(); // 새 ID 생성
                context.Checksum = GenerateChecksum(context.ContextData);
                await AddAsync(context);
                importedCount++;
            }
        }

        return importedCount;
    }

    #endregion

    #region IOrganizationScopedRepository 구현

    /// <summary>
    /// 조직별 모든 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> GetByOrganizationIdAsync(Guid organizationId)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId)
            .OrderBy(c => c.Priority)
            .ThenByDescending(c => c.LastAccessedAt)
            .ToListAsync();
    }

    /// <summary>
    /// ID와 조직으로 컨텍스트 조회
    /// </summary>
    public async Task<ConnectedIdContext?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .FirstOrDefaultAsync(c => c.Id == id && c.OrganizationId == organizationId);
    }

    /// <summary>
    /// 조건과 조직으로 컨텍스트 조회
    /// </summary>
    public async Task<IEnumerable<ConnectedIdContext>> FindByOrganizationAsync(
        Guid organizationId, 
        System.Linq.Expressions.Expression<Func<ConnectedIdContext, bool>> predicate)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId)
            .Where(predicate)
            .ToListAsync();
    }

    /// <summary>
    /// 조직별 페이징된 컨텍스트 조회
    /// </summary>
    public async Task<(IEnumerable<ConnectedIdContext> Items, int TotalCount)> GetPagedByOrganizationAsync(
        Guid organizationId,
        int pageNumber,
        int pageSize,
        System.Linq.Expressions.Expression<Func<ConnectedIdContext, bool>>? predicate = null,
        System.Linq.Expressions.Expression<Func<ConnectedIdContext, object>>? orderBy = null,
        bool isDescending = false)
    {
        var query = Query().Where(c => c.OrganizationId == organizationId);

        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        var totalCount = await query.CountAsync();

        if (orderBy != null)
        {
            query = isDescending
                ? query.OrderByDescending(orderBy)
                : query.OrderBy(orderBy);
        }
        else
        {
            query = query.OrderBy(c => c.Priority).ThenByDescending(c => c.LastAccessedAt);
        }

        var items = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (items, totalCount);
    }

    /// <summary>
    /// 조직 내 컨텍스트 존재 여부 확인
    /// </summary>
    public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId)
    {
        return await Query()
            .AnyAsync(c => c.Id == id && c.OrganizationId == organizationId);
    }

    /// <summary>
    /// 조직별 컨텍스트 개수 조회
    /// </summary>
    public async Task<int> CountByOrganizationAsync(
        Guid organizationId, 
        System.Linq.Expressions.Expression<Func<ConnectedIdContext, bool>>? predicate = null)
    {
        var query = Query().Where(c => c.OrganizationId == organizationId);

        if (predicate != null)
        {
            query = query.Where(predicate);
        }

        return await query.CountAsync();
    }

    /// <summary>
    /// 조직의 모든 컨텍스트 삭제
    /// </summary>
    public async Task DeleteAllByOrganizationAsync(Guid organizationId)
    {
        var contexts = await Query()
            .Where(c => c.OrganizationId == organizationId)
            .ToListAsync();

        if (contexts.Any())
        {
            await DeleteRangeAsync(contexts);
        }
    }

    #endregion

    #region 유틸리티

    /// <summary>
    /// 컨텍스트 생성 또는 업데이트 (Upsert) - 핵심 메서드
    /// </summary>
    public async Task<ConnectedIdContext> UpsertContextAsync(
        Guid connectedId,
        string contextKey,
        ConnectedIdContextType contextType,
        string contextData,
        TimeSpan? expiration = null,
        string? metadataJson = null,
        CancellationToken cancellationToken = default)
    {
        var expiresAt = DateTime.UtcNow.Add(expiration ?? TimeSpan.FromMinutes(ConnectedIdConstants.Cache.ContextTtl / 60));
        
        var existing = await Query()
            .FirstOrDefaultAsync(c => c.ConnectedId == connectedId && 
                                    c.ContextKey == contextKey, 
                               cancellationToken);

        if (existing != null)
        {
            // 기존 컨텍스트 업데이트
            existing.ContextData = contextData;
            existing.MetadataJson = metadataJson;
            existing.ExpiresAt = expiresAt;
            existing.LastAccessedAt = DateTime.UtcNow;
            existing.AccessCount++;
            
            // Hot Path 자동 감지
            if (existing.AccessCount >= ConnectedIdConstants.Limits.HighPriorityThreshold)
            {
                existing.IsHotPath = true;
                existing.GrpcCacheEnabled = true;
            }

            existing.Checksum = GenerateChecksum(contextData);
            
            await UpdateAsync(existing);
            return existing;
        }
        else
        {
            // 새 컨텍스트 생성
            var newContext = new ConnectedIdContext
            {
                ConnectedId = connectedId,
                ContextKey = contextKey,
                ContextType = contextType,
                ContextData = contextData,
                MetadataJson = metadataJson,
                ExpiresAt = expiresAt,
                LastAccessedAt = DateTime.UtcNow,
                AccessCount = 1,
                Priority = ConnectedIdConstants.Limits.DefaultPriority,
                Checksum = GenerateChecksum(contextData)
            };

            await AddAsync(newContext);
            return newContext;
        }
    }

    /// <summary>
    /// 컨텍스트 키 생성 헬퍼 메서드
    /// </summary>
    public string GenerateContextKey(Guid connectedId, ConnectedIdContextType contextType, Guid? applicationId = null, string? suffix = null)
    {
        var key = $"{ConnectedIdConstants.Cache.ContextCacheKeyPrefix}{connectedId}:{contextType}";
        
        if (applicationId.HasValue)
        {
            key += $":app:{applicationId}";
        }
        
        if (!string.IsNullOrEmpty(suffix))
        {
            key += $":{suffix}";
        }
        
        return key;
    }

    /// <summary>
    /// 컨텍스트 데이터 무결성 검증용 체크섬 생성
    /// </summary>
    private string GenerateChecksum(string contextData)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(contextData));
        return Convert.ToBase64String(hashBytes)[..16]; // 16자리로 단축
    }

    /// <summary>
    /// 컨텍스트 만료 임박 여부 확인
    /// </summary>
    public bool IsNearExpiry(ConnectedIdContext context)
    {
        var threshold = DateTime.UtcNow.AddSeconds(ConnectedIdConstants.Limits.NearExpirySeconds);
        return context.ExpiresAt <= threshold;
    }

    /// <summary>
    /// 최근 접근 여부 확인
    /// </summary>
    public bool IsRecentlyAccessed(ConnectedIdContext context)
    {
        var threshold = DateTime.UtcNow.AddSeconds(-ConnectedIdConstants.Limits.RecentAccessSeconds);
        return context.LastAccessedAt >= threshold;
    }

    /// <summary>
    /// 컨텍스트 우선순위 계산 (접근 빈도 기반)
    /// </summary>
    public int CalculatePriority(ConnectedIdContext context)
    {
        // 접근 횟수와 최근 접근 시간을 고려한 우선순위 계산
        var accessScore = Math.Min(context.AccessCount / 10, 5); // 최대 5점
        var recentScore = IsRecentlyAccessed(context) ? 3 : 0;    // 최대 3점
        var hotPathScore = context.IsHotPath ? 2 : 0;             // 최대 2점
        
        return Math.Min(accessScore + recentScore + hotPathScore, ConnectedIdConstants.Limits.MaxPriority);
    }

    #endregion
}