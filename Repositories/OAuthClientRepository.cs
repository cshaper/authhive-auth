using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using System.Text.Json;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// OAuth Client Repository - OAuth 클라이언트 관리 Repository
/// AuthHive v15 OAuth 2.0 클라이언트 애플리케이션 관리 시스템
/// </summary>
public class OAuthClientRepository : OrganizationScopedRepository<OAuthClient>, IOAuthClientRepository
{
    public OAuthClientRepository(AuthDbContext context) : base(context)
    {
    }

    #region 기본 조회

    /// <summary>
    /// 클라이언트 ID로 조회
    /// </summary>
    public async Task<OAuthClient?> GetByClientIdAsync(string clientId)
    {
        return await Query()
            .Include(c => c.PlatformApplication)
            .FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    /// <summary>
    /// 애플리케이션별 OAuth 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetByApplicationIdAsync(Guid applicationId)
    {
        return await Query()
            .Where(c => c.ApplicationId == applicationId)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// 활성 OAuth 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetActiveClientsAsync(Guid organizationId)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId && c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// Grant Type별 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetByGrantTypeAsync(
        Guid organizationId,
        OAuthGrantType grantType)
    {
        var grantTypeString = grantType.ToString();

        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.IsActive &&
                       c.AllowedGrantTypes.Contains(grantTypeString))
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 검증 메서드

    /// <summary>
    /// 클라이언트 시크릿 검증
    /// </summary>
    public async Task<bool> ValidateClientSecretAsync(string clientId, string clientSecretHash)
    {
        var client = await Query()
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client == null) return false;

        // Public 클라이언트는 시크릿이 필요하지 않음
        if (client.ClientType == OAuthClientType.Public && !client.RequireClientSecret)
        {
            return true;
        }

        // Confidential 클라이언트는 시크릿 검증 필수
        if (client.ClientType == OAuthClientType.Confidential || client.RequireClientSecret)
        {
            return !string.IsNullOrEmpty(client.ClientSecretHash) && 
                   client.ClientSecretHash == clientSecretHash;
        }

        return false;
    }

    /// <summary>
    /// 리다이렉트 URI 유효성 검증
    /// </summary>
    public async Task<bool> IsRedirectUriValidAsync(string clientId, string redirectUri)
    {
        var client = await Query()
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client?.RedirectUris == null) return false;

        try
        {
            var allowedUris = JsonSerializer.Deserialize<List<string>>(client.RedirectUris);
            return allowedUris?.Contains(redirectUri, StringComparer.OrdinalIgnoreCase) ?? false;
        }
        catch (JsonException)
        {
            // JSON 파싱 실패 시 false 반환
            return false;
        }
    }

    /// <summary>
    /// 스코프 유효성 검증
    /// </summary>
    public async Task<bool> AreScopesAllowedAsync(string clientId, List<string> scopes)
    {
        var client = await Query()
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client?.AllowedScopes == null) return false;

        try
        {
            var allowedScopes = JsonSerializer.Deserialize<List<string>>(client.AllowedScopes);
            if (allowedScopes == null) return false;

            // 요청된 모든 스코프가 허용된 스코프에 포함되는지 확인
            return scopes.All(scope => allowedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    #endregion

    #region 업데이트 메서드

    /// <summary>
    /// 마지막 사용 시간 업데이트
    /// </summary>
    public async Task UpdateLastUsedAsync(Guid clientId)
    {
        var client = await GetByIdAsync(clientId);
        if (client != null)
        {
            client.LastUsedAt = DateTime.UtcNow;
            await UpdateAsync(client);
        }
    }

    #endregion

    #region 관계 데이터 포함 조회

    /// <summary>
    /// 관련 데이터 포함 조회
    /// </summary>
    public async Task<OAuthClient?> GetWithTokensAsync(
        Guid id,
        bool includeAccessTokens = false,
        bool includeRefreshTokens = false)
    {
        var query = Query().Where(c => c.Id == id);

        if (includeAccessTokens)
        {
            query = query.Include(c => c.AccessTokens.Where(t => t.IsActive && !t.IsRevoked));
        }

        if (includeRefreshTokens)
        {
            query = query.Include(c => c.RefreshTokens.Where(t => t.IsActive));
        }

        query = query.Include(c => c.PlatformApplication);

        return await query.FirstOrDefaultAsync();
    }

    #endregion

    #region 고급 조회 메서드

    /// <summary>
    /// 클라이언트 타입별 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetByClientTypeAsync(
        Guid organizationId,
        OAuthClientType clientType)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId && 
                       c.ClientType == clientType &&
                       c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// PKCE 필수 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetPkceRequiredClientsAsync(Guid organizationId)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.RequirePkce &&
                       c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// 오프라인 액세스 허용 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetOfflineAccessClientsAsync(Guid organizationId)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.AllowOfflineAccess &&
                       c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// 최근 사용된 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetRecentlyUsedClientsAsync(
        Guid organizationId,
        int days = 30,
        int limit = 10)
    {
        var since = DateTime.UtcNow.AddDays(-days);

        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.LastUsedAt >= since &&
                       c.IsActive)
            .OrderByDescending(c => c.LastUsedAt)
            .Take(limit)
            .Include(c => c.PlatformApplication)
            .ToListAsync();
    }

    /// <summary>
    /// 사용되지 않는 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetUnusedClientsAsync(
        Guid organizationId,
        int inactiveDays = 90)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       (c.LastUsedAt == null || c.LastUsedAt < cutoffDate))
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 검색 및 필터링

    /// <summary>
    /// 클라이언트 검색
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> SearchClientsAsync(
        Guid organizationId,
        string searchTerm,
        bool? isActive = null,
        OAuthClientType? clientType = null,
        int limit = 50)
    {
        var query = Query().Where(c => c.OrganizationId == organizationId);

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(c => 
                c.ClientName.Contains(searchTerm) ||
                c.ClientId.Contains(searchTerm) ||
                (c.Description != null && c.Description.Contains(searchTerm)));
        }

        if (isActive.HasValue)
        {
            query = query.Where(c => c.IsActive == isActive.Value);
        }

        if (clientType.HasValue)
        {
            query = query.Where(c => c.ClientType == clientType.Value);
        }

        return await query
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .Take(limit)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 스코프를 가진 클라이언트 조회
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetClientsWithScopeAsync(
        Guid organizationId,
        string scope)
    {
        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.IsActive &&
                       c.AllowedScopes.Contains(scope))
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 통계 및 분석

    /// <summary>
    /// 조직의 OAuth 클라이언트 통계
    /// </summary>
    public async Task<OAuthClientStatistics> GetClientStatisticsAsync(Guid organizationId)
    {
        var clients = await Query()
            .Where(c => c.OrganizationId == organizationId)
            .ToListAsync();

        var stats = new OAuthClientStatistics
        {
            TotalClients = clients.Count,
            ActiveClients = clients.Count(c => c.IsActive),
            InactiveClients = clients.Count(c => !c.IsActive),
            ConfidentialClients = clients.Count(c => c.ClientType == OAuthClientType.Confidential),
            PublicClients = clients.Count(c => c.ClientType == OAuthClientType.Public),
            PkceRequiredClients = clients.Count(c => c.RequirePkce),
            OfflineAccessClients = clients.Count(c => c.AllowOfflineAccess)
        };

        // 최근 사용 통계
        var recentlyUsed = clients.Where(c => c.LastUsedAt >= DateTime.UtcNow.AddDays(-30)).Count();
        stats.RecentlyUsedClients = recentlyUsed;

        return stats;
    }

    /// <summary>
    /// Grant Type 사용 분포
    /// </summary>
    public async Task<Dictionary<string, int>> GetGrantTypeDistributionAsync(Guid organizationId)
    {
        var clients = await Query()
            .Where(c => c.OrganizationId == organizationId && c.IsActive)
            .Select(c => c.AllowedGrantTypes)
            .ToListAsync();

        var grantTypeCount = new Dictionary<string, int>();

        foreach (var allowedGrantTypes in clients)
        {
            try
            {
                var grantTypes = JsonSerializer.Deserialize<List<string>>(allowedGrantTypes);
                if (grantTypes != null)
                {
                    foreach (var grantType in grantTypes)
                    {
                        grantTypeCount[grantType] = grantTypeCount.GetValueOrDefault(grantType) + 1;
                    }
                }
            }
            catch (JsonException)
            {
                // JSON 파싱 실패 시 무시
                continue;
            }
        }

        return grantTypeCount;
    }

    #endregion

    #region 유지보수 메서드

    /// <summary>
    /// 비활성 클라이언트 정리
    /// </summary>
    public async Task<int> CleanupInactiveClientsAsync(
        Guid organizationId,
        int inactiveDays = 180)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

        var inactiveClients = await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       !c.IsActive &&
                       c.CreatedAt < cutoffDate)
            .ToListAsync();

        if (!inactiveClients.Any()) return 0;

        await DeleteRangeAsync(inactiveClients);
        return inactiveClients.Count;
    }

    /// <summary>
    /// 클라이언트 일괄 비활성화
    /// </summary>
    public async Task<int> BulkDeactivateClientsAsync(IEnumerable<Guid> clientIds)
    {
        var clients = await Query()
            .Where(c => clientIds.Contains(c.Id))
            .ToListAsync();

        foreach (var client in clients)
        {
            client.IsActive = false;
        }

        if (clients.Any())
        {
            await UpdateRangeAsync(clients);
        }

        return clients.Count;
    }

    #endregion

    #region 보안 관련

    /// <summary>
    /// 의심스러운 클라이언트 활동 감지
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> DetectSuspiciousClientsAsync(
        Guid organizationId,
        int unusualActivityThreshold = 1000)
    {
        // 실제 구현에서는 AccessTokens와의 관계를 통해 
        // 비정상적으로 많은 토큰을 발행한 클라이언트를 찾아야 함
        
        return await Query()
            .Where(c => c.OrganizationId == organizationId && c.IsActive)
            .Include(c => c.AccessTokens)
            .Where(c => c.AccessTokens.Count > unusualActivityThreshold)
            .Include(c => c.PlatformApplication)
            .ToListAsync();
    }

    /// <summary>
    /// 클라이언트 시크릿 순환 필요 여부 확인
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetClientsNeedingSecretRotationAsync(
        Guid organizationId,
        int rotationDays = 90)
    {
        var rotationDate = DateTime.UtcNow.AddDays(-rotationDays);

        return await Query()
            .Where(c => c.OrganizationId == organizationId &&
                       c.ClientType == OAuthClientType.Confidential &&
                       c.IsActive &&
                       c.UpdatedAt < rotationDate)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.UpdatedAt)
            .ToListAsync();
    }

    #endregion
}

/// <summary>
/// OAuth 클라이언트 통계 DTO
/// </summary>
public class OAuthClientStatistics
{
    public int TotalClients { get; set; }
    public int ActiveClients { get; set; }
    public int InactiveClients { get; set; }
    public int ConfidentialClients { get; set; }
    public int PublicClients { get; set; }
    public int PkceRequiredClients { get; set; }
    public int OfflineAccessClients { get; set; }
    public int RecentlyUsedClients { get; set; }
}