using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories;

/// <summary>
/// OAuth Client Repository - OAuth 클라이언트 관리 Repository
/// AuthHive v15 OAuth 2.0 클라이언트 애플리케이션 관리 시스템
/// 
/// BaseRepository를 상속받아 기본 CRUD, 캐싱, 조직 스코프 기능을 자동으로 제공받음
/// </summary>
public class OAuthClientRepository : BaseRepository<OAuthClient>, IOAuthClientRepository
{
    // JSON 직렬화 옵션 (성능 최적화)
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public OAuthClientRepository(
        AuthDbContext context, 
        IOrganizationContext organizationContext,
        IMemoryCache? cache = null) 
        : base(context, organizationContext, cache)
    {
    }

    #region 기본 조회 - BaseRepository 기능 활용

    /// <summary>
    /// 클라이언트 ID로 조회 (캐시 활용)
    /// OAuth 인증 플로우에서 가장 빈번하게 호출되므로 캐싱이 중요
    /// </summary>
    public async Task<OAuthClient?> GetByClientIdAsync(string clientId)
    {
        // 캐시 키 생성
        string cacheKey = $"OAuthClient:ClientId:{clientId}";
        
        if (_cache != null && _cache.TryGetValue(cacheKey, out OAuthClient? cachedClient))
        {
            return cachedClient;
        }

        var client = await Query()
            .Include(c => c.PlatformApplication)
            .FirstOrDefaultAsync(c => c.ClientId == clientId);

        // 캐시 저장 (15분 유지)
        if (client != null && _cache != null)
        {
            _cache.Set(cacheKey, client, TimeSpan.FromMinutes(15));
        }

        return client;
    }

    /// <summary>
    /// 애플리케이션별 OAuth 클라이언트 조회
    /// 애플리케이션 설정 페이지에서 사용
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
    /// 대시보드 및 관리 페이지에서 사용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetActiveClientsAsync(Guid organizationId)
    {
        // BaseRepository의 QueryForOrganization 활용
        return await QueryForOrganization(organizationId)
            .Where(c => c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// Grant Type별 클라이언트 조회
    /// 보안 감사 및 정책 관리에서 사용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetByGrantTypeAsync(
        Guid organizationId,
        OAuthGrantType grantType)
    {
        var grantTypeString = grantType.ToString();

        return await QueryForOrganization(organizationId)
            .Where(c => c.IsActive && c.AllowedGrantTypes.Contains(grantTypeString))
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 검증 메서드 - 보안 핵심 로직

    /// <summary>
    /// 클라이언트 시크릿 검증 (캐시 활용으로 성능 개선)
    /// 토큰 엔드포인트에서 매번 호출되므로 성능이 중요
    /// </summary>
    public async Task<bool> ValidateClientSecretAsync(string clientId, string clientSecretHash)
    {
        var client = await GetByClientIdAsync(clientId); // 캐시된 메서드 활용
        
        if (client == null || !client.IsActive) 
            return false;

        // Public 클라이언트는 시크릿 불필요
        if (client.ClientType == OAuthClientType.Public && !client.RequireClientSecret)
            return true;

        // Confidential 클라이언트는 시크릿 필수
        return !string.IsNullOrEmpty(client.ClientSecretHash) && 
               client.ClientSecretHash == clientSecretHash;
    }

    /// <summary>
    /// 리다이렉트 URI 유효성 검증
    /// Authorization Code 플로우에서 CSRF 공격 방지
    /// </summary>
    public async Task<bool> IsRedirectUriValidAsync(string clientId, string redirectUri)
    {
        var client = await GetByClientIdAsync(clientId); // 캐시 활용
        
        if (client?.RedirectUris == null) 
            return false;

        try
        {
            var allowedUris = JsonSerializer.Deserialize<List<string>>(
                client.RedirectUris, _jsonOptions);
            
            // 대소문자 구분 없이 정확한 매칭 필요
            return allowedUris?.Contains(redirectUri, StringComparer.OrdinalIgnoreCase) ?? false;
        }
        catch (JsonException)
        {
            // JSON 파싱 실패는 보안상 거부
            return false;
        }
    }

    /// <summary>
    /// 스코프 유효성 검증
    /// 클라이언트가 요청한 권한이 허용 범위 내인지 확인
    /// </summary>
    public async Task<bool> AreScopesAllowedAsync(string clientId, List<string> scopes)
    {
        var client = await GetByClientIdAsync(clientId); // 캐시 활용
        
        if (client?.AllowedScopes == null) 
            return false;

        try
        {
            var allowedScopes = JsonSerializer.Deserialize<List<string>>(
                client.AllowedScopes, _jsonOptions);
            
            if (allowedScopes == null) 
                return false;

            // 모든 요청 스코프가 허용 목록에 있어야 함
            return scopes.All(scope => 
                allowedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase));
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
    /// 클라이언트 활동 추적 및 비활성 클라이언트 감지용
    /// </summary>
    public async Task UpdateLastUsedAsync(Guid clientId)
    {
        var client = await GetByIdAsync(clientId);
        if (client != null)
        {
            client.LastUsedAt = DateTime.UtcNow;
            await UpdateAsync(client); // BaseRepository의 캐시 무효화 자동 처리
        }
    }

    #endregion

    #region 관계 데이터 포함 조회

    /// <summary>
    /// 관련 토큰 데이터 포함 조회
    /// 클라이언트 상세 페이지에서 토큰 현황 표시용
    /// </summary>
    public async Task<OAuthClient?> GetWithTokensAsync(
        Guid id,
        bool includeAccessTokens = false,
        bool includeRefreshTokens = false)
    {
        var query = Query().Where(c => c.Id == id);

        // 활성 토큰만 포함 (성능 최적화)
        if (includeAccessTokens)
        {
            query = query.Include(c => c.AccessTokens
                .Where(t => t.IsActive && !t.IsRevoked));
        }

        if (includeRefreshTokens)
        {
            query = query.Include(c => c.RefreshTokens
                .Where(t => t.IsActive));
        }

        query = query.Include(c => c.PlatformApplication);

        return await query.FirstOrDefaultAsync();
    }

    #endregion

    #region 고급 조회 메서드

    /// <summary>
    /// 클라이언트 타입별 조회
    /// 보안 정책 적용 및 감사용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetByClientTypeAsync(
        Guid organizationId,
        OAuthClientType clientType)
    {
        return await QueryForOrganization(organizationId)
            .Where(c => c.ClientType == clientType && c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// PKCE 필수 클라이언트 조회
    /// Public 클라이언트 보안 강화 정책 관리
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetPkceRequiredClientsAsync(Guid organizationId)
    {
        return await QueryForOrganization(organizationId)
            .Where(c => c.RequirePkce && c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// 오프라인 액세스 허용 클라이언트 조회
    /// Refresh Token 정책 관리용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetOfflineAccessClientsAsync(Guid organizationId)
    {
        return await QueryForOrganization(organizationId)
            .Where(c => c.AllowOfflineAccess && c.IsActive)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    /// <summary>
    /// 최근 사용된 클라이언트 조회
    /// 대시보드 위젯 및 활동 모니터링용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetRecentlyUsedClientsAsync(
        Guid organizationId,
        int days = 30,
        int limit = 10)
    {
        var since = DateTime.UtcNow.AddDays(-days);

        return await QueryForOrganization(organizationId)
            .Where(c => c.LastUsedAt >= since && c.IsActive)
            .OrderByDescending(c => c.LastUsedAt)
            .Take(limit)
            .Include(c => c.PlatformApplication)
            .ToListAsync();
    }

    /// <summary>
    /// 사용되지 않는 클라이언트 조회
    /// 정리 대상 식별 및 보안 감사용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetUnusedClientsAsync(
        Guid organizationId,
        int inactiveDays = 90)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

        return await QueryForOrganization(organizationId)
            .Where(c => c.LastUsedAt == null || c.LastUsedAt < cutoffDate)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 검색 및 필터링

    /// <summary>
    /// 클라이언트 검색
    /// 관리자 UI의 검색 기능 구현
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> SearchClientsAsync(
        Guid organizationId,
        string searchTerm,
        bool? isActive = null,
        OAuthClientType? clientType = null,
        int limit = 50)
    {
        var query = QueryForOrganization(organizationId);

        // 검색어 적용
        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(c => 
                c.ClientName.Contains(searchTerm) ||
                c.ClientId.Contains(searchTerm) ||
                (c.Description != null && c.Description.Contains(searchTerm)));
        }

        // 필터 적용
        if (isActive.HasValue)
            query = query.Where(c => c.IsActive == isActive.Value);

        if (clientType.HasValue)
            query = query.Where(c => c.ClientType == clientType.Value);

        return await query
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .Take(limit)
            .ToListAsync();
    }

    /// <summary>
    /// 특정 스코프를 가진 클라이언트 조회
    /// 권한 감사 및 정책 변경 영향 분석용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetClientsWithScopeAsync(
        Guid organizationId,
        string scope)
    {
        return await QueryForOrganization(organizationId)
            .Where(c => c.IsActive && c.AllowedScopes.Contains(scope))
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.ClientName)
            .ToListAsync();
    }

    #endregion

    #region 통계 및 분석 - BaseRepository의 GetGroupCountAsync 활용

    /// <summary>
    /// 조직의 OAuth 클라이언트 통계
    /// 대시보드 메인 화면 통계 위젯용
    /// </summary>
    public async Task<OAuthClientStatistics> GetClientStatisticsAsync(Guid organizationId)
    {
        // BaseRepository의 통계 기능 활용
        var clients = await QueryForOrganization(organizationId).ToListAsync();

        return new OAuthClientStatistics
        {
            TotalClients = clients.Count,
            ActiveClients = clients.Count(c => c.IsActive),
            InactiveClients = clients.Count(c => !c.IsActive),
            ConfidentialClients = clients.Count(c => c.ClientType == OAuthClientType.Confidential),
            PublicClients = clients.Count(c => c.ClientType == OAuthClientType.Public),
            PkceRequiredClients = clients.Count(c => c.RequirePkce),
            OfflineAccessClients = clients.Count(c => c.AllowOfflineAccess),
            RecentlyUsedClients = clients.Count(c => 
                c.LastUsedAt >= DateTime.UtcNow.AddDays(-30))
        };
    }

    /// <summary>
    /// Grant Type 사용 분포
    /// 보안 정책 수립을 위한 사용 패턴 분석
    /// </summary>
    public async Task<Dictionary<string, int>> GetGrantTypeDistributionAsync(Guid organizationId)
    {
        var clients = await QueryForOrganization(organizationId)
            .Where(c => c.IsActive)
            .Select(c => c.AllowedGrantTypes)
            .ToListAsync();

        var grantTypeCount = new Dictionary<string, int>();

        foreach (var allowedGrantTypes in clients)
        {
            try
            {
                var grantTypes = JsonSerializer.Deserialize<List<string>>(
                    allowedGrantTypes, _jsonOptions);
                
                if (grantTypes != null)
                {
                    foreach (var grantType in grantTypes)
                    {
                        grantTypeCount[grantType] = 
                            grantTypeCount.GetValueOrDefault(grantType) + 1;
                    }
                }
            }
            catch (JsonException)
            {
                // 손상된 데이터는 무시
                continue;
            }
        }

        return grantTypeCount;
    }

    #endregion

    #region 유지보수 메서드

    /// <summary>
    /// 비활성 클라이언트 정리
    /// 크론잡으로 주기적으로 실행하여 DB 정리
    /// </summary>
    public async Task<int> CleanupInactiveClientsAsync(
        Guid organizationId,
        int inactiveDays = 180)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

        var inactiveClients = await QueryForOrganization(organizationId)
            .Where(c => !c.IsActive && c.CreatedAt < cutoffDate)
            .ToListAsync();

        if (!inactiveClients.Any()) 
            return 0;

        // BaseRepository의 DeleteRangeAsync 활용 (캐시 자동 무효화)
        await DeleteRangeAsync(inactiveClients);
        await _context.SaveChangesAsync();
        
        return inactiveClients.Count;
    }

    /// <summary>
    /// 클라이언트 일괄 비활성화
    /// 보안 사고 시 긴급 대응용
    /// </summary>
    public async Task<int> BulkDeactivateClientsAsync(IEnumerable<Guid> clientIds)
    {
        var clientIdList = clientIds.ToList();
        var clients = await Query()
            .Where(c => clientIdList.Contains(c.Id))
            .ToListAsync();

        foreach (var client in clients)
        {
            client.IsActive = false;
            // 캐시 무효화를 위해 개별 업데이트
            await UpdateAsync(client);
        }

        await _context.SaveChangesAsync();
        return clients.Count;
    }

    #endregion

    #region 보안 관련

    /// <summary>
    /// 의심스러운 클라이언트 활동 감지
    /// 보안 모니터링 대시보드 및 알림 시스템용
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> DetectSuspiciousClientsAsync(
        Guid organizationId,
        int unusualActivityThreshold = 1000)
    {
        // 비정상적으로 많은 토큰을 발행한 클라이언트 감지
        return await QueryForOrganization(organizationId)
            .Where(c => c.IsActive)
            .Include(c => c.AccessTokens)
            .Where(c => c.AccessTokens.Count > unusualActivityThreshold)
            .Include(c => c.PlatformApplication)
            .ToListAsync();
    }

    /// <summary>
    /// 클라이언트 시크릿 순환 필요 여부 확인
    /// 보안 정책에 따른 주기적 시크릿 변경 알림
    /// </summary>
    public async Task<IEnumerable<OAuthClient>> GetClientsNeedingSecretRotationAsync(
        Guid organizationId,
        int rotationDays = 90)
    {
        var rotationDate = DateTime.UtcNow.AddDays(-rotationDays);

        return await QueryForOrganization(organizationId)
            .Where(c => c.ClientType == OAuthClientType.Confidential &&
                       c.IsActive &&
                       c.UpdatedAt < rotationDate)
            .Include(c => c.PlatformApplication)
            .OrderBy(c => c.UpdatedAt)
            .ToListAsync();
    }

    #endregion
}