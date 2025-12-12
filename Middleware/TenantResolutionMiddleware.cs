// Path: AuthHive.Auth/Middleware/TenantResolutionMiddleware.cs
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.ConnectedId; 
using AuthHive.Infra.Persistence.Context;

namespace AuthHive.Auth.Middleware
{
    /// <summary>
    /// 멀티테넌트 컨텍스트 결정 미들웨어
    /// <br/>
    /// 역할: 요청 헤더나 토큰에서 OrganizationId와 ConnectedId를 추출하고,
    /// 유효성을 검증한 후 DbContext와 HttpContext에 테넌트 정보를 설정합니다.
    /// </summary>
    public class TenantResolutionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _serviceScopeFactory;
        private readonly ILogger<TenantResolutionMiddleware> _logger;

        public TenantResolutionMiddleware(
            RequestDelegate next,
            IServiceScopeFactory serviceScopeFactory,
            ILogger<TenantResolutionMiddleware> logger)
        {
            _next = next;
            _serviceScopeFactory = serviceScopeFactory;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // 미들웨어는 싱글톤이지만 DbContext는 Scoped이므로 스코프 생성 필요
            using var scope = _serviceScopeFactory.CreateScope();
            var authDbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            
            // ✅ 변경: 읽기 작업만 수행하므로 Query Repository 주입
            var connectedIdQueryRepository = scope.ServiceProvider.GetRequiredService<IConnectedIdQueryRepository>();

            try
            {
                // 1. 토큰(Claims)에서 정보 추출
                var orgIdFromToken = GetOrganizationIdFromClaims(context.User);
                var connectedIdFromToken = GetConnectedIdFromClaims(context.User);

                // 2. 헤더에서 조직 컨텍스트 추출 (클라이언트가 명시적으로 요청한 경우)
                var orgIdFromHeader = GetOrganizationIdFromHeaders(context.Request);

                // 3. 우선순위에 따른 최종 조직 ID 결정 (토큰 > 헤더)
                // 보안상 토큰에 박힌 OrgId가 있다면 그것을 신뢰합니다.
                var resolvedOrgId = ResolveOrganizationId(orgIdFromToken, orgIdFromHeader);

                // 4. ConnectedId 유효성 및 멤버십 검증 (보안 핵심)
                if (connectedIdFromToken.HasValue && resolvedOrgId.HasValue)
                {
                    // 해당 ConnectedId가 실제로 그 조직에 속해 있는지 DB 조회
                    var isValidMembership = await ValidateConnectedIdMembership(
                        connectedIdQueryRepository, 
                        connectedIdFromToken.Value, 
                        resolvedOrgId.Value);

                    if (!isValidMembership)
                    {
                        _logger.LogWarning(
                            "Security Alert: Invalid membership attempt. ConnectedId {ConnectedId} is not a member of Organization {OrganizationId}", 
                            connectedIdFromToken, resolvedOrgId);
                        
                        context.Response.StatusCode = 403; // Forbidden
                        await context.Response.WriteAsync("Forbidden: Invalid organization membership configuration.");
                        return; // 파이프라인 중단
                    }
                }

                // 5. 컨텍스트 설정 (Global Filters 및 Controller에서 사용)
                
                // 5-1. 조직 ID 설정
                if (resolvedOrgId.HasValue)
                {
                    authDbContext.CurrentOrganizationId = resolvedOrgId.Value;
                    context.Items["CurrentOrganizationId"] = resolvedOrgId.Value;
                    
                    _logger.LogDebug("Tenant Context Resolved: OrganizationId={OrganizationId}", resolvedOrgId);
                }

                // 5-2. Connected ID 설정
                if (connectedIdFromToken.HasValue)
                {
                    authDbContext.CurrentConnectedId = connectedIdFromToken.Value;
                    context.Items["CurrentConnectedId"] = connectedIdFromToken.Value;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Critical Error during tenant resolution middleware execution.");
                // 심각한 에러가 발생해도 인증이 없는 엔드포인트(로그인 등)를 위해 진행할지,
                // 아니면 여기서 500을 낼지 결정해야 함. 보통은 로그만 남기고 진행하되, 
                // 이후 로직에서 OrgId가 없으면 에러가 날 것임.
            }

            // 다음 미들웨어로 진행
            await _next(context);
        }

        // --- Helper Methods ---

        private Guid? GetOrganizationIdFromClaims(ClaimsPrincipal user)
        {
            var orgIdClaim = user.FindFirst("org_id");
            if (orgIdClaim != null && Guid.TryParse(orgIdClaim.Value, out var orgId) && orgId != Guid.Empty)
            {
                return orgId;
            }
            return null;
        }

        private Guid? GetConnectedIdFromClaims(ClaimsPrincipal user)
        {
            var connectedIdClaim = user.FindFirst("connected_id");
            if (connectedIdClaim != null && Guid.TryParse(connectedIdClaim.Value, out var connectedId))
            {
                return connectedId;
            }
            return null;
        }

        private Guid? GetOrganizationIdFromHeaders(HttpRequest request)
        {
            // X-Organization-Id 헤더 확인 (주로 로그인 전이나 토큰 없이 조회할 때 사용될 수 있음)
            var orgHeader = request.Headers["X-Organization-Id"].FirstOrDefault();
            if (!string.IsNullOrEmpty(orgHeader) && Guid.TryParse(orgHeader, out var orgId))
            {
                return orgId;
            }
            return null;
        }

        private Guid? ResolveOrganizationId(Guid? fromToken, Guid? fromHeader)
        {
            // 토큰에 있는 정보가 가장 강력한 신뢰성을 가짐
            return fromToken ?? fromHeader;
        }

        private async Task<bool> ValidateConnectedIdMembership(
            IConnectedIdQueryRepository connectedIdRepository, // ✅ Query Repository 사용
            Guid connectedId, 
            Guid organizationId)
        {
            try
            {
                // IReadRepository의 GetByIdAsync 사용 (Tracking 없음)
                var connectedIdEntity = await connectedIdRepository.GetByIdAsync(connectedId);
                
                if (connectedIdEntity == null)
                {
                    _logger.LogWarning("Tenant Resolution: ConnectedId {ConnectedId} not found in database.", connectedId);
                    return false;
                }

                // 엔티티의 소속 조직 ID와 요청된 조직 ID가 일치하는지 확인
                return connectedIdEntity.OrganizationId == organizationId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Tenant Resolution: Error validating ConnectedId membership.");
                return false; // 검증 실패로 간주하여 안전하게 차단
            }
        }
    }
}