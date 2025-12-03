using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Infra.Persistence.Context;
using System.Security.Claims;

namespace AuthHive.Auth.Middleware
{
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
           using var scope = _serviceScopeFactory.CreateScope();
           var authDbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
           var connectedIdRepository = scope.ServiceProvider.GetRequiredService<IConnectedIdRepository>();

           try
           {
               // 1. 토큰에서 추출된 정보 확인
               var orgIdFromToken = GetOrganizationIdFromClaims(context.User);
               var connectedIdFromToken = GetConnectedIdFromClaims(context.User);

               // 2. 헤더에서 조직 컨텍스트 추출 (선택적)
               var orgIdFromHeader = GetOrganizationIdFromHeaders(context.Request);

               // 3. 우선순위에 따른 조직 ID 결정
               var resolvedOrgId = ResolveOrganizationId(orgIdFromToken, orgIdFromHeader);

               // 4. ConnectedId 검증 및 조직 멤버십 확인
               if (connectedIdFromToken.HasValue && resolvedOrgId.HasValue)
               {
                   var isValidMembership = await ValidateConnectedIdMembership(
                       connectedIdRepository, 
                       connectedIdFromToken.Value, 
                       resolvedOrgId.Value);

                   if (!isValidMembership)
                   {
                       _logger.LogWarning("Invalid membership: ConnectedId {ConnectedId} not member of Organization {OrganizationId}", 
                           connectedIdFromToken, resolvedOrgId);
                       
                       // 403 Forbidden 응답
                       context.Response.StatusCode = 403;
                       await context.Response.WriteAsync("Forbidden: Invalid organization membership");
                       return;
                   }
               }

               // 5. AuthDbContext에 최종 조직 컨텍스트 설정
               if (resolvedOrgId.HasValue)
               {
                   authDbContext.CurrentOrganizationId = resolvedOrgId.Value;
                   _logger.LogDebug("Tenant resolved: OrganizationId = {OrganizationId}", resolvedOrgId);
                   
                   // HTTP Context에도 조직 정보 저장 (Controller에서 사용 가능)
                   context.Items["CurrentOrganizationId"] = resolvedOrgId.Value;
               }

               if (connectedIdFromToken.HasValue)
               {
                   authDbContext.CurrentConnectedId = connectedIdFromToken.Value;
                   context.Items["CurrentConnectedId"] = connectedIdFromToken.Value;
               }
           }
           catch (Exception ex)
           {
               _logger.LogError(ex, "Error during tenant resolution");
               // 에러가 발생해도 요청을 계속 진행 (기본값 사용)
           }

           await _next(context);
       }

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
           // X-Organization-Id 헤더에서 조직 ID 추출 (선택적)
           var orgHeader = request.Headers["X-Organization-Id"].FirstOrDefault();
           if (!string.IsNullOrEmpty(orgHeader) && Guid.TryParse(orgHeader, out var orgId))
           {
               return orgId;
           }
           return null;
       }

       private Guid? ResolveOrganizationId(Guid? fromToken, Guid? fromHeader)
       {
           // 우선순위: 토큰 > 헤더
           return fromToken ?? fromHeader;
       }

       private async Task<bool> ValidateConnectedIdMembership(
           IConnectedIdRepository connectedIdRepository, 
           Guid connectedId, 
           Guid organizationId)
       {
           try
           {
               // ConnectedId가 해당 조직의 멤버인지 확인
               var connectedIdEntity = await connectedIdRepository.GetByIdAsync(connectedId);
               
               if (connectedIdEntity == null)
               {
                   _logger.LogWarning("ConnectedId {ConnectedId} not found", connectedId);
                   return false;
               }

               return connectedIdEntity.OrganizationId == organizationId;
           }
           catch (Exception ex)
           {
               _logger.LogError(ex, "Error validating ConnectedId membership");
               return false;
           }
       }
   }
}