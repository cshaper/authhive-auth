using AuthHive.Core.Interfaces.Auth.Provider;
using System.Security.Claims;
using System; // Exception
using System.Linq; // FirstOrDefault
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AuthHive.Infra.Persistence.Context;

namespace AuthHive.Auth.Middleware
{
    public class PasetoAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _serviceScopeFactory;
        private readonly ILogger<PasetoAuthenticationMiddleware> _logger;

        public PasetoAuthenticationMiddleware(
            RequestDelegate next,
            IServiceScopeFactory serviceScopeFactory,
            ILogger<PasetoAuthenticationMiddleware> logger)
        {
            _next = next;
            _serviceScopeFactory = serviceScopeFactory;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var token = ExtractTokenFromHeader(context.Request);

            if (!string.IsNullOrEmpty(token))
            {
                using var scope = _serviceScopeFactory.CreateScope();
                var tokenProvider = scope.ServiceProvider.GetRequiredService<ITokenProvider>();
                var authDbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

                try
                {
                    // [Fix CS1061] 메서드 이름 수정 (ValidateAccessTokenAsync -> ValidateTokenAsync)
                    // [Fix Logic] 반환 타입 변경 대응 (Result<T> -> ClaimsPrincipal?)
                    var claimsPrincipal = await tokenProvider.ValidateTokenAsync(token);

                    if (claimsPrincipal != null)
                    {
                        context.User = claimsPrincipal;

                        // Claims에서 ID들 추출
                        var userIdClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                                          claimsPrincipal.FindFirst("sub");
                        var connectedIdClaim = claimsPrincipal.FindFirst("connected_id");
                        var orgIdClaim = claimsPrincipal.FindFirst("org_id");
                        
                        // (필요하다면 session_id도 추출)
                        // var sessionIdClaim = claimsPrincipal.FindFirst("session_id");

                        // AuthDbContext에 현재 컨텍스트 설정 (RLS)
                        if (Guid.TryParse(connectedIdClaim?.Value, out var connectedId))
                        {
                            authDbContext.CurrentConnectedId = connectedId;
                            _logger.LogDebug("Set CurrentConnectedId: {ConnectedId}", connectedId);
                        }

                        if (Guid.TryParse(orgIdClaim?.Value, out var orgId) && orgId != Guid.Empty)
                        {
                            authDbContext.CurrentOrganizationId = orgId;
                            _logger.LogDebug("Set CurrentOrganizationId: {OrganizationId}", orgId);
                        }

                        _logger.LogDebug("Token validated successfully for user: {UserId}", userIdClaim?.Value);
                    }
                    else
                    {
                        _logger.LogWarning("Token validation failed: Invalid token or signature.");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during token validation");
                }
            }

            await _next(context);
        }

        private string? ExtractTokenFromHeader(HttpRequest request)
        {
            var authHeader = request.Headers.Authorization.FirstOrDefault();
            
            if (string.IsNullOrEmpty(authHeader))
                return null;

            if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return authHeader["Bearer ".Length..].Trim();

            return null;
        }
    }
}