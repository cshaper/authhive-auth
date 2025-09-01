using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Auth.Data.Context;
using System.Security.Claims;

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
                    var validationResult = await tokenProvider.ValidateAccessTokenAsync(token);

                    if (validationResult.IsSuccess && validationResult.Data != null)
                    {
                        var claimsPrincipal = validationResult.Data;
                        context.User = claimsPrincipal;

                        // Claims에서 ID들 추출
                        var userIdClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                                         claimsPrincipal.FindFirst("sub");
                        var connectedIdClaim = claimsPrincipal.FindFirst("connected_id");
                        var orgIdClaim = claimsPrincipal.FindFirst("org_id");
                        var sessionIdClaim = claimsPrincipal.FindFirst("session_id");

                        // AuthDbContext에 현재 컨텍스트 설정
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
                        _logger.LogWarning("Token validation failed: {ErrorMessage}", validationResult.ErrorMessage);
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