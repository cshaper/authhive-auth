using System;
using System.Linq;
using System.Security.Claims;
using AuthHive.Core.Interfaces.Base;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// 현재 요청의 조직 컨텍스트 구현 - AuthHive v15
    /// JWT 토큰 또는 HTTP 헤더에서 조직 정보를 추출하여 제공합니다.
    /// </summary>
    public class OrganizationContext : IOrganizationContext
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<OrganizationContext> _logger;
        private Guid? _organizationId;
        private bool _organizationIdResolved;

        public OrganizationContext(
            IHttpContextAccessor httpContextAccessor,
            ILogger<OrganizationContext> logger)
        {
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 현재 요청을 처리 중인 조직의 ID
        /// </summary>
        public Guid OrganizationId
        {
            get
            {
                if (!_organizationIdResolved)
                {
                    _organizationId = ResolveOrganizationId();
                    _organizationIdResolved = true;
                }

                if (!_organizationId.HasValue)
                {
                    _logger.LogError("Organization context not found in the current request");
                    throw new UnauthorizedAccessException("Organization context not found. Please ensure you are authenticated with a valid organization.");
                }

                return _organizationId.Value;
            }
        }
        public Guid? CurrentOrganizationId => HasOrganization ? OrganizationId : null;
        /// <summary>
        /// 조직이 설정되어 있는지 여부
        /// </summary>
        public bool HasOrganization
        {
            get
            {
                if (!_organizationIdResolved)
                {
                    _organizationId = ResolveOrganizationId();
                    _organizationIdResolved = true;
                }

                return _organizationId.HasValue;
            }
        }

        /// <summary>
        /// 조직 ID를 해결하는 내부 메서드
        /// 우선순위: JWT Claims > HTTP Headers > Route Values > Query String
        /// </summary>
        private Guid? ResolveOrganizationId()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                _logger.LogWarning("HttpContext is null. Cannot resolve organization context.");
                return null;
            }

            // 1. JWT 클레임에서 추출 (가장 우선순위 높음)
            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                // org_id 클레임 확인
                var orgIdClaim = httpContext.User.FindFirst("org_id")
                    ?? httpContext.User.FindFirst("organization_id")
                    ?? httpContext.User.FindFirst(ClaimTypes.GroupSid)
                    ?? httpContext.User.FindFirst("OrganizationId");

                if (orgIdClaim != null && Guid.TryParse(orgIdClaim.Value, out var orgIdFromClaim))
                {
                    _logger.LogDebug("Organization ID {OrganizationId} resolved from JWT claim", orgIdFromClaim);
                    return orgIdFromClaim;
                }
            }

            // 2. HTTP 헤더에서 추출
            if (httpContext.Request.Headers.TryGetValue("X-Organization-Id", out var orgHeader))
            {
                var headerValue = orgHeader.FirstOrDefault();
                if (!string.IsNullOrEmpty(headerValue) && Guid.TryParse(headerValue, out var orgIdFromHeader))
                {
                    _logger.LogDebug("Organization ID {OrganizationId} resolved from HTTP header", orgIdFromHeader);
                    return orgIdFromHeader;
                }
            }

            // 3. Route 값에서 추출 (예: /api/organizations/{organizationId}/...)
            if (httpContext.Request.RouteValues.TryGetValue("organizationId", out var routeValue))
            {
                if (routeValue != null && Guid.TryParse(routeValue.ToString(), out var orgIdFromRoute))
                {
                    _logger.LogDebug("Organization ID {OrganizationId} resolved from route", orgIdFromRoute);
                    return orgIdFromRoute;
                }
            }

            // 4. Query String에서 추출 (예: ?organizationId=...)
            if (httpContext.Request.Query.TryGetValue("organizationId", out var queryValue))
            {
                var queryString = queryValue.FirstOrDefault();
                if (!string.IsNullOrEmpty(queryString) && Guid.TryParse(queryString, out var orgIdFromQuery))
                {
                    _logger.LogDebug("Organization ID {OrganizationId} resolved from query string", orgIdFromQuery);
                    return orgIdFromQuery;
                }
            }

            // 5. 쿠키에서 추출 (선택적)
            if (httpContext.Request.Cookies.TryGetValue("organization_id", out var cookieValue))
            {
                if (!string.IsNullOrEmpty(cookieValue) && Guid.TryParse(cookieValue, out var orgIdFromCookie))
                {
                    _logger.LogDebug("Organization ID {OrganizationId} resolved from cookie", orgIdFromCookie);
                    return orgIdFromCookie;
                }
            }

            _logger.LogDebug("Could not resolve organization ID from any source");
            return null;
        }

        /// <summary>
        /// 조직 컨텍스트를 특정 값으로 설정 (테스트 또는 특수 시나리오용)
        /// </summary>
        public void SetOrganizationId(Guid organizationId)
        {
            _organizationId = organizationId;
            _organizationIdResolved = true;
            _logger.LogInformation("Organization context manually set to {OrganizationId}", organizationId);
        }

        /// <summary>
        /// 조직 컨텍스트 초기화
        /// </summary>
        public void Clear()
        {
            _organizationId = null;
            _organizationIdResolved = false;
            _logger.LogDebug("Organization context cleared");
        }
    }
}