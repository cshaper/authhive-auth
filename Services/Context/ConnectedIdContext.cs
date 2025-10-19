using System;
using System.Linq;
using System.Security.Claims;
using AuthHive.Core.Interfaces.Base;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// 현재 요청의 사용자(ConnectedId) 컨텍스트 구현 - AuthHive v15
    /// JWT 토큰 또는 HTTP 헤더에서 사용자 정보를 추출하여 제공합니다.
    /// </summary>
    public class ConnectedIdContext : IConnectedIdContext
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<ConnectedIdContext> _logger;
        private Guid? _connectedId;
        private bool _connectedIdResolved;

        public ConnectedIdContext(
            IHttpContextAccessor httpContextAccessor,
            ILogger<ConnectedIdContext> logger)
        {
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 현재 요청을 수행하는 ConnectedId
        /// </summary>
        public Guid? ConnectedId
        {
            get
            {
                if (!_connectedIdResolved)
                {
                    _connectedId = ResolveConnectedId();
                    _connectedIdResolved = true;
                }

                return _connectedId;
            }
        }

        /// <summary>
        /// 인증된 사용자인지 여부
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext == null)
                    return false;

                // 1. 표준 인증 확인
                if (httpContext.User?.Identity?.IsAuthenticated == true)
                    return true;

                // 2. ConnectedId가 있는지 확인
                if (ConnectedId.HasValue)
                    return true;

                // 3. API Key 인증 확인
                if (httpContext.Request.Headers.ContainsKey("X-API-Key"))
                    return true;

                return false;
            }
        }
        /// <summary>
        /// 현재 컨텍스트에 유효한 ConnectedId가 있는지 여부를 확인합니다.
        /// </summary>
        public bool HasConnectedId => ConnectedId.HasValue;
        /// <summary>
        /// ConnectedId를 해결하는 내부 메서드
        /// 우선순위: JWT Claims > HTTP Headers > API Key Context
        /// </summary>
        private Guid? ResolveConnectedId()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                _logger.LogWarning("HttpContext is null. Cannot resolve ConnectedId context.");
                return null;
            }

            // 1. JWT 클레임에서 추출 (가장 우선순위 높음)
            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                // connected_id 클레임 확인 (다양한 형식 지원)
                var connectedIdClaim = httpContext.User.FindFirst("connected_id")
                    ?? httpContext.User.FindFirst("ConnectedId")
                    ?? httpContext.User.FindFirst("sub")  // OpenID Connect subject
                    ?? httpContext.User.FindFirst(ClaimTypes.NameIdentifier)
                    ?? httpContext.User.FindFirst("user_id");

                if (connectedIdClaim != null && Guid.TryParse(connectedIdClaim.Value, out var connIdFromClaim))
                {
                    _logger.LogDebug("ConnectedId {ConnectedId} resolved from JWT claim", connIdFromClaim);
                    return connIdFromClaim;
                }

                // 사용자 이름으로부터 ConnectedId 조회가 필요한 경우
                var usernameClaim = httpContext.User.FindFirst(ClaimTypes.Name)
                    ?? httpContext.User.FindFirst("username")
                    ?? httpContext.User.FindFirst("email");

                if (usernameClaim != null)
                {
                    _logger.LogDebug("Username {Username} found in claims, but ConnectedId lookup required", usernameClaim.Value);
                    // TODO: Repository를 통해 username으로 ConnectedId 조회
                    // 순환 의존성을 피하기 위해 별도 서비스로 처리 필요
                }
            }

            // 2. HTTP 헤더에서 추출
            if (httpContext.Request.Headers.TryGetValue("X-Connected-Id", out var connectedHeader))
            {
                var headerValue = connectedHeader.FirstOrDefault();
                if (!string.IsNullOrEmpty(headerValue) && Guid.TryParse(headerValue, out var connIdFromHeader))
                {
                    _logger.LogDebug("ConnectedId {ConnectedId} resolved from HTTP header", connIdFromHeader);
                    return connIdFromHeader;
                }
            }

            // 3. API Key 컨텍스트에서 추출
            if (httpContext.Items.TryGetValue("ConnectedId", out var contextValue))
            {
                if (contextValue is Guid connIdFromContext)
                {
                    _logger.LogDebug("ConnectedId {ConnectedId} resolved from API key context", connIdFromContext);
                    return connIdFromContext;
                }
            }

            // 4. 세션에서 추출 (선택적)
            if (httpContext.Session != null)
            {
                try
                {
                    var sessionConnectedId = httpContext.Session.GetString("ConnectedId");
                    if (!string.IsNullOrEmpty(sessionConnectedId) && Guid.TryParse(sessionConnectedId, out var connIdFromSession))
                    {
                        _logger.LogDebug("ConnectedId {ConnectedId} resolved from session", connIdFromSession);
                        return connIdFromSession;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to read ConnectedId from session");
                }
            }

            // 5. 쿠키에서 추출 (선택적)
            if (httpContext.Request.Cookies.TryGetValue("connected_id", out var cookieValue))
            {
                if (!string.IsNullOrEmpty(cookieValue) && Guid.TryParse(cookieValue, out var connIdFromCookie))
                {
                    _logger.LogDebug("ConnectedId {ConnectedId} resolved from cookie", connIdFromCookie);
                    return connIdFromCookie;
                }
            }

            _logger.LogDebug("Could not resolve ConnectedId from any source");
            return null;
        }

        /// <summary>
        /// ConnectedId를 특정 값으로 설정 (테스트 또는 특수 시나리오용)
        /// </summary>
        public void SetConnectedId(Guid? connectedId)
        {
            _connectedId = connectedId;
            _connectedIdResolved = true;
            
            if (connectedId.HasValue)
            {
                _logger.LogInformation("ConnectedId context manually set to {ConnectedId}", connectedId.Value);
            }
            else
            {
                _logger.LogInformation("ConnectedId context manually cleared");
            }
        }

        /// <summary>
        /// ConnectedId 컨텍스트 초기화
        /// </summary>
        public void Clear()
        {
            _connectedId = null;
            _connectedIdResolved = false;
            _logger.LogDebug("ConnectedId context cleared");
        }

        /// <summary>
        /// 현재 사용자의 역할 확인
        /// </summary>
        public bool IsInRole(string role)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User == null)
                return false;

            return httpContext.User.IsInRole(role);
        }

        /// <summary>
        /// 현재 사용자의 특정 클레임 값 가져오기
        /// </summary>
        public string? GetClaimValue(string claimType)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User == null)
                return null;

            var claim = httpContext.User.FindFirst(claimType);
            return claim?.Value;
        }
    }

    /// <summary>
    /// Session 확장 메서드
    /// </summary>
    public static class SessionExtensions
    {
        public static void SetString(this ISession session, string key, string value)
        {
            session.Set(key, System.Text.Encoding.UTF8.GetBytes(value));
        }

        public static string? GetString(this ISession session, string key)
        {
            var data = session.Get(key);
            if (data == null)
                return null;
            
            return System.Text.Encoding.UTF8.GetString(data);
        }

        public static byte[]? Get(this ISession session, string key)
        {
            session.TryGetValue(key, out byte[]? value);
            return value;
        }
    }
}