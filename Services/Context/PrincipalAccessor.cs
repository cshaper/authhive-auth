using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Base;
using Microsoft.AspNetCore.Http;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// IPrincipalAccessor의 구현체입니다. - v16 최종본
    /// IHttpContextAccessor를 통해 현재 HTTP 요청의 ClaimsPrincipal(인증된 사용자 정보)에 접근합니다.
    /// 이 클래스는 DI(종속성 주입)를 통해 Scoped 라이프타임으로 등록되어야 합니다.
    /// </summary>
    public class PrincipalAccessor : IPrincipalAccessor
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public PrincipalAccessor(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        /// <inheritdoc />
        // 수정: private -> public으로 변경하여 인터페이스 멤버를 올바르게 구현합니다.
        public ClaimsPrincipal? Principal => _httpContextAccessor.HttpContext?.User;

        /// <inheritdoc />
        public Task<ClaimsPrincipal?> GetPrincipalAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Principal);
        }

        /// <inheritdoc />
        public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated ?? false;
        
        /// <inheritdoc />
        public Guid? UserId => GetGuidClaimValue(System.Security.Claims.ClaimTypes.NameIdentifier);

        /// <inheritdoc />
        public Guid? ConnectedId => GetGuidClaimValue(AuthConstants.ClaimTypes.ConnectedId);

        /// <inheritdoc />
        public Guid? OrganizationId => GetGuidClaimValue(AuthConstants.ClaimTypes.OrganizationId);

        /// <inheritdoc />
        public Guid? SessionId => GetGuidClaimValue(AuthConstants.ClaimTypes.SessionId);
        
        /// <inheritdoc />
        public string? IpAddress => _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
        
        /// <inheritdoc />
        public bool HasConnectedId => ConnectedId.HasValue && ConnectedId.Value != Guid.Empty;

        /// <summary>
        /// ClaimsPrincipal에서 Guid 타입의 클레임 값을 안전하게 파싱하여 가져오는 헬퍼 메서드입니다.
        /// </summary>
        private Guid? GetGuidClaimValue(string claimType)
        {
            var claimValue = Principal?.FindFirst(claimType)?.Value;

            if (string.IsNullOrEmpty(claimValue) || !Guid.TryParse(claimValue, out var guidValue))
            {
                return null;
            }

            return guidValue;
        }
    }
}

