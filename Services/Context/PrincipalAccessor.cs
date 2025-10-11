using System;
using System.Security.Claims;
using AuthHive.Core.Constants.Auth; // AuthConstants 사용
using AuthHive.Core.Interfaces.Base;
using Microsoft.AspNetCore.Http;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// IHttpContextAccessor를 사용하여 현재 요청의 Principal 정보를 구현하는 클래스입니다.
    /// PASETO 토큰에서 커스텀 클레임을 파싱하여 필요한 ID를 제공합니다.
    /// </summary>
    public class PrincipalAccessor : IPrincipalAccessor
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public PrincipalAccessor(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// 현재 HTTP 컨텍스트에서 ClaimsPrincipal을 가져옵니다.
        /// </summary>
        public ClaimsPrincipal? Principal => _httpContextAccessor.HttpContext?.User;

        /// <summary>
        /// "sub" 클레임에서 User ID를 파싱합니다. 실패 시 Guid.Empty를 반환합니다.
        /// </summary>
        public Guid UserId => GetGuidClaim(AuthConstants.ClaimTypes.Subject);//Subject ==> UserId

        /// <summary>
        /// "cid" 클레임에서 Connected ID를 파싱합니다. 실패 시 Guid.Empty를 반환합니다.
        /// </summary>
        public Guid ConnectedId => GetGuidClaim(AuthConstants.ClaimTypes.ConnectedId);

        /// <summary>
        /// "org_id" 클레임에서 Organization ID를 파싱합니다. 실패 시 Guid.Empty를 반환합니다.
        /// </summary>
        public Guid OrganizationId => GetGuidClaim(AuthConstants.ClaimTypes.OrganizationId);

        /// <summary>
        /// Principal에서 특정 클레임 타입의 값을 Guid로 안전하게 파싱하는 헬퍼 메서드입니다.
        /// </summary>
        /// <param name="claimType">찾으려는 클레임의 타입</param>
        /// <returns>파싱된 Guid 또는 실패 시 Guid.Empty</returns>
        private Guid GetGuidClaim(string claimType)
        {
            var claimValue = Principal?.FindFirstValue(claimType);
            return Guid.TryParse(claimValue, out var parsedGuid) ? parsedGuid : Guid.Empty;
        }
    }
}